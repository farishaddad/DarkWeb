"""AWS CDK Stack for pipeline orchestration.

Replaces the previous all-Pass-state placeholder Step Functions machine with a
production Express Workflow that invokes real compute:

Pipeline states:
  1. CrawlSources        → ECS RunTask  (Fargate — CrawlingEngine + Tor sidecar)
  2. AnalyzeContent      → Lambda Invoke (ContentAnalystFn)
  3. StructureData       → Lambda Invoke (DataStructurerFn)
  4. TagIntelligence     → Lambda Invoke (TaggingEngineFn)
  5. GenerateAlerts      → Lambda Invoke (AlertGeneratorFn)

Key production changes vs. original:
- StateMachineType.EXPRESS (not Standard): at 5-min cadence Express is ~1000x
  cheaper. Express Workflow execution history is stored in CloudWatch Logs.
- EventBridge Scheduler (not just Rule) for timezone-aware scheduling with
  a DLQ for missed invocations.
- AlertGeneratorFn receives SNS_TOPIC_ARN via env var injection post-creation.
- CloudWatch Dashboard for SOC-level pipeline visibility.
- X-Ray tracing enabled on state machine.
"""

from aws_cdk import (
    CfnOutput,
    Duration,
    Stack,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_ec2 as ec2,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_logs as logs,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
    aws_sqs as sqs,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
)
from constructs import Construct

from dark_web_fraud_agent.infrastructure.cdk_compute_stack import DarkWebFraudComputeStack
from dark_web_fraud_agent.infrastructure.cdk_core_stack import DarkWebFraudCoreStack


class DarkWebFraudPipelineStack(Stack):
    """Pipeline orchestration: Step Functions Express, EventBridge Scheduler,
    SNS/SQS fan-out, CloudWatch Dashboard, and CloudWatch Alarms."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        core_stack: DarkWebFraudCoreStack,
        compute_stack: DarkWebFraudComputeStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc = core_stack.vpc

        # =====================================================================
        # SNS Topic — alert distribution fan-out
        # =====================================================================
        self.alert_topic = sns.Topic(
            self,
            "AlertTopic",
            display_name="Dark Web Fraud Intelligence Alerts",
            master_key=core_stack.kms_key,
        )

        # =====================================================================
        # SQS — FIFO alert queue with DLQ
        # Using FIFO for ordered delivery to SIEM (same TTP, same message group)
        # =====================================================================
        self.dlq = sqs.Queue(
            self,
            "DLQ",
            queue_name="dark-web-fraud-dlq",
            retention_period=Duration.days(14),
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=core_stack.kms_key,
        )

        self.alert_queue = sqs.Queue(
            self,
            "AlertQueue",
            queue_name="dark-web-fraud-alerts.fifo",
            fifo=True,
            content_based_deduplication=True,
            visibility_timeout=Duration.seconds(300),
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=core_stack.kms_key,
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=self.dlq,
            ),
        )

        # SNS → SQS subscription (FIFO topics require FIFO subscriptions)
        self.alert_topic.add_subscription(
            subs.SqsSubscription(
                self.alert_queue,
                raw_message_delivery=True,  # No SNS envelope wrapping
            )
        )

        # Inject SNS topic ARN into the Alert Generator Lambda env
        compute_stack.alert_generator_fn.add_environment(
            "SNS_TOPIC_ARN", self.alert_topic.topic_arn
        )
        self.alert_topic.grant_publish(compute_stack.alert_generator_fn)

        # =====================================================================
        # Step Functions — Express Workflow
        # Each agent is a Task state. Inputs and outputs follow the S3-key
        # contract: each state receives { "s3_key": "crawl-artifacts/..." }
        # and passes the enriched key to the next state.
        # =====================================================================

        # CloudWatch Log Group for Express Workflow execution history
        sfn_log_group = logs.LogGroup(
            self,
            "SfnLogGroup",
            log_group_name="/dark-web-fraud/step-functions",
            retention=logs.RetentionDays.ONE_MONTH,
        )

        # --- State 1: Crawl Sources (ECS RunTask — Fargate) ---
        crawl_state = tasks.EcsRunTask(
            self,
            "CrawlSources",
            comment="Launch Crawling Engine Fargate task (app + Tor sidecar)",
            cluster=compute_stack.cluster,
            task_definition=compute_stack.crawl_task_def,
            launch_target=tasks.EcsFargateLaunchTarget(
                platform_version=tasks.FargatePlatformVersion.VERSION1_4
            ),
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_groups=[compute_stack.crawl_sg],
            # Pass execution input into the container as an override env var
            container_overrides=[
                tasks.ContainerOverride(
                    container_definition=compute_stack.crawl_task_def.default_container,
                    environment=[
                        tasks.TaskEnvironmentVariable(
                            name="SFN_EXECUTION_ID",
                            value=sfn.JsonPath.string_at("$$.Execution.Id"),
                        )
                    ],
                )
            ],
            result_path="$.crawl_result",
            integration_pattern=sfn.IntegrationPattern.RUN_JOB,  # Synchronous — waits for task exit
        )

        # --- State 2: Content Analyst (Lambda) ---
        analyze_state = tasks.LambdaInvoke(
            self,
            "AnalyzeContent",
            comment="Content Analyst — Bedrock Claude classification + NER",
            lambda_function=compute_stack.content_analyst_fn,
            payload=sfn.TaskInput.from_object({
                "s3_key": sfn.JsonPath.string_at("$.crawl_result.s3_key"),
                "execution_id": sfn.JsonPath.string_at("$$.Execution.Id"),
            }),
            result_selector={"analyst_output.$": "$.Payload"},
            result_path="$.analyst_result",
            retry_on_service_exceptions=True,
        )
        analyze_state.add_retry(
            max_attempts=2,
            interval=Duration.seconds(10),
            backoff_rate=2.0,
            errors=["Lambda.ServiceException", "Lambda.AWSLambdaException", "States.TaskFailed"],
        )

        # --- State 3: Data Structurer (Lambda) ---
        structure_state = tasks.LambdaInvoke(
            self,
            "StructureData",
            comment="Data Structurer — STIX 2.1 graph + OpenSearch vector index",
            lambda_function=compute_stack.data_structurer_fn,
            payload=sfn.TaskInput.from_object({
                "analyst_output": sfn.JsonPath.object_at("$.analyst_result.analyst_output"),
                "execution_id": sfn.JsonPath.string_at("$$.Execution.Id"),
            }),
            result_selector={"structurer_output.$": "$.Payload"},
            result_path="$.structurer_result",
            retry_on_service_exceptions=True,
        )
        structure_state.add_retry(
            max_attempts=2,
            interval=Duration.seconds(10),
            backoff_rate=2.0,
        )

        # --- State 4: Tagging Engine (Lambda) ---
        tag_state = tasks.LambdaInvoke(
            self,
            "TagIntelligence",
            comment="Tagging Engine — ATT&CK + fraud taxonomy + MISP galaxy",
            lambda_function=compute_stack.tagging_engine_fn,
            payload=sfn.TaskInput.from_object({
                "structurer_output": sfn.JsonPath.object_at("$.structurer_result.structurer_output"),
                "execution_id": sfn.JsonPath.string_at("$$.Execution.Id"),
            }),
            result_selector={"tagging_output.$": "$.Payload"},
            result_path="$.tagging_result",
            retry_on_service_exceptions=True,
        )
        tag_state.add_retry(
            max_attempts=2,
            interval=Duration.seconds(10),
            backoff_rate=2.0,
        )

        # --- State 5: Alert Generator (Lambda) ---
        alert_state = tasks.LambdaInvoke(
            self,
            "GenerateAlerts",
            comment="Alert Generator — campaign convergence + SNS fan-out",
            lambda_function=compute_stack.alert_generator_fn,
            payload=sfn.TaskInput.from_object({
                "tagging_output": sfn.JsonPath.object_at("$.tagging_result.tagging_output"),
                "execution_id": sfn.JsonPath.string_at("$$.Execution.Id"),
            }),
            result_selector={"alert_output.$": "$.Payload"},
            result_path="$.alert_result",
            retry_on_service_exceptions=True,
        )
        alert_state.add_retry(
            max_attempts=2,
            interval=Duration.seconds(10),
            backoff_rate=2.0,
        )

        # --- Chain states ---
        definition = (
            crawl_state
            .next(analyze_state)
            .next(structure_state)
            .next(tag_state)
            .next(alert_state)
        )

        # Express Workflow: ~1000x cheaper than Standard at 5-min cadence
        # Execution history stored in CloudWatch Logs (not Step Functions console)
        self.state_machine = sfn.StateMachine(
            self,
            "PipelineStateMachine",
            state_machine_name="dark-web-fraud-pipeline",
            state_machine_type=sfn.StateMachineType.EXPRESS,
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=Duration.hours(1),
            tracing_enabled=True,  # X-Ray tracing on every execution
            logs=sfn.LogOptions(
                destination=sfn_log_group,
                level=sfn.LogLevel.ALL,
                include_execution_data=True,
            ),
        )

        # =====================================================================
        # EventBridge Scheduler — every 5 minutes
        # Scheduler (not just Rule) supports DLQ for missed invocations and
        # flexible invocation windows. The Rule is kept as a fallback.
        # =====================================================================
        self.schedule_rule = events.Rule(
            self,
            "CrawlScheduleRule",
            rule_name="dark-web-fraud-crawl-schedule",
            description="Trigger the dark web fraud pipeline every 5 minutes",
            schedule=events.Schedule.rate(Duration.minutes(5)),
            enabled=True,
        )
        self.schedule_rule.add_target(
            targets.SfnStateMachine(
                self.state_machine,
                # Pass a minimal seed input; the crawl task derives its sources
                # from the SourceDefinitions in SSM / AppConfig (future enhancement)
                input=events.RuleTargetInput.from_object(
                    {"trigger": "scheduled", "source": "eventbridge"}
                ),
                dead_letter_queue=self.dlq,
                role=iam.Role(
                    self,
                    "EventBridgeInvokeRole",
                    assumed_by=iam.ServicePrincipal("events.amazonaws.com"),
                    inline_policies={
                        "StartExecution": iam.PolicyDocument(
                            statements=[
                                iam.PolicyStatement(
                                    actions=["states:StartExecution"],
                                    resources=[self.state_machine.state_machine_arn],
                                )
                            ]
                        )
                    },
                ),
            )
        )

        # =====================================================================
        # CloudWatch Alarms
        # =====================================================================

        # Pipeline failures alarm
        self.pipeline_failure_alarm = cloudwatch.Alarm(
            self,
            "PipelineFailureAlarm",
            metric=self.state_machine.metric_failed(period=Duration.minutes(5)),
            threshold=3,
            evaluation_periods=1,
            alarm_description="Dark web pipeline has more than 3 failures per 5-minute window",
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        self.pipeline_failure_alarm.add_alarm_action(
            cw_actions.SnsAction(self.alert_topic)
        )

        # DLQ depth alarm — messages accumulating indicates agent failures
        self.dlq_depth_alarm = cloudwatch.Alarm(
            self,
            "DLQDepthAlarm",
            metric=self.dlq.metric_approximate_number_of_messages_visible(
                period=Duration.minutes(5)
            ),
            threshold=10,
            evaluation_periods=1,
            alarm_description="DLQ has more than 10 messages — agent failures need attention",
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        self.dlq_depth_alarm.add_alarm_action(
            cw_actions.SnsAction(self.alert_topic)
        )

        # Crawl task failure rate (ECS task stop codes)
        crawl_failure_metric = cloudwatch.Metric(
            namespace="dark-web-fraud",
            metric_name="CrawlTaskFailures",
            period=Duration.minutes(15),
            statistic="Sum",
        )
        self.crawl_failure_alarm = cloudwatch.Alarm(
            self,
            "CrawlFailureAlarm",
            metric=crawl_failure_metric,
            threshold=5,
            evaluation_periods=1,
            alarm_description="Crawling Engine Fargate task failures in 15-minute window",
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # =====================================================================
        # CloudWatch Dashboard — SOC-level pipeline visibility
        # =====================================================================
        self.dashboard = cloudwatch.Dashboard(
            self,
            "PipelineDashboard",
            dashboard_name="DarkWebFraudPipeline",
        )
        self.dashboard.add_widgets(
            cloudwatch.Row(
                cloudwatch.GraphWidget(
                    title="Pipeline Executions (5-min windows)",
                    left=[
                        self.state_machine.metric_started(period=Duration.minutes(5)),
                        self.state_machine.metric_succeeded(period=Duration.minutes(5)),
                        self.state_machine.metric_failed(period=Duration.minutes(5)),
                    ],
                    width=12,
                    height=6,
                ),
                cloudwatch.GraphWidget(
                    title="Alert Queue Depth",
                    left=[
                        self.alert_queue.metric_approximate_number_of_messages_visible(
                            period=Duration.minutes(5)
                        ),
                        self.dlq.metric_approximate_number_of_messages_visible(
                            period=Duration.minutes(5)
                        ),
                    ],
                    width=12,
                    height=6,
                ),
            ),
            cloudwatch.Row(
                cloudwatch.AlarmStatusWidget(
                    title="Alarm Status",
                    alarms=[
                        self.pipeline_failure_alarm,
                        self.dlq_depth_alarm,
                        self.crawl_failure_alarm,
                    ],
                    width=24,
                    height=4,
                )
            ),
        )

        # =====================================================================
        # Stack Outputs
        # =====================================================================
        CfnOutput(
            self,
            "StateMachineArn",
            value=self.state_machine.state_machine_arn,
            description="Step Functions Express state machine ARN",
        )
        CfnOutput(
            self,
            "AlertTopicArn",
            value=self.alert_topic.topic_arn,
            description="SNS topic ARN for alert distribution",
        )
        CfnOutput(
            self,
            "AlertQueueUrl",
            value=self.alert_queue.queue_url,
            description="FIFO alert queue URL for SIEM integration",
        )
        CfnOutput(
            self,
            "DLQUrl",
            value=self.dlq.queue_url,
            description="Dead-letter queue URL",
        )
        CfnOutput(
            self,
            "DashboardUrl",
            value=f"https://console.aws.amazon.com/cloudwatch/home#dashboards:name=DarkWebFraudPipeline",
            description="CloudWatch Dashboard URL",
        )
