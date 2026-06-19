"""AWS CDK Stack for pipeline orchestration (Step Functions, EventBridge, SNS/SQS, CloudWatch)."""

from aws_cdk import (
    CfnOutput,
    Duration,
    Stack,
    aws_cloudwatch as cloudwatch,
    aws_events as events,
    aws_events_targets as targets,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
    aws_sqs as sqs,
    aws_stepfunctions as sfn,
)
from constructs import Construct


class DarkWebFraudPipelineStack(Stack):
    """Pipeline orchestration stack: Step Functions, EventBridge, SNS/SQS, CloudWatch alarms."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- SNS Topic for alert distribution ---
        self.alert_topic = sns.Topic(
            self,
            "AlertTopic",
            display_name="Dark Web Fraud Intelligence Alerts",
        )

        # --- SQS Dead-Letter Queue (14 day retention) ---
        self.dlq = sqs.Queue(
            self,
            "DLQ",
            queue_name="dark-web-fraud-dlq",
            retention_period=Duration.days(14),
        )

        # --- SQS Alert Queue with DLQ redrive policy ---
        self.alert_queue = sqs.Queue(
            self,
            "AlertQueue",
            queue_name="dark-web-fraud-alerts",
            visibility_timeout=Duration.seconds(300),
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=self.dlq,
            ),
        )

        # --- SNS subscription to SQS alert queue ---
        self.alert_topic.add_subscription(subs.SqsSubscription(self.alert_queue))

        # --- Step Functions State Machine ---
        # Placeholder Pass states for each agent in the pipeline
        crawl_state = sfn.Pass(
            self,
            "CrawlSources",
            comment="Invoke Crawling Engine Agent",
        )

        analyze_state = sfn.Pass(
            self,
            "AnalyzeContent",
            comment="Invoke Content Analyst Agent",
        )

        structure_state = sfn.Pass(
            self,
            "StructureData",
            comment="Invoke Data Structurer Agent",
        )

        tag_state = sfn.Pass(
            self,
            "TagIntelligence",
            comment="Invoke Tagging Engine Agent",
        )

        alert_state = sfn.Pass(
            self,
            "GenerateAlerts",
            comment="Invoke Alert Generator Agent",
        )

        # Chain agents in pipeline order
        definition = (
            crawl_state
            .next(analyze_state)
            .next(structure_state)
            .next(tag_state)
            .next(alert_state)
        )

        self.state_machine = sfn.StateMachine(
            self,
            "PipelineStateMachine",
            state_machine_name="dark-web-fraud-pipeline",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=Duration.hours(1),
        )

        # --- EventBridge rule (every 5 minutes → state machine) ---
        self.schedule_rule = events.Rule(
            self,
            "CrawlScheduleRule",
            rule_name="dark-web-fraud-crawl-schedule",
            schedule=events.Schedule.rate(Duration.minutes(5)),
            enabled=True,
        )

        self.schedule_rule.add_target(
            targets.SfnStateMachine(self.state_machine)
        )

        # --- CloudWatch Alarms ---
        # Pipeline failures alarm (> 3 failures per evaluation period)
        self.pipeline_failure_alarm = cloudwatch.Alarm(
            self,
            "PipelineFailureAlarm",
            metric=self.state_machine.metric_failed(),
            threshold=3,
            evaluation_periods=1,
            alarm_description="Alert when pipeline has more than 3 failures per evaluation period",
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        )

        # DLQ depth alarm (> 10 messages)
        self.dlq_depth_alarm = cloudwatch.Alarm(
            self,
            "DLQDepthAlarm",
            metric=self.dlq.metric_approximate_number_of_messages_visible(),
            threshold=10,
            evaluation_periods=1,
            alarm_description="Alert when DLQ has more than 10 messages",
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        )

        # --- Stack Outputs ---
        CfnOutput(
            self,
            "StateMachineArn",
            value=self.state_machine.state_machine_arn,
            description="Step Functions state machine ARN",
        )

        CfnOutput(
            self,
            "AlertTopicArn",
            value=self.alert_topic.topic_arn,
            description="SNS topic ARN for alert distribution",
        )

        CfnOutput(
            self,
            "DLQUrl",
            value=self.dlq.queue_url,
            description="Dead-letter queue URL",
        )
