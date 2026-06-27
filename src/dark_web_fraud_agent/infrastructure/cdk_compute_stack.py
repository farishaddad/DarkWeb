"""AWS CDK Stack for compute infrastructure.

Defines:
- ECR repository for the Crawling Engine container image
- ECS Cluster + Fargate Task Definition (app container + Tor sidecar)
- Security Group for crawl tasks (egress-only, no inbound)
- Lambda functions for the 4 stateless agents (Content Analyst, Data Structurer,
  Tagging Engine, Alert Generator) — each with a dedicated IAM role scoped to
  exactly the permissions that agent's code calls
- DynamoDB Streams event source on the ConvergenceTable to trigger the Alert
  Generator reactively when convergence thresholds are crossed

Usage in app.py:
    compute = DarkWebFraudComputeStack(
        app, "DarkWebFraudCompute",
        core_stack=core,
        intelligence_stack=intelligence,
    )
"""

import aws_cdk as cdk
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_ec2 as ec2,
    aws_ecr as ecr,
    aws_ecs as ecs,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_lambda_event_sources as lambda_event_sources,
    aws_logs as logs,
    CfnOutput,
)
from constructs import Construct

from dark_web_fraud_agent.infrastructure.cdk_core_stack import DarkWebFraudCoreStack
from dark_web_fraud_agent.infrastructure.cdk_intelligence_stack import DarkWebFraudIntelligenceStack


class DarkWebFraudComputeStack(Stack):
    """Compute infrastructure: ECR, ECS/Fargate, Lambda, per-agent IAM roles."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        core_stack: DarkWebFraudCoreStack,
        intelligence_stack: DarkWebFraudIntelligenceStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Unpack cross-stack references
        vpc = core_stack.vpc
        artifacts_bucket = core_stack.artifacts_bucket
        agent_state_table = core_stack.agent_state_table
        convergence_table = core_stack.convergence_table
        tor_credentials = core_stack.tor_credentials
        misp_api_key = core_stack.misp_api_key
        kms_key = core_stack.kms_key

        opensearch_endpoint = intelligence_stack.opensearch_collection.attr_collection_endpoint
        opensearch_arn = intelligence_stack.opensearch_collection.attr_arn

        # =====================================================================
        # ECR Repository — Crawling Engine container image
        # =====================================================================
        self.crawling_ecr_repo = ecr.Repository(
            self,
            "CrawlingEngineRepo",
            repository_name="dark-web-fraud/crawling-engine",
            encryption=ecr.RepositoryEncryption.KMS,
            encryption_key=kms_key,
            image_scan_on_push=True,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                ecr.LifecycleRule(
                    max_image_count=5,
                    description="Retain the 5 most recent images",
                )
            ],
        )

        # =====================================================================
        # ECS Cluster
        # =====================================================================
        self.cluster = ecs.Cluster(
            self,
            "FraudAgentCluster",
            cluster_name="dark-web-fraud-agents",
            vpc=vpc,
            container_insights=True,
        )

        # =====================================================================
        # IAM Roles — Fargate task (task role + execution role)
        # =====================================================================

        # Task Role: runtime permissions for the crawling engine container code
        self.crawl_task_role = iam.Role(
            self,
            "CrawlTaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            role_name="dark-web-fraud-crawl-task-role",
            description="Runtime permissions for the Crawling Engine Fargate task",
        )
        artifacts_bucket.grant_read_write(self.crawl_task_role)
        agent_state_table.grant_read_write_data(self.crawl_task_role)
        tor_credentials.grant_read(self.crawl_task_role)
        kms_key.grant_encrypt_decrypt(self.crawl_task_role)
        # X-Ray tracing
        self.crawl_task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
                resources=["*"],
            )
        )

        # Execution Role: permissions for ECS *control plane* to start the task
        # (pull image from ECR, write container logs, read secrets for env injection)
        self.crawl_execution_role = iam.Role(
            self,
            "CrawlExecutionRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSTaskExecutionRolePolicy"
                )
            ],
        )
        self.crawling_ecr_repo.grant_pull(self.crawl_execution_role)
        # Allow ECS to read the Tor password secret for container env injection
        tor_credentials.grant_read(self.crawl_execution_role)

        # =====================================================================
        # CloudWatch Log Groups — one per container/function
        # =====================================================================
        crawl_log_group = logs.LogGroup(
            self,
            "CrawlLogGroup",
            log_group_name="/dark-web-fraud/crawling-engine",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )
        analyst_log_group = logs.LogGroup(
            self,
            "AnalystLogGroup",
            log_group_name="/dark-web-fraud/content-analyst",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )
        structurer_log_group = logs.LogGroup(
            self,
            "StructurerLogGroup",
            log_group_name="/dark-web-fraud/data-structurer",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )
        tagging_log_group = logs.LogGroup(
            self,
            "TaggingLogGroup",
            log_group_name="/dark-web-fraud/tagging-engine",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )
        alert_log_group = logs.LogGroup(
            self,
            "AlertLogGroup",
            log_group_name="/dark-web-fraud/alert-generator",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # =====================================================================
        # Fargate Task Definition — App container + Tor sidecar
        # =====================================================================
        self.crawl_task_def = ecs.FargateTaskDefinition(
            self,
            "CrawlTaskDef",
            family="dark-web-fraud-crawling-engine",
            cpu=1024,         # 1 vCPU shared across both containers
            memory_limit_mib=2048,
            task_role=self.crawl_task_role,
            execution_role=self.crawl_execution_role,
        )

        # --- Tor Sidecar ---
        # Exposes SOCKS5 on 9050 and control port on 9051 (loopback only —
        # no port mappings needed since app container shares the task network namespace).
        # CrawlingEngine.get_proxy_url() connects to 127.0.0.1:9050 by default.
        tor_container = self.crawl_task_def.add_container(
            "TorSidecar",
            # Use the official Tor proxy image or replace with a hardened internal image
            image=ecs.ContainerImage.from_registry("peterdavehello/tor-socks-proxy:latest"),
            container_name="tor-sidecar",
            cpu=256,
            memory_limit_mib=512,
            essential=True,  # If Tor dies, restart the whole task
            secrets={
                # Injected as TOR_HASHED_CONTROL_PASSWORD env var at task launch
                "TOR_HASHED_CONTROL_PASSWORD": ecs.Secret.from_secrets_manager(
                    tor_credentials
                ),
            },
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", "nc -z 127.0.0.1 9050 || exit 1"],
                interval=Duration.seconds(15),
                timeout=Duration.seconds(5),
                retries=3,
                start_period=Duration.seconds(20),
            ),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="tor-sidecar",
                log_group=crawl_log_group,
            ),
        )

        # --- Crawling Engine App Container ---
        app_container = self.crawl_task_def.add_container(
            "CrawlingEngineApp",
            image=ecs.ContainerImage.from_ecr_repository(
                self.crawling_ecr_repo, tag="latest"
            ),
            container_name="crawling-engine",
            cpu=768,
            memory_limit_mib=1536,
            essential=True,
            environment={
                "TOR_SOCKS_HOST": "127.0.0.1",
                "TOR_SOCKS_PORT": "9050",
                "TOR_CONTROL_PORT": "9051",
                "S3_BUCKET": artifacts_bucket.bucket_name,
                "DYNAMODB_TABLE": agent_state_table.table_name,
                "AWS_REGION": Stack.of(self).region,
            },
            secrets={
                "TOR_CONTROL_PASSWORD": ecs.Secret.from_secrets_manager(tor_credentials),
            },
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="crawling-engine",
                log_group=crawl_log_group,
            ),
        )

        # App container only starts after Tor sidecar passes its health check
        app_container.add_container_dependencies(
            ecs.ContainerDependency(
                container=tor_container,
                condition=ecs.ContainerDependencyCondition.HEALTHY,
            )
        )

        # --- Security Group for Crawl Tasks ---
        # Allow all egress (Tor traffic must reach the internet via NAT Gateway).
        # No inbound rules — crawl tasks are not reachable from within the VPC.
        self.crawl_sg = ec2.SecurityGroup(
            self,
            "CrawlTaskSG",
            vpc=vpc,
            security_group_name="dark-web-fraud-crawl-sg",
            description="Egress-only SG for Crawling Engine Fargate tasks",
            allow_all_outbound=True,
        )

        # =====================================================================
        # Lambda Functions — 4 stateless pipeline agents
        #
        # Code packaging: Code.from_asset("src") bundles the src/ directory.
        # Add a Makefile target or CDK BundlingOptions to pip-install
        # requirements.txt into the asset before deployment.
        #
        # Handler convention: each agent module should expose a `handler(event, context)`
        # function as the Lambda entry point — e.g.:
        #   dark_web_fraud_agent/agents/content_analyst.py  → def handler(event, ctx): ...
        # =====================================================================

        common_lambda_kwargs = dict(
            runtime=lambda_.Runtime.PYTHON_3_12,
            code=lambda_.Code.from_asset("src"),
            vpc=vpc,
            # Isolated subnet — reaches AWS services only via VPC Interface Endpoints,
            # never traverses the internet
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
            ),
            tracing=lambda_.Tracing.ACTIVE,
        )

        # ---- Content Analyst -----------------------------------------------
        analyst_role = iam.Role(
            self,
            "AnalystRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="dark-web-fraud-content-analyst-role",
            description="Content Analyst Lambda — Bedrock + S3 read only",
        )
        analyst_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            )
        )
        analyst_role.add_to_policy(
            iam.PolicyStatement(
                sid="BedrockInference",
                actions=["bedrock:InvokeModel", "bedrock:ApplyGuardrail"],
                # Scope to specific model ARN(s) in production
                resources=["*"],
            )
        )
        analyst_role.add_to_policy(
            iam.PolicyStatement(
                sid="AgentCoreKB",
                # IAM namespace is bedrock-agentcore: (not bedrock-agentcore-control:)
                actions=["bedrock-agentcore:Retrieve", "bedrock-agentcore:RetrieveAndGenerate"],
                resources=["*"],
            )
        )
        analyst_role.add_to_policy(
            iam.PolicyStatement(
                sid="XRayTracing",
                actions=["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
                resources=["*"],
            )
        )
        artifacts_bucket.grant_read(analyst_role)
        kms_key.grant_decrypt(analyst_role)

        self.content_analyst_fn = lambda_.Function(
            self,
            "ContentAnalystFn",
            function_name="dark-web-fraud-content-analyst",
            handler="dark_web_fraud_agent.agents.content_analyst.handler",
            timeout=Duration.minutes(5),
            memory_size=1024,
            role=analyst_role,
            log_group=analyst_log_group,
            environment={
                "S3_BUCKET": artifacts_bucket.bucket_name,
                "BEDROCK_MODEL_ID": "anthropic.claude-opus-4-5",
                "AWS_REGION": Stack.of(self).region,
            },
            **common_lambda_kwargs,
        )

        # ---- Data Structurer -----------------------------------------------
        structurer_role = iam.Role(
            self,
            "StructurerRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="dark-web-fraud-data-structurer-role",
            description="Data Structurer Lambda — Bedrock embeddings + OpenSearch writes",
        )
        structurer_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            )
        )
        structurer_role.add_to_policy(
            iam.PolicyStatement(
                sid="BedrockEmbeddings",
                actions=["bedrock:InvokeModel"],
                resources=["*"],  # Scope to Titan embed model ARN
            )
        )
        structurer_role.add_to_policy(
            iam.PolicyStatement(
                sid="OpenSearchWrite",
                actions=["aoss:APIAccessAll"],
                resources=[opensearch_arn],
            )
        )
        structurer_role.add_to_policy(
            iam.PolicyStatement(
                sid="XRayTracing",
                actions=["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
                resources=["*"],
            )
        )
        artifacts_bucket.grant_read_write(structurer_role)
        misp_api_key.grant_read(structurer_role)
        kms_key.grant_encrypt_decrypt(structurer_role)

        self.data_structurer_fn = lambda_.Function(
            self,
            "DataStructurerFn",
            function_name="dark-web-fraud-data-structurer",
            handler="dark_web_fraud_agent.agents.data_structurer.handler",
            timeout=Duration.minutes(5),
            memory_size=1024,
            role=structurer_role,
            log_group=structurer_log_group,
            environment={
                "S3_BUCKET": artifacts_bucket.bucket_name,
                "OPENSEARCH_ENDPOINT": opensearch_endpoint,
                "BEDROCK_EMBEDDING_MODEL_ID": "amazon.titan-embed-text-v2:0",
                "AWS_REGION": Stack.of(self).region,
            },
            **common_lambda_kwargs,
        )

        # ---- Tagging Engine ------------------------------------------------
        tagging_role = iam.Role(
            self,
            "TaggingRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="dark-web-fraud-tagging-engine-role",
            description="Tagging Engine Lambda — AgentCore KB reads + MISP writes",
        )
        tagging_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            )
        )
        tagging_role.add_to_policy(
            iam.PolicyStatement(
                sid="AgentCoreKBRead",
                actions=["bedrock-agentcore:Retrieve"],
                resources=["*"],
            )
        )
        tagging_role.add_to_policy(
            iam.PolicyStatement(
                sid="XRayTracing",
                actions=["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
                resources=["*"],
            )
        )
        artifacts_bucket.grant_read_write(tagging_role)
        misp_api_key.grant_read(tagging_role)
        kms_key.grant_encrypt_decrypt(tagging_role)

        self.tagging_engine_fn = lambda_.Function(
            self,
            "TaggingEngineFn",
            function_name="dark-web-fraud-tagging-engine",
            handler="dark_web_fraud_agent.agents.tagging_engine.handler",
            timeout=Duration.minutes(3),
            memory_size=512,
            role=tagging_role,
            log_group=tagging_log_group,
            environment={
                "S3_BUCKET": artifacts_bucket.bucket_name,
                "AWS_REGION": Stack.of(self).region,
            },
            **common_lambda_kwargs,
        )

        # ---- Alert Generator -----------------------------------------------
        alert_role = iam.Role(
            self,
            "AlertRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="dark-web-fraud-alert-generator-role",
            description="Alert Generator Lambda — OpenSearch reads + SNS publish + DynamoDB convergence",
        )
        alert_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            )
        )
        alert_role.add_to_policy(
            iam.PolicyStatement(
                sid="OpenSearchRead",
                actions=["aoss:APIAccessAll"],
                resources=[opensearch_arn],
            )
        )
        alert_role.add_to_policy(
            iam.PolicyStatement(
                sid="SnsPublish",
                # SNS topic ARN is injected via env var from the Pipeline stack
                actions=["sns:Publish"],
                resources=["*"],  # Scoped to specific topic ARN in pipeline stack
            )
        )
        alert_role.add_to_policy(
            iam.PolicyStatement(
                sid="XRayTracing",
                actions=["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
                resources=["*"],
            )
        )
        convergence_table.grant_read_write_data(alert_role)
        artifacts_bucket.grant_read_write(alert_role)
        kms_key.grant_encrypt_decrypt(alert_role)

        self.alert_generator_fn = lambda_.Function(
            self,
            "AlertGeneratorFn",
            function_name="dark-web-fraud-alert-generator",
            handler="dark_web_fraud_agent.agents.alert_generator.handler",
            timeout=Duration.minutes(3),
            memory_size=512,
            role=alert_role,
            log_group=alert_log_group,
            environment={
                "S3_BUCKET": artifacts_bucket.bucket_name,
                "DYNAMODB_CONVERGENCE_TABLE": convergence_table.table_name,
                "OPENSEARCH_ENDPOINT": opensearch_endpoint,
                "AWS_REGION": Stack.of(self).region,
                # SNS_TOPIC_ARN injected by PipelineStack after topic is created
            },
            **common_lambda_kwargs,
        )

        # --- Reactive DynamoDB Streams trigger for Alert Generator ---
        # ConvergenceTable has Streams enabled (NEW_AND_OLD_IMAGES) in CoreStack.
        # When new convergence records are written, trigger alert evaluation immediately
        # rather than waiting for the next Step Functions execution cycle.
        self.alert_generator_fn.add_event_source(
            lambda_event_sources.DynamoEventSource(
                convergence_table,
                starting_position=lambda_.StartingPosition.LATEST,
                batch_size=10,
                bisect_batch_on_error=True,  # Halve batch on error to isolate bad record
                retry_attempts=2,
                filters=[
                    # Only trigger on INSERT events — convergence records are write-once
                    lambda_.FilterCriteria.filter(
                        {"eventName": lambda_.FilterRule.is_equal("INSERT")}
                    )
                ],
            )
        )

        # =====================================================================
        # Stack Outputs
        # =====================================================================
        CfnOutput(self, "ClusterArn", value=self.cluster.cluster_arn)
        CfnOutput(self, "CrawlTaskDefArn", value=self.crawl_task_def.task_definition_arn)
        CfnOutput(self, "CrawlingEcrRepoUri", value=self.crawling_ecr_repo.repository_uri)
        CfnOutput(self, "ContentAnalystFnArn", value=self.content_analyst_fn.function_arn)
        CfnOutput(self, "DataStructurerFnArn", value=self.data_structurer_fn.function_arn)
        CfnOutput(self, "TaggingEngineFnArn", value=self.tagging_engine_fn.function_arn)
        CfnOutput(self, "AlertGeneratorFnArn", value=self.alert_generator_fn.function_arn)
