"""AWS CDK Stack for core infrastructure.

Provisions:
- Multi-AZ VPC with public / private-egress / isolated subnets
  and 2 NAT Gateways (one per AZ for HA)
- VPC Interface Endpoints for Bedrock, Secrets Manager, OpenSearch, ECR,
  CloudWatch Logs — Lambda/ECS agents never route AWS API calls via NAT
- S3 Gateway Endpoint (free, removes S3 traffic from NAT bandwidth)
- DynamoDB Gateway Endpoint (free)
- KMS Customer Managed Key (CMK) for encryption at rest across all services
- S3 artifacts bucket with CMK encryption, Object Lock (WORM for forensic
  integrity), versioning, and Intelligent-Tiering lifecycle
- DynamoDB tables:
    - Agent State (crawl circuit-breaker state)
    - Convergence (TTP convergence + entity co-occurrence with TTL + GSI)
- Secrets Manager secrets for Tor proxy and MISP API credentials
- Per-agent IAM roles with least-privilege policies

Requirements: 1.1, 8.1
"""

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    Tags,
    aws_dynamodb as dynamodb,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_kms as kms,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
)
from constructs import Construct


class DarkWebFraudCoreStack(Stack):
    """Core infrastructure: VPC, KMS, S3, DynamoDB, Secrets Manager, IAM.

    This stack has no dependencies and must be deployed first.
    All other stacks depend on resources exported from here.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Apply project-wide tags to all resources in this stack
        Tags.of(self).add("Project", "dark-web-fraud")
        Tags.of(self).add("Env", "prod")

        # =================================================================
        # KMS Customer Managed Key
        # Shared CMK — key policies scope access per-agent IAM role.
        # =================================================================
        self.kms_key = kms.Key(
            self,
            "DarkWebFraudCMK",
            alias="alias/dark-web-fraud",
            description="Dark Web Fraud Intelligence Agent — CMK for all data at rest",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # =================================================================
        # VPC — two NAT Gateways for HA Tor egress
        # =================================================================
        self.vpc = ec2.Vpc(
            self,
            "TorProxyVpc",
            max_azs=2,
            nat_gateways=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                    # Fargate crawl tasks — egress via NAT → Tor
                ),
                ec2.SubnetConfiguration(
                    name="Isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                    # Lambda agents — reach AWS services ONLY via VPC endpoints
                ),
            ],
        )

        # =================================================================
        # VPC Gateway Endpoints (free — no per-hour cost)
        # =================================================================
        self.vpc.add_gateway_endpoint(
            "S3GatewayEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
        )

        self.vpc.add_gateway_endpoint(
            "DynamoDBGatewayEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.DYNAMODB,
        )

        # =================================================================
        # VPC Interface Endpoints — keep Lambda/ECS off NAT for AWS APIs
        # =================================================================
        endpoint_sg = ec2.SecurityGroup(
            self,
            "VpcEndpointSG",
            vpc=self.vpc,
            security_group_name="dark-web-fraud-vpc-endpoint-sg",
            description="Allow HTTPS from Isolated subnets to VPC Interface Endpoints",
            allow_all_outbound=False,
        )

        for subnet in self.vpc.isolated_subnets:
            endpoint_sg.add_ingress_rule(
                peer=ec2.Peer.ipv4(subnet.ipv4_cidr_block),
                connection=ec2.Port.tcp(443),
                description=f"HTTPS from Isolated subnet {subnet.node.id}",
            )

        isolated_selection = ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
        )

        # Secrets Manager (used by crawl task + Lambda agents)
        self.vpc.add_interface_endpoint(
            "SecretsManagerEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
            subnets=isolated_selection,
            security_groups=[endpoint_sg],
            private_dns_enabled=True,
        )

        # Bedrock Runtime (Content Analyst + Data Structurer)
        self.vpc.add_interface_endpoint(
            "BedrockRuntimeEndpoint",
            service=ec2.InterfaceVpcEndpointService(
                f"com.amazonaws.{self.region}.bedrock-runtime", port=443
            ),
            subnets=isolated_selection,
            security_groups=[endpoint_sg],
            private_dns_enabled=True,
        )

        # OpenSearch Serverless (Data Structurer + Alert Generator)
        self.vpc.add_interface_endpoint(
            "OpenSearchServerlessEndpoint",
            service=ec2.InterfaceVpcEndpointService(
                f"com.amazonaws.{self.region}.aoss", port=443
            ),
            subnets=isolated_selection,
            security_groups=[endpoint_sg],
            private_dns_enabled=True,
        )

        # ECR (Fargate image pull without NAT)
        self.vpc.add_interface_endpoint(
            "EcrApiEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR,
            subnets=isolated_selection,
            security_groups=[endpoint_sg],
            private_dns_enabled=True,
        )
        self.vpc.add_interface_endpoint(
            "EcrDockerEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
            subnets=isolated_selection,
            security_groups=[endpoint_sg],
            private_dns_enabled=True,
        )

        # CloudWatch Logs (Lambda + ECS log shipping)
        self.vpc.add_interface_endpoint(
            "CloudWatchLogsEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            subnets=isolated_selection,
            security_groups=[endpoint_sg],
            private_dns_enabled=True,
        )

        # =================================================================
        # S3 Artifacts Bucket
        # - CMK encryption (auditable via CloudTrail)
        # - Versioning + Object Lock (WORM) for forensic integrity
        # - Intelligent-Tiering lifecycle (archives cold artifacts)
        # =================================================================
        self.artifacts_bucket = s3.Bucket(
            self,
            "ArtifactsBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN,
            versioned=True,
            object_lock_enabled=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="IntelligentTiering",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                            transition_after=Duration.days(0),
                        ),
                    ],
                    noncurrent_version_expiration=Duration.days(90),
                    abort_incomplete_multipart_upload_after=Duration.days(7),
                ),
                s3.LifecycleRule(
                    id="ExpireRawArtifacts",
                    prefix="crawl-artifacts/",
                    expiration=Duration.days(365),
                ),
            ],
        )

        # =================================================================
        # DynamoDB Tables — CMK encryption, PAY_PER_REQUEST billing
        # =================================================================

        # Agent state table (crawl circuit-breaker state)
        self.agent_state_table = dynamodb.Table(
            self,
            "AgentStateTable",
            table_name="dark-web-fraud-agent-state",
            partition_key=dynamodb.Attribute(
                name="PK", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="SK", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.kms_key,
            removal_policy=RemovalPolicy.RETAIN,
            point_in_time_recovery=True,
        )

        # Convergence table (TTP convergence + entity co-occurrence)
        # Streams enabled: Alert Generator Lambda triggers on convergence events
        self.convergence_table = dynamodb.Table(
            self,
            "ConvergenceTable",
            table_name="dark-web-fraud-convergence",
            partition_key=dynamodb.Attribute(
                name="PK", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="SK", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.kms_key,
            removal_policy=RemovalPolicy.RETAIN,
            time_to_live_attribute="TTL",
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            point_in_time_recovery=True,
        )

        # GSI: entity-cooccurrence-index
        # PK: PK (STRING) — queries ENTITY#bank_name#<institution> items
        # SK: SK (STRING)
        # Projection: ALL
        self.convergence_table.add_global_secondary_index(
            index_name="entity-cooccurrence-index",
            partition_key=dynamodb.Attribute(
                name="PK", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="SK", type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # =================================================================
        # Secrets Manager — Tor + MISP credentials
        # =================================================================
        self.tor_credentials = secretsmanager.Secret(
            self,
            "TorCredentials",
            secret_name="dark-web-fraud/tor-control-password",
            description="Tor control port password for CrawlingEngine circuit rotation",
            encryption_key=self.kms_key,
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True,
                password_length=32,
            ),
        )

        self.misp_api_key = secretsmanager.Secret(
            self,
            "MispApiKey",
            secret_name="dark-web-fraud/misp-api-key",
            description="MISP REST API key for event publishing",
            encryption_key=self.kms_key,
        )

        # =================================================================
        # IAM Roles — least-privilege per agent
        # =================================================================

        # Crawling Engine role (ECS Fargate task)
        self.crawling_engine_role = iam.Role(
            self,
            "CrawlingEngineRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            role_name="dark-web-fraud-crawling-engine",
            description="Crawling Engine — S3 write, DynamoDB state, Secrets read",
        )
        self.artifacts_bucket.grant_read_write(self.crawling_engine_role)
        self.agent_state_table.grant_read_write_data(self.crawling_engine_role)
        self.tor_credentials.grant_read(self.crawling_engine_role)

        # Content Analyst role (Lambda)
        self.content_analyst_role = iam.Role(
            self,
            "ContentAnalystRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="dark-web-fraud-content-analyst",
            description="Content Analyst — S3 read, Bedrock invoke",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
            ],
        )
        self.artifacts_bucket.grant_read(self.content_analyst_role)
        self.content_analyst_role.add_to_policy(
            iam.PolicyStatement(
                actions=["bedrock:InvokeModel", "bedrock:ApplyGuardrail"],
                resources=["*"],
                effect=iam.Effect.ALLOW,
            )
        )

        # Data Structurer role (Lambda)
        self.data_structurer_role = iam.Role(
            self,
            "DataStructurerRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="dark-web-fraud-data-structurer",
            description="Data Structurer — S3 read/write, OpenSearch, Bedrock embeddings",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
            ],
        )
        self.artifacts_bucket.grant_read_write(self.data_structurer_role)
        self.data_structurer_role.add_to_policy(
            iam.PolicyStatement(
                actions=["bedrock:InvokeModel"],
                resources=["*"],
                effect=iam.Effect.ALLOW,
            )
        )
        self.data_structurer_role.add_to_policy(
            iam.PolicyStatement(
                actions=["aoss:APIAccessAll"],
                resources=["*"],
                effect=iam.Effect.ALLOW,
            )
        )
        self.misp_api_key.grant_read(self.data_structurer_role)

        # Tagging Engine role (Lambda)
        self.tagging_engine_role = iam.Role(
            self,
            "TaggingEngineRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="dark-web-fraud-tagging-engine",
            description="Tagging Engine — S3 read (taxonomy), Knowledge Base query",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
            ],
        )
        self.artifacts_bucket.grant_read(self.tagging_engine_role)
        self.tagging_engine_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "bedrock:Retrieve",
                    "bedrock:RetrieveAndGenerate",
                ],
                resources=["*"],
                effect=iam.Effect.ALLOW,
            )
        )
        self.misp_api_key.grant_read(self.tagging_engine_role)

        # Alert Generator role (Lambda)
        self.alert_generator_role = iam.Role(
            self,
            "AlertGeneratorRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="dark-web-fraud-alert-generator",
            description="Alert Generator — DynamoDB convergence, OpenSearch query, SNS publish",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
            ],
        )
        self.convergence_table.grant_read_write_data(self.alert_generator_role)
        self.artifacts_bucket.grant_read(self.alert_generator_role)
        self.alert_generator_role.add_to_policy(
            iam.PolicyStatement(
                actions=["aoss:APIAccessAll"],
                resources=["*"],
                effect=iam.Effect.ALLOW,
            )
        )
        self.alert_generator_role.add_to_policy(
            iam.PolicyStatement(
                actions=["cloudwatch:PutMetricData"],
                resources=["*"],
                conditions={
                    "StringEquals": {"cloudwatch:namespace": "dark-web-fraud"}
                },
                effect=iam.Effect.ALLOW,
            )
        )

        # =================================================================
        # Stack Outputs
        # =================================================================
        CfnOutput(self, "VpcId", value=self.vpc.vpc_id)
        CfnOutput(self, "BucketName", value=self.artifacts_bucket.bucket_name)
        CfnOutput(self, "KmsKeyArn", value=self.kms_key.key_arn)

        # SSM parameter for cross-stack KMS ARN reference (avoids dependency cycles)
        ssm.StringParameter(
            self,
            "KmsKeyArnParam",
            parameter_name="/dark-web-fraud/kms-key-arn",
            string_value=self.kms_key.key_arn,
        )
        CfnOutput(
            self,
            "AgentStateTableName",
            value=self.agent_state_table.table_name,
        )
        CfnOutput(
            self,
            "ConvergenceTableName",
            value=self.convergence_table.table_name,
        )
        CfnOutput(
            self,
            "ConvergenceTableStreamArn",
            value=self.convergence_table.table_stream_arn or "streams-not-enabled",
            description="DynamoDB Streams ARN for Alert Generator Lambda event source",
        )
