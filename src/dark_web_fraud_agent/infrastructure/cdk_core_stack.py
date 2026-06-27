"""AWS CDK Stack for core infrastructure.

Provisions:
- Multi-AZ VPC with public / private-egress / isolated subnets
  and 2 NAT Gateways (one per AZ — previously single-AZ SPOF)
- VPC Interface Endpoints for Bedrock, Secrets Manager, and OpenSearch so
  Lambda / ECS agents never route AWS API calls via the NAT Gateway
- S3 Gateway Endpoint (free, removes S3 traffic from NAT bandwidth)
- KMS Customer Managed Key (CMK) — used by S3, DynamoDB, ECR, and Secrets Manager
  so every decrypt/encrypt is auditable via CloudTrail
- S3 artifacts bucket with CMK encryption, Object Lock (WORM for forensic
  integrity), versioning, and Intelligent-Tiering lifecycle
- DynamoDB tables with CMK encryption and Streams enabled on ConvergenceTable
  (NEW_AND_OLD_IMAGES) so the Alert Generator Lambda can react to convergence
  events without waiting for the Step Functions polling cycle
- Secrets Manager secrets for Tor and MISP credentials
- Per-agent IAM roles (scoped least-privilege)
"""

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_dynamodb as dynamodb,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_kms as kms,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
)
from constructs import Construct


class DarkWebFraudCoreStack(Stack):
    """Core infrastructure: VPC, KMS, S3, DynamoDB, Secrets Manager, IAM."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # =====================================================================
        # KMS Customer Managed Key
        # Shared CMK — individual key policies in each resource scope access
        # per-agent IAM role.  In a higher-security environment, use separate
        # CMKs per data classification tier (raw / structured / alerts).
        # =====================================================================
        self.kms_key = kms.Key(
            self,
            "DarkWebFraudCMK",
            alias="alias/dark-web-fraud",
            description="Dark Web Fraud Intelligence Agent — CMK for all data at rest",
            enable_key_rotation=True,  # Annual rotation
            removal_policy=RemovalPolicy.RETAIN,
        )

        # =====================================================================
        # VPC — two NAT Gateways (previously single NAT = SPOF for Tor egress)
        # =====================================================================
        self.vpc = ec2.Vpc(
            self,
            "TorProxyVpc",
            max_azs=2,
            nat_gateways=2,       # One NAT per AZ — eliminates cross-AZ failover gap
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
                    # Fargate crawl tasks run here — egress via NAT → Tor internet
                ),
                ec2.SubnetConfiguration(
                    name="Isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                    # Lambda agents run here — reach AWS services ONLY via
                    # VPC endpoints, never the internet
                ),
            ],
        )

        # =====================================================================
        # VPC Endpoints — prevent Lambda/ECS API calls traversing NAT Gateway
        # =====================================================================

        # S3 Gateway Endpoint (free, handles S3 traffic for all subnets)
        self.vpc.add_gateway_endpoint(
            "S3GatewayEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
        )

        # DynamoDB Gateway Endpoint (free)
        self.vpc.add_gateway_endpoint(
            "DynamoDBGatewayEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.DYNAMODB,
        )

        # Shared Security Group for VPC Interface Endpoints (Isolated subnet agents)
        endpoint_sg = ec2.SecurityGroup(
            self,
            "VpcEndpointSG",
            vpc=self.vpc,
            security_group_name="dark-web-fraud-vpc-endpoint-sg",
            description="Allow HTTPS from Isolated subnets to VPC Interface Endpoints",
            allow_all_outbound=False,
        )
        # Allow inbound HTTPS from Isolated subnet CIDR(s)
        for subnet in self.vpc.isolated_subnets:
            endpoint_sg.add_ingress_rule(
                peer=ec2.Peer.ipv4(subnet.ipv4_cidr_block),
                connection=ec2.Port.tcp(443),
                description=f"HTTPS from Isolated subnet {subnet.subnet_id}",
            )

        isolated_selection = ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
        )

        # Secrets Manager Interface Endpoint (used by crawl task + Lambda agents)
        self.vpc.add_interface_endpoint(
            "SecretsManagerEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
            subnets=isolated_selection,
            security_groups=[endpoint_sg],
            private_dns_enabled=True,
        )

        # Bedrock runtime Interface Endpoint (used by Content Analyst + Structurer)
        self.vpc.add_interface_endpoint(
            "BedrockRuntimeEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME,
            subnets=isolated_selection,
            security_groups=[endpoint_sg],
            private_dns_enabled=True,
        )

        # OpenSearch Serverless Interface Endpoint (Structurer + Alert Generator)
        self.vpc.add_interface_endpoint(
            "OpenSearchServerlessEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.OPENSEARCH_SERVERLESS,
            subnets=isolated_selection,
            security_groups=[endpoint_sg],
            private_dns_enabled=True,
        )

        # ECR Interface Endpoints (needed for Fargate to pull images without NAT)
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

        # CloudWatch Logs (Lambda + ECS log shipping without internet)
        self.vpc.add_interface_endpoint(
            "CloudWatchLogsEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            subnets=isolated_selection,
            security_groups=[endpoint_sg],
            private_dns_enabled=True,
        )

        # =====================================================================
        # S3 Artifacts Bucket
        # - CMK encryption (replaces previous S3_MANAGED)
        # - Versioning + Object Lock (WORM) for forensic evidence integrity
        # - Intelligent-Tiering lifecycle (auto-archives cold artifacts)
        # - Replication requires a destination bucket in another region — set up
        #   manually in a second region and uncomment the replication config.
        # =====================================================================
        self.artifacts_bucket = s3.Bucket(
            self,
            "ArtifactsBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            bucket_key_enabled=True,       # Reduces KMS API calls by ~99%
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
                            transition_after=Duration.days(0),  # Immediate
                        )
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

        # =====================================================================
        # DynamoDB Tables — CMK encryption + Streams
        # =====================================================================

        # Agent state table (crawl circuit breaker state)
        self.agent_state_table = dynamodb.Table(
            self,
            "AgentStateTable",
            table_name="dark-web-fraud-agent-state",
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.kms_key,
            removal_policy=RemovalPolicy.RETAIN,
            point_in_time_recovery=True,
        )

        # Convergence table (campaign convergence tracking with TTL)
        # Streams enabled: Alert Generator Lambda triggers on INSERT events
        self.convergence_table = dynamodb.Table(
            self,
            "ConvergenceTable",
            table_name="dark-web-fraud-convergence",
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.kms_key,
            removal_policy=RemovalPolicy.RETAIN,
            time_to_live_attribute="TTL",
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,  # Required for Lambda trigger
            point_in_time_recovery=True,
        )

        # =====================================================================
        # Secrets Manager — Tor + MISP credentials
        # =====================================================================
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
            # Rotation: attach a rotation Lambda targeting your MISP instance
            # self.misp_api_key.add_rotation_schedule(...)
        )

        # =====================================================================
        # Crawling Engine IAM Role (kept here for backward compat reference —
        # the full role is now created in ComputeStack as CrawlTaskRole)
        # =====================================================================
        self.crawling_engine_role = iam.Role(
            self,
            "CrawlingEngineRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            role_name="dark-web-fraud-crawling-engine-legacy-role",
            description="Legacy reference role — superseded by ComputeStack CrawlTaskRole",
        )
        self.artifacts_bucket.grant_read_write(self.crawling_engine_role)
        self.agent_state_table.grant_read_write_data(self.crawling_engine_role)
        self.tor_credentials.grant_read(self.crawling_engine_role)

        # =====================================================================
        # Stack Outputs
        # =====================================================================
        CfnOutput(self, "VpcId", value=self.vpc.vpc_id)
        CfnOutput(self, "BucketName", value=self.artifacts_bucket.bucket_name)
        CfnOutput(self, "KmsKeyArn", value=self.kms_key.key_arn)
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
            description="DynamoDB Streams ARN — used by Alert Generator Lambda event source",
        )
