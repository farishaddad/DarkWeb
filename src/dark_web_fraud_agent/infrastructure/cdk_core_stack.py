"""AWS CDK Stack for core infrastructure (VPC, S3, DynamoDB, Secrets Manager, IAM)."""
from aws_cdk import Stack, Duration, RemovalPolicy, CfnOutput
from aws_cdk import aws_ec2 as ec2, aws_s3 as s3, aws_dynamodb as dynamodb, aws_secretsmanager as secretsmanager, aws_iam as iam
from constructs import Construct


class DarkWebFraudCoreStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.vpc = ec2.Vpc(
            self,
            "TorProxyVpc",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="Public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24),
                ec2.SubnetConfiguration(name="Private", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS, cidr_mask=24),
                ec2.SubnetConfiguration(name="Isolated", subnet_type=ec2.SubnetType.PRIVATE_ISOLATED, cidr_mask=24),
            ],
        )

        self.artifacts_bucket = s3.Bucket(
            self,
            "ArtifactsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            versioned=True,
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(365))],
        )

        self.agent_state_table = dynamodb.Table(
            self,
            "AgentStateTable",
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
        )

        self.convergence_table = dynamodb.Table(
            self,
            "ConvergenceTable",
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
            time_to_live_attribute="TTL",
        )

        self.tor_credentials = secretsmanager.Secret(self, "TorCredentials", description="Tor control port password")
        self.misp_api_key = secretsmanager.Secret(self, "MispApiKey", description="MISP REST API key")

        self.crawling_engine_role = iam.Role(
            self, "CrawlingEngineRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
        )
        self.artifacts_bucket.grant_read_write(self.crawling_engine_role)
        self.agent_state_table.grant_read_write_data(self.crawling_engine_role)
        self.tor_credentials.grant_read(self.crawling_engine_role)

        CfnOutput(self, "VpcId", value=self.vpc.vpc_id)
        CfnOutput(self, "BucketName", value=self.artifacts_bucket.bucket_name)
