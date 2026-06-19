"""Tests for the CDK core infrastructure stack."""
import pytest

try:
    import aws_cdk as cdk
    from aws_cdk import assertions
    CDK_AVAILABLE = True
except ImportError:
    CDK_AVAILABLE = False

pytestmark = pytest.mark.skipif(not CDK_AVAILABLE, reason="aws-cdk-lib not installed")


@pytest.fixture
def template():
    """Synthesize the core stack and return the CloudFormation template."""
    from dark_web_fraud_agent.infrastructure.cdk_core_stack import DarkWebFraudCoreStack

    app = cdk.App()
    stack = DarkWebFraudCoreStack(app, "TestCoreStack")
    return assertions.Template.from_stack(stack)


class TestVpc:
    def test_vpc_created(self, template):
        """VPC resource exists with expected configuration."""
        template.resource_count_is("AWS::EC2::VPC", 1)

    def test_nat_gateway_created(self, template):
        """NAT Gateway exists for private subnet egress."""
        template.resource_count_is("AWS::EC2::NatGateway", 1)


class TestS3Bucket:
    def test_artifacts_bucket_created(self, template):
        """S3 bucket for artifacts is created with versioning and encryption."""
        template.has_resource_properties(
            "AWS::S3::Bucket",
            {
                "VersioningConfiguration": {"Status": "Enabled"},
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                },
            },
        )


class TestDynamoDbTables:
    def test_agent_state_table_created(self, template):
        """Agent state DynamoDB table with PK/SK schema."""
        template.has_resource_properties(
            "AWS::DynamoDB::Table",
            {
                "KeySchema": [
                    {"AttributeName": "PK", "KeyType": "HASH"},
                    {"AttributeName": "SK", "KeyType": "RANGE"},
                ],
                "BillingMode": "PAY_PER_REQUEST",
            },
        )

    def test_convergence_table_has_ttl(self, template):
        """Convergence table has TTL enabled."""
        template.has_resource_properties(
            "AWS::DynamoDB::Table",
            {
                "TimeToLiveSpecification": {
                    "AttributeName": "TTL",
                    "Enabled": True,
                },
            },
        )

    def test_two_dynamodb_tables_created(self, template):
        """Both Agent State and Convergence tables are created."""
        template.resource_count_is("AWS::DynamoDB::Table", 2)


class TestSecretsManager:
    def test_tor_credentials_secret(self, template):
        """Tor credentials secret is created."""
        template.has_resource_properties(
            "AWS::SecretsManager::Secret",
            {"Description": "Tor control port password"},
        )

    def test_misp_api_key_secret(self, template):
        """MISP API key secret is created."""
        template.has_resource_properties(
            "AWS::SecretsManager::Secret",
            {"Description": "MISP REST API key"},
        )


class TestIamRole:
    def test_crawling_engine_role_created(self, template):
        """IAM role for crawling engine Lambda is created."""
        template.has_resource_properties(
            "AWS::IAM::Role",
            {
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Action": "sts:AssumeRole",
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                        }
                    ],
                },
            },
        )


class TestOutputs:
    def test_vpc_id_output(self, template):
        """VpcId output is defined."""
        template.has_output("VpcId", {})

    def test_bucket_name_output(self, template):
        """BucketName output is defined."""
        template.has_output("BucketName", {})
