"""Unit tests for the CDK Intelligence Infrastructure Stack."""

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
    """Synthesize the intelligence stack and return the CloudFormation template."""
    from dark_web_fraud_agent.infrastructure.cdk_intelligence_stack import (
        DarkWebFraudIntelligenceStack,
    )

    app = cdk.App()
    stack = DarkWebFraudIntelligenceStack(app, "TestIntelligenceStack")
    return assertions.Template.from_stack(stack)


class TestOpenSearchCollection:
    """Tests for the OpenSearch Serverless VECTORSEARCH collection."""

    def test_collection_exists_with_vectorsearch_type(self, template):
        """Verify the VECTORSEARCH collection is created."""
        template.has_resource_properties(
            "AWS::OpenSearchServerless::Collection",
            {
                "Name": "threat-intel",
                "Type": "VECTORSEARCH",
            },
        )

    def test_collection_has_description(self, template):
        """Verify the collection includes a description."""
        template.has_resource_properties(
            "AWS::OpenSearchServerless::Collection",
            {
                "Description": assertions.Match.string_like_regexp(".*vector search.*"),
            },
        )


class TestSecurityPolicies:
    """Tests for OpenSearch Serverless security policies."""

    def test_encryption_policy_exists(self, template):
        """Verify the encryption security policy is created."""
        template.has_resource_properties(
            "AWS::OpenSearchServerless::SecurityPolicy",
            {
                "Name": "threat-intel-encryption",
                "Type": "encryption",
            },
        )

    def test_network_policy_exists(self, template):
        """Verify the network security policy is created."""
        template.has_resource_properties(
            "AWS::OpenSearchServerless::SecurityPolicy",
            {
                "Name": "threat-intel-network",
                "Type": "network",
            },
        )


class TestAccessPolicy:
    """Tests for the OpenSearch Serverless access policy."""

    def test_access_policy_exists(self, template):
        """Verify the data access policy is created."""
        template.has_resource_properties(
            "AWS::OpenSearchServerless::AccessPolicy",
            {
                "Name": "threat-intel-access",
                "Type": "data",
            },
        )


class TestOutputs:
    """Tests for stack outputs."""

    def test_opensearch_endpoint_output_exists(self, template):
        """Verify the OpenSearch endpoint is exported as an output."""
        template.has_output(
            "OpenSearchEndpoint",
            {
                "Description": "OpenSearch Serverless VECTORSEARCH endpoint",
            },
        )


class TestResourceCount:
    """Tests for expected resource counts."""

    def test_has_one_collection(self, template):
        """Verify exactly one OpenSearch collection is created."""
        template.resource_count_is("AWS::OpenSearchServerless::Collection", 1)

    def test_has_two_security_policies(self, template):
        """Verify two security policies are created (encryption + network)."""
        template.resource_count_is("AWS::OpenSearchServerless::SecurityPolicy", 2)

    def test_has_one_access_policy(self, template):
        """Verify one access policy is created."""
        template.resource_count_is("AWS::OpenSearchServerless::AccessPolicy", 1)
