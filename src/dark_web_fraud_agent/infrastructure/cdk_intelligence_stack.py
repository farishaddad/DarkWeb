"""AWS CDK Stack for intelligence infrastructure.

Provisions:
- OpenSearch Serverless VECTORSEARCH collection for threat intel embedding search
- CMK encryption policy (uses the CMK from CoreStack)
- Network policy scoped to VPC endpoint only (removes AllowFromPublic=true)
- Data access policy scoped to specific agent IAM roles (Structurer + Alert Generator)
  rather than the account root

Security change from original:
  Previous: AllowFromPublic=true — collection was reachable from the internet.
  Fixed:    AllowFromPublic=false + SourceVPCEs referencing the OpenSearch
            Serverless VPC Interface Endpoint created in CoreStack.
"""

import json

from aws_cdk import (
    CfnOutput,
    Stack,
    aws_opensearchserverless as aoss,
)
from constructs import Construct

from dark_web_fraud_agent.infrastructure.cdk_core_stack import DarkWebFraudCoreStack


class DarkWebFraudIntelligenceStack(Stack):
    """Intelligence infrastructure: OpenSearch Serverless VECTORSEARCH."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        core_stack: DarkWebFraudCoreStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account_id = Stack.of(self).account

        # =====================================================================
        # Encryption Policy — CMK from CoreStack (not AWS-owned key)
        # =====================================================================
        encryption_policy = aoss.CfnSecurityPolicy(
            self,
            "EncryptionPolicy",
            name="threat-intel-encryption",
            type="encryption",
            policy=json.dumps({
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": ["collection/threat-intel"],
                    }
                ],
                # Use the CMK ARN from CoreStack for customer-controlled encryption
                "KmsARN": core_stack.kms_key.key_arn,
            }),
        )

        # =====================================================================
        # Network Policy — VPC endpoint only (CRITICAL SECURITY FIX)
        #
        # Previous config had AllowFromPublic=true which exposed the collection
        # endpoint to the internet. This scopes it to the OpenSearch Serverless
        # VPC Interface Endpoint created in CoreStack.
        #
        # The VPC endpoint ID is resolved at deploy time via CloudFormation
        # cross-stack references. We reference it by finding the endpoint in
        # the VPC's interface endpoints.
        # =====================================================================

        # Retrieve the OpenSearch Serverless VPC endpoint ID
        # This is the Interface Endpoint created in CoreStack
        opensearch_vpc_endpoint_id = core_stack.vpc.node.find_child(
            "OpenSearchServerlessEndpoint"
        ).vpc_endpoint_id

        network_policy = aoss.CfnNetworkPolicy(
            self,
            "NetworkPolicy",
            name="threat-intel-network",
            type="network",
            policy=json.dumps([
                {
                    "Rules": [
                        {
                            "ResourceType": "collection",
                            "Resource": ["collection/threat-intel"],
                        },
                        {
                            "ResourceType": "dashboard",
                            "Resource": ["collection/threat-intel"],
                        },
                    ],
                    "AllowFromPublic": False,
                    # Only allow access via the VPC Interface Endpoint
                    "SourceVPCEs": [opensearch_vpc_endpoint_id],
                }
            ]),
        )

        # =====================================================================
        # Data Access Policy — scoped to specific IAM roles
        # Previous config granted aoss:* to the account root.
        # Now restricted to the Structurer and Alert Generator Lambda roles,
        # which are the only agents that need read/write access.
        # =====================================================================
        access_policy = aoss.CfnAccessPolicy(
            self,
            "AccessPolicy",
            name="threat-intel-access",
            type="data",
            policy=json.dumps([
                {
                    "Rules": [
                        {
                            "ResourceType": "index",
                            "Resource": ["index/threat-intel/*"],
                            "Permission": [
                                "aoss:CreateIndex",
                                "aoss:WriteDocument",
                                "aoss:UpdateIndex",
                                "aoss:DeleteIndex",
                            ],
                        },
                        {
                            "ResourceType": "collection",
                            "Resource": ["collection/threat-intel"],
                            "Permission": ["aoss:CreateCollectionItems"],
                        },
                    ],
                    # Write access: Data Structurer only
                    "Principal": [
                        f"arn:aws:iam::{account_id}:role/dark-web-fraud-data-structurer-role",
                    ],
                },
                {
                    "Rules": [
                        {
                            "ResourceType": "index",
                            "Resource": ["index/threat-intel/*"],
                            "Permission": [
                                "aoss:ReadDocument",
                                "aoss:DescribeIndex",
                            ],
                        },
                        {
                            "ResourceType": "collection",
                            "Resource": ["collection/threat-intel"],
                            "Permission": ["aoss:DescribeCollectionItems"],
                        },
                    ],
                    # Read access: Alert Generator + Bedrock Knowledge Base service
                    "Principal": [
                        f"arn:aws:iam::{account_id}:role/dark-web-fraud-alert-generator-role",
                        "arn:aws:iam::aws:policy/AmazonBedrockFullAccess",
                    ],
                },
            ]),
        )

        # =====================================================================
        # OpenSearch Serverless Collection
        # =====================================================================
        self.opensearch_collection = aoss.CfnCollection(
            self,
            "ThreatIntelCollection",
            name="threat-intel",
            type="VECTORSEARCH",
            description="Threat intelligence vector search — dark web fraud patterns",
        )
        self.opensearch_collection.add_dependency(encryption_policy)
        self.opensearch_collection.add_dependency(network_policy)
        self.opensearch_collection.add_dependency(access_policy)

        # =====================================================================
        # Stack Outputs
        # =====================================================================
        CfnOutput(
            self,
            "OpenSearchEndpoint",
            value=self.opensearch_collection.attr_collection_endpoint,
            description="OpenSearch Serverless VECTORSEARCH endpoint (VPC-only access)",
        )
        CfnOutput(
            self,
            "OpenSearchCollectionArn",
            value=self.opensearch_collection.attr_arn,
            description="OpenSearch Serverless collection ARN",
        )
