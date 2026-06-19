"""AWS CDK Stack for intelligence infrastructure (OpenSearch, Knowledge Base, Guardrails)."""

from aws_cdk import (
    Stack,
    CfnOutput,
    aws_opensearchserverless as aoss,
)
from constructs import Construct


class DarkWebFraudIntelligenceStack(Stack):
    """Intelligence infrastructure: OpenSearch Serverless, Knowledge Base, Guardrails."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # OpenSearch Serverless VECTORSEARCH Collection
        # Security policy - encryption
        encryption_policy = aoss.CfnSecurityPolicy(self, "EncryptionPolicy",
            name="threat-intel-encryption",
            type="encryption",
            policy='{"Rules":[{"ResourceType":"collection","Resource":["collection/threat-intel"]}],"AWSOwnedKey":true}',
        )

        # Security policy - network (public for now, VPC endpoint in production)
        network_policy = aoss.CfnNetworkPolicy(self, "NetworkPolicy",
            name="threat-intel-network",
            type="network",
            policy='[{"Rules":[{"ResourceType":"collection","Resource":["collection/threat-intel"]},{"ResourceType":"dashboard","Resource":["collection/threat-intel"]}],"AllowFromPublic":true}]',
        )

        # Access policy
        access_policy = aoss.CfnAccessPolicy(self, "AccessPolicy",
            name="threat-intel-access",
            type="data",
            policy=f'[{{"Rules":[{{"ResourceType":"index","Resource":["index/threat-intel/*"],"Permission":["aoss:*"]}},{{"ResourceType":"collection","Resource":["collection/threat-intel"],"Permission":["aoss:*"]}}],"Principal":["arn:aws:iam::{Stack.of(self).account}:root"]}}]',
        )

        # OpenSearch Serverless Collection (VECTORSEARCH type)
        self.opensearch_collection = aoss.CfnCollection(self, "ThreatIntelCollection",
            name="threat-intel",
            type="VECTORSEARCH",
            description="GPU-accelerated vector search for threat intelligence correlation",
        )
        self.opensearch_collection.add_dependency(encryption_policy)
        self.opensearch_collection.add_dependency(network_policy)
        self.opensearch_collection.add_dependency(access_policy)

        # Output the collection endpoint
        CfnOutput(self, "OpenSearchEndpoint",
            value=self.opensearch_collection.attr_collection_endpoint,
            description="OpenSearch Serverless VECTORSEARCH endpoint",
        )
