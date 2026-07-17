"""AWS CDK Stack for intelligence infrastructure.

Provisions:
- OpenSearch Serverless VECTORSEARCH collection for threat intel embedding search
- OpenSearch index template with knn_vector mapping (dimension 1024, HNSW, cosine)
- AgentCore Managed Knowledge Base with Smart Parsing over historical threat intel
- Bedrock Guardrails (prompt injection, harmful content, sensitive data detection)
- CMK encryption policy (uses the CMK from CoreStack)
- Network policy scoped to Lambda agents via public HTTPS + IAM SigV4 auth
- Data access policy scoped to specific agent IAM roles (Structurer + Alert Generator)

Security:
  - Data access policies scope write to Data Structurer role, read to Alert Generator
  - Bedrock Guardrails intercept prompt injection and harmful content from dark web
  - Knowledge Base uses OpenSearch Serverless as vector store with CMK encryption
"""

import json

from aws_cdk import (
    CfnOutput,
    RemovalPolicy,
    Stack,
    Tags,
    aws_bedrock as bedrock,
    aws_iam as iam,
    aws_opensearchserverless as aoss,
)
from constructs import Construct

from dark_web_fraud_agent.infrastructure.cdk_core_stack import DarkWebFraudCoreStack


class DarkWebFraudIntelligenceStack(Stack):
    """Intelligence infrastructure: OpenSearch Serverless, Knowledge Base, Guardrails."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        core_stack: DarkWebFraudCoreStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account_id = Stack.of(self).account
        region = Stack.of(self).region

        # Apply project-wide tags
        Tags.of(self).add("Project", "dark-web-fraud")
        Tags.of(self).add("Env", "prod")

        # =====================================================================
        # OpenSearch Serverless — VECTORSEARCH Collection
        # =====================================================================

        # Encryption Policy — CMK from CoreStack
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
                "KmsARN": core_stack.kms_key.key_arn,
            }),
        )

        # Network Policy — Lambda agents reach via public HTTPS + IAM SigV4
        network_policy = aoss.CfnSecurityPolicy(
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
                    "AllowFromPublic": True,
                }
            ]),
        )

        # Data Access Policy — scoped to Data Structurer (write) and Alert Generator (read)
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
                    "Principal": [
                        f"arn:aws:iam::{account_id}:role/dark-web-fraud-alert-generator-role",
                        f"arn:aws:iam::{account_id}:role/dark-web-fraud-knowledge-base-role",
                    ],
                },
            ]),
        )

        # OpenSearch Serverless Collection
        self.opensearch_collection = aoss.CfnCollection(
            self,
            "ThreatIntelCollection",
            name="threat-intel",
            type="VECTORSEARCH",
            description="Threat intelligence vector search — dark web fraud patterns",
            standby_replicas="DISABLED",  # Halves baseline OCU cost for dev/test
        )
        self.opensearch_collection.add_dependency(encryption_policy)
        self.opensearch_collection.add_dependency(network_policy)
        self.opensearch_collection.add_dependency(access_policy)

        # =====================================================================
        # OpenSearch Index Template — knn_vector mapping
        #
        # The index "threat-intel-vectors" is created at deploy time via the
        # OpenSearch index template. The mapping defines:
        #   - knn_vector field (dimension 1024, HNSW engine, cosine space)
        #   - metadata fields (stix_id, tier, severity, fraud_category, entities, tags)
        #
        # Note: OpenSearch Serverless does not support index templates via CDK.
        # The Data Structurer agent creates the index on first write using the
        # opensearch-py client with the following mapping. We define it here as
        # a constant for documentation and reference in agent config.
        # =====================================================================
        self.opensearch_index_mapping = {
            "settings": {
                "index": {
                    "knn": True,
                    "knn.algo_param.ef_search": 512,
                }
            },
            "mappings": {
                "properties": {
                    "embedding": {
                        "type": "knn_vector",
                        "dimension": 1024,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "nmslib",
                            "parameters": {
                                "ef_construction": 512,
                                "m": 16,
                            },
                        },
                    },
                    "stix_id": {"type": "keyword"},
                    "tier": {"type": "keyword"},
                    "severity": {"type": "integer"},
                    "fraud_category": {"type": "keyword"},
                    "entities": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "source_url": {"type": "keyword"},
                    "crawl_timestamp": {"type": "date"},
                    "content_snippet": {"type": "text"},
                    "stix_type": {"type": "keyword"},
                    "created_at": {"type": "date"},
                }
            },
        }

        # =====================================================================
        # Bedrock Guardrails — Content Safety for Dark Web Material
        #
        # Applied before Content Analyst processes raw dark web text.
        # Filters: prompt injection, harmful content, sensitive data (PII/financial).
        # =====================================================================
        self.guardrail = bedrock.CfnGuardrail(
            self,
            "ContentSafetyGuardrail",
            name="dark-web-fraud-content-safety",
            description=(
                "Content safety guardrail for dark web fraud intelligence processing. "
                "Detects prompt injection attempts, filters harmful content, and "
                "identifies sensitive financial data (PII, card numbers, account details)."
            ),
            blocked_input_messaging=(
                "This content has been blocked by the content safety guardrail. "
                "The input contains potentially harmful or injected instructions."
            ),
            blocked_outputs_messaging=(
                "This output has been blocked by the content safety guardrail. "
                "The generated response contains potentially harmful content."
            ),
            # Content policy — filter harmful content categories
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(
                filters_config=[
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="HATE",
                        input_strength="HIGH",
                        output_strength="HIGH",
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="INSULTS",
                        input_strength="HIGH",
                        output_strength="HIGH",
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="SEXUAL",
                        input_strength="HIGH",
                        output_strength="HIGH",
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="VIOLENCE",
                        input_strength="LOW",
                        output_strength="MEDIUM",
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="MISCONDUCT",
                        input_strength="LOW",
                        output_strength="MEDIUM",
                    ),
                ],
            ),
            # Sensitive information policy — detect PII and financial data
            sensitive_information_policy_config=bedrock.CfnGuardrail.SensitiveInformationPolicyConfigProperty(
                pii_entities_config=[
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="CREDIT_DEBIT_CARD_NUMBER",
                        action="ANONYMIZE",
                    ),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="CREDIT_DEBIT_CARD_CVV",
                        action="ANONYMIZE",
                    ),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="CREDIT_DEBIT_CARD_EXPIRY",
                        action="ANONYMIZE",
                    ),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="US_BANK_ACCOUNT_NUMBER",
                        action="ANONYMIZE",
                    ),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="US_BANK_ROUTING_NUMBER",
                        action="ANONYMIZE",
                    ),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="UK_NATIONAL_INSURANCE_NUMBER",
                        action="ANONYMIZE",
                    ),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="US_SOCIAL_SECURITY_NUMBER",
                        action="ANONYMIZE",
                    ),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="EMAIL",
                        action="ANONYMIZE",
                    ),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="PHONE",
                        action="ANONYMIZE",
                    ),
                ],
                regexes_config=[
                    bedrock.CfnGuardrail.RegexConfigProperty(
                        name="SWIFT_BIC_Code",
                        description="Detect SWIFT/BIC codes in content",
                        pattern=r"[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?",
                        action="ANONYMIZE",
                    ),
                    bedrock.CfnGuardrail.RegexConfigProperty(
                        name="BTC_Wallet_Address",
                        description="Detect Bitcoin wallet addresses",
                        pattern=r"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}",
                        action="ANONYMIZE",
                    ),
                    bedrock.CfnGuardrail.RegexConfigProperty(
                        name="BIN_Range",
                        description="Detect BIN ranges (first 6 digits of card numbers)",
                        pattern=r"\b[0-9]{6}\b",
                        action="ANONYMIZE",
                    ),
                ],
            ),
            # Word policy — block prompt injection patterns
            word_policy_config=bedrock.CfnGuardrail.WordPolicyConfigProperty(
                managed_word_lists_config=[
                    bedrock.CfnGuardrail.ManagedWordsConfigProperty(
                        type="PROFANITY",
                    ),
                ],
                words_config=[
                    bedrock.CfnGuardrail.WordConfigProperty(text="ignore previous instructions"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="disregard above"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="override system prompt"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="new instructions:"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="forget everything"),
                ],
            ),
        )

        # Create a guardrail version for production use
        self.guardrail_version = bedrock.CfnGuardrailVersion(
            self,
            "ContentSafetyGuardrailVersion",
            guardrail_identifier=self.guardrail.attr_guardrail_id,
            description="Initial production version for dark web content safety",
        )

        # =====================================================================
        # AgentCore Managed Knowledge Base — Smart Parsing
        #
        # RAG pipeline over historical threat intelligence corpus.
        # Uses OpenSearch Serverless as the vector store.
        # Smart Parsing handles multi-format dark web data (HTML, text, JSON).
        # =====================================================================

        # IAM role for the Knowledge Base service
        self.knowledge_base_role = iam.Role(
            self,
            "KnowledgeBaseRole",
            role_name="dark-web-fraud-knowledge-base-role",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
            description="IAM role for Bedrock Knowledge Base to access OpenSearch and S3",
        )

        # Grant the KB role access to the embeddings model
        self.knowledge_base_role.add_to_policy(
            iam.PolicyStatement(
                sid="InvokeEmbeddingModel",
                actions=["bedrock:InvokeModel"],
                resources=[
                    f"arn:aws:bedrock:{region}::foundation-model/amazon.titan-embed-text-v2:0",
                ],
            )
        )

        # Grant the KB role access to OpenSearch Serverless collection
        self.knowledge_base_role.add_to_policy(
            iam.PolicyStatement(
                sid="OpenSearchServerlessAccess",
                actions=[
                    "aoss:APIAccessAll",
                ],
                resources=[
                    self.opensearch_collection.attr_arn,
                ],
            )
        )

        # Grant the KB role access to S3 artifacts bucket for data source
        core_stack.artifacts_bucket.grant_read(self.knowledge_base_role)

        # Grant KMS decrypt for the CMK
        core_stack.kms_key.grant_decrypt(self.knowledge_base_role)

        # Knowledge Base definition
        self.knowledge_base = bedrock.CfnKnowledgeBase(
            self,
            "ThreatIntelKnowledgeBase",
            name="dark-web-fraud-threat-intel-kb",
            description=(
                "Historical threat intelligence knowledge base for dark web fraud patterns. "
                "Uses Smart Parsing for multi-format documents (STIX JSON, HTML, plaintext). "
                "Supports Agentic Retriever for complex multi-step queries over threat actor profiles."
            ),
            role_arn=self.knowledge_base_role.role_arn,
            knowledge_base_configuration=bedrock.CfnKnowledgeBase.KnowledgeBaseConfigurationProperty(
                type="VECTOR",
                vector_knowledge_base_configuration=bedrock.CfnKnowledgeBase.VectorKnowledgeBaseConfigurationProperty(
                    embedding_model_arn=f"arn:aws:bedrock:{region}::foundation-model/amazon.titan-embed-text-v2:0",
                ),
            ),
            storage_configuration=bedrock.CfnKnowledgeBase.StorageConfigurationProperty(
                type="OPENSEARCH_SERVERLESS",
                opensearch_serverless_configuration=bedrock.CfnKnowledgeBase.OpenSearchServerlessConfigurationProperty(
                    collection_arn=self.opensearch_collection.attr_arn,
                    vector_index_name="threat-intel-kb-vectors",
                    field_mapping=bedrock.CfnKnowledgeBase.OpenSearchServerlessFieldMappingProperty(
                        vector_field="embedding",
                        text_field="content_snippet",
                        metadata_field="metadata",
                    ),
                ),
            ),
        )

        # Knowledge Base Data Source — S3 bucket with STIX bundles
        self.knowledge_base_data_source = bedrock.CfnDataSource(
            self,
            "ThreatIntelDataSource",
            name="stix-bundles-source",
            description="STIX 2.1 bundles and tag manifests from dark web crawling pipeline",
            knowledge_base_id=self.knowledge_base.attr_knowledge_base_id,
            data_source_configuration=bedrock.CfnDataSource.DataSourceConfigurationProperty(
                type="S3",
                s3_configuration=bedrock.CfnDataSource.S3DataSourceConfigurationProperty(
                    bucket_arn=core_stack.artifacts_bucket.bucket_arn,
                    inclusion_prefixes=[
                        "stix-bundles/",
                        "tag-manifests/",
                    ],
                ),
            ),
            vector_ingestion_configuration=bedrock.CfnDataSource.VectorIngestionConfigurationProperty(
                chunking_configuration=bedrock.CfnDataSource.ChunkingConfigurationProperty(
                    chunking_strategy="FIXED_SIZE",
                    fixed_size_chunking_configuration=bedrock.CfnDataSource.FixedSizeChunkingConfigurationProperty(
                        max_tokens=512,
                        overlap_percentage=20,
                    ),
                ),
                parsing_configuration=bedrock.CfnDataSource.ParsingConfigurationProperty(
                    parsing_strategy="BEDROCK_FOUNDATION_MODEL",
                    bedrock_foundation_model_configuration=bedrock.CfnDataSource.BedrockFoundationModelConfigurationProperty(
                        model_arn=f"arn:aws:bedrock:{region}::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
                    ),
                ),
            ),
        )

        # =====================================================================
        # Stack Outputs
        # =====================================================================
        CfnOutput(
            self,
            "OpenSearchEndpoint",
            value=self.opensearch_collection.attr_collection_endpoint,
            description="OpenSearch Serverless VECTORSEARCH endpoint",
        )
        CfnOutput(
            self,
            "OpenSearchCollectionArn",
            value=self.opensearch_collection.attr_arn,
            description="OpenSearch Serverless collection ARN",
        )
        CfnOutput(
            self,
            "GuardrailId",
            value=self.guardrail.attr_guardrail_id,
            description="Bedrock Guardrail ID for content safety",
        )
        CfnOutput(
            self,
            "GuardrailArn",
            value=self.guardrail.attr_guardrail_arn,
            description="Bedrock Guardrail ARN for content safety",
        )
        CfnOutput(
            self,
            "GuardrailVersionId",
            value=self.guardrail_version.attr_version,
            description="Bedrock Guardrail version for production use",
        )
        CfnOutput(
            self,
            "KnowledgeBaseId",
            value=self.knowledge_base.attr_knowledge_base_id,
            description="Bedrock Knowledge Base ID for threat intel RAG",
        )
        CfnOutput(
            self,
            "KnowledgeBaseArn",
            value=self.knowledge_base.attr_knowledge_base_arn,
            description="Bedrock Knowledge Base ARN",
        )
        CfnOutput(
            self,
            "OpenSearchIndexMapping",
            value=json.dumps(self.opensearch_index_mapping),
            description="OpenSearch index mapping for threat-intel-vectors index (applied by Data Structurer on first write)",
        )
