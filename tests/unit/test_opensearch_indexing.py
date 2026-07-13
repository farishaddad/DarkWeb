"""Unit tests for OpenSearch Serverless vector indexing in the Data Structurer agent.

Tests verify that:
- index_to_opensearch() generates embeddings and indexes documents correctly
- ensure_index_mapping() creates the index with knn_vector configuration
- _generate_embedding() invokes Bedrock with proper parameters
- _get_object_summary() produces meaningful text for various STIX object types
- _create_opensearch_client() creates a properly configured client
- Document structure includes all required metadata fields (stix_id, tier, severity,
  fraud_category, entities, tags, intelligence_vector, created_at)
"""

import io
import json
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
import stix2

from dark_web_fraud_agent.agents.data_structurer import DataStructurer, StructurerConfig
from dark_web_fraud_agent.models.content_analyst import ExtractedEntity


@pytest.fixture
def config():
    """Create a StructurerConfig for testing."""
    return StructurerConfig(
        opensearch_endpoint="https://abc123.eu-west-2.aoss.amazonaws.com",
        opensearch_collection_name="dark-web-fraud-intel",
        misp_url="https://misp.example.com",
        misp_secret_arn="arn:aws:secretsmanager:eu-west-2:123456789:secret:misp-key",
        bedrock_embedding_model_id="amazon.titan-embed-text-v2:0",
        s3_bucket="dark-web-artifacts",
    )


@pytest.fixture
def structurer(config):
    """Create a DataStructurer with configuration."""
    return DataStructurer(config=config)


@pytest.fixture
def mock_opensearch_client():
    """Create a mock OpenSearch client."""
    client = MagicMock()
    client.index.return_value = {"_id": "doc-123", "_index": "dark-web-fraud-intel", "result": "created"}
    client.indices = MagicMock()
    client.indices.exists.return_value = False
    client.indices.create.return_value = {"acknowledged": True}
    return client


@pytest.fixture
def mock_bedrock_client():
    """Create a mock Bedrock runtime client."""
    client = MagicMock()
    embedding = [0.1] * 1024  # 1024-dimension vector
    response_body = io.BytesIO(json.dumps({"embedding": embedding}).encode())
    client.invoke_model.return_value = {"body": response_body}
    return client


@pytest.fixture
def sample_bundle(structurer):
    """Create a sample STIX bundle for testing."""
    entity = ExtractedEntity(
        entity_type="ip_address",
        value="192.168.1.100",
        context="C2 server IP from dark web forum",
        confidence=0.95,
    )
    sco = structurer.create_stix_sco(entity)

    actor_entity = ExtractedEntity(
        entity_type="bank_name",
        value="DarkVendor",
        context="Known threat actor",
        confidence=0.88,
    )
    sdo = structurer.create_stix_sdo(actor_entity, "threat-actor")

    return structurer.build_bundle([sco, sdo])


@pytest.fixture
def sample_metadata():
    """Create sample metadata for indexing with entities and tags."""
    return {
        "tier": "indicator",
        "severity_score": 7,
        "fraud_category": "account_takeover",
        "entities": [
            {"entity_type": "ip_address", "value": "192.168.1.100"},
            {"entity_type": "bank_name", "value": "DarkVendor"},
        ],
        "tags": ["mitre-attack:technique=\"T1531\"", "fraud:type=\"account_takeover\""],
    }


# --- _get_object_summary Tests ---


class TestGetObjectSummary:
    """Tests for _get_object_summary() method."""

    def test_summary_includes_type(self, structurer):
        """Summary always includes the STIX object type."""
        entity = ExtractedEntity(
            entity_type="ip_address", value="10.0.0.1", context="test", confidence=0.9
        )
        sco = structurer.create_stix_sco(entity)

        summary = structurer._get_object_summary(sco)

        assert "Type: ipv4-addr" in summary

    def test_summary_includes_name_for_sdo(self, structurer):
        """Summary includes name for SDOs that have a name field."""
        entity = ExtractedEntity(
            entity_type="bank_name", value="BadActor", context="test", confidence=0.9
        )
        sdo = structurer.create_stix_sdo(entity, "threat-actor")

        summary = structurer._get_object_summary(sdo)

        assert "Name: BadActor" in summary

    def test_summary_includes_description_for_sdo(self, structurer):
        """Summary includes description for SDOs that have it."""
        entity = ExtractedEntity(
            entity_type="bank_name",
            value="PhishKit",
            context="Advanced phishing toolkit",
            confidence=0.85,
        )
        sdo = structurer.create_stix_sdo(entity, "attack-pattern")

        summary = structurer._get_object_summary(sdo)

        assert "Description:" in summary

    def test_summary_includes_value_for_sco(self, structurer):
        """Summary includes value for SCOs that have a value field."""
        entity = ExtractedEntity(
            entity_type="ip_address", value="192.168.1.1", context="test", confidence=0.9
        )
        sco = structurer.create_stix_sco(entity)

        summary = structurer._get_object_summary(sco)

        assert "Value: 192.168.1.1" in summary

    def test_summary_parts_joined_with_pipe(self, structurer):
        """Summary parts are joined with ' | ' separator."""
        entity = ExtractedEntity(
            entity_type="ip_address", value="10.0.0.1", context="test", confidence=0.9
        )
        sco = structurer.create_stix_sco(entity)

        summary = structurer._get_object_summary(sco)

        assert " | " in summary


# --- _generate_embedding Tests ---


class TestGenerateEmbedding:
    """Tests for _generate_embedding() method."""

    def test_generate_embedding_invokes_bedrock(self, structurer, mock_bedrock_client):
        """_generate_embedding calls Bedrock with the correct model and text."""
        structurer._bedrock_client = mock_bedrock_client

        entity = ExtractedEntity(
            entity_type="ip_address", value="10.0.0.1", context="test", confidence=0.9
        )
        sco = structurer.create_stix_sco(entity)

        result = structurer._generate_embedding(sco)

        mock_bedrock_client.invoke_model.assert_called_once()
        call_kwargs = mock_bedrock_client.invoke_model.call_args[1]
        assert call_kwargs["modelId"] == "amazon.titan-embed-text-v2:0"
        assert call_kwargs["contentType"] == "application/json"

        # Verify the body contains inputText
        body = json.loads(call_kwargs["body"])
        assert "inputText" in body
        assert "10.0.0.1" in body["inputText"]

    def test_generate_embedding_returns_vector(self, structurer, mock_bedrock_client):
        """_generate_embedding returns the embedding vector from Bedrock response."""
        structurer._bedrock_client = mock_bedrock_client

        entity = ExtractedEntity(
            entity_type="ip_address", value="10.0.0.1", context="test", confidence=0.9
        )
        sco = structurer.create_stix_sco(entity)

        result = structurer._generate_embedding(sco)

        assert isinstance(result, list)
        assert len(result) == 1024
        assert all(isinstance(v, float) for v in result)

    def test_generate_embedding_creates_client_if_none(self, structurer):
        """_generate_embedding creates a Bedrock client if none exists."""
        assert structurer._bedrock_client is None

        with patch("boto3.client") as mock_boto3_client:
            embedding = [0.5] * 1024
            mock_client = MagicMock()
            response_body = io.BytesIO(json.dumps({"embedding": embedding}).encode())
            mock_client.invoke_model.return_value = {"body": response_body}
            mock_boto3_client.return_value = mock_client

            entity = ExtractedEntity(
                entity_type="ip_address", value="10.0.0.1", context="test", confidence=0.9
            )
            sco = structurer.create_stix_sco(entity)

            result = structurer._generate_embedding(sco)

            mock_boto3_client.assert_called_once_with(
                "bedrock-runtime", region_name="eu-west-2"
            )
            assert result == embedding


# --- ensure_index_mapping Tests ---


class TestEnsureIndexMapping:
    """Tests for ensure_index_mapping() method."""

    def test_creates_index_with_knn_vector_mapping(self, structurer, mock_opensearch_client):
        """ensure_index_mapping creates index with knn_vector field config."""
        structurer._opensearch_client = mock_opensearch_client
        mock_opensearch_client.indices.exists.return_value = False

        structurer.ensure_index_mapping()

        mock_opensearch_client.indices.create.assert_called_once()
        call_args = mock_opensearch_client.indices.create.call_args
        body = call_args[1]["body"]

        # Verify knn_vector field
        vector_props = body["mappings"]["properties"]["intelligence_vector"]
        assert vector_props["type"] == "knn_vector"
        assert vector_props["dimension"] == 1024
        assert vector_props["method"]["name"] == "hnsw"
        assert vector_props["method"]["space_type"] == "cosinesimil"

    def test_skips_creation_if_index_exists(self, structurer, mock_opensearch_client):
        """ensure_index_mapping does not create if index already exists."""
        structurer._opensearch_client = mock_opensearch_client
        mock_opensearch_client.indices.exists.return_value = True

        structurer.ensure_index_mapping()

        mock_opensearch_client.indices.create.assert_not_called()

    def test_uses_configured_index_name(self, structurer, mock_opensearch_client):
        """ensure_index_mapping uses get_index_name() for the index."""
        structurer._opensearch_client = mock_opensearch_client
        mock_opensearch_client.indices.exists.return_value = False

        structurer.ensure_index_mapping()

        call_args = mock_opensearch_client.indices.create.call_args
        assert call_args[1]["index"] == "dark-web-fraud-intel"

    def test_mapping_includes_metadata_fields(self, structurer, mock_opensearch_client):
        """Index mapping includes stix_id, tier, severity, entities, tags fields."""
        structurer._opensearch_client = mock_opensearch_client
        mock_opensearch_client.indices.exists.return_value = False

        structurer.ensure_index_mapping()

        call_args = mock_opensearch_client.indices.create.call_args
        props = call_args[1]["body"]["mappings"]["properties"]

        assert props["stix_id"]["type"] == "keyword"
        assert props["tier"]["type"] == "keyword"
        assert props["severity_score"]["type"] == "integer"
        assert props["fraud_category"]["type"] == "keyword"
        assert props["entities"]["type"] == "nested"
        assert props["tags"]["type"] == "keyword"
        assert props["created_at"]["type"] == "date"

    def test_handles_resource_already_exists_exception(self, structurer, mock_opensearch_client):
        """ensure_index_mapping handles race condition gracefully."""
        structurer._opensearch_client = mock_opensearch_client
        mock_opensearch_client.indices.exists.return_value = False
        mock_opensearch_client.indices.create.side_effect = Exception(
            "resource_already_exists_exception"
        )

        # Should not raise
        structurer.ensure_index_mapping()

    def test_raises_runtime_error_on_unknown_failure(self, structurer, mock_opensearch_client):
        """ensure_index_mapping raises RuntimeError on unexpected failures."""
        structurer._opensearch_client = mock_opensearch_client
        mock_opensearch_client.indices.exists.return_value = False
        mock_opensearch_client.indices.create.side_effect = Exception("connection timeout")

        with pytest.raises(RuntimeError, match="Failed to create OpenSearch index"):
            structurer.ensure_index_mapping()

    def test_creates_opensearch_client_if_none(self, structurer):
        """ensure_index_mapping creates client if _opensearch_client is None."""
        assert structurer._opensearch_client is None

        mock_client = MagicMock()
        mock_client.indices.exists.return_value = True

        with patch.object(structurer, "_create_opensearch_client", return_value=mock_client):
            structurer.ensure_index_mapping()
            assert structurer._opensearch_client is mock_client

    def test_knn_setting_enabled(self, structurer, mock_opensearch_client):
        """Index settings enable knn."""
        structurer._opensearch_client = mock_opensearch_client
        mock_opensearch_client.indices.exists.return_value = False

        structurer.ensure_index_mapping()

        call_args = mock_opensearch_client.indices.create.call_args
        settings = call_args[1]["body"]["settings"]
        assert settings["index"]["knn"] is True


# --- index_to_opensearch Tests ---


class TestIndexToOpenSearch:
    """Tests for index_to_opensearch() method."""

    def test_indexes_all_bundle_objects(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """index_to_opensearch indexes every object in the bundle."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        doc_ids = structurer.index_to_opensearch(sample_bundle, sample_metadata)

        assert len(doc_ids) == len(sample_bundle.objects)
        assert mock_opensearch_client.index.call_count == len(sample_bundle.objects)

    def test_returns_document_ids(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """index_to_opensearch returns a list of OpenSearch document IDs."""
        mock_opensearch_client.index.side_effect = [
            {"_id": f"doc-{i}", "_index": "dark-web-fraud-intel", "result": "created"}
            for i in range(len(sample_bundle.objects))
        ]
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        doc_ids = structurer.index_to_opensearch(sample_bundle, sample_metadata)

        assert doc_ids == ["doc-0", "doc-1"]

    def test_document_contains_required_fields(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """Each indexed document contains all required metadata fields."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        assert "stix_id" in doc
        assert "stix_type" in doc
        assert "tier" in doc
        assert "severity_score" in doc
        assert "fraud_category" in doc
        assert "entities" in doc
        assert "tags" in doc
        assert "content_summary" in doc
        assert "created_at" in doc
        assert "intelligence_vector" in doc

    def test_document_metadata_from_input(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """Document metadata values are populated from the metadata argument."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        assert doc["tier"] == "indicator"
        assert doc["severity_score"] == 7
        assert doc["fraud_category"] == "account_takeover"

    def test_document_includes_entities_list(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """Document includes entities list from metadata."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        assert doc["entities"] == [
            {"entity_type": "ip_address", "value": "192.168.1.100"},
            {"entity_type": "bank_name", "value": "DarkVendor"},
        ]

    def test_document_includes_tags_list(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """Document includes tags list from metadata."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        assert doc["tags"] == [
            "mitre-attack:technique=\"T1531\"",
            "fraud:type=\"account_takeover\"",
        ]

    def test_document_stix_fields_from_object(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """Document stix_id and stix_type come from the STIX object."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        first_obj = sample_bundle.objects[0]
        assert doc["stix_id"] == first_obj.id
        assert doc["stix_type"] == first_obj.type

    def test_uses_configured_index_name(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """index_to_opensearch uses the collection name from config."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        assert first_call[1]["index"] == "dark-web-fraud-intel"

    def test_default_metadata_values(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle
    ):
        """Default metadata values are used when not provided."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        structurer.index_to_opensearch(sample_bundle, {})

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        assert doc["tier"] == "observable"
        assert doc["severity_score"] == 1
        assert doc["fraud_category"] is None
        assert doc["entities"] == []
        assert doc["tags"] == []

    def test_creates_opensearch_client_if_none(
        self, structurer, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """index_to_opensearch creates client if _opensearch_client is None."""
        structurer._bedrock_client = mock_bedrock_client
        assert structurer._opensearch_client is None

        mock_os_client = MagicMock()
        mock_os_client.index.return_value = {
            "_id": "doc-new", "_index": "dark-web-fraud-intel", "result": "created"
        }

        with patch.object(structurer, "_create_opensearch_client", return_value=mock_os_client):
            structurer.index_to_opensearch(sample_bundle, sample_metadata)

            assert structurer._opensearch_client is mock_os_client

    def test_embedding_vector_included_in_document(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """Each document has an intelligence_vector field with the embedding."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        assert "intelligence_vector" in doc
        assert isinstance(doc["intelligence_vector"], list)
        assert len(doc["intelligence_vector"]) == 1024

    def test_created_at_is_iso_format(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """created_at field is in ISO format."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        parsed = datetime.fromisoformat(doc["created_at"])
        assert parsed is not None


# --- get_index_name Tests ---


class TestGetIndexName:
    """Tests for get_index_name() method."""

    def test_returns_config_collection_name(self, structurer):
        """get_index_name returns the configured collection name."""
        assert structurer.get_index_name() == "dark-web-fraud-intel"

    def test_returns_default_when_no_config(self):
        """get_index_name returns default when no config is provided."""
        structurer = DataStructurer(config=None)
        assert structurer.get_index_name() == "dark-web-fraud-intel"


# --- _create_opensearch_client Tests ---


class TestCreateOpenSearchClient:
    """Tests for _create_opensearch_client() method."""

    @patch.dict(os.environ, {"AWS_REGION": "eu-west-2"})
    @patch("boto3.Session")
    def test_creates_client_with_aws_auth(self, mock_session_class, config):
        """_create_opensearch_client creates OpenSearch client with AWS4Auth."""
        structurer = DataStructurer(config=config)

        mock_session = MagicMock()
        mock_creds = MagicMock()
        mock_creds.access_key = "AKIAIOSFODNN7EXAMPLE"
        mock_creds.secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        mock_creds.token = "FwoGZXIvYXdzEBYaDHqa0..."
        mock_session.get_credentials.return_value = mock_creds
        mock_session_class.return_value = mock_session

        with patch("opensearchpy.OpenSearch") as mock_os_class, \
             patch("requests_aws4auth.AWS4Auth") as mock_auth_class:
            mock_os_class.return_value = MagicMock()
            mock_auth_class.return_value = MagicMock()

            client = structurer._create_opensearch_client()

            mock_auth_class.assert_called_once_with(
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "eu-west-2",
                "aoss",
                session_token="FwoGZXIvYXdzEBYaDHqa0...",
            )

            mock_os_class.assert_called_once()
            call_kwargs = mock_os_class.call_args[1]
            assert call_kwargs["use_ssl"] is True
            assert call_kwargs["verify_certs"] is True
            assert call_kwargs["hosts"] == [
                {"host": "abc123.eu-west-2.aoss.amazonaws.com", "port": 443}
            ]


# --- Integration-style tests with full flow ---


class TestOpenSearchIndexingFlow:
    """Integration-style tests for the full indexing flow."""

    def test_single_sco_indexing(self, structurer, mock_opensearch_client, mock_bedrock_client):
        """Index a single SCO object and verify document structure."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        entity = ExtractedEntity(
            entity_type="ip_address",
            value="45.33.32.156",
            context="Known C2 infrastructure",
            confidence=0.95,
        )
        sco = structurer.create_stix_sco(entity)
        bundle = structurer.build_bundle([sco])

        metadata = {
            "tier": "observable",
            "severity_score": 3,
            "fraud_category": None,
            "entities": [{"entity_type": "ip_address", "value": "45.33.32.156"}],
            "tags": ["tlp:white"],
        }
        doc_ids = structurer.index_to_opensearch(bundle, metadata)

        assert len(doc_ids) == 1
        call_kwargs = mock_opensearch_client.index.call_args[1]
        doc = call_kwargs["body"]
        assert doc["stix_type"] == "ipv4-addr"
        assert "45.33.32.156" in doc["content_summary"]
        assert doc["entities"] == [{"entity_type": "ip_address", "value": "45.33.32.156"}]
        assert doc["tags"] == ["tlp:white"]

    def test_multiple_objects_indexing(self, structurer, mock_opensearch_client, mock_bedrock_client):
        """Index a bundle with multiple objects."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        mock_opensearch_client.index.side_effect = [
            {"_id": f"doc-{i}", "_index": "dark-web-fraud-intel", "result": "created"}
            for i in range(3)
        ]

        objects = []
        objects.append(structurer.create_stix_sco(
            ExtractedEntity(entity_type="ip_address", value="10.0.0.1", context="c2", confidence=0.9)
        ))
        objects.append(structurer.create_stix_sdo(
            ExtractedEntity(entity_type="bank_name", value="Actor", context="ctx", confidence=0.8),
            "threat-actor",
        ))
        objects.append(structurer.create_stix_relationship(
            objects[1].id, objects[0].id, "uses"
        ))

        bundle = structurer.build_bundle(objects)
        metadata = {
            "tier": "ttp",
            "severity_score": 9,
            "fraud_category": "mfa_bypass",
            "entities": [
                {"entity_type": "ip_address", "value": "10.0.0.1"},
                {"entity_type": "bank_name", "value": "Actor"},
            ],
            "tags": ["mitre-attack:technique=\"T1111\""],
        }

        doc_ids = structurer.index_to_opensearch(bundle, metadata)

        assert len(doc_ids) == 3
        assert mock_opensearch_client.index.call_count == 3
