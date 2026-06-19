"""Unit tests for OpenSearch Serverless vector indexing in the Data Structurer agent.

Tests verify that:
- index_to_opensearch() generates embeddings and indexes documents correctly
- _generate_embedding() invokes Bedrock with proper parameters
- _get_object_summary() produces meaningful text for various STIX object types
- _create_opensearch_client() creates a properly configured client
- Document structure includes all required metadata fields
"""

import io
import json
from unittest.mock import MagicMock, AsyncMock, patch

import pytest
import stix2

from dark_web_fraud_agent.agents.data_structurer import DataStructurer, StructurerConfig
from dark_web_fraud_agent.models.content_analyst import ExtractedEntity


@pytest.fixture
def config():
    """Create a StructurerConfig for testing."""
    return StructurerConfig(
        opensearch_endpoint="https://abc123.us-east-1.aoss.amazonaws.com",
        opensearch_collection_name="threat-intel",
        misp_url="https://misp.example.com",
        misp_secret_arn="arn:aws:secretsmanager:us-east-1:123456789:secret:misp-key",
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
    client.index.return_value = {"_id": "doc-123", "_index": "threat-intel", "result": "created"}
    return client


@pytest.fixture
def mock_bedrock_client():
    """Create a mock Bedrock runtime client."""
    client = MagicMock()
    # Create a fake embedding response
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
    """Create sample metadata for indexing."""
    return {
        "tier": "indicator",
        "severity_score": 7,
        "confidence": 0.85,
        "fraud_category": "account_takeover",
        "tags": ["banking", "ato"],
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

    def test_summary_for_artifact_without_name_or_value(self, structurer):
        """Artifact SCO (btc_wallet) produces summary with just type."""
        entity = ExtractedEntity(
            entity_type="btc_wallet",
            value="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            context="BTC wallet",
            confidence=0.98,
        )
        sco = structurer.create_stix_sco(entity)

        summary = structurer._get_object_summary(sco)

        # Artifact doesn't have name or value attributes in the STIX sense
        assert "Type: artifact" in summary


# --- _generate_embedding Tests ---


class TestGenerateEmbedding:
    """Tests for _generate_embedding() method."""

    @pytest.mark.asyncio
    async def test_generate_embedding_invokes_bedrock(self, structurer, mock_bedrock_client):
        """_generate_embedding calls Bedrock with the correct model and text."""
        structurer._bedrock_client = mock_bedrock_client

        entity = ExtractedEntity(
            entity_type="ip_address", value="10.0.0.1", context="test", confidence=0.9
        )
        sco = structurer.create_stix_sco(entity)

        result = await structurer._generate_embedding(sco)

        mock_bedrock_client.invoke_model.assert_called_once()
        call_kwargs = mock_bedrock_client.invoke_model.call_args[1]
        assert call_kwargs["modelId"] == "amazon.titan-embed-text-v2:0"
        assert call_kwargs["contentType"] == "application/json"

        # Verify the body contains inputText
        body = json.loads(call_kwargs["body"])
        assert "inputText" in body
        assert "10.0.0.1" in body["inputText"]

    @pytest.mark.asyncio
    async def test_generate_embedding_returns_vector(self, structurer, mock_bedrock_client):
        """_generate_embedding returns the embedding vector from Bedrock response."""
        structurer._bedrock_client = mock_bedrock_client

        entity = ExtractedEntity(
            entity_type="ip_address", value="10.0.0.1", context="test", confidence=0.9
        )
        sco = structurer.create_stix_sco(entity)

        result = await structurer._generate_embedding(sco)

        assert isinstance(result, list)
        assert len(result) == 1024
        assert all(isinstance(v, float) for v in result)

    @pytest.mark.asyncio
    async def test_generate_embedding_creates_client_if_none(self, structurer):
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

            result = await structurer._generate_embedding(sco)

            mock_boto3_client.assert_called_once_with("bedrock-runtime")
            assert result == embedding


# --- index_to_opensearch Tests ---


class TestIndexToOpenSearch:
    """Tests for index_to_opensearch() method."""

    @pytest.mark.asyncio
    async def test_indexes_all_bundle_objects(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """index_to_opensearch indexes every object in the bundle."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        doc_ids = await structurer.index_to_opensearch(sample_bundle, sample_metadata)

        assert len(doc_ids) == len(sample_bundle.objects)
        assert mock_opensearch_client.index.call_count == len(sample_bundle.objects)

    @pytest.mark.asyncio
    async def test_returns_document_ids(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """index_to_opensearch returns a list of OpenSearch document IDs."""
        # Make each call return a unique ID
        mock_opensearch_client.index.side_effect = [
            {"_id": f"doc-{i}", "_index": "threat-intel", "result": "created"}
            for i in range(len(sample_bundle.objects))
        ]
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        doc_ids = await structurer.index_to_opensearch(sample_bundle, sample_metadata)

        assert doc_ids == ["doc-0", "doc-1"]

    @pytest.mark.asyncio
    async def test_document_contains_required_fields(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """Each indexed document contains all required metadata fields."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        await structurer.index_to_opensearch(sample_bundle, sample_metadata)

        # Check the first indexed document
        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        assert "stix_id" in doc
        assert "stix_type" in doc
        assert "tier" in doc
        assert "severity_score" in doc
        assert "confidence" in doc
        assert "fraud_category" in doc
        assert "content_summary" in doc
        assert "created_at" in doc
        assert "intelligence_vector" in doc

    @pytest.mark.asyncio
    async def test_document_metadata_from_input(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """Document metadata values are populated from the metadata argument."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        await structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        assert doc["tier"] == "indicator"
        assert doc["severity_score"] == 7
        assert doc["confidence"] == 0.85
        assert doc["fraud_category"] == "account_takeover"

    @pytest.mark.asyncio
    async def test_document_stix_fields_from_object(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """Document stix_id and stix_type come from the STIX object."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        await structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        first_obj = sample_bundle.objects[0]
        assert doc["stix_id"] == first_obj.id
        assert doc["stix_type"] == first_obj.type

    @pytest.mark.asyncio
    async def test_uses_configured_index_name(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """index_to_opensearch uses the collection name from config."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        await structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        assert first_call[1]["index"] == "threat-intel"

    @pytest.mark.asyncio
    async def test_default_metadata_values(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle
    ):
        """Default metadata values are used when not provided."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        # Pass empty metadata
        await structurer.index_to_opensearch(sample_bundle, {})

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        assert doc["tier"] == "observable"
        assert doc["severity_score"] == 1
        assert doc["confidence"] == 0.0
        assert doc["fraud_category"] is None

    @pytest.mark.asyncio
    async def test_creates_opensearch_client_if_none(self, structurer, mock_bedrock_client, sample_bundle, sample_metadata):
        """index_to_opensearch creates client if _opensearch_client is None."""
        structurer._bedrock_client = mock_bedrock_client
        assert structurer._opensearch_client is None

        mock_os_client = MagicMock()
        mock_os_client.index.return_value = {"_id": "doc-new", "_index": "threat-intel", "result": "created"}

        with patch.object(structurer, "_create_opensearch_client", return_value=mock_os_client) as mock_create:
            await structurer.index_to_opensearch(sample_bundle, sample_metadata)

            mock_create.assert_called_once()
            assert structurer._opensearch_client is mock_os_client

    @pytest.mark.asyncio
    async def test_embedding_vector_included_in_document(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """Each document has an intelligence_vector field with the embedding."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        await structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        assert "intelligence_vector" in doc
        assert isinstance(doc["intelligence_vector"], list)
        assert len(doc["intelligence_vector"]) == 1024

    @pytest.mark.asyncio
    async def test_created_at_is_iso_format(
        self, structurer, mock_opensearch_client, mock_bedrock_client, sample_bundle, sample_metadata
    ):
        """created_at field is in ISO format."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        await structurer.index_to_opensearch(sample_bundle, sample_metadata)

        first_call = mock_opensearch_client.index.call_args_list[0]
        doc = first_call[1]["body"]

        # Should be parseable as ISO format datetime
        from datetime import datetime as dt
        parsed = dt.fromisoformat(doc["created_at"])
        assert parsed is not None


# --- _create_opensearch_client Tests ---


class TestCreateOpenSearchClient:
    """Tests for _create_opensearch_client() method."""

    @patch("boto3.Session")
    def test_creates_client_with_aws_auth(self, mock_session_class, config):
        """_create_opensearch_client creates OpenSearch client with AWS4Auth."""
        structurer = DataStructurer(config=config)

        # Mock credentials
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

            # Verify AWS4Auth was created with correct params
            mock_auth_class.assert_called_once_with(
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "us-east-1",  # extracted from endpoint
                "aoss",
                session_token="FwoGZXIvYXdzEBYaDHqa0...",
            )

            # Verify OpenSearch client was created with SSL
            mock_os_class.assert_called_once()
            call_kwargs = mock_os_class.call_args[1]
            assert call_kwargs["use_ssl"] is True
            assert call_kwargs["verify_certs"] is True
            assert call_kwargs["hosts"] == [
                {"host": "abc123.us-east-1.aoss.amazonaws.com", "port": 443}
            ]


# --- Integration-style tests with full flow ---


class TestOpenSearchIndexingFlow:
    """Integration-style tests for the full indexing flow."""

    @pytest.mark.asyncio
    async def test_single_sco_indexing(self, structurer, mock_opensearch_client, mock_bedrock_client):
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

        metadata = {"tier": "observable", "severity_score": 3, "confidence": 0.95}
        doc_ids = await structurer.index_to_opensearch(bundle, metadata)

        assert len(doc_ids) == 1
        call_kwargs = mock_opensearch_client.index.call_args[1]
        doc = call_kwargs["body"]
        assert doc["stix_type"] == "ipv4-addr"
        assert "45.33.32.156" in doc["content_summary"]

    @pytest.mark.asyncio
    async def test_multiple_objects_indexing(self, structurer, mock_opensearch_client, mock_bedrock_client):
        """Index a bundle with multiple objects."""
        structurer._opensearch_client = mock_opensearch_client
        structurer._bedrock_client = mock_bedrock_client

        # Generate unique IDs for each indexed doc
        mock_opensearch_client.index.side_effect = [
            {"_id": f"doc-{i}", "_index": "threat-intel", "result": "created"}
            for i in range(3)
        ]

        objects = []
        # IP SCO
        objects.append(structurer.create_stix_sco(
            ExtractedEntity(entity_type="ip_address", value="10.0.0.1", context="c2", confidence=0.9)
        ))
        # Threat Actor SDO
        objects.append(structurer.create_stix_sdo(
            ExtractedEntity(entity_type="bank_name", value="Actor", context="ctx", confidence=0.8),
            "threat-actor",
        ))
        # Relationship
        objects.append(structurer.create_stix_relationship(
            objects[1].id, objects[0].id, "uses"
        ))

        bundle = structurer.build_bundle(objects)
        metadata = {"tier": "ttp", "severity_score": 9}

        doc_ids = await structurer.index_to_opensearch(bundle, metadata)

        assert len(doc_ids) == 3
        assert mock_opensearch_client.index.call_count == 3
