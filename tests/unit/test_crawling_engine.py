"""Unit tests for the Crawling Engine module.

Tests CrawlResult model, S3 artifact storage, SHA-256 content hashing,
and CrawlingEngine agent with Tor proxy connectivity and circuit rotation.
Uses moto to mock S3 and Secrets Manager interactions.
"""

import hashlib
import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, AsyncMock, patch

import boto3
import pytest
from moto import mock_aws

from dark_web_fraud_agent.agents.crawling_engine import (
    CrawlResult,
    CrawlingEngine,
    _generate_s3_key,
    compute_content_hash,
    store_artifact,
)
from dark_web_fraud_agent.config.settings import CrawlConfig, SourceDefinition, SourceType

BUCKET_NAME = "test-crawl-artifacts"
DYNAMODB_TABLE = "test-crawl-state"
SECRETS_PREFIX = "darkweb/tor"


@pytest.fixture
def s3_client():
    """Create a mocked S3 client with a test bucket."""
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET_NAME)
        yield client


@pytest.fixture
def crawl_config():
    """Create a valid CrawlConfig for testing."""
    return CrawlConfig(
        sources=[
            SourceDefinition(
                url="http://darkforum.onion",
                source_type=SourceType.ONION,
                category="forum",
                crawl_interval_seconds=300,
                requires_auth=False,
            )
        ],
        tor_socks_port=9050,
        tor_control_port=9051,
        max_retries=3,
        circuit_rotation_interval=300,
        request_timeout=30,
        s3_bucket=BUCKET_NAME,
        dynamodb_table=DYNAMODB_TABLE,
        secrets_manager_prefix=SECRETS_PREFIX,
    )


@pytest.fixture
def mock_tor_controller():
    """Create a mock stem Controller."""
    controller = MagicMock()
    controller.is_authenticated.return_value = True
    controller.get_info.return_value = "198.51.100.42"
    return controller


@pytest.fixture
def mock_secrets_client():
    """Create a mock Secrets Manager client that returns a Tor password."""
    client = MagicMock()
    client.get_secret_value.return_value = {
        "SecretString": json.dumps({"password": "test-tor-password"})
    }
    return client


class TestComputeContentHash:
    """Tests for SHA-256 content hashing."""

    def test_returns_hex_sha256(self):
        """Hash output matches Python hashlib SHA-256."""
        content = "test dark web content"
        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert compute_content_hash(content) == expected

    def test_empty_string_hash(self):
        """Empty string produces a valid SHA-256 hash."""
        result = compute_content_hash("")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic(self):
        """Same content always produces same hash."""
        content = "duplicate content check"
        assert compute_content_hash(content) == compute_content_hash(content)

    def test_different_content_different_hash(self):
        """Different content produces different hashes."""
        hash1 = compute_content_hash("content A")
        hash2 = compute_content_hash("content B")
        assert hash1 != hash2

    def test_unicode_content(self):
        """Unicode content is properly hashed."""
        content = "Данные с темной сети 🕸️"
        result = compute_content_hash(content)
        assert len(result) == 64


class TestGenerateS3Key:
    """Tests for S3 key generation."""

    def test_key_contains_date_partition(self):
        """Generated key includes date-based partitioning."""
        timestamp = datetime(2024, 6, 15, 10, 30, 0, tzinfo=UTC)
        key = _generate_s3_key("http://example.onion", timestamp, "abc123def456")
        assert "2024/06/15" in key

    def test_key_starts_with_prefix(self):
        """Generated key starts with crawl-artifacts/ prefix."""
        timestamp = datetime(2024, 1, 1, tzinfo=UTC)
        key = _generate_s3_key("http://test.onion", timestamp, "hash123")
        assert key.startswith("crawl-artifacts/")

    def test_key_ends_with_txt(self):
        """Generated key ends with .txt extension."""
        timestamp = datetime(2024, 1, 1, tzinfo=UTC)
        key = _generate_s3_key("http://test.onion", timestamp, "hash123")
        assert key.endswith(".txt")

    def test_key_contains_hash_prefix(self):
        """Generated key contains first 16 chars of content hash."""
        timestamp = datetime(2024, 1, 1, tzinfo=UTC)
        content_hash = "abcdef1234567890abcdef1234567890"
        key = _generate_s3_key("http://test.onion", timestamp, content_hash)
        assert "abcdef1234567890" in key


class TestStoreArtifact:
    """Tests for S3 artifact storage with annotations."""

    def test_stores_content_in_s3(self, s3_client):
        """Raw content is stored as an S3 object."""
        content = "Leaked BIN data: 4111 1111 xxxx"
        metadata = {
            "source_url": "http://forum.onion/post/123",
            "source_category": "forum",
            "crawl_timestamp": datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC),
            "proxy_identity": "exit-node-1",
            "response_status": 200,
            "content_hash": compute_content_hash(content),
        }

        s3_key, annotation_id = store_artifact(
            content=content,
            metadata=metadata,
            s3_bucket=BUCKET_NAME,
            s3_client=s3_client,
        )

        # Verify content was stored
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=s3_key)
        stored_content = response["Body"].read().decode("utf-8")
        assert stored_content == content

    def test_returns_valid_s3_key(self, s3_client):
        """Returned S3 key is a valid path."""
        content = "test content"
        metadata = {
            "source_url": "http://market.onion",
            "source_category": "marketplace",
            "crawl_timestamp": datetime(2024, 3, 10, tzinfo=UTC),
            "proxy_identity": "proxy-2",
            "response_status": 200,
            "content_hash": compute_content_hash(content),
        }

        s3_key, _ = store_artifact(
            content=content,
            metadata=metadata,
            s3_bucket=BUCKET_NAME,
            s3_client=s3_client,
        )

        assert s3_key.startswith("crawl-artifacts/")
        assert "2024/03/10" in s3_key

    def test_returns_annotation_id(self, s3_client):
        """Returned annotation ID has expected format."""
        content = "sample content"
        metadata = {
            "source_url": "http://paste.onion",
            "source_category": "paste",
            "crawl_timestamp": datetime(2024, 1, 5, tzinfo=UTC),
            "proxy_identity": "proxy-3",
            "response_status": 200,
            "content_hash": compute_content_hash(content),
        }

        _, annotation_id = store_artifact(
            content=content,
            metadata=metadata,
            s3_bucket=BUCKET_NAME,
            s3_client=s3_client,
        )

        assert annotation_id.startswith("ann-")
        assert len(annotation_id) > 4

    def test_annotation_contains_metadata(self, s3_client):
        """S3 annotation sidecar contains the source metadata."""
        content = "darknet intel data"
        metadata = {
            "source_url": "http://darkforum.onion/thread/99",
            "source_category": "forum",
            "crawl_timestamp": datetime(2024, 7, 20, 8, 30, tzinfo=UTC),
            "proxy_identity": "exit-node-5",
            "response_status": 200,
            "content_hash": compute_content_hash(content),
        }

        s3_key, annotation_id = store_artifact(
            content=content,
            metadata=metadata,
            s3_bucket=BUCKET_NAME,
            s3_client=s3_client,
        )

        # Read annotation sidecar
        annotation_key = f"{s3_key}.annotation.json"
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=annotation_key)
        annotation_data = json.loads(response["Body"].read().decode("utf-8"))

        assert annotation_data["source_url"] == "http://darkforum.onion/thread/99"
        assert annotation_data["source_category"] == "forum"
        assert annotation_data["proxy_identity"] == "exit-node-5"
        assert annotation_data["response_status"] == 200
        assert annotation_data["annotation_id"] == annotation_id
        assert annotation_data["artifact_key"] == s3_key

    def test_s3_object_metadata_includes_hash(self, s3_client):
        """S3 object user metadata includes the content hash."""
        content = "content for metadata check"
        content_hash = compute_content_hash(content)
        metadata = {
            "source_url": "http://test.onion",
            "source_category": "marketplace",
            "crawl_timestamp": datetime(2024, 5, 1, tzinfo=UTC),
            "proxy_identity": "proxy-x",
            "response_status": 200,
            "content_hash": content_hash,
        }

        s3_key, _ = store_artifact(
            content=content,
            metadata=metadata,
            s3_bucket=BUCKET_NAME,
            s3_client=s3_client,
        )

        response = s3_client.head_object(Bucket=BUCKET_NAME, Key=s3_key)
        assert response["Metadata"]["content-hash"] == content_hash

    def test_content_type_is_text_plain(self, s3_client):
        """Stored artifact has text/plain content type."""
        content = "plain text crawl"
        metadata = {
            "source_url": "http://test.onion",
            "source_category": "forum",
            "crawl_timestamp": datetime(2024, 1, 1, tzinfo=UTC),
            "proxy_identity": "proxy-1",
            "response_status": 200,
            "content_hash": compute_content_hash(content),
        }

        s3_key, _ = store_artifact(
            content=content,
            metadata=metadata,
            s3_bucket=BUCKET_NAME,
            s3_client=s3_client,
        )

        response = s3_client.head_object(Bucket=BUCKET_NAME, Key=s3_key)
        assert response["ContentType"] == "text/plain"


class TestCrawlResult:
    """Tests for the CrawlResult dataclass."""

    def test_create_crawl_result(self):
        """CrawlResult can be instantiated with all required fields."""
        now = datetime.now(UTC)
        content = "test content"
        result = CrawlResult(
            source_url="http://forum.onion/post/1",
            source_category="forum",
            raw_content=content,
            crawl_timestamp=now,
            proxy_identity="exit-node-1",
            response_status=200,
            content_hash=compute_content_hash(content),
            s3_artifact_key="crawl-artifacts/2024/01/01/abc123/def456.txt",
            s3_annotation_id="ann-abc123def456",
        )

        assert result.source_url == "http://forum.onion/post/1"
        assert result.source_category == "forum"
        assert result.raw_content == content
        assert result.crawl_timestamp == now
        assert result.proxy_identity == "exit-node-1"
        assert result.response_status == 200
        assert result.content_hash == compute_content_hash(content)
        assert result.s3_artifact_key == "crawl-artifacts/2024/01/01/abc123/def456.txt"
        assert result.s3_annotation_id == "ann-abc123def456"

    def test_content_hash_matches_raw_content(self):
        """Content hash in CrawlResult matches SHA-256 of raw_content."""
        content = "leaked credentials: admin@bank.com:password123"
        content_hash = compute_content_hash(content)
        result = CrawlResult(
            source_url="http://paste.onion/xyz",
            source_category="paste",
            raw_content=content,
            crawl_timestamp=datetime.now(UTC),
            proxy_identity="proxy-2",
            response_status=200,
            content_hash=content_hash,
            s3_artifact_key="key",
            s3_annotation_id="ann-id",
        )

        assert result.content_hash == hashlib.sha256(content.encode("utf-8")).hexdigest()



class TestCrawlingEngineInit:
    """Tests for CrawlingEngine initialization."""

    def test_init_sets_agent_config(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """CrawlingEngine sets agent_id and agent_name from config."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        assert engine.config.agent_id == "crawling-engine"
        assert engine.config.agent_name == "Crawling Engine"
        assert engine.config.s3_bucket == BUCKET_NAME
        assert engine.config.dynamodb_table == DYNAMODB_TABLE

    def test_init_stores_crawl_config(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """CrawlingEngine stores the CrawlConfig."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        assert engine.crawl_config is crawl_config
        assert engine.crawl_config.tor_socks_port == 9050
        assert engine.crawl_config.tor_control_port == 9051

    def test_init_not_running(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """CrawlingEngine is not running after initialization."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        assert engine.is_running is False
        assert engine.current_ip is None


class TestCrawlingEngineStartStop:
    """Tests for CrawlingEngine start() and stop() lifecycle."""

    @pytest.mark.asyncio
    async def test_start_sets_running(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """start() sets the engine to running state."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()
        assert engine.is_running is True

    @pytest.mark.asyncio
    async def test_start_health_is_healthy(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """start() sets health status to healthy."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()
        health = engine.get_health()
        assert health.status == "healthy"

    @pytest.mark.asyncio
    async def test_stop_sets_not_running(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """stop() sets the engine to not-running state."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()
        await engine.stop()
        assert engine.is_running is False
        assert engine.current_ip is None

    @pytest.mark.asyncio
    async def test_stop_closes_tor_controller(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """stop() closes the Tor controller connection."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()
        await engine.stop()
        mock_tor_controller.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_health_is_stopped(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """stop() sets health status to stopped."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()
        await engine.stop()
        health = engine.get_health()
        assert health.status == "stopped"


class TestCrawlingEngineRotateCircuit:
    """Tests for CrawlingEngine.rotate_circuit()."""

    @pytest.mark.asyncio
    async def test_rotate_circuit_returns_ip(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """rotate_circuit() returns a new exit node IP."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()
        new_ip = await engine.rotate_circuit()
        assert new_ip == "198.51.100.42"

    @pytest.mark.asyncio
    async def test_rotate_circuit_sends_newnym(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """rotate_circuit() sends NEWNYM signal to Tor controller."""
        from stem import Signal

        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()
        await engine.rotate_circuit()
        mock_tor_controller.signal.assert_called_once_with(Signal.NEWNYM)

    @pytest.mark.asyncio
    async def test_rotate_circuit_updates_current_ip(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """rotate_circuit() updates the current_ip property."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()
        assert engine.current_ip is None
        await engine.rotate_circuit()
        assert engine.current_ip == "198.51.100.42"

    @pytest.mark.asyncio
    async def test_rotate_circuit_raises_when_not_running(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """rotate_circuit() raises RuntimeError if engine is not started."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        with pytest.raises(RuntimeError, match="not running"):
            await engine.rotate_circuit()

    @pytest.mark.asyncio
    async def test_rotate_circuit_different_ips(self, crawl_config, mock_secrets_client):
        """rotate_circuit() returns different IPs on successive rotations."""
        controller = MagicMock()
        controller.is_authenticated.return_value = True
        controller.get_info.side_effect = ["198.51.100.1", "203.0.113.55"]

        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=controller,
        )
        await engine.start()

        ip1 = await engine.rotate_circuit()
        ip2 = await engine.rotate_circuit()

        assert ip1 == "198.51.100.1"
        assert ip2 == "203.0.113.55"
        assert ip1 != ip2


class TestCrawlingEngineSecretsManager:
    """Tests for CrawlingEngine Secrets Manager credential retrieval."""

    @pytest.mark.asyncio
    async def test_retrieves_tor_credential_json(self, crawl_config, mock_tor_controller):
        """start() retrieves Tor password from Secrets Manager (JSON format)."""
        secrets_client = MagicMock()
        secrets_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"password": "my-secret-password"})
        }

        # Use a non-authenticated controller to trigger credential retrieval
        controller = MagicMock()
        controller.is_authenticated.return_value = False

        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=secrets_client,
            tor_controller=controller,
        )
        await engine.start()

        secrets_client.get_secret_value.assert_called_once_with(
            SecretId=f"{SECRETS_PREFIX}/tor-control-password"
        )
        controller.authenticate.assert_called_once_with(password="my-secret-password")

    @pytest.mark.asyncio
    async def test_retrieves_tor_credential_plain_string(self, crawl_config, mock_tor_controller):
        """start() retrieves Tor password from Secrets Manager (plain string format)."""
        secrets_client = MagicMock()
        secrets_client.get_secret_value.return_value = {
            "SecretString": "plain-password-value"
        }

        controller = MagicMock()
        controller.is_authenticated.return_value = False

        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=secrets_client,
            tor_controller=controller,
        )
        await engine.start()

        controller.authenticate.assert_called_once_with(password="plain-password-value")

    @pytest.mark.asyncio
    async def test_skips_auth_if_already_authenticated(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """start() skips authentication if controller is already authenticated."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()
        # Already authenticated controller should not trigger authenticate()
        mock_tor_controller.authenticate.assert_not_called()


class TestCrawlingEngineProxyUrl:
    """Tests for CrawlingEngine.get_proxy_url()."""

    def test_proxy_url_default_port(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """get_proxy_url() returns SOCKS5 URL with configured port."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        assert engine.get_proxy_url() == "socks5://127.0.0.1:9050"

    def test_proxy_url_custom_port(self, mock_tor_controller, mock_secrets_client):
        """get_proxy_url() uses custom SOCKS5 port from config."""
        config = CrawlConfig(
            sources=[],
            tor_socks_port=19050,
            tor_control_port=19051,
            max_retries=3,
            circuit_rotation_interval=300,
            request_timeout=30,
            s3_bucket=BUCKET_NAME,
            dynamodb_table=DYNAMODB_TABLE,
            secrets_manager_prefix=SECRETS_PREFIX,
        )
        engine = CrawlingEngine(
            crawl_config=config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        assert engine.get_proxy_url() == "socks5://127.0.0.1:19050"


class TestCrawlingEngineHealth:
    """Tests for CrawlingEngine.get_health()."""

    def test_health_returns_agent_health(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """get_health() returns an AgentHealth instance."""
        from dark_web_fraud_agent.models.shared import AgentHealth

        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        health = engine.get_health()
        assert isinstance(health, AgentHealth)
        assert health.agent_id == "crawling-engine"

    def test_health_updates_heartbeat(self, crawl_config, mock_tor_controller, mock_secrets_client):
        """get_health() updates the last_heartbeat timestamp."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        before = datetime.now(UTC)
        health = engine.get_health()
        assert health.last_heartbeat >= before
