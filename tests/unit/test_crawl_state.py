"""Unit tests for CrawlingEngine DynamoDB state tracking and health reporting.

Tests the _write_crawl_state method and uptime-aware get_health()
using moto mock_aws for DynamoDB.
"""

import hashlib
import json
import time
from datetime import UTC, datetime
from unittest.mock import MagicMock

import boto3
import pytest
from moto import mock_aws

from dark_web_fraud_agent.agents.crawling_engine import CrawlingEngine
from dark_web_fraud_agent.config.settings import CrawlConfig, SourceDefinition, SourceType

BUCKET_NAME = "test-crawl-artifacts"
DYNAMODB_TABLE = "test-crawl-state"
SECRETS_PREFIX = "darkweb/tor"


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
    """Create a mock Secrets Manager client."""
    client = MagicMock()
    client.get_secret_value.return_value = {
        "SecretString": json.dumps({"password": "test-tor-password"})
    }
    return client


@pytest.fixture
def dynamodb_table():
    """Create a mocked DynamoDB table for crawl state tracking."""
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName=DYNAMODB_TABLE,
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield dynamodb


class TestWriteCrawlState:
    """Tests for CrawlingEngine._write_crawl_state DynamoDB tracking."""

    @pytest.mark.asyncio
    async def test_writes_item_to_dynamodb(
        self, crawl_config, mock_tor_controller, mock_secrets_client, dynamodb_table
    ):
        """_write_crawl_state writes a crawl state item to DynamoDB."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        engine._dynamodb_client = dynamodb_table

        source_url = "http://darkforum.onion/thread/42"
        content_hash = "abc123def456"

        await engine._write_crawl_state(source_url, content_hash, success=True)

        # Verify the item was written
        table = dynamodb_table.Table(DYNAMODB_TABLE)
        source_hash = hashlib.sha256(source_url.encode()).hexdigest()[:16]

        response = table.query(
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={":pk": f"SOURCE#{source_hash}"},
        )
        items = response["Items"]
        assert len(items) == 1
        item = items[0]
        assert item["source_url"] == source_url
        assert item["last_content_hash"] == content_hash
        assert item["success"] is True

    @pytest.mark.asyncio
    async def test_pk_uses_source_url_hash(
        self, crawl_config, mock_tor_controller, mock_secrets_client, dynamodb_table
    ):
        """PK is SOURCE# followed by the first 16 chars of the URL's SHA-256."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        engine._dynamodb_client = dynamodb_table

        source_url = "http://market.onion/listing/99"
        await engine._write_crawl_state(source_url, "somehash", success=True)

        table = dynamodb_table.Table(DYNAMODB_TABLE)
        expected_hash = hashlib.sha256(source_url.encode()).hexdigest()[:16]

        response = table.query(
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={":pk": f"SOURCE#{expected_hash}"},
        )
        assert len(response["Items"]) == 1

    @pytest.mark.asyncio
    async def test_sk_starts_with_crawl_prefix(
        self, crawl_config, mock_tor_controller, mock_secrets_client, dynamodb_table
    ):
        """SK starts with CRAWL# followed by an ISO timestamp."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        engine._dynamodb_client = dynamodb_table

        await engine._write_crawl_state("http://test.onion", "hash123", success=False)

        table = dynamodb_table.Table(DYNAMODB_TABLE)
        source_hash = hashlib.sha256("http://test.onion".encode()).hexdigest()[:16]

        response = table.query(
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={":pk": f"SOURCE#{source_hash}"},
        )
        item = response["Items"][0]
        assert item["SK"].startswith("CRAWL#")

    @pytest.mark.asyncio
    async def test_records_failure_state(
        self, crawl_config, mock_tor_controller, mock_secrets_client, dynamodb_table
    ):
        """_write_crawl_state records success=False for failed crawls."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        engine._dynamodb_client = dynamodb_table

        await engine._write_crawl_state("http://down.onion", "emptyhash", success=False)

        table = dynamodb_table.Table(DYNAMODB_TABLE)
        source_hash = hashlib.sha256("http://down.onion".encode()).hexdigest()[:16]

        response = table.query(
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={":pk": f"SOURCE#{source_hash}"},
        )
        item = response["Items"][0]
        assert item["success"] is False

    @pytest.mark.asyncio
    async def test_includes_next_crawl_due(
        self, crawl_config, mock_tor_controller, mock_secrets_client, dynamodb_table
    ):
        """_write_crawl_state includes a next_crawl_due timestamp."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        engine._dynamodb_client = dynamodb_table

        before = datetime.now(UTC)
        await engine._write_crawl_state("http://test.onion", "hash", success=True)

        table = dynamodb_table.Table(DYNAMODB_TABLE)
        source_hash = hashlib.sha256("http://test.onion".encode()).hexdigest()[:16]

        response = table.query(
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={":pk": f"SOURCE#{source_hash}"},
        )
        item = response["Items"][0]
        assert "next_crawl_due" in item
        # next_crawl_due should be a valid ISO timestamp
        next_due = datetime.fromisoformat(item["next_crawl_due"])
        assert next_due > before

    @pytest.mark.asyncio
    async def test_includes_last_crawl_timestamp(
        self, crawl_config, mock_tor_controller, mock_secrets_client, dynamodb_table
    ):
        """_write_crawl_state includes a last_crawl_timestamp."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        engine._dynamodb_client = dynamodb_table

        before = datetime.now(UTC)
        await engine._write_crawl_state("http://test.onion", "hash", success=True)

        table = dynamodb_table.Table(DYNAMODB_TABLE)
        source_hash = hashlib.sha256("http://test.onion".encode()).hexdigest()[:16]

        response = table.query(
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={":pk": f"SOURCE#{source_hash}"},
        )
        item = response["Items"][0]
        crawl_ts = datetime.fromisoformat(item["last_crawl_timestamp"])
        assert crawl_ts >= before

    @pytest.mark.asyncio
    async def test_initializes_dynamodb_client_if_none(
        self, crawl_config, mock_tor_controller, mock_secrets_client
    ):
        """_write_crawl_state creates a DynamoDB resource if client is None."""
        with mock_aws():
            # Create the table first
            dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
            dynamodb.create_table(
                TableName=DYNAMODB_TABLE,
                KeySchema=[
                    {"AttributeName": "PK", "KeyType": "HASH"},
                    {"AttributeName": "SK", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "PK", "AttributeType": "S"},
                    {"AttributeName": "SK", "AttributeType": "S"},
                ],
                BillingMode="PAY_PER_REQUEST",
            )

            engine = CrawlingEngine(
                crawl_config=crawl_config,
                secrets_client=mock_secrets_client,
                tor_controller=mock_tor_controller,
            )
            assert engine._dynamodb_client is None

            await engine._write_crawl_state("http://test.onion", "hash", success=True)

            assert engine._dynamodb_client is not None


class TestHealthUptime:
    """Tests for CrawlingEngine.get_health() uptime calculation."""

    @pytest.mark.asyncio
    async def test_uptime_increases_after_start(
        self, crawl_config, mock_tor_controller, mock_secrets_client
    ):
        """get_health() uptime_seconds increases after start()."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()

        # Small delay to accumulate uptime
        time.sleep(0.05)

        health = engine.get_health()
        assert health.uptime_seconds > 0

    @pytest.mark.asyncio
    async def test_uptime_zero_before_start(
        self, crawl_config, mock_tor_controller, mock_secrets_client
    ):
        """get_health() uptime_seconds is 0 before start()."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        health = engine.get_health()
        assert health.uptime_seconds == 0.0

    @pytest.mark.asyncio
    async def test_uptime_stops_after_stop(
        self, crawl_config, mock_tor_controller, mock_secrets_client
    ):
        """get_health() uptime_seconds does not increase after stop()."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()
        time.sleep(0.05)
        await engine.stop()

        health = engine.get_health()
        # After stop, _is_running is False so uptime should not be recalculated
        assert health.uptime_seconds == 0.0

    @pytest.mark.asyncio
    async def test_health_heartbeat_updated(
        self, crawl_config, mock_tor_controller, mock_secrets_client
    ):
        """get_health() updates last_heartbeat on every call."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        await engine.start()

        before = datetime.now(UTC)
        health = engine.get_health()
        assert health.last_heartbeat >= before

    def test_start_time_none_before_start(
        self, crawl_config, mock_tor_controller, mock_secrets_client
    ):
        """_start_time is None before start() is called."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        assert engine._start_time is None

    @pytest.mark.asyncio
    async def test_start_time_set_after_start(
        self, crawl_config, mock_tor_controller, mock_secrets_client
    ):
        """_start_time is set after start() is called."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        before = datetime.now(UTC)
        await engine.start()
        assert engine._start_time is not None
        assert engine._start_time >= before
