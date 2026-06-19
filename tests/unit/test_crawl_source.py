"""Unit tests for crawl_source with retry logic and CircuitBreakerState.

Tests cover:
- CircuitBreakerState dataclass behavior (is_open, should_attempt_recovery)
- crawl_source() happy path with mocked aiohttp responses
- Retry logic with circuit rotation on failure
- Circuit breaker blocking when open
- Reconnection logic on connectivity loss
- HTML stripping from crawled content
"""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from dark_web_fraud_agent.agents.crawling_engine import (
    CircuitBreakerState,
    CrawlError,
    CrawlingEngine,
    _strip_html_tags,
    compute_content_hash,
)
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
def source_definition():
    """Create a test source definition."""
    return SourceDefinition(
        url="http://darkforum.onion/thread/1",
        source_type=SourceType.ONION,
        category="forum",
        crawl_interval_seconds=300,
        requires_auth=False,
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
def mock_s3_client():
    """Create a mock S3 client."""
    client = MagicMock()
    client.put_object.return_value = {}
    return client


def _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client):
    """Create a CrawlingEngine with mocked dependencies."""
    engine = CrawlingEngine(
        crawl_config=crawl_config,
        secrets_client=mock_secrets_client,
        tor_controller=mock_tor_controller,
    )
    engine._s3_client = mock_s3_client
    engine._is_running = True
    engine._current_ip = "198.51.100.42"
    engine._health.status = "healthy"
    return engine


class TestStripHtmlTags:
    """Tests for _strip_html_tags helper."""

    def test_strips_basic_tags(self):
        """Basic HTML tags are removed."""
        html = "<p>Hello <b>world</b></p>"
        assert _strip_html_tags(html) == "Hello world"

    def test_strips_complex_html(self):
        """Complex HTML with attributes is stripped."""
        html = '<div class="post"><a href="http://x.onion">link</a></div>'
        assert _strip_html_tags(html) == "link"

    def test_plain_text_unchanged(self):
        """Plain text without HTML tags is returned unchanged."""
        text = "No HTML here"
        assert _strip_html_tags(text) == "No HTML here"

    def test_collapses_whitespace(self):
        """Multiple whitespace characters are collapsed to single space."""
        html = "<p>  Hello   world  </p>"
        result = _strip_html_tags(html)
        assert result == "Hello world"

    def test_empty_string(self):
        """Empty string returns empty string."""
        assert _strip_html_tags("") == ""


class TestCircuitBreakerState:
    """Tests for CircuitBreakerState dataclass."""

    def test_default_state_is_closed(self):
        """Default state is closed with zero failures."""
        state = CircuitBreakerState(source_url_hash="abc123")
        assert state.state == "closed"
        assert state.consecutive_failures == 0
        assert state.last_failure_time is None

    def test_is_open_false_below_threshold(self):
        """is_open is False when consecutive_failures < 5."""
        state = CircuitBreakerState(source_url_hash="abc", consecutive_failures=4)
        assert state.is_open is False

    def test_is_open_true_at_threshold(self):
        """is_open is True when consecutive_failures == 5."""
        state = CircuitBreakerState(source_url_hash="abc", consecutive_failures=5)
        assert state.is_open is True

    def test_is_open_true_above_threshold(self):
        """is_open is True when consecutive_failures > 5."""
        state = CircuitBreakerState(source_url_hash="abc", consecutive_failures=10)
        assert state.is_open is True

    def test_should_attempt_recovery_no_failure_time(self):
        """should_attempt_recovery is True when no failure has been recorded."""
        state = CircuitBreakerState(source_url_hash="abc", consecutive_failures=5)
        assert state.should_attempt_recovery is True

    def test_should_attempt_recovery_timeout_elapsed(self):
        """should_attempt_recovery is True when recovery_timeout has elapsed."""
        past = datetime.now(UTC) - timedelta(seconds=120)
        state = CircuitBreakerState(
            source_url_hash="abc",
            consecutive_failures=5,
            last_failure_time=past,
            recovery_timeout=60,
        )
        assert state.should_attempt_recovery is True

    def test_should_attempt_recovery_timeout_not_elapsed(self):
        """should_attempt_recovery is False when recovery_timeout hasn't elapsed."""
        recent = datetime.now(UTC) - timedelta(seconds=10)
        state = CircuitBreakerState(
            source_url_hash="abc",
            consecutive_failures=5,
            last_failure_time=recent,
            recovery_timeout=60,
        )
        assert state.should_attempt_recovery is False

    def test_record_failure_increments_count(self):
        """record_failure increments consecutive_failures."""
        state = CircuitBreakerState(source_url_hash="abc")
        state.record_failure()
        assert state.consecutive_failures == 1
        state.record_failure()
        assert state.consecutive_failures == 2

    def test_record_failure_sets_last_failure_time(self):
        """record_failure sets last_failure_time to now."""
        state = CircuitBreakerState(source_url_hash="abc")
        before = datetime.now(UTC)
        state.record_failure()
        assert state.last_failure_time is not None
        assert state.last_failure_time >= before

    def test_record_failure_opens_circuit_at_threshold(self):
        """record_failure sets state to 'open' at 5 consecutive failures."""
        state = CircuitBreakerState(source_url_hash="abc", consecutive_failures=4)
        state.record_failure()
        assert state.state == "open"
        assert state.is_open is True

    def test_record_success_resets_state(self):
        """record_success resets to closed with zero failures."""
        state = CircuitBreakerState(
            source_url_hash="abc",
            consecutive_failures=3,
            state="half-open",
            last_failure_time=datetime.now(UTC),
        )
        state.record_success()
        assert state.consecutive_failures == 0
        assert state.state == "closed"
        assert state.last_failure_time is None

    def test_default_recovery_timeout_is_60(self):
        """Default recovery_timeout is 60 seconds."""
        state = CircuitBreakerState(source_url_hash="abc")
        assert state.recovery_timeout == 60


class TestCrawlSourceSuccess:
    """Tests for crawl_source() happy path."""

    @pytest.mark.asyncio
    async def test_crawl_source_returns_crawl_result(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() returns a CrawlResult on successful crawl."""
        engine = _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client)

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="<html><body>Forum post content</body></html>")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch(
                "dark_web_fraud_agent.agents.crawling_engine.store_artifact",
                return_value=("crawl-artifacts/2024/01/01/key.txt", "ann-123"),
            ):
                result = await engine.crawl_source(source_definition)

        assert result.source_url == "http://darkforum.onion/thread/1"
        assert result.source_category == "forum"
        assert result.raw_content == "Forum post content"
        assert result.response_status == 200
        assert result.s3_artifact_key == "crawl-artifacts/2024/01/01/key.txt"
        assert result.s3_annotation_id == "ann-123"

    @pytest.mark.asyncio
    async def test_crawl_source_computes_content_hash(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() computes SHA-256 hash of extracted content."""
        engine = _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client)

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="<p>content data</p>")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch(
                "dark_web_fraud_agent.agents.crawling_engine.store_artifact",
                return_value=("key", "ann"),
            ):
                result = await engine.crawl_source(source_definition)

        expected_hash = compute_content_hash("content data")
        assert result.content_hash == expected_hash

    @pytest.mark.asyncio
    async def test_crawl_source_strips_html_tags(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() strips HTML tags and returns plain text."""
        engine = _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client)

        html = "<div><h1>Title</h1><p>Body <b>text</b></p></div>"
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value=html)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch(
                "dark_web_fraud_agent.agents.crawling_engine.store_artifact",
                return_value=("key", "ann"),
            ):
                result = await engine.crawl_source(source_definition)

        assert result.raw_content == "Title Body text"

    @pytest.mark.asyncio
    async def test_crawl_source_raises_when_not_running(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() raises RuntimeError if engine is not started."""
        engine = CrawlingEngine(
            crawl_config=crawl_config,
            secrets_client=mock_secrets_client,
            tor_controller=mock_tor_controller,
        )
        # Engine is not started, _is_running is False

        with pytest.raises(RuntimeError, match="not running"):
            await engine.crawl_source(source_definition)


class TestCrawlSourceRetryLogic:
    """Tests for crawl_source() retry logic with circuit rotation."""

    @pytest.mark.asyncio
    async def test_retries_on_failure_up_to_max(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() retries up to max_retries on failure."""
        engine = _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(
            side_effect=aiohttp.ClientConnectionError("Connection failed")
        )
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(CrawlError, match="All 3 crawl attempts failed"):
                await engine.crawl_source(source_definition)

    @pytest.mark.asyncio
    async def test_rotates_circuit_on_retry(
        self, crawl_config, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() rotates circuit on each retry."""
        controller = MagicMock()
        controller.is_authenticated.return_value = True
        controller.get_info.side_effect = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

        engine = _make_engine(crawl_config, controller, mock_secrets_client, mock_s3_client)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(
            side_effect=aiohttp.ClientConnectionError("fail")
        )
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(CrawlError):
                await engine.crawl_source(source_definition)

        # Signal should be called for retries (not first attempt)
        from stem import Signal
        assert controller.signal.call_count == 2  # 2 retries after first attempt

    @pytest.mark.asyncio
    async def test_succeeds_on_second_attempt(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() succeeds if retry after initial failure works."""
        engine = _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client)

        # First call fails, second succeeds
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="<p>success</p>")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        call_count = {"n": 0}

        def side_effect_get(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise aiohttp.ClientConnectionError("first attempt fails")
            return mock_response

        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=side_effect_get)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch(
                "dark_web_fraud_agent.agents.crawling_engine.store_artifact",
                return_value=("key", "ann"),
            ):
                result = await engine.crawl_source(source_definition)

        assert result.raw_content == "success"
        assert result.response_status == 200


class TestCrawlSourceCircuitBreaker:
    """Tests for crawl_source() circuit breaker behavior."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_blocks_when_open_no_recovery(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() raises CrawlError when circuit breaker is open and recovery timeout not elapsed."""
        engine = _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client)

        # Pre-set circuit breaker to open with recent failure
        source_url_hash = compute_content_hash(source_definition.url)
        state = CircuitBreakerState(
            source_url_hash=source_url_hash,
            consecutive_failures=5,
            state="open",
            last_failure_time=datetime.now(UTC) - timedelta(seconds=10),
            recovery_timeout=60,
        )
        engine._circuit_breaker_cache = {source_url_hash: state}

        with pytest.raises(CrawlError, match="Circuit breaker open"):
            await engine.crawl_source(source_definition)

    @pytest.mark.asyncio
    async def test_circuit_breaker_allows_half_open_after_timeout(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() allows attempt when circuit is open but recovery timeout elapsed."""
        engine = _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client)

        # Pre-set circuit breaker with elapsed timeout
        source_url_hash = compute_content_hash(source_definition.url)
        state = CircuitBreakerState(
            source_url_hash=source_url_hash,
            consecutive_failures=5,
            state="open",
            last_failure_time=datetime.now(UTC) - timedelta(seconds=120),
            recovery_timeout=60,
        )
        engine._circuit_breaker_cache = {source_url_hash: state}

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="<p>recovered</p>")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch(
                "dark_web_fraud_agent.agents.crawling_engine.store_artifact",
                return_value=("key", "ann"),
            ):
                result = await engine.crawl_source(source_definition)

        assert result.raw_content == "recovered"
        # Circuit breaker should be reset after success
        saved_state = engine._circuit_breaker_cache[source_url_hash]
        assert saved_state.consecutive_failures == 0
        assert saved_state.state == "closed"

    @pytest.mark.asyncio
    async def test_circuit_breaker_records_failures(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() records failures in circuit breaker state."""
        engine = _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(
            side_effect=aiohttp.ClientConnectionError("Connection failed")
        )
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(CrawlError):
                await engine.crawl_source(source_definition)

        # Check that failures were recorded
        source_url_hash = compute_content_hash(source_definition.url)
        state = engine._circuit_breaker_cache[source_url_hash]
        assert state.consecutive_failures == 3  # max_retries = 3


class TestCrawlSourceReconnection:
    """Tests for crawl_source() reconnection on connectivity loss."""

    @pytest.mark.asyncio
    async def test_reconnection_on_connection_error(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() attempts reconnection on connectivity loss."""
        engine = _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client)

        # All attempts fail with connection error
        mock_session = AsyncMock()
        mock_session.get = MagicMock(
            side_effect=ConnectionRefusedError("Connection refused")
        )
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(CrawlError):
                await engine.crawl_source(source_definition)

        # Reconnection calls rotate_circuit, signal NEWNYM is called
        # 2 retries (after first) + 3 reconnection attempts = multiple NEWNYM signals
        from stem import Signal
        assert mock_tor_controller.signal.call_count >= 2

    @pytest.mark.asyncio
    async def test_no_reconnection_on_non_connectivity_error(
        self, crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client, source_definition
    ):
        """crawl_source() does not attempt reconnection on non-connectivity errors."""
        engine = _make_engine(crawl_config, mock_tor_controller, mock_secrets_client, mock_s3_client)

        # Fail with ValueError (not a connectivity error)
        mock_session = AsyncMock()
        mock_session.get = MagicMock(
            side_effect=ValueError("Bad response format")
        )
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(CrawlError):
                await engine.crawl_source(source_definition)

        # Only retry rotations, no extra reconnection calls
        # On retries (attempt 1, 2 after first) the engine rotates, but no extra reconnection
        from stem import Signal
        # 2 rotations for retry attempts (not first attempt)
        assert mock_tor_controller.signal.call_count == 2
