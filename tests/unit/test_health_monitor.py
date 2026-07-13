"""Unit tests for PipelineHealthMonitor, RetryConfig, and DeadLetterQueueRouter."""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from dark_web_fraud_agent.infrastructure.health_monitor import (
    DeadLetterQueueRouter,
    PipelineHealthMonitor,
    RetryConfig,
)
from dark_web_fraud_agent.models.shared import AgentHealth


class TestRetryConfig:
    """Tests for RetryConfig dataclass and exponential backoff calculation."""

    def test_default_values(self):
        config = RetryConfig()
        assert config.max_retries == 3
        assert config.base_delay == 2.0
        assert config.backoff_factor == 2.0
        assert config.max_delay == 60.0

    def test_custom_values(self):
        config = RetryConfig(max_retries=5, base_delay=1.0, backoff_factor=3.0, max_delay=120.0)
        assert config.max_retries == 5
        assert config.base_delay == 1.0
        assert config.backoff_factor == 3.0
        assert config.max_delay == 120.0

    def test_delay_for_attempt_exponential_backoff(self):
        config = RetryConfig(base_delay=2.0, backoff_factor=2.0)
        # attempt 0: 2 * 2^0 = 2
        assert config.delay_for_attempt(0) == 2.0
        # attempt 1: 2 * 2^1 = 4
        assert config.delay_for_attempt(1) == 4.0
        # attempt 2: 2 * 2^2 = 8
        assert config.delay_for_attempt(2) == 8.0

    def test_delay_capped_by_max_delay(self):
        config = RetryConfig(base_delay=2.0, backoff_factor=2.0, max_delay=10.0)
        # attempt 3: 2 * 2^3 = 16, capped to 10
        assert config.delay_for_attempt(3) == 10.0
        # attempt 10: large value, capped to 10
        assert config.delay_for_attempt(10) == 10.0

    def test_negative_max_retries_raises_value_error(self):
        with pytest.raises(ValueError, match="max_retries must be non-negative"):
            RetryConfig(max_retries=-1)

    def test_zero_base_delay_raises_value_error(self):
        with pytest.raises(ValueError, match="base_delay must be positive"):
            RetryConfig(base_delay=0)

    def test_backoff_factor_less_than_one_raises_value_error(self):
        with pytest.raises(ValueError, match="backoff_factor must be >= 1"):
            RetryConfig(backoff_factor=0.5)

    def test_zero_retries_allowed(self):
        config = RetryConfig(max_retries=0)
        assert config.max_retries == 0


class TestDeadLetterQueueRouter:
    """Tests for DeadLetterQueueRouter DLQ routing."""

    @pytest.fixture
    def mock_sqs_client(self):
        return MagicMock()

    @pytest.fixture
    def router(self, mock_sqs_client):
        return DeadLetterQueueRouter(
            dlq_url="https://sqs.eu-west-2.amazonaws.com/123456789012/dark-web-fraud-dlq",
            sqs_client=mock_sqs_client,
        )

    def test_route_to_dlq_returns_message_id(self, router, mock_sqs_client):
        mock_sqs_client.send_message.return_value = {"MessageId": "msg-abc-123"}

        item = {"correlation_id": "corr-1", "s3_key": "crawl-artifacts/item1"}
        error = RuntimeError("Processing failed")

        result = router.route_to_dlq(item, error)

        assert result == "msg-abc-123"

    def test_route_to_dlq_sends_correct_message_body(self, router, mock_sqs_client):
        mock_sqs_client.send_message.return_value = {"MessageId": "msg-xyz"}

        item = {"data": "test-payload"}
        error = ValueError("Invalid content")

        router.route_to_dlq(item, error)

        call_kwargs = mock_sqs_client.send_message.call_args[1]
        body = json.loads(call_kwargs["MessageBody"])
        assert body["item"] == {"data": "test-payload"}
        assert body["error_type"] == "ValueError"
        assert body["error_message"] == "Invalid content"
        assert "failed_at" in body

    def test_route_to_dlq_sends_message_attributes(self, router, mock_sqs_client):
        mock_sqs_client.send_message.return_value = {"MessageId": "msg-attr"}

        router.route_to_dlq({"key": "val"}, TimeoutError("timed out"))

        call_kwargs = mock_sqs_client.send_message.call_args[1]
        attrs = call_kwargs["MessageAttributes"]
        assert attrs["ErrorType"]["StringValue"] == "TimeoutError"
        assert "FailedAt" in attrs

    def test_route_to_dlq_uses_correct_queue_url(self, router, mock_sqs_client):
        mock_sqs_client.send_message.return_value = {"MessageId": "msg-url"}

        router.route_to_dlq({"item": 1}, Exception("err"))

        call_kwargs = mock_sqs_client.send_message.call_args[1]
        assert call_kwargs["QueueUrl"] == (
            "https://sqs.eu-west-2.amazonaws.com/123456789012/dark-web-fraud-dlq"
        )

    def test_route_to_dlq_raises_runtime_error_on_failure(self, router, mock_sqs_client):
        mock_sqs_client.send_message.side_effect = Exception("SQS unavailable")

        with pytest.raises(RuntimeError, match="Failed to route item to DLQ"):
            router.route_to_dlq({"item": 1}, ValueError("bad"))


class TestPipelineHealthMonitor:
    """Tests for PipelineHealthMonitor health aggregation and DLQ routing."""

    def _make_health(self, agent_id: str, status: str) -> AgentHealth:
        return AgentHealth(
            agent_id=agent_id,
            status=status,
            processing_throughput=10.0,
            error_rate=0.0 if status == "healthy" else 0.5,
            queue_depth=0,
            last_heartbeat=datetime.now(UTC),
            uptime_seconds=100.0,
            bedrock_token_count=0,
            bedrock_error_rate=0.0,
        )

    def test_aggregate_health_all_healthy(self):
        monitor = PipelineHealthMonitor()
        monitor.register_agent_health(self._make_health("crawling_engine", "healthy"))
        monitor.register_agent_health(self._make_health("content_analyst", "healthy"))
        monitor.register_agent_health(self._make_health("data_structurer", "healthy"))
        monitor.register_agent_health(self._make_health("tagging_engine", "healthy"))
        monitor.register_agent_health(self._make_health("alert_generator", "healthy"))

        assert monitor.aggregate_health() == "healthy"

    def test_aggregate_health_non_core_agent_degraded(self):
        monitor = PipelineHealthMonitor()
        monitor.register_agent_health(self._make_health("crawling_engine", "healthy"))
        monitor.register_agent_health(self._make_health("content_analyst", "healthy"))
        monitor.register_agent_health(self._make_health("data_structurer", "healthy"))
        monitor.register_agent_health(self._make_health("tagging_engine", "degraded"))
        monitor.register_agent_health(self._make_health("alert_generator", "healthy"))

        assert monitor.aggregate_health() == "degraded"

    def test_aggregate_health_core_agent_unhealthy_returns_critical(self):
        monitor = PipelineHealthMonitor()
        monitor.register_agent_health(self._make_health("crawling_engine", "failed"))
        monitor.register_agent_health(self._make_health("content_analyst", "healthy"))
        monitor.register_agent_health(self._make_health("data_structurer", "healthy"))

        assert monitor.aggregate_health() == "critical"

    def test_aggregate_health_content_analyst_down_returns_critical(self):
        monitor = PipelineHealthMonitor()
        monitor.register_agent_health(self._make_health("crawling_engine", "healthy"))
        monitor.register_agent_health(self._make_health("content_analyst", "degraded"))
        monitor.register_agent_health(self._make_health("data_structurer", "healthy"))

        assert monitor.aggregate_health() == "critical"

    def test_aggregate_health_empty_returns_healthy(self):
        monitor = PipelineHealthMonitor()
        assert monitor.aggregate_health() == "healthy"

    def test_register_agent_health_updates_existing(self):
        monitor = PipelineHealthMonitor()
        monitor.register_agent_health(self._make_health("crawling_engine", "healthy"))
        monitor.register_agent_health(self._make_health("crawling_engine", "failed"))

        health = monitor.get_agent_health("crawling_engine")
        assert health is not None
        assert health.status == "failed"

    def test_get_agent_health_returns_none_for_unknown(self):
        monitor = PipelineHealthMonitor()
        assert monitor.get_agent_health("unknown_agent") is None

    def test_get_health_summary(self):
        monitor = PipelineHealthMonitor()
        monitor.register_agent_health(self._make_health("crawling_engine", "healthy"))
        monitor.register_agent_health(self._make_health("tagging_engine", "degraded"))

        summary = monitor.get_health_summary()
        assert summary["pipeline_status"] == "degraded"
        assert summary["healthy_count"] == 1
        assert summary["total_count"] == 2
        assert "crawling_engine" in summary["per_agent"]
        assert "tagging_engine" in summary["per_agent"]

    def test_route_to_dlq_delegates_to_router(self):
        mock_sqs = MagicMock()
        mock_sqs.send_message.return_value = {"MessageId": "dlq-msg-1"}

        monitor = PipelineHealthMonitor(
            dlq_url="https://sqs.eu-west-2.amazonaws.com/123456789012/dlq",
            sqs_client=mock_sqs,
        )
        item = {"correlation_id": "test-corr"}
        error = ValueError("test error")

        result = monitor.route_to_dlq(item, error)
        assert result == "dlq-msg-1"

    def test_route_to_dlq_raises_when_not_configured(self):
        monitor = PipelineHealthMonitor()  # no dlq_url

        with pytest.raises(RuntimeError, match="DLQ routing is not configured"):
            monitor.route_to_dlq({"item": 1}, Exception("err"))

    def test_retry_config_accessible(self):
        config = RetryConfig(max_retries=5, base_delay=1.0)
        monitor = PipelineHealthMonitor(retry_config=config)
        assert monitor.retry_config.max_retries == 5
        assert monitor.retry_config.base_delay == 1.0

    def test_custom_core_agent_ids(self):
        """Custom core_agent_ids overrides default set."""
        monitor = PipelineHealthMonitor(
            core_agent_ids=frozenset({"agent_a"})
        )
        monitor.register_agent_health(self._make_health("agent_a", "failed"))
        monitor.register_agent_health(self._make_health("agent_b", "healthy"))

        assert monitor.aggregate_health() == "critical"
