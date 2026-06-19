"""Unit tests for agent fault isolation and health monitoring."""

from datetime import UTC, datetime

import pytest

from dark_web_fraud_agent.infrastructure.fault_isolation import (
    AgentFailure,
    FaultIsolator,
)
from dark_web_fraud_agent.models.shared import AgentHealth


class TestAgentFailure:
    """Tests for AgentFailure dataclass."""

    def test_create_failure_with_defaults(self):
        failure = AgentFailure(
            agent_id="content_analyst",
            error_message="Connection timeout",
            error_type="TimeoutError",
        )
        assert failure.agent_id == "content_analyst"
        assert failure.error_message == "Connection timeout"
        assert failure.error_type == "TimeoutError"
        assert failure.correlation_id is None
        assert failure.recoverable is True
        assert failure.timestamp is not None

    def test_create_failure_with_correlation_id(self):
        failure = AgentFailure(
            agent_id="crawling_engine",
            error_message="Tor circuit failed",
            error_type="CircuitError",
            correlation_id="corr-123",
            recoverable=False,
        )
        assert failure.correlation_id == "corr-123"
        assert failure.recoverable is False


class TestFaultIsolator:
    """Tests for FaultIsolator class."""

    def test_initial_state(self):
        isolator = FaultIsolator()
        assert not isolator.is_isolated("any_agent")
        assert isolator.get_failure_history() == []

    def test_record_failure_returns_agent_failure(self):
        isolator = FaultIsolator()
        error = ValueError("bad input")
        failure = isolator.record_failure("agent_1", error, correlation_id="corr-1")

        assert isinstance(failure, AgentFailure)
        assert failure.agent_id == "agent_1"
        assert failure.error_message == "bad input"
        assert failure.error_type == "ValueError"
        assert failure.correlation_id == "corr-1"

    def test_agent_isolated_after_max_consecutive_failures(self):
        isolator = FaultIsolator(max_consecutive_failures=3)
        error = RuntimeError("fail")

        # Record 2 failures - not yet isolated
        isolator.record_failure("agent_1", error)
        isolator.record_failure("agent_1", error)
        assert not isolator.is_isolated("agent_1")

        # 3rd failure triggers isolation
        isolator.record_failure("agent_1", error)
        assert isolator.is_isolated("agent_1")

    def test_success_resets_failure_count(self):
        isolator = FaultIsolator(max_consecutive_failures=3)
        error = RuntimeError("fail")

        isolator.record_failure("agent_1", error)
        isolator.record_failure("agent_1", error)
        # Success resets the counter
        isolator.record_success("agent_1")

        # Need 3 more consecutive failures to isolate
        isolator.record_failure("agent_1", error)
        isolator.record_failure("agent_1", error)
        assert not isolator.is_isolated("agent_1")

    def test_restore_agent(self):
        isolator = FaultIsolator(max_consecutive_failures=2)
        error = RuntimeError("fail")

        isolator.record_failure("agent_1", error)
        isolator.record_failure("agent_1", error)
        assert isolator.is_isolated("agent_1")

        isolator.restore_agent("agent_1")
        assert not isolator.is_isolated("agent_1")

    def test_restore_resets_failure_count(self):
        isolator = FaultIsolator(max_consecutive_failures=2)
        error = RuntimeError("fail")

        # Isolate
        isolator.record_failure("agent_1", error)
        isolator.record_failure("agent_1", error)
        assert isolator.is_isolated("agent_1")

        # Restore and verify counter is reset
        isolator.restore_agent("agent_1")
        isolator.record_failure("agent_1", error)
        assert not isolator.is_isolated("agent_1")

    def test_isolation_does_not_affect_other_agents(self):
        isolator = FaultIsolator(max_consecutive_failures=2)
        error = RuntimeError("fail")

        isolator.record_failure("agent_1", error)
        isolator.record_failure("agent_1", error)
        assert isolator.is_isolated("agent_1")
        assert not isolator.is_isolated("agent_2")

    def test_get_failure_history_all(self):
        isolator = FaultIsolator()
        isolator.record_failure("agent_1", ValueError("err1"))
        isolator.record_failure("agent_2", TypeError("err2"))

        history = isolator.get_failure_history()
        assert len(history) == 2
        assert history[0].agent_id == "agent_1"
        assert history[1].agent_id == "agent_2"

    def test_get_failure_history_filtered_by_agent(self):
        isolator = FaultIsolator()
        isolator.record_failure("agent_1", ValueError("err1"))
        isolator.record_failure("agent_2", TypeError("err2"))
        isolator.record_failure("agent_1", RuntimeError("err3"))

        history = isolator.get_failure_history(agent_id="agent_1")
        assert len(history) == 2
        assert all(f.agent_id == "agent_1" for f in history)


class TestPipelineHealth:
    """Tests for pipeline health aggregation."""

    def _make_health(self, agent_id: str, status: str) -> AgentHealth:
        return AgentHealth(
            agent_id=agent_id,
            status=status,
            processing_throughput=10.0,
            error_rate=0.0,
            queue_depth=0,
            last_heartbeat=datetime.now(UTC),
            uptime_seconds=100.0,
            bedrock_token_count=0,
            bedrock_error_rate=0.0,
        )

    def test_all_healthy(self):
        isolator = FaultIsolator()
        healths = [
            self._make_health("agent_1", "healthy"),
            self._make_health("agent_2", "healthy"),
            self._make_health("agent_3", "healthy"),
        ]
        result = isolator.get_pipeline_health(healths)
        assert result["status"] == "healthy"
        assert result["healthy_agents"] == 3
        assert result["total_agents"] == 3
        assert result["isolated_agents"] == []
        assert result["total_failures"] == 0

    def test_degraded_when_some_unhealthy(self):
        isolator = FaultIsolator()
        healths = [
            self._make_health("agent_1", "healthy"),
            self._make_health("agent_2", "failed"),
            self._make_health("agent_3", "healthy"),
        ]
        result = isolator.get_pipeline_health(healths)
        assert result["status"] == "degraded"
        assert result["healthy_agents"] == 2
        assert result["total_agents"] == 3

    def test_failed_when_all_unhealthy(self):
        isolator = FaultIsolator()
        healths = [
            self._make_health("agent_1", "failed"),
            self._make_health("agent_2", "degraded"),
        ]
        result = isolator.get_pipeline_health(healths)
        assert result["status"] == "failed"
        assert result["healthy_agents"] == 0

    def test_pipeline_health_includes_isolated_agents(self):
        isolator = FaultIsolator(max_consecutive_failures=1)
        isolator.record_failure("agent_2", RuntimeError("boom"))

        healths = [
            self._make_health("agent_1", "healthy"),
            self._make_health("agent_2", "failed"),
        ]
        result = isolator.get_pipeline_health(healths)
        assert "agent_2" in result["isolated_agents"]
        assert result["total_failures"] == 1

    def test_empty_agent_list(self):
        isolator = FaultIsolator()
        result = isolator.get_pipeline_health([])
        # No agents means all zero are healthy out of zero total -> "healthy"
        assert result["status"] == "healthy"
        assert result["healthy_agents"] == 0
        assert result["total_agents"] == 0
