"""Unit tests for PipelineScheduler and AgentInitializer.

Tests use mocked boto3 EventBridge client and mocked agents to verify:
- PipelineScheduler enable/disable/query operations
- AgentInitializer ordered initialization and health verification
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from dark_web_fraud_agent.infrastructure.scheduler import (
    AgentInitializer,
    InitializationResult,
    PipelineScheduler,
    ScheduleStatus,
)
from dark_web_fraud_agent.models.shared import AgentBase, AgentConfig, AgentHealth


# --- Helpers ---


def _make_health(agent_id: str, status: str = "healthy") -> AgentHealth:
    """Create an AgentHealth instance for testing."""
    return AgentHealth(
        agent_id=agent_id,
        status=status,
        processing_throughput=0.0,
        error_rate=0.0,
        queue_depth=0,
        last_heartbeat=datetime.now(UTC),
        uptime_seconds=10.0,
        bedrock_token_count=0,
        bedrock_error_rate=0.0,
    )


class FakeAgent(AgentBase):
    """Fake agent for testing AgentInitializer."""

    def __init__(self, agent_id: str, health_status: str = "healthy", should_raise: bool = False):
        config = AgentConfig(agent_id=agent_id, agent_name=agent_id.replace("-", " ").title())
        super().__init__(config)
        self._health.status = health_status
        self._should_raise = should_raise

    def get_health(self) -> AgentHealth:
        if self._should_raise:
            raise RuntimeError(f"Agent {self._config.agent_id} is unreachable")
        self._health.last_heartbeat = datetime.now(UTC)
        return self._health


# --- PipelineScheduler Tests ---


class TestPipelineScheduler:
    """Tests for PipelineScheduler EventBridge operations."""

    def setup_method(self):
        self.mock_events = MagicMock()
        self.scheduler = PipelineScheduler(
            rule_name="dark-web-pipeline-trigger",
            events_client=self.mock_events,
        )

    def test_rule_name_property(self):
        assert self.scheduler.rule_name == "dark-web-pipeline-trigger"

    def test_enable_calls_enable_rule(self):
        self.scheduler.enable()
        self.mock_events.enable_rule.assert_called_once_with(
            Name="dark-web-pipeline-trigger"
        )

    def test_disable_calls_disable_rule(self):
        self.scheduler.disable()
        self.mock_events.disable_rule.assert_called_once_with(
            Name="dark-web-pipeline-trigger"
        )

    def test_get_status_returns_schedule_status(self):
        self.mock_events.describe_rule.return_value = {
            "Name": "dark-web-pipeline-trigger",
            "State": "ENABLED",
            "ScheduleExpression": "rate(5 minutes)",
            "Description": "Triggers the dark web crawl pipeline",
        }

        status = self.scheduler.get_status()

        assert isinstance(status, ScheduleStatus)
        assert status.rule_name == "dark-web-pipeline-trigger"
        assert status.state == "ENABLED"
        assert status.schedule_expression == "rate(5 minutes)"
        assert status.description == "Triggers the dark web crawl pipeline"

    def test_get_status_handles_missing_optional_fields(self):
        self.mock_events.describe_rule.return_value = {
            "Name": "dark-web-pipeline-trigger",
        }

        status = self.scheduler.get_status()

        assert status.state == "UNKNOWN"
        assert status.schedule_expression == ""
        assert status.description == ""

    def test_is_enabled_returns_true_when_enabled(self):
        self.mock_events.describe_rule.return_value = {
            "Name": "dark-web-pipeline-trigger",
            "State": "ENABLED",
            "ScheduleExpression": "rate(5 minutes)",
        }

        assert self.scheduler.is_enabled() is True

    def test_is_enabled_returns_false_when_disabled(self):
        self.mock_events.describe_rule.return_value = {
            "Name": "dark-web-pipeline-trigger",
            "State": "DISABLED",
            "ScheduleExpression": "rate(5 minutes)",
        }

        assert self.scheduler.is_enabled() is False

    def test_enable_propagates_client_error(self):
        from botocore.exceptions import ClientError

        self.mock_events.enable_rule.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Rule not found"}},
            "EnableRule",
        )

        with pytest.raises(ClientError):
            self.scheduler.enable()


# --- AgentInitializer Tests ---


class TestAgentInitializer:
    """Tests for AgentInitializer ordered initialization and health checks."""

    def test_initialize_all_healthy_agents(self):
        agents = [
            FakeAgent("crawling-engine"),
            FakeAgent("content-analyst"),
            FakeAgent("data-structurer"),
            FakeAgent("tagging-engine"),
            FakeAgent("alert-generator"),
        ]

        initializer = AgentInitializer(agents)
        results = initializer.initialize_all()

        assert len(results) == 5
        assert all(r.success for r in results)
        assert all(r.health is not None for r in results)
        assert initializer.all_healthy()

    def test_initialize_stops_on_failed_agent(self):
        agents = [
            FakeAgent("crawling-engine"),
            FakeAgent("content-analyst", health_status="failed"),
            FakeAgent("data-structurer"),
            FakeAgent("tagging-engine"),
            FakeAgent("alert-generator"),
        ]

        initializer = AgentInitializer(agents)
        results = initializer.initialize_all()

        # Should stop after the second agent (content-analyst) fails
        assert len(results) == 2
        assert results[0].success is True
        assert results[1].success is False
        assert results[1].agent_id == "content-analyst"
        assert not initializer.all_healthy()

    def test_initialize_handles_exception_in_get_health(self):
        agents = [
            FakeAgent("crawling-engine"),
            FakeAgent("content-analyst", should_raise=True),
            FakeAgent("data-structurer"),
        ]

        initializer = AgentInitializer(agents)
        results = initializer.initialize_all()

        assert len(results) == 2
        assert results[0].success is True
        assert results[1].success is False
        assert "unreachable" in results[1].error
        assert results[1].health is None

    def test_initialize_accepts_degraded_status(self):
        agents = [
            FakeAgent("crawling-engine", health_status="degraded"),
            FakeAgent("content-analyst"),
        ]

        initializer = AgentInitializer(agents)
        results = initializer.initialize_all()

        assert len(results) == 2
        assert all(r.success for r in results)
        assert initializer.all_healthy()

    def test_agents_property_returns_ordered_list(self):
        agents = [
            FakeAgent("crawling-engine"),
            FakeAgent("content-analyst"),
        ]

        initializer = AgentInitializer(agents)

        assert initializer.agents is agents
        assert len(initializer.agents) == 2

    def test_results_empty_before_initialization(self):
        agents = [FakeAgent("crawling-engine")]
        initializer = AgentInitializer(agents)

        assert initializer.results == []

    def test_all_healthy_false_when_no_results(self):
        agents = [FakeAgent("crawling-engine")]
        initializer = AgentInitializer(agents)

        assert not initializer.all_healthy()

    def test_initialization_result_fields(self):
        agents = [FakeAgent("crawling-engine")]
        initializer = AgentInitializer(agents)
        results = initializer.initialize_all()

        result = results[0]
        assert result.agent_id == "crawling-engine"
        assert result.success is True
        assert result.health.agent_id == "crawling-engine"
        assert result.health.status == "healthy"
        assert result.error is None
