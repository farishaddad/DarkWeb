"""Unit tests for PipelineScheduler, AgentInitializer, and MapStateConfig.

Tests use mocked boto3 EventBridge client and mocked agents to verify:
- PipelineScheduler create/enable/disable/query/delete operations
- AgentInitializer ordered initialization and health verification
- MapStateConfig validation and state definition generation
"""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from dark_web_fraud_agent.infrastructure.scheduler import (
    AgentInitializer,
    InitializationResult,
    MapStateConfig,
    PipelineScheduler,
    ScheduleStatus,
    _DEFAULT_MAX_CONCURRENCY,
    _DEFAULT_RULE_DESCRIPTION,
    _DEFAULT_RULE_NAME,
    _DEFAULT_SCHEDULE_EXPRESSION,
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
            rule_name="dark-web-fraud-crawl-schedule",
            events_client=self.mock_events,
        )

    def test_rule_name_property(self):
        assert self.scheduler.rule_name == "dark-web-fraud-crawl-schedule"

    def test_default_rule_name(self):
        """Default rule name matches the expected convention."""
        scheduler = PipelineScheduler(events_client=self.mock_events)
        assert scheduler.rule_name == _DEFAULT_RULE_NAME

    def test_enable_calls_enable_rule(self):
        self.scheduler.enable()
        self.mock_events.enable_rule.assert_called_once_with(
            Name="dark-web-fraud-crawl-schedule"
        )

    def test_disable_calls_disable_rule(self):
        self.scheduler.disable()
        self.mock_events.disable_rule.assert_called_once_with(
            Name="dark-web-fraud-crawl-schedule"
        )

    def test_get_status_returns_schedule_status(self):
        self.mock_events.describe_rule.return_value = {
            "Name": "dark-web-fraud-crawl-schedule",
            "State": "ENABLED",
            "ScheduleExpression": "rate(6 hours)",
            "Description": "Triggers the dark web fraud intelligence crawl pipeline",
        }
        self.mock_events.list_targets_by_rule.return_value = {
            "Targets": [
                {
                    "Id": "step-functions-pipeline",
                    "Arn": "arn:aws:states:eu-west-2:123456789012:stateMachine:pipeline",
                }
            ]
        }

        status = self.scheduler.get_status()

        assert isinstance(status, ScheduleStatus)
        assert status.rule_name == "dark-web-fraud-crawl-schedule"
        assert status.state == "ENABLED"
        assert status.schedule_expression == "rate(6 hours)"
        assert status.target_arn == "arn:aws:states:eu-west-2:123456789012:stateMachine:pipeline"

    def test_get_status_handles_missing_optional_fields(self):
        self.mock_events.describe_rule.return_value = {
            "Name": "dark-web-fraud-crawl-schedule",
        }
        self.mock_events.list_targets_by_rule.return_value = {"Targets": []}

        status = self.scheduler.get_status()

        assert status.state == "UNKNOWN"
        assert status.schedule_expression == ""
        assert status.description == ""
        assert status.target_arn == ""

    def test_get_status_handles_list_targets_failure(self):
        self.mock_events.describe_rule.return_value = {
            "Name": "dark-web-fraud-crawl-schedule",
            "State": "ENABLED",
            "ScheduleExpression": "rate(6 hours)",
        }
        self.mock_events.list_targets_by_rule.side_effect = Exception("API Error")

        status = self.scheduler.get_status()

        assert status.state == "ENABLED"
        assert status.target_arn == ""

    def test_is_enabled_returns_true_when_enabled(self):
        self.mock_events.describe_rule.return_value = {
            "Name": "dark-web-fraud-crawl-schedule",
            "State": "ENABLED",
            "ScheduleExpression": "rate(6 hours)",
        }
        self.mock_events.list_targets_by_rule.return_value = {"Targets": []}

        assert self.scheduler.is_enabled() is True

    def test_is_enabled_returns_false_when_disabled(self):
        self.mock_events.describe_rule.return_value = {
            "Name": "dark-web-fraud-crawl-schedule",
            "State": "DISABLED",
            "ScheduleExpression": "rate(6 hours)",
        }
        self.mock_events.list_targets_by_rule.return_value = {"Targets": []}

        assert self.scheduler.is_enabled() is False

    def test_enable_propagates_client_error(self):
        from botocore.exceptions import ClientError

        self.mock_events.enable_rule.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Rule not found"}},
            "EnableRule",
        )

        with pytest.raises(ClientError):
            self.scheduler.enable()


class TestPipelineSchedulerCreateSchedule:
    """Tests for PipelineScheduler.create_schedule()."""

    def setup_method(self):
        self.mock_events = MagicMock()
        self.scheduler = PipelineScheduler(
            rule_name="dark-web-fraud-crawl-schedule",
            events_client=self.mock_events,
        )
        self.state_machine_arn = (
            "arn:aws:states:eu-west-2:123456789012:stateMachine:dark-web-fraud-pipeline"
        )
        self.role_arn = (
            "arn:aws:iam::123456789012:role/EventBridgeStepFunctionsRole"
        )

    def test_create_schedule_calls_put_rule_with_defaults(self):
        self.mock_events.put_rule.return_value = {
            "RuleArn": "arn:aws:events:eu-west-2:123456789012:rule/dark-web-fraud-crawl-schedule"
        }

        rule_arn = self.scheduler.create_schedule(
            state_machine_arn=self.state_machine_arn,
            role_arn=self.role_arn,
        )

        self.mock_events.put_rule.assert_called_once_with(
            Name="dark-web-fraud-crawl-schedule",
            ScheduleExpression=_DEFAULT_SCHEDULE_EXPRESSION,
            State="ENABLED",
            Description=_DEFAULT_RULE_DESCRIPTION,
        )
        assert rule_arn == "arn:aws:events:eu-west-2:123456789012:rule/dark-web-fraud-crawl-schedule"

    def test_create_schedule_sets_step_functions_target(self):
        self.mock_events.put_rule.return_value = {
            "RuleArn": "arn:aws:events:eu-west-2:123456789012:rule/dark-web-fraud-crawl-schedule"
        }

        self.scheduler.create_schedule(
            state_machine_arn=self.state_machine_arn,
            role_arn=self.role_arn,
        )

        self.mock_events.put_targets.assert_called_once()
        call_kwargs = self.mock_events.put_targets.call_args[1]
        assert call_kwargs["Rule"] == "dark-web-fraud-crawl-schedule"
        targets = call_kwargs["Targets"]
        assert len(targets) == 1
        assert targets[0]["Id"] == "step-functions-pipeline"
        assert targets[0]["Arn"] == self.state_machine_arn
        assert targets[0]["RoleArn"] == self.role_arn

    def test_create_schedule_target_input_contains_metadata(self):
        self.mock_events.put_rule.return_value = {
            "RuleArn": "arn:aws:events:eu-west-2:123456789012:rule/test"
        }

        self.scheduler.create_schedule(
            state_machine_arn=self.state_machine_arn,
            role_arn=self.role_arn,
            schedule_expression="cron(0 */6 * * ? *)",
        )

        call_kwargs = self.mock_events.put_targets.call_args[1]
        target_input = json.loads(call_kwargs["Targets"][0]["Input"])
        assert target_input["source"] == "eventbridge-schedule"
        assert target_input["rule_name"] == "dark-web-fraud-crawl-schedule"
        assert target_input["schedule_expression"] == "cron(0 */6 * * ? *)"

    def test_create_schedule_custom_expression(self):
        self.mock_events.put_rule.return_value = {"RuleArn": "arn:aws:events:eu-west-2:123456789012:rule/test"}

        self.scheduler.create_schedule(
            state_machine_arn=self.state_machine_arn,
            role_arn=self.role_arn,
            schedule_expression="cron(0 */6 * * ? *)",
            description="Custom schedule",
        )

        call_kwargs = self.mock_events.put_rule.call_args[1]
        assert call_kwargs["ScheduleExpression"] == "cron(0 */6 * * ? *)"
        assert call_kwargs["Description"] == "Custom schedule"

    def test_create_schedule_disabled(self):
        self.mock_events.put_rule.return_value = {"RuleArn": "arn:aws:events:eu-west-2:123456789012:rule/test"}

        self.scheduler.create_schedule(
            state_machine_arn=self.state_machine_arn,
            role_arn=self.role_arn,
            enabled=False,
        )

        call_kwargs = self.mock_events.put_rule.call_args[1]
        assert call_kwargs["State"] == "DISABLED"

    def test_create_schedule_raises_on_empty_state_machine_arn(self):
        with pytest.raises(ValueError, match="state_machine_arn must not be empty"):
            self.scheduler.create_schedule(
                state_machine_arn="",
                role_arn=self.role_arn,
            )

    def test_create_schedule_raises_on_empty_role_arn(self):
        with pytest.raises(ValueError, match="role_arn must not be empty"):
            self.scheduler.create_schedule(
                state_machine_arn=self.state_machine_arn,
                role_arn="",
            )


class TestPipelineSchedulerDeleteSchedule:
    """Tests for PipelineScheduler.delete_schedule()."""

    def setup_method(self):
        self.mock_events = MagicMock()
        self.scheduler = PipelineScheduler(
            rule_name="dark-web-fraud-crawl-schedule",
            events_client=self.mock_events,
        )

    def test_delete_schedule_removes_targets_then_rule(self):
        self.scheduler.delete_schedule()

        self.mock_events.remove_targets.assert_called_once_with(
            Rule="dark-web-fraud-crawl-schedule",
            Ids=["step-functions-pipeline"],
        )
        self.mock_events.delete_rule.assert_called_once_with(
            Name="dark-web-fraud-crawl-schedule"
        )

    def test_delete_schedule_removes_targets_before_rule(self):
        """Targets must be removed before the rule can be deleted."""
        call_order = []
        self.mock_events.remove_targets.side_effect = lambda **k: call_order.append("remove_targets")
        self.mock_events.delete_rule.side_effect = lambda **k: call_order.append("delete_rule")

        self.scheduler.delete_schedule()

        assert call_order == ["remove_targets", "delete_rule"]


class TestPipelineSchedulerUpdateSchedule:
    """Tests for PipelineScheduler.update_schedule()."""

    def setup_method(self):
        self.mock_events = MagicMock()
        self.scheduler = PipelineScheduler(
            rule_name="dark-web-fraud-crawl-schedule",
            events_client=self.mock_events,
        )

    def test_update_schedule_calls_put_rule(self):
        self.mock_events.put_rule.return_value = {
            "RuleArn": "arn:aws:events:eu-west-2:123456789012:rule/dark-web-fraud-crawl-schedule"
        }

        rule_arn = self.scheduler.update_schedule("rate(12 hours)")

        self.mock_events.put_rule.assert_called_once_with(
            Name="dark-web-fraud-crawl-schedule",
            ScheduleExpression="rate(12 hours)",
        )
        assert rule_arn == "arn:aws:events:eu-west-2:123456789012:rule/dark-web-fraud-crawl-schedule"


# --- MapStateConfig Tests ---


class TestMapStateConfig:
    """Tests for MapStateConfig validation and state definition generation."""

    def test_default_values(self):
        config = MapStateConfig()
        assert config.max_concurrency == 10
        assert config.items_path == "$.crawlResults"
        assert config.result_path == "$.processedResults"
        assert config.retry_max_attempts == 3
        assert config.retry_backoff_rate == 2.0
        assert config.retry_interval_seconds == 5

    def test_custom_values(self):
        config = MapStateConfig(
            max_concurrency=5,
            items_path="$.items",
            result_path="$.output",
            retry_max_attempts=2,
            retry_backoff_rate=3.0,
            retry_interval_seconds=10,
        )
        assert config.max_concurrency == 5
        assert config.items_path == "$.items"
        assert config.result_path == "$.output"
        assert config.retry_max_attempts == 2
        assert config.retry_backoff_rate == 3.0
        assert config.retry_interval_seconds == 10

    def test_invalid_max_concurrency_zero(self):
        with pytest.raises(ValueError, match="max_concurrency must be >= 1"):
            MapStateConfig(max_concurrency=0)

    def test_invalid_max_concurrency_negative(self):
        with pytest.raises(ValueError, match="max_concurrency must be >= 1"):
            MapStateConfig(max_concurrency=-1)

    def test_invalid_retry_max_attempts_negative(self):
        with pytest.raises(ValueError, match="retry_max_attempts must be >= 0"):
            MapStateConfig(retry_max_attempts=-1)

    def test_invalid_retry_backoff_rate_below_one(self):
        with pytest.raises(ValueError, match="retry_backoff_rate must be >= 1.0"):
            MapStateConfig(retry_backoff_rate=0.5)

    def test_to_state_definition_structure(self):
        config = MapStateConfig()
        definition = config.to_state_definition()

        assert definition["Type"] == "Map"
        assert definition["ItemsPath"] == "$.crawlResults"
        assert definition["ResultPath"] == "$.processedResults"
        assert definition["MaxConcurrency"] == 10

    def test_to_state_definition_has_iterator_with_states(self):
        config = MapStateConfig()
        definition = config.to_state_definition()

        iterator = definition["Iterator"]
        assert iterator["StartAt"] == "AnalyzeContent"
        states = iterator["States"]
        assert "AnalyzeContent" in states
        assert "CheckFraudRelevance" in states
        assert "StructureData" in states
        assert "TagIntelligence" in states
        assert "GenerateAlerts" in states
        assert "DiscardIrrelevant" in states

    def test_to_state_definition_max_concurrency_custom(self):
        config = MapStateConfig(max_concurrency=20)
        definition = config.to_state_definition()
        assert definition["MaxConcurrency"] == 20

    def test_to_state_definition_retry_config_propagated(self):
        config = MapStateConfig(
            retry_max_attempts=5,
            retry_interval_seconds=10,
            retry_backoff_rate=3.0,
        )
        definition = config.to_state_definition()

        # Check retry config on AnalyzeContent
        analyze_state = definition["Iterator"]["States"]["AnalyzeContent"]
        retry = analyze_state["Retry"][0]
        assert retry["MaxAttempts"] == 5
        assert retry["IntervalSeconds"] == 10
        assert retry["BackoffRate"] == 3.0

    def test_to_state_definition_discard_irrelevant_is_succeed(self):
        config = MapStateConfig()
        definition = config.to_state_definition()

        discard = definition["Iterator"]["States"]["DiscardIrrelevant"]
        assert discard["Type"] == "Succeed"

    def test_to_state_definition_generate_alerts_ends_iterator(self):
        config = MapStateConfig()
        definition = config.to_state_definition()

        alerts = definition["Iterator"]["States"]["GenerateAlerts"]
        assert alerts.get("End") is True

    def test_to_state_definition_choice_routes_fraud_relevant(self):
        config = MapStateConfig()
        definition = config.to_state_definition()

        choice = definition["Iterator"]["States"]["CheckFraudRelevance"]
        assert choice["Type"] == "Choice"
        assert choice["Default"] == "DiscardIrrelevant"
        assert choice["Choices"][0]["Variable"] == "$.isFraudRelevant"
        assert choice["Choices"][0]["BooleanEquals"] is True
        assert choice["Choices"][0]["Next"] == "StructureData"

    def test_to_state_definition_is_valid_json(self):
        config = MapStateConfig()
        definition = config.to_state_definition()
        # Must be JSON serializable
        serialized = json.dumps(definition)
        deserialized = json.loads(serialized)
        assert deserialized == definition


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

    def test_initialization_order_is_dependency_order(self):
        """Agents are initialized in the order provided: crawl → content → data → tag → alert."""
        initialized_order = []

        class OrderTrackingAgent(AgentBase):
            def __init__(self, agent_id: str):
                config = AgentConfig(agent_id=agent_id, agent_name=agent_id)
                super().__init__(config)

            def get_health(self) -> AgentHealth:
                initialized_order.append(self._config.agent_id)
                return self._health

        agents = [
            OrderTrackingAgent("crawling-engine"),
            OrderTrackingAgent("content-analyst"),
            OrderTrackingAgent("data-structurer"),
            OrderTrackingAgent("tagging-engine"),
            OrderTrackingAgent("alert-generator"),
        ]

        initializer = AgentInitializer(agents)
        initializer.initialize_all()

        assert initialized_order == [
            "crawling-engine",
            "content-analyst",
            "data-structurer",
            "tagging-engine",
            "alert-generator",
        ]
