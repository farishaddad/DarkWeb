"""Unit tests for shared data models and interfaces."""

from datetime import UTC, datetime

import pytest

from dark_web_fraud_agent.models import (
    AgentBase,
    AgentConfig,
    AgentHealth,
    IntelligenceTier,
    StepFunctionsPipelineState,
    TierLink,
)


class TestAgentHealth:
    """Tests for AgentHealth dataclass."""

    def test_create_agent_health(self):
        health = AgentHealth(
            agent_id="crawling-engine-001",
            status="healthy",
            processing_throughput=12.5,
            error_rate=0.02,
            queue_depth=3,
            last_heartbeat=datetime(2026, 6, 15, 14, 30, 0),
            uptime_seconds=3600.0,
            bedrock_token_count=15000,
            bedrock_error_rate=0.01,
        )
        assert health.agent_id == "crawling-engine-001"
        assert health.status == "healthy"
        assert health.processing_throughput == 12.5
        assert health.error_rate == 0.02
        assert health.queue_depth == 3
        assert health.last_heartbeat == datetime(2026, 6, 15, 14, 30, 0)
        assert health.uptime_seconds == 3600.0
        assert health.bedrock_token_count == 15000
        assert health.bedrock_error_rate == 0.01

    def test_agent_health_status_values(self):
        """Verify all expected status values can be assigned."""
        for status in ("healthy", "degraded", "failed"):
            health = AgentHealth(
                agent_id="test",
                status=status,
                processing_throughput=0.0,
                error_rate=0.0,
                queue_depth=0,
                last_heartbeat=datetime.now(UTC),
                uptime_seconds=0.0,
                bedrock_token_count=0,
                bedrock_error_rate=0.0,
            )
            assert health.status == status


class TestStepFunctionsPipelineState:
    """Tests for StepFunctionsPipelineState dataclass."""

    def test_create_pipeline_state(self):
        state = StepFunctionsPipelineState(
            execution_arn="arn:aws:states:us-east-1:123456789:execution:pipeline:abc-123",
            current_step="ContentAnalyst",
            correlation_id="corr-uuid-001",
            started_at=datetime(2026, 6, 15, 14, 0, 0),
            items_processed=5,
            errors=[{"agent": "CrawlingEngine", "message": "Tor timeout"}],
        )
        assert state.execution_arn == "arn:aws:states:us-east-1:123456789:execution:pipeline:abc-123"
        assert state.current_step == "ContentAnalyst"
        assert state.correlation_id == "corr-uuid-001"
        assert state.items_processed == 5
        assert len(state.errors) == 1

    def test_pipeline_state_default_errors(self):
        state = StepFunctionsPipelineState(
            execution_arn="arn:aws:states:us-east-1:123:execution:pipe:x",
            current_step="CrawlSources",
            correlation_id="corr-001",
            started_at=datetime.now(UTC),
            items_processed=0,
        )
        assert state.errors == []


class TestIntelligenceTier:
    """Tests for IntelligenceTier enum."""

    def test_tier_values(self):
        assert IntelligenceTier.OBSERVABLE.value == "observable"
        assert IntelligenceTier.INDICATOR.value == "indicator"
        assert IntelligenceTier.TTP.value == "ttp"

    def test_tier_membership(self):
        assert len(IntelligenceTier) == 3

    def test_tier_from_value(self):
        assert IntelligenceTier("observable") == IntelligenceTier.OBSERVABLE
        assert IntelligenceTier("indicator") == IntelligenceTier.INDICATOR
        assert IntelligenceTier("ttp") == IntelligenceTier.TTP

    def test_invalid_tier_raises(self):
        with pytest.raises(ValueError):
            IntelligenceTier("unknown")


class TestTierLink:
    """Tests for TierLink dataclass."""

    def test_create_tier_link(self):
        link = TierLink(
            source_id="indicator--abc-123",
            source_tier=IntelligenceTier.INDICATOR,
            target_id="attack-pattern--xyz-789",
            target_tier=IntelligenceTier.TTP,
            relationship_type="supports",
        )
        assert link.source_id == "indicator--abc-123"
        assert link.source_tier == IntelligenceTier.INDICATOR
        assert link.target_id == "attack-pattern--xyz-789"
        assert link.target_tier == IntelligenceTier.TTP
        assert link.relationship_type == "supports"

    def test_tier_link_relationship_types(self):
        """Verify all valid relationship types."""
        for rel_type in ("derived-from", "supports", "indicates"):
            link = TierLink(
                source_id="src-1",
                source_tier=IntelligenceTier.OBSERVABLE,
                target_id="tgt-1",
                target_tier=IntelligenceTier.INDICATOR,
                relationship_type=rel_type,
            )
            assert link.relationship_type == rel_type


class TestAgentConfig:
    """Tests for AgentConfig dataclass."""

    def test_create_agent_config(self):
        config = AgentConfig(
            agent_id="crawling-engine-001",
            agent_name="Crawling Engine",
            s3_bucket="darkweb-artifacts-bucket",
            dynamodb_table="agent-state-table",
        )
        assert config.agent_id == "crawling-engine-001"
        assert config.agent_name == "Crawling Engine"
        assert config.s3_bucket == "darkweb-artifacts-bucket"
        assert config.dynamodb_table == "agent-state-table"

    def test_agent_config_optional_fields(self):
        config = AgentConfig(
            agent_id="test-agent",
            agent_name="Test Agent",
        )
        assert config.s3_bucket is None
        assert config.dynamodb_table is None


class TestAgentBase:
    """Tests for AgentBase abstract class."""

    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            AgentBase(AgentConfig(agent_id="test", agent_name="Test"))

    def test_concrete_agent_implementation(self):
        class ConcreteAgent(AgentBase):
            def get_health(self) -> AgentHealth:
                return self._health

        config = AgentConfig(agent_id="concrete-001", agent_name="Concrete Agent")
        agent = ConcreteAgent(config)

        assert agent.config.agent_id == "concrete-001"
        health = agent.get_health()
        assert health.agent_id == "concrete-001"
        assert health.status == "healthy"
        assert health.processing_throughput == 0.0
        assert health.bedrock_token_count == 0

    def test_agent_initial_health(self):
        class TestAgent(AgentBase):
            def get_health(self) -> AgentHealth:
                return self._health

        config = AgentConfig(agent_id="test-001", agent_name="Test")
        agent = TestAgent(config)
        health = agent.get_health()

        assert health.status == "healthy"
        assert health.error_rate == 0.0
        assert health.queue_depth == 0
        assert health.uptime_seconds == 0.0
        assert health.bedrock_error_rate == 0.0
