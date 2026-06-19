"""Unit tests for the Alert Generator agent.

Tests cover:
- Campaign convergence detection (3+ items within time window)
- Expired item pruning
- Alert generation with correct structure
- Health reporting
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from dark_web_fraud_agent.agents.alert_generator import (
    AlertGenerator,
    ConvergenceItem,
)
from dark_web_fraud_agent.models.shared import AgentConfig


class TestAlertGeneratorInit:
    """Test AlertGenerator initialization."""

    def test_default_config(self):
        agent = AlertGenerator()
        assert agent.config.agent_id == "alert-generator"
        assert agent.config.agent_name == "Alert Generator"

    def test_custom_config(self):
        config = AgentConfig(agent_id="custom-alert", agent_name="Custom Alert Gen")
        agent = AlertGenerator(config=config)
        assert agent.config.agent_id == "custom-alert"

    def test_custom_convergence_window(self):
        window = timedelta(hours=12)
        agent = AlertGenerator(convergence_window=window)
        assert agent._convergence_window == window

    def test_health_initial_state(self):
        agent = AlertGenerator()
        health = agent.get_health()
        assert health.agent_id == "alert-generator"
        assert health.status == "healthy"


class TestTrackItem:
    """Test item tracking for convergence detection."""

    def test_track_single_item(self):
        agent = AlertGenerator()
        agent.track_item("stix-001", "ttp-abc", "indicator")
        assert "ttp-abc" in agent._convergence_tracker
        assert len(agent._convergence_tracker["ttp-abc"]) == 1
        assert agent._convergence_tracker["ttp-abc"][0].stix_id == "stix-001"

    def test_track_multiple_items_same_ttp(self):
        agent = AlertGenerator()
        agent.track_item("stix-001", "ttp-abc", "indicator")
        agent.track_item("stix-002", "ttp-abc", "observable")
        agent.track_item("stix-003", "ttp-abc", "indicator")
        assert len(agent._convergence_tracker["ttp-abc"]) == 3

    def test_track_items_different_ttps(self):
        agent = AlertGenerator()
        agent.track_item("stix-001", "ttp-abc", "indicator")
        agent.track_item("stix-002", "ttp-xyz", "observable")
        assert len(agent._convergence_tracker["ttp-abc"]) == 1
        assert len(agent._convergence_tracker["ttp-xyz"]) == 1

    def test_tracked_item_has_timestamp(self):
        agent = AlertGenerator()
        before = datetime.now(UTC)
        agent.track_item("stix-001", "ttp-abc", "indicator")
        after = datetime.now(UTC)
        item = agent._convergence_tracker["ttp-abc"][0]
        assert before <= item.timestamp <= after


class TestCampaignConvergence:
    """Test campaign convergence detection logic."""

    def test_no_convergence_with_fewer_than_3_items(self):
        agent = AlertGenerator()
        agent.track_item("stix-001", "ttp-abc", "indicator")
        agent.track_item("stix-002", "ttp-abc", "observable")
        result = agent.check_campaign_convergence("ttp-abc")
        assert result is None

    def test_convergence_with_exactly_3_items(self):
        agent = AlertGenerator()
        agent.track_item("stix-001", "ttp-abc", "indicator")
        agent.track_item("stix-002", "ttp-abc", "observable")
        agent.track_item("stix-003", "ttp-abc", "indicator")
        result = agent.check_campaign_convergence("ttp-abc")
        assert result is not None
        assert len(result) == 3
        assert "stix-001" in result
        assert "stix-002" in result
        assert "stix-003" in result

    def test_convergence_with_more_than_3_items(self):
        agent = AlertGenerator()
        for i in range(5):
            agent.track_item(f"stix-{i:03d}", "ttp-abc", "indicator")
        result = agent.check_campaign_convergence("ttp-abc")
        assert result is not None
        assert len(result) == 5

    def test_no_convergence_for_unknown_ttp(self):
        agent = AlertGenerator()
        result = agent.check_campaign_convergence("ttp-unknown")
        assert result is None

    def test_convergence_only_for_specific_ttp(self):
        agent = AlertGenerator()
        # 3 items for ttp-abc
        for i in range(3):
            agent.track_item(f"stix-a{i}", "ttp-abc", "indicator")
        # 2 items for ttp-xyz
        for i in range(2):
            agent.track_item(f"stix-b{i}", "ttp-xyz", "observable")

        assert agent.check_campaign_convergence("ttp-abc") is not None
        assert agent.check_campaign_convergence("ttp-xyz") is None


class TestPruneExpired:
    """Test expired item pruning."""

    def test_expired_items_are_removed(self):
        agent = AlertGenerator(convergence_window=timedelta(hours=1))
        # Manually add an expired item
        expired_time = datetime.now(UTC) - timedelta(hours=2)
        agent._convergence_tracker["ttp-abc"] = [
            ConvergenceItem(
                stix_id="stix-old",
                ttp_reference="ttp-abc",
                tier="indicator",
                timestamp=expired_time,
            )
        ]
        # Pruning happens during check
        result = agent.check_campaign_convergence("ttp-abc")
        assert result is None
        assert len(agent._convergence_tracker["ttp-abc"]) == 0

    def test_fresh_items_preserved_after_pruning(self):
        agent = AlertGenerator(convergence_window=timedelta(hours=1))
        # Add one expired and three fresh items
        expired_time = datetime.now(UTC) - timedelta(hours=2)
        agent._convergence_tracker["ttp-abc"] = [
            ConvergenceItem(
                stix_id="stix-old",
                ttp_reference="ttp-abc",
                tier="indicator",
                timestamp=expired_time,
            )
        ]
        agent.track_item("stix-001", "ttp-abc", "indicator")
        agent.track_item("stix-002", "ttp-abc", "observable")
        agent.track_item("stix-003", "ttp-abc", "indicator")

        result = agent.check_campaign_convergence("ttp-abc")
        assert result is not None
        assert "stix-old" not in result
        assert len(result) == 3

    def test_pruning_on_track_item(self):
        agent = AlertGenerator(convergence_window=timedelta(hours=1))
        # Add an expired item directly
        expired_time = datetime.now(UTC) - timedelta(hours=2)
        agent._convergence_tracker["ttp-abc"] = [
            ConvergenceItem(
                stix_id="stix-old",
                ttp_reference="ttp-abc",
                tier="indicator",
                timestamp=expired_time,
            )
        ]
        # Track a new item - this triggers pruning
        agent.track_item("stix-new", "ttp-abc", "indicator")
        # Only the new item should remain
        assert len(agent._convergence_tracker["ttp-abc"]) == 1
        assert agent._convergence_tracker["ttp-abc"][0].stix_id == "stix-new"


class TestGenerateCampaignAlert:
    """Test campaign alert generation."""

    def test_alert_structure(self):
        agent = AlertGenerator()
        crawl_time = datetime.now(UTC) - timedelta(minutes=30)
        alert = agent.generate_campaign_alert(
            ttp_reference="ttp-abc",
            ttp_description="Account takeover via credential stuffing",
            affected_institutions=["Bank A", "Bank B"],
            related_ids=["stix-001", "stix-002", "stix-003"],
            source_url="http://example.onion/forum",
            crawl_timestamp=crawl_time,
        )

        assert alert.alert_type == "campaign_alert"
        assert alert.severity == "high"
        assert alert.ttp_description == "Account takeover via credential stuffing"
        assert alert.affected_institutions == ["Bank A", "Bank B"]
        assert alert.related_intelligence == ["stix-001", "stix-002", "stix-003"]

    def test_alert_has_detection_rule(self):
        agent = AlertGenerator()
        crawl_time = datetime.now(UTC)
        alert = agent.generate_campaign_alert(
            ttp_reference="ttp-abc",
            ttp_description="Test TTP",
            affected_institutions=["Bank A"],
            related_ids=["stix-001", "stix-002", "stix-003"],
            source_url="http://example.onion",
            crawl_timestamp=crawl_time,
        )

        assert len(alert.recommended_detection_rules) == 1
        rule = alert.recommended_detection_rules[0]
        assert rule.rule_type == "sigma"
        assert "ttp-abc" in rule.rule_content
        assert rule.confidence == 0.8

    def test_alert_provenance(self):
        agent = AlertGenerator()
        crawl_time = datetime.now(UTC) - timedelta(minutes=10)
        alert = agent.generate_campaign_alert(
            ttp_reference="ttp-abc",
            ttp_description="Test TTP",
            affected_institutions=["Bank A"],
            related_ids=["stix-001"],
            source_url="http://darkweb.onion/page",
            crawl_timestamp=crawl_time,
        )

        assert alert.provenance.original_source_url == "http://darkweb.onion/page"
        assert alert.provenance.crawl_timestamp == crawl_time
        assert "alert-generator" in alert.provenance.processing_chain
        assert len(alert.provenance.processing_chain) == 5

    def test_alert_has_unique_id(self):
        agent = AlertGenerator()
        crawl_time = datetime.now(UTC)
        alert1 = agent.generate_campaign_alert(
            ttp_reference="ttp-abc",
            ttp_description="Test",
            affected_institutions=["Bank A"],
            related_ids=["stix-001"],
            source_url="http://example.onion",
            crawl_timestamp=crawl_time,
        )
        alert2 = agent.generate_campaign_alert(
            ttp_reference="ttp-abc",
            ttp_description="Test",
            affected_institutions=["Bank A"],
            related_ids=["stix-001"],
            source_url="http://example.onion",
            crawl_timestamp=crawl_time,
        )
        assert alert1.alert_id != alert2.alert_id

    def test_alert_created_at_is_recent(self):
        agent = AlertGenerator()
        before = datetime.now(UTC)
        alert = agent.generate_campaign_alert(
            ttp_reference="ttp-abc",
            ttp_description="Test",
            affected_institutions=["Bank A"],
            related_ids=["stix-001"],
            source_url="http://example.onion",
            crawl_timestamp=datetime.now(UTC),
        )
        after = datetime.now(UTC)
        assert before <= alert.created_at <= after
