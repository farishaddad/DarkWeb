"""Unit tests for alert data models (FraudAlert, AlertProvenance, DetectionRule)."""

from datetime import UTC, datetime

import pytest

from dark_web_fraud_agent.models import (
    ALERT_TYPES,
    RULE_TYPES,
    SEVERITY_LEVELS,
    AlertProvenance,
    DetectionRule,
    FraudAlert,
)


class TestDetectionRule:
    """Tests for DetectionRule dataclass."""

    def test_create_yara_rule(self):
        rule = DetectionRule(
            rule_type="yara",
            rule_content='rule fraud_kit { strings: $a = "phishing" condition: $a }',
            confidence=0.85,
        )
        assert rule.rule_type == "yara"
        assert "phishing" in rule.rule_content
        assert rule.confidence == 0.85

    def test_create_sigma_rule(self):
        rule = DetectionRule(
            rule_type="sigma",
            rule_content="title: MFA Bypass Detection\nlogsource:\n  product: banking",
            confidence=0.72,
        )
        assert rule.rule_type == "sigma"
        assert rule.confidence == 0.72

    def test_create_custom_rule(self):
        rule = DetectionRule(
            rule_type="custom",
            rule_content="IF transaction_velocity > 100 THEN flag_fraud",
            confidence=0.6,
        )
        assert rule.rule_type == "custom"

    def test_all_valid_rule_types(self):
        for rule_type in RULE_TYPES:
            rule = DetectionRule(
                rule_type=rule_type,
                rule_content="test content",
                confidence=0.5,
            )
            assert rule.rule_type == rule_type

    def test_invalid_rule_type_raises(self):
        with pytest.raises(ValueError, match="Invalid rule_type"):
            DetectionRule(
                rule_type="invalid",
                rule_content="content",
                confidence=0.5,
            )

    def test_confidence_boundary_zero(self):
        rule = DetectionRule(rule_type="yara", rule_content="test", confidence=0.0)
        assert rule.confidence == 0.0

    def test_confidence_boundary_one(self):
        rule = DetectionRule(rule_type="yara", rule_content="test", confidence=1.0)
        assert rule.confidence == 1.0

    def test_confidence_below_zero_raises(self):
        with pytest.raises(ValueError, match="confidence must be between"):
            DetectionRule(rule_type="yara", rule_content="test", confidence=-0.1)

    def test_confidence_above_one_raises(self):
        with pytest.raises(ValueError, match="confidence must be between"):
            DetectionRule(rule_type="sigma", rule_content="test", confidence=1.1)


class TestAlertProvenance:
    """Tests for AlertProvenance dataclass."""

    def test_create_provenance(self):
        provenance = AlertProvenance(
            original_source_url="http://darkforumxyz.onion/thread/12345",
            crawl_timestamp=datetime(2026, 6, 15, 10, 30, 0, tzinfo=UTC),
            s3_artifact_key="crawl-artifacts/2026/06/15/abc123.html",
            processing_chain=["crawling-engine-001", "content-analyst-001", "alert-generator-001"],
        )
        assert provenance.original_source_url == "http://darkforumxyz.onion/thread/12345"
        assert provenance.crawl_timestamp == datetime(2026, 6, 15, 10, 30, 0, tzinfo=UTC)
        assert provenance.s3_artifact_key == "crawl-artifacts/2026/06/15/abc123.html"
        assert len(provenance.processing_chain) == 3
        assert provenance.processing_chain[0] == "crawling-engine-001"

    def test_provenance_default_processing_chain(self):
        provenance = AlertProvenance(
            original_source_url="http://example.onion/page",
            crawl_timestamp=datetime.now(UTC),
            s3_artifact_key="artifacts/test.html",
        )
        assert provenance.processing_chain == []

    def test_provenance_with_empty_processing_chain(self):
        provenance = AlertProvenance(
            original_source_url="http://market.onion/listing/99",
            crawl_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            s3_artifact_key="artifacts/listing.json",
            processing_chain=[],
        )
        assert provenance.processing_chain == []


class TestFraudAlert:
    """Tests for FraudAlert dataclass."""

    def _make_provenance(self) -> AlertProvenance:
        return AlertProvenance(
            original_source_url="http://forum.onion/thread/999",
            crawl_timestamp=datetime(2026, 6, 15, 8, 0, 0, tzinfo=UTC),
            s3_artifact_key="crawl-artifacts/2026/06/15/thread999.html",
            processing_chain=["crawling-engine-001", "content-analyst-001"],
        )

    def _make_detection_rule(self) -> DetectionRule:
        return DetectionRule(
            rule_type="sigma",
            rule_content="title: Detect MFA bypass\nlogsource:\n  product: auth",
            confidence=0.9,
        )

    def test_create_ttp_alert(self):
        provenance = self._make_provenance()
        rule = self._make_detection_rule()
        alert = FraudAlert(
            alert_id="alert-uuid-001",
            alert_type="ttp_alert",
            severity="high",
            ttp_description="MFA bypass using SIM swap targeting major banks",
            affected_institutions=["Bank of America", "Chase", "Wells Fargo"],
            recommended_detection_rules=[rule],
            related_intelligence=["indicator--abc123", "attack-pattern--xyz789"],
            provenance=provenance,
            created_at=datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC),
        )
        assert alert.alert_id == "alert-uuid-001"
        assert alert.alert_type == "ttp_alert"
        assert alert.severity == "high"
        assert "MFA bypass" in alert.ttp_description
        assert len(alert.affected_institutions) == 3
        assert len(alert.recommended_detection_rules) == 1
        assert len(alert.related_intelligence) == 2
        assert alert.provenance.original_source_url == "http://forum.onion/thread/999"
        assert alert.sns_message_id is None

    def test_create_campaign_alert(self):
        alert = FraudAlert(
            alert_id="alert-uuid-002",
            alert_type="campaign_alert",
            severity="critical",
            ttp_description="Coordinated phishing campaign targeting UK banks",
            affected_institutions=["HSBC", "Barclays", "Lloyds"],
            recommended_detection_rules=[
                DetectionRule(rule_type="yara", rule_content="rule test {}", confidence=0.8),
                DetectionRule(rule_type="sigma", rule_content="title: test", confidence=0.75),
            ],
            related_intelligence=["indicator--111", "indicator--222", "indicator--333"],
            provenance=self._make_provenance(),
            created_at=datetime.now(UTC),
        )
        assert alert.alert_type == "campaign_alert"
        assert alert.severity == "critical"
        assert len(alert.recommended_detection_rules) == 2

    def test_create_summary_digest(self):
        alert = FraudAlert(
            alert_id="alert-uuid-003",
            alert_type="summary_digest",
            severity="low",
            ttp_description="Weekly digest of low-severity findings",
            affected_institutions=[],
            recommended_detection_rules=[],
            related_intelligence=["indicator--aaa", "indicator--bbb"],
            provenance=self._make_provenance(),
            created_at=datetime.now(UTC),
        )
        assert alert.alert_type == "summary_digest"
        assert alert.severity == "low"
        assert alert.affected_institutions == []
        assert alert.recommended_detection_rules == []

    def test_all_valid_alert_types(self):
        for alert_type in ALERT_TYPES:
            alert = FraudAlert(
                alert_id="test-id",
                alert_type=alert_type,
                severity="medium",
                ttp_description="Test",
                affected_institutions=[],
                recommended_detection_rules=[],
                related_intelligence=[],
                provenance=self._make_provenance(),
                created_at=datetime.now(UTC),
            )
            assert alert.alert_type == alert_type

    def test_all_valid_severity_levels(self):
        for severity in SEVERITY_LEVELS:
            alert = FraudAlert(
                alert_id="test-id",
                alert_type="ttp_alert",
                severity=severity,
                ttp_description="Test",
                affected_institutions=[],
                recommended_detection_rules=[],
                related_intelligence=[],
                provenance=self._make_provenance(),
                created_at=datetime.now(UTC),
            )
            assert alert.severity == severity

    def test_invalid_alert_type_raises(self):
        with pytest.raises(ValueError, match="Invalid alert_type"):
            FraudAlert(
                alert_id="test-id",
                alert_type="unknown_alert",
                severity="high",
                ttp_description="Test",
                affected_institutions=[],
                recommended_detection_rules=[],
                related_intelligence=[],
                provenance=self._make_provenance(),
                created_at=datetime.now(UTC),
            )

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            FraudAlert(
                alert_id="test-id",
                alert_type="ttp_alert",
                severity="extreme",
                ttp_description="Test",
                affected_institutions=[],
                recommended_detection_rules=[],
                related_intelligence=[],
                provenance=self._make_provenance(),
                created_at=datetime.now(UTC),
            )

    def test_alert_with_sns_message_id(self):
        alert = FraudAlert(
            alert_id="test-id",
            alert_type="ttp_alert",
            severity="high",
            ttp_description="Test alert",
            affected_institutions=["TestBank"],
            recommended_detection_rules=[],
            related_intelligence=[],
            provenance=self._make_provenance(),
            created_at=datetime.now(UTC),
            sns_message_id="msg-abc-123-def-456",
        )
        assert alert.sns_message_id == "msg-abc-123-def-456"

    def test_alert_provenance_relationship(self):
        """Verify alert's provenance contains crawl_timestamp before created_at."""
        crawl_time = datetime(2026, 6, 15, 8, 0, 0, tzinfo=UTC)
        alert_time = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)
        provenance = AlertProvenance(
            original_source_url="http://test.onion",
            crawl_timestamp=crawl_time,
            s3_artifact_key="test/key",
            processing_chain=["agent-1"],
        )
        alert = FraudAlert(
            alert_id="test-id",
            alert_type="ttp_alert",
            severity="medium",
            ttp_description="Test",
            affected_institutions=[],
            recommended_detection_rules=[],
            related_intelligence=[],
            provenance=provenance,
            created_at=alert_time,
        )
        assert alert.provenance.crawl_timestamp < alert.created_at
