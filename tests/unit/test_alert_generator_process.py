"""Unit tests for AlertGenerator.process() orchestration method.

Tests cover:
- Full pipeline: tracking → convergence → alert generation → publishing
- High-severity immediate alerts
- Cross-entity co-occurrence alerts
- Summary digest path
- No-op when stix_bundle_key or fraud_category missing
- SNS publishing integration via mocked boto3
"""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from dark_web_fraud_agent.agents.alert_generator import AlertGenerator
from dark_web_fraud_agent.models.alerts import FraudAlert


def _make_event(
    severity_score: int = 5,
    fraud_category: str = "mfa_bypass",
    tags: list[str] | None = None,
    entities: list[dict] | None = None,
    stix_bundle_key: str = "stix-bundles/2024/06/01/bundle-001",
    tier: str = "indicator",
    s3_key: str = "crawl-artifacts/2024/06/01/page123",
) -> dict:
    """Create a sample Step Functions payload event."""
    return {
        "stix_bundle_key": stix_bundle_key,
        "fraud_category": fraud_category,
        "severity_score": severity_score,
        "tags": tags or ["mitre-attack:technique=\"T1111\""],
        "entities": entities or [{"entity_type": "bank_name", "value": "HSBC"}],
        "s3_key": s3_key,
        "tier": tier,
    }


class TestProcessNoOp:
    """Test cases where process() returns None without generating alerts."""

    def test_returns_none_when_stix_bundle_key_missing(self):
        agent = AlertGenerator()
        event = _make_event()
        event["stix_bundle_key"] = None
        result = agent.process(event, sns_topic_arn="arn:aws:sns:eu-west-2:123:topic")
        assert result is None

    def test_returns_none_when_fraud_category_missing(self):
        agent = AlertGenerator()
        event = _make_event()
        event["fraud_category"] = None
        result = agent.process(event, sns_topic_arn="arn:aws:sns:eu-west-2:123:topic")
        assert result is None

    def test_returns_none_when_no_convergence_and_low_severity(self):
        agent = AlertGenerator()
        event = _make_event(severity_score=3)
        result = agent.process(event, sns_topic_arn="arn:aws:sns:eu-west-2:123:topic")
        assert result is None


class TestProcessHighSeverityAlert:
    """Test immediate alert generation for high severity scores."""

    def test_high_severity_triggers_immediate_alert(self):
        agent = AlertGenerator()
        event = _make_event(severity_score=8)
        mock_sns = MagicMock()
        mock_sns.publish.return_value = {"MessageId": "msg-123"}

        result = agent.process(event, sns_topic_arn="arn:aws:sns:eu-west-2:123:topic", sns_client=mock_sns)

        assert result is not None
        assert isinstance(result, FraudAlert)
        assert result.alert_type == "campaign_alert"
        assert result.severity == "high"

    def test_high_severity_uses_env_threshold(self):
        agent = AlertGenerator()
        event = _make_event(severity_score=9)
        mock_sns = MagicMock()
        mock_sns.publish.return_value = {"MessageId": "msg-456"}

        with patch.dict(os.environ, {"HIGH_SEVERITY_THRESHOLD": "10"}):
            result = agent.process(event, sns_topic_arn="arn:aws:sns:eu-west-2:123:topic", sns_client=mock_sns)

        # Severity 9 is below threshold 10, no convergence → None
        assert result is None

    def test_high_severity_includes_affected_institutions(self):
        agent = AlertGenerator()
        entities = [
            {"entity_type": "bank_name", "value": "HSBC"},
            {"entity_type": "bank_name", "value": "Barclays"},
            {"entity_type": "btc_wallet", "value": "1A2B3C..."},
        ]
        event = _make_event(severity_score=8, entities=entities)
        mock_sns = MagicMock()
        mock_sns.publish.return_value = {"MessageId": "msg-789"}

        result = agent.process(event, sns_topic_arn="arn:aws:sns:eu-west-2:123:topic", sns_client=mock_sns)

        assert result is not None
        assert "HSBC" in result.affected_institutions
        assert "Barclays" in result.affected_institutions


class TestProcessConvergence:
    """Test campaign convergence-triggered alert generation."""

    def test_convergence_triggers_campaign_alert(self):
        agent = AlertGenerator()
        mock_sns = MagicMock()
        mock_sns.publish.return_value = {"MessageId": "converge-msg"}

        # Track 2 items first (below threshold)
        for i in range(2):
            agent.track_item(
                f"stix-pre-{i}",
                "mitre-attack:technique=\"T1111\"",
                "indicator",
            )

        # Third item via process() should trigger convergence
        event = _make_event(severity_score=3)
        result = agent.process(event, sns_topic_arn="arn:aws:sns:eu-west-2:123:topic", sns_client=mock_sns)

        assert result is not None
        assert result.alert_type == "campaign_alert"
        assert len(result.related_intelligence) >= 3

    def test_convergence_uses_attack_tag_as_ttp_reference(self):
        agent = AlertGenerator()
        mock_sns = MagicMock()
        mock_sns.publish.return_value = {"MessageId": "msg-ref"}

        # Pre-populate with the same TTP reference
        ttp_ref = "mitre-attack:technique=\"T1566\""
        for i in range(2):
            agent.track_item(f"stix-pre-{i}", ttp_ref, "indicator")

        event = _make_event(severity_score=3, tags=[ttp_ref])
        result = agent.process(event, sns_topic_arn="arn:aws:sns:eu-west-2:123:topic", sns_client=mock_sns)

        assert result is not None
        assert "T1566" in result.recommended_detection_rules[0].rule_content


class TestProcessPublishing:
    """Test SNS publishing within process()."""

    @mock_aws
    def test_process_publishes_to_sns(self):
        sns_client = boto3.client("sns", region_name="eu-west-2")
        topic = sns_client.create_topic(Name="fraud-alerts")
        topic_arn = topic["TopicArn"]

        agent = AlertGenerator()
        event = _make_event(severity_score=8)

        result = agent.process(event, sns_topic_arn=topic_arn, sns_client=sns_client)

        assert result is not None
        assert result.sns_message_id is not None

    @mock_aws
    def test_process_uses_env_sns_topic_arn(self):
        sns_client = boto3.client("sns", region_name="eu-west-2")
        topic = sns_client.create_topic(Name="fraud-alerts")
        topic_arn = topic["TopicArn"]

        agent = AlertGenerator()
        event = _make_event(severity_score=8)

        with patch.dict(os.environ, {"SNS_TOPIC_ARN": topic_arn}):
            result = agent.process(event, sns_client=sns_client)

        assert result is not None
        assert result.sns_message_id is not None

    def test_process_skips_publish_when_no_topic(self):
        agent = AlertGenerator()
        event = _make_event(severity_score=8)

        with patch.dict(os.environ, {"SNS_TOPIC_ARN": ""}, clear=False):
            result = agent.process(event, sns_topic_arn="")

        # Alert generated but not published (no topic)
        assert result is not None
        assert result.sns_message_id is None


class TestProcessSummaryDigest:
    """Test summary digest path in process()."""

    def test_digest_path_returns_summary_alert(self):
        agent = AlertGenerator()
        event = {
            "digest_items": [
                {"stix_id": "indicator--001", "severity": "low", "fraud_category": "phishing"},
                {"stix_id": "indicator--002", "severity": "medium", "fraud_category": "ato"},
            ],
            "digest_period": "Week of 2024-06-01",
        }
        mock_sns = MagicMock()
        mock_sns.publish.return_value = {"MessageId": "digest-msg"}

        result = agent.process(event, sns_topic_arn="arn:aws:sns:eu-west-2:123:topic", sns_client=mock_sns)

        assert result is not None
        assert result.alert_type == "summary_digest"
        assert result.severity == "low"
        assert "Week of 2024-06-01" in result.ttp_description

    def test_digest_path_publishes_to_sns(self):
        agent = AlertGenerator()
        event = {
            "digest_items": [
                {"stix_id": "indicator--001", "severity": "low", "fraud_category": "phishing"},
            ],
            "digest_period": "June 2024",
        }
        mock_sns = MagicMock()
        mock_sns.publish.return_value = {"MessageId": "digest-pub-msg"}

        result = agent.process(event, sns_topic_arn="arn:aws:sns:eu-west-2:123:topic", sns_client=mock_sns)

        assert result is not None
        mock_sns.publish.assert_called_once()
        call_kwargs = mock_sns.publish.call_args[1]
        assert call_kwargs["TopicArn"] == "arn:aws:sns:eu-west-2:123:topic"

    def test_digest_path_skips_publish_when_no_topic(self):
        agent = AlertGenerator()
        event = {
            "digest_items": [
                {"stix_id": "indicator--001", "severity": "low", "fraud_category": "phishing"},
            ],
            "digest_period": "June 2024",
        }

        result = agent.process(event, sns_topic_arn="")

        assert result is not None
        assert result.alert_type == "summary_digest"
        assert result.sns_message_id is None
