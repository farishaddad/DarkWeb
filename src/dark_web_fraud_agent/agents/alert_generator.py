"""Alert Generator agent for campaign convergence and alert publishing."""

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

import boto3

from dark_web_fraud_agent.models.alerts import (
    AlertProvenance,
    DetectionRule,
    FraudAlert,
)
from dark_web_fraud_agent.models.shared import AgentBase, AgentConfig, AgentHealth


@dataclass
class ConvergenceItem:
    """An item tracked for campaign convergence."""

    stix_id: str
    ttp_reference: str  # STIX ID of the related TTP
    tier: str
    timestamp: datetime


class AlertGenerator(AgentBase):
    """Alert Generator agent that detects campaign convergence and produces alerts.

    Tracks intelligence items referencing common TTPs within a configurable time window.
    When 3+ items converge around the same TTP, a consolidated campaign alert is generated.
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        convergence_window: timedelta = timedelta(hours=24),
    ):
        if config is None:
            config = AgentConfig(agent_id="alert-generator", agent_name="Alert Generator")
        super().__init__(config)
        self._convergence_window = convergence_window
        self._convergence_tracker: dict[str, list[ConvergenceItem]] = {}  # TTP ID -> items

    def get_health(self) -> AgentHealth:
        """Return the current health status of the Alert Generator."""
        return self._health

    def track_item(self, stix_id: str, ttp_reference: str, tier: str) -> None:
        """Track an intelligence item for campaign convergence detection.

        Items are associated with a TTP reference and timestamped. Expired items
        (older than the convergence window) are pruned on each call.
        """
        item = ConvergenceItem(
            stix_id=stix_id,
            ttp_reference=ttp_reference,
            tier=tier,
            timestamp=datetime.now(UTC),
        )
        if ttp_reference not in self._convergence_tracker:
            self._convergence_tracker[ttp_reference] = []
        self._convergence_tracker[ttp_reference].append(item)
        # Prune expired items
        self._prune_expired(ttp_reference)

    def check_campaign_convergence(self, ttp_reference: str) -> Optional[list[str]]:
        """Check if 3+ items converge around a TTP within the time window.

        Returns list of STIX IDs if convergence detected, None otherwise.
        """
        self._prune_expired(ttp_reference)
        items = self._convergence_tracker.get(ttp_reference, [])
        if len(items) >= 3:
            return [item.stix_id for item in items]
        return None

    def generate_campaign_alert(
        self,
        ttp_reference: str,
        ttp_description: str,
        affected_institutions: list[str],
        related_ids: list[str],
        source_url: str,
        crawl_timestamp: datetime,
    ) -> FraudAlert:
        """Generate a consolidated campaign alert.

        Called when campaign convergence is detected (3+ items around a common TTP).
        Produces a FraudAlert with type 'campaign_alert' and high severity.
        """
        return FraudAlert(
            alert_id=str(uuid.uuid4()),
            alert_type="campaign_alert",
            severity="high",
            ttp_description=ttp_description,
            affected_institutions=affected_institutions,
            recommended_detection_rules=[
                DetectionRule(
                    rule_type="sigma",
                    rule_content=f"title: Campaign for {ttp_reference}",
                    confidence=0.8,
                )
            ],
            related_intelligence=related_ids,
            provenance=AlertProvenance(
                original_source_url=source_url,
                crawl_timestamp=crawl_timestamp,
                s3_artifact_key="",
                processing_chain=[
                    "crawling-engine",
                    "content-analyst",
                    "data-structurer",
                    "tagging-engine",
                    "alert-generator",
                ],
            ),
            created_at=datetime.now(UTC),
        )

    def _prune_expired(self, ttp_reference: str) -> None:
        """Remove items older than the convergence window."""
        cutoff = datetime.now(UTC) - self._convergence_window
        if ttp_reference in self._convergence_tracker:
            self._convergence_tracker[ttp_reference] = [
                item
                for item in self._convergence_tracker[ttp_reference]
                if item.timestamp > cutoff
            ]

    async def publish_alert(
        self,
        alert: FraudAlert,
        sns_topic_arn: str,
        sns_client: Any = None,
    ) -> str:
        """Publish a FraudAlert as JSON to an SNS topic.

        Args:
            alert: The FraudAlert to publish.
            sns_topic_arn: The ARN of the SNS topic to publish to.
            sns_client: Optional boto3 SNS client. Created if not provided.

        Returns:
            The SNS MessageId from the publish response.
        """
        if sns_client is None:
            sns_client = boto3.client("sns")

        message_body = json.dumps(self.format_for_api(alert))

        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=message_body,
            Subject=f"FraudAlert [{alert.severity.upper()}]: {alert.alert_type}",
            MessageAttributes={
                "alert_type": {
                    "DataType": "String",
                    "StringValue": alert.alert_type,
                },
                "severity": {
                    "DataType": "String",
                    "StringValue": alert.severity,
                },
            },
        )

        message_id = response["MessageId"]
        alert.sns_message_id = message_id
        return message_id

    def format_for_api(self, alert: FraudAlert) -> dict:
        """Convert a FraudAlert to a JSON-serializable dict for API integration.

        Includes all fields, converts datetime to ISO string, and flattens
        provenance into the dict.

        Args:
            alert: The FraudAlert to format.

        Returns:
            A JSON-serializable dictionary representation.
        """
        result: dict[str, Any] = {
            "alert_id": alert.alert_id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "ttp_description": alert.ttp_description,
            "affected_institutions": alert.affected_institutions,
            "recommended_detection_rules": [
                {
                    "rule_type": rule.rule_type,
                    "rule_content": rule.rule_content,
                    "confidence": rule.confidence,
                }
                for rule in alert.recommended_detection_rules
            ],
            "related_intelligence": alert.related_intelligence,
            "created_at": alert.created_at.isoformat(),
            "sns_message_id": alert.sns_message_id,
            # Flattened provenance fields
            "original_source_url": alert.provenance.original_source_url,
            "crawl_timestamp": alert.provenance.crawl_timestamp.isoformat(),
            "s3_artifact_key": alert.provenance.s3_artifact_key,
            "processing_chain": alert.provenance.processing_chain,
        }
        return result

    def generate_summary_digest(
        self,
        items: list[dict],
        period_description: str,
    ) -> FraudAlert:
        """Create a summary_digest alert summarizing low/medium findings.

        Args:
            items: List of dicts with keys "stix_id", "severity", "fraud_category".
            period_description: Human-readable description of the reporting period.

        Returns:
            A FraudAlert of type "summary_digest" with severity "low".
        """
        stix_ids = [item["stix_id"] for item in items]

        # Build a description summarizing the findings
        category_counts: dict[str, int] = {}
        for item in items:
            cat = item.get("fraud_category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        description_parts = [
            f"Summary digest for {period_description}.",
            f"Total items: {len(items)}.",
        ]
        for cat, count in sorted(category_counts.items()):
            description_parts.append(f"  {cat}: {count}")

        provenance = AlertProvenance(
            original_source_url="aggregate",
            crawl_timestamp=datetime.now(UTC),
            s3_artifact_key="",
            processing_chain=["alert_generator"],
        )

        alert = FraudAlert(
            alert_id=str(uuid.uuid4()),
            alert_type="summary_digest",
            severity="low",
            ttp_description="\n".join(description_parts),
            affected_institutions=[],
            recommended_detection_rules=[],
            related_intelligence=stix_ids,
            provenance=provenance,
            created_at=datetime.now(UTC),
        )

        return alert
