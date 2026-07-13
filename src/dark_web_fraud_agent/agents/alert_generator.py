
# ---------------------------------------------------------------------------
# Sigma rule generator + ATT&CK logsource maps
# ---------------------------------------------------------------------------

_SIGMA_LOGSOURCE_MAP = {
    "T1111": {"category": "authentication", "product": "windows"},
    "T1566": {"category": "webserver"},
    "T1078": {"category": "authentication"},
    "T1585": {"category": "network"},
    "T1539": {"category": "proxy"},
    # Extended — new fraud categories
    "T1136": {"category": "network", "service": "newaccountmonitoring"},
    "T1499": {"category": "webserver"},
    "T1531": {"category": "authentication"},
    "T1583": {"category": "network"},
    "T1598": {"category": "application"},
}

_SIGMA_TITLE_MAP = {
    "T1111": "MFA Interception Detected",
    "T1566": "Phishing Kit Deployment Detected",
    "T1078": "Account Takeover via Valid Credentials",
    "T1585": "Synthetic Identity Account Creation",
    "T1539": "Card-Not-Present Session Cookie Theft",
    # Extended — new fraud categories
    "T1136": "New Account Fraud via Stolen Identity (Fullz)",
    "T1499": "Recurring Billing Aggregation Fraud Detected",
    "T1531": "Money Mule Network Activity Detected",
    "T1583": "Investment Fraud / Fake Exchange Infrastructure",
    "T1598": "Social Engineering — Romance Script / Pig Butchering",
}


def _generate_sigma_rule(ttp_reference: str, ttp_description: str) -> str:
    """Generate a syntactically valid Sigma YAML detection rule.

    Required Sigma fields: title, id, status, description, logsource,
    detection, condition, falsepositives, level.
    """
    import uuid as _uuid
    import datetime as _dt

    technique_id = None
    if "=" in ttp_reference:
        technique_id = ttp_reference.split("=")[-1].strip()
    elif len(ttp_reference) >= 5 and ttp_reference.startswith("T"):
        technique_id = ttp_reference

    logsource = _SIGMA_LOGSOURCE_MAP.get(technique_id, {"category": "security"})
    title = _SIGMA_TITLE_MAP.get(technique_id, f"Dark Web Campaign: {ttp_reference[:60]}")
    logsource_lines = "\n    ".join(f"{k}: {v}" for k, v in logsource.items())
    attack_tag = (
        f"attack.{technique_id.lower().replace('.', '_')}"
        if technique_id else "attack.t0000"
    )

    return (
        f"title: {title}\n"
        f"id: {_uuid.uuid4()}\n"
        f"status: experimental\n"
        f"description: |\n"
        f"    Auto-generated from dark web campaign convergence.\n"
        f"    TTP: {ttp_reference}\n"
        f"    Context: {ttp_description[:200]}\n"
        f"references:\n"
        f"    - https://attack.mitre.org/techniques/{technique_id or 'T0000'}/\n"
        f"author: dark-web-fraud-agent\n"
        f"date: {_dt.date.today().isoformat()}\n"
        f"tags:\n"
        f"    - {attack_tag}\n"
        f"logsource:\n"
        f"    {logsource_lines}\n"
        f"detection:\n"
        f"    selection:\n"
        f"        EventID|contains:\n"
        f"            - '4625'\n"
        f"            - '4648'\n"
        f"    condition: selection\n"
        f"falsepositives:\n"
        f"    - Legitimate authentication activity\n"
        f"    - Security testing\n"
        f"level: high\n"
    )



# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------

# Module-level SNS client — reused across warm invocations
_sns_client = boto3.client("sns")


def handler(event: dict, context) -> dict:
    """Lambda handler for the Alert Generator pipeline step.

    Handles two invocation paths:

    1. Step Functions (scheduled pipeline):
       Receives Tagging Engine output, tracks the TTP in DynamoDB, checks
       for campaign convergence (3+ items referencing same TTP), and
       publishes a campaign alert to SNS if threshold is crossed.

    2. DynamoDB Streams (reactive):
       Triggered by INSERT events on ConvergenceTable. Evaluates each
       new item's TTP reference for convergence immediately rather than
       waiting for the next pipeline cycle.

    Expected input (Step Functions path):
        {
            "s3_key": "...",
            "execution_id": "...",
            "stix_bundle_key": "...",
            "tags": [...],
            "fraud_category": "mfa_bypass",
            "severity_score": 7,
        }
    """
    import json as _json
    import logging
    logger = logging.getLogger(__name__)

    sns_topic_arn: str = os.environ["SNS_TOPIC_ARN"]
    high_severity_threshold: int = int(os.environ.get("HIGH_SEVERITY_THRESHOLD", "7"))

    generator = AlertGenerator(
        convergence_window=__import__("datetime").timedelta(hours=24)
    )

    # --- DynamoDB Streams path ---
    # When invoked from Streams, event has "Records" not pipeline keys
    if "Records" in event:
        published = []
        for record in event["Records"]:
            if record.get("eventName") != "INSERT":
                continue
            new_image = record.get("dynamodb", {}).get("NewImage", {})
            ttp_ref = new_image.get("ttp_reference", {}).get("S", "")
            if not ttp_ref:
                continue
            converged = generator.check_campaign_convergence(ttp_ref)
            if converged:
                alert = generator.generate_campaign_alert(
                    ttp_reference=ttp_ref,
                    ttp_description=f"Campaign convergence detected: {ttp_ref}",
                    affected_institutions=[],
                    related_ids=converged,
                    source_url="dynamodb-streams",
                    crawl_timestamp=__import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    ),
                )
                mid = generator.publish_alert(alert, sns_topic_arn, _sns_client)
                published.append(mid)
        return {"published_alerts": published}

    # --- Step Functions pipeline path ---
    s3_key: str = event.get("s3_key", "")
    execution_id: str = event.get("execution_id", "unknown")
    stix_bundle_key: str | None = event.get("stix_bundle_key")
    fraud_category: str | None = event.get("fraud_category")
    severity_score: int = int(event.get("severity_score", 3))

    alert_published = None
    convergence_ids = None

    if stix_bundle_key and fraud_category:
        # Derive a stable TTP reference key from the fraud_category + tag fingerprint
        tags = event.get("tags", [])
        attack_tags = [t for t in tags if t.startswith("mitre-attack:")]
        ttp_ref = attack_tags[0] if attack_tags else f"fraud:{fraud_category}"

        # Track this item for convergence (written to DynamoDB with TTL)
        # Also index entity values for cross-entity co-occurrence (CHAPS-026)
        entities_payload = event.get("entities", [])
        generator.track_item(
            stix_id=stix_bundle_key,
            ttp_reference=ttp_ref,
            tier=event.get("tier", "observable"),
            entity_values=entities_payload,
        )

        # Check TTP convergence — or immediate alert on high severity
        convergence_ids = generator.check_campaign_convergence(ttp_ref)

        # Check cross-entity co-occurrence for CHAPS-026 composite alerts
        if not convergence_ids:
            for entity in entities_payload:
                if entity.get("entity_type") == "bank_name":
                    convergence_ids = generator.check_entity_cooccurrence(
                        entity_type="bank_name",
                        entity_value=entity["value"],
                    )
                    if convergence_ids:
                        # Override TTP description to reflect composite signal
                        fraud_category = f"{fraud_category}+cross_signal_cooccurrence"
                        break

        immediate_alert = severity_score >= high_severity_threshold

        if convergence_ids or immediate_alert:
            from datetime import datetime, timezone
            alert = generator.generate_campaign_alert(
                ttp_reference=ttp_ref,
                ttp_description=f"[{fraud_category}] Campaign or high-severity intelligence detected",
                affected_institutions=[],
                related_ids=convergence_ids or [stix_bundle_key],
                source_url=s3_key,
                crawl_timestamp=datetime.now(timezone.utc),
            )
            alert_published = generator.publish_alert(alert, sns_topic_arn, _sns_client)
            generator.update_health(items_processed=1, errors=0)
        logger.info("AlertGenerator: published alert %s for TTP %s", alert_published, ttp_ref)

    return {
        "s3_key": s3_key,
        "execution_id": execution_id,
        "stix_bundle_key": stix_bundle_key,
        "fraud_category": fraud_category,
        "severity_score": severity_score,
        "convergence_ids": convergence_ids,
        "alert_published": alert_published,
    }
import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

import boto3
from boto3.dynamodb.conditions import Attr, Key

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
        # In-memory tracker kept for unit tests only. Lambda production path
        # uses DynamoDB (track_item / check_campaign_convergence below).
        self._convergence_tracker: dict[str, list[ConvergenceItem]] = {}

    def get_health(self) -> AgentHealth:
        """Return the current health status of the Alert Generator."""
        return self._health

    def _get_convergence_table(self):
        """Return the DynamoDB Table resource (env var injected by CDK)."""
        table_name = os.environ.get("DYNAMODB_CONVERGENCE_TABLE", "dark-web-fraud-convergence")
        return boto3.resource("dynamodb").Table(table_name)


    def track_item(
        self,
        stix_id: str,
        ttp_reference: str,
        tier: str,
        entity_values: list[dict] | None = None,
    ) -> None:
        """Track an intelligence item in DynamoDB for campaign convergence.

        Items are written with a TTL so DynamoDB auto-expires them when the
        convergence window closes — no manual pruning needed.

        Args:
            stix_id: STIX bundle ID for this intelligence item.
            ttp_reference: The ATT&CK technique / fraud category key used for convergence.
            tier: Intelligence tier ("observable", "indicator", or "ttp").
            entity_values: Optional list of extracted entity dicts
                ({"entity_type": ..., "value": ...}) for cross-entity co-occurrence
                tracking (CHAPS-026 pattern: credential listing + mule script same institution).
        """
        table = self._get_convergence_table()
        ttl = int((datetime.now(UTC) + self._convergence_window).timestamp())
        table.put_item(Item={
            "PK": f"CONV#{ttp_reference}",
            "SK": f"ITEM#{stix_id}",
            "stix_id": stix_id,
            "ttp_reference": ttp_reference,
            "tier": tier,
            "timestamp": datetime.now(UTC).isoformat(),
            "TTL": ttl,
        })

        # Cross-entity co-occurrence: index each bank_name entity independently.
        # When the same institution appears in both a Source 1 credential listing
        # and a Source 2 mule-recruitment post within the convergence window,
        # a composite alert is generated linking both signals (CHAPS-026).
        if entity_values:
            for entity in entity_values:
                if entity.get("entity_type") == "bank_name":
                    bank_key = f"ENTITY#bank_name#{entity['value'].lower()}"
                    table.put_item(Item={
                        "PK": bank_key,
                        "SK": f"ITEM#{stix_id}",
                        "stix_id": stix_id,
                        "ttp_reference": ttp_reference,
                        "tier": tier,
                        "entity_type": "bank_name",
                        "entity_value": entity["value"].lower(),
                        "timestamp": datetime.now(UTC).isoformat(),
                        "TTL": ttl,
                    })

    def check_campaign_convergence(self, ttp_reference: str) -> Optional[list[str]]:
        """Check if 3+ items reference the same TTP within the convergence window.

        Queries DynamoDB ConvergenceTable — items are auto-expired by TTL.
        Returns list of STIX IDs if convergence is detected, None otherwise.
        """
        table = self._get_convergence_table()
        resp = table.query(
            KeyConditionExpression=Key("PK").eq(f"CONV#{ttp_reference}"),
        )
        items = resp.get("Items", [])
        if len(items) >= 3:
            return [item["stix_id"] for item in items]
        return None

    def check_entity_cooccurrence(self, entity_type: str, entity_value: str) -> Optional[list[str]]:
        """Check whether the same entity appears in signals from multiple source tiers.

        Implements cross-signal co-occurrence for CHAPS-026: detects when the same
        institution name appears in both a Source 1 credential listing (tier=observable)
        and a Source 2 mule-recruitment post (tier=ttp) within the convergence window.
        Two or more signals across different tiers referencing the same entity triggers
        a composite alert linking both intelligence layers.

        Args:
            entity_type: Entity type to check (currently only "bank_name" is indexed).
            entity_value: The entity value to look up (case-insensitive).

        Returns:
            List of STIX IDs if cross-tier co-occurrence is detected (>=2 items
            spanning at least 2 distinct tiers), otherwise None.
        """
        table = self._get_convergence_table()
        # Use the GSI name from the environment variable so CDK can rotate the
        # index name without a Lambda code change. Defaults to the name set
        # in cdk_core_stack.py ("entity-cooccurrence-index").
        index_name = os.environ.get("ENTITY_INDEX_NAME", "entity-cooccurrence-index")
        resp = table.query(
            IndexName=index_name,
            KeyConditionExpression=Key("PK").eq(
                f"ENTITY#{entity_type}#{entity_value.lower()}"
            ),
        )
        items = resp.get("Items", [])
        if len(items) < 2:
            return None
        # Require items from at least 2 distinct intelligence tiers
        tiers = {item.get("tier") for item in items}
        if len(tiers) >= 2:
            return [item["stix_id"] for item in items]
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
                    rule_content=_generate_sigma_rule(ttp_reference, ttp_description),
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

    def publish_alert(
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
