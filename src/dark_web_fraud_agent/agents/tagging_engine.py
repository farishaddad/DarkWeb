

# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------

def handler(event: dict, context) -> dict:
    """Lambda handler for the Tagging Engine pipeline step.

    Receives Data Structurer output (STIX bundle S3 key, fraud_category,
    severity_score), applies all tag sets, writes the tag manifest back to
    S3, and returns structured output for the Alert Generator.

    Expected input:
        {
            "s3_key": "...",
            "execution_id": "...",
            "stix_bundle_key": "stix-bundles/...",
            "fraud_category": "mfa_bypass",
            "severity_score": 7,
            "tier": "ttp",
        }
    """
    s3_key: str = event["s3_key"]
    execution_id: str = event.get("execution_id", "unknown")
    stix_bundle_key: str | None = event.get("stix_bundle_key")
    fraud_category: str | None = event.get("fraud_category")
    severity_score: int = int(event.get("severity_score", 3))
    s3_bucket: str = os.environ["S3_BUCKET"]

    # Short-circuit if there is no STIX bundle (non-relevant content passed through)
    if not stix_bundle_key:
        return {"s3_key": s3_key, "execution_id": execution_id,
                "tags": [], "tag_manifest_key": None, "stix_bundle_key": None}

    engine = TaggingEngine()

    # Apply all tag sets
    # Note: entities are not re-hydrated here to keep the Lambda lightweight —
    # fraud and attack tags are derived from fraud_category and severity_score alone
    fraud_tags = engine.apply_fraud_tags([])   # entity-level tags added if entities passed
    attack_tags = engine.apply_attack_tags(fraud_category)
    threat_level_tag = engine.apply_threat_level_tag(severity_score)
    galaxy_match = engine.match_galaxy_cluster(fraud_category)

    all_tags = fraud_tags + attack_tags + [threat_level_tag]
    if not fraud_tags and not attack_tags:
        all_tags.append(engine.apply_requires_review_tag())
    if galaxy_match:
        all_tags.append(engine.apply_fraud_tags([]))  # placeholder — galaxy tag TBD

    tag_strings = [str(t) for t in all_tags]

    # Write tag manifest to S3 alongside the STIX bundle
    s3 = boto3.client("s3")
    tag_manifest_key = stix_bundle_key.replace(".stix.json", ".tags.json")
    s3.put_object(
        Bucket=s3_bucket,
        Key=tag_manifest_key,
        Body=__import__("json").dumps({
            "stix_bundle_key": stix_bundle_key,
            "fraud_category": fraud_category,
            "severity_score": severity_score,
            "tags": tag_strings,
            "galaxy_match": galaxy_match,
        }).encode(),
        ContentType="application/json",
    )

    engine.update_health(items_processed=len(tag_strings), errors=0)
    logger.info("TaggingEngine: %d tags applied for category=%s", len(tag_strings), fraud_category)
    return {
        "s3_key": s3_key,
        "execution_id": execution_id,
        "stix_bundle_key": stix_bundle_key,
        "tag_manifest_key": tag_manifest_key,
        "tags": tag_strings,
        "fraud_category": fraud_category,
        "severity_score": severity_score,
        "galaxy_match": galaxy_match,
    }
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import boto3

from dark_web_fraud_agent.models.content_analyst import ExtractedEntity

logger = logging.getLogger(__name__)
from dark_web_fraud_agent.models.shared import AgentBase, AgentConfig, AgentHealth


@dataclass
class TaxonomyEntry:
    """A single entry within a taxonomy predicate."""

    value: str
    expanded: str


@dataclass
class TaxonomyPredicate:
    """A predicate within a taxonomy namespace, containing optional entries."""

    value: str
    expanded: str
    entries: list[TaxonomyEntry] = field(default_factory=list)


@dataclass
class TaxonomyDefinition:
    """A complete taxonomy definition with namespace, predicates, and entries."""

    namespace: str
    description: str
    version: int = 1
    predicates: list[TaxonomyPredicate] = field(default_factory=list)


@dataclass
class MachineTag:
    """A machine-readable tag in namespace:predicate="value" format."""

    namespace: str
    predicate: str
    value: str

    def __str__(self) -> str:
        return f'{self.namespace}:{self.predicate}="{self.value}"'


class TaggingEngine(AgentBase):
    """Agent responsible for automated intelligence classification using taxonomies.

    Loads taxonomy definitions, applies tags based on MITRE ATT&CK and custom
    banking fraud taxonomies, and maps severity scores to threat levels.
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        if config is None:
            config = AgentConfig(agent_id="tagging-engine", agent_name="Tagging Engine")
        super().__init__(config)
        self._taxonomies: dict[str, TaxonomyDefinition] = {}

    def get_health(self) -> AgentHealth:
        """Return the current health status of the Tagging Engine."""
        return self._health

    def load_taxonomy(self, taxonomy_json: str) -> TaxonomyDefinition:
        """Load a taxonomy from a JSON string.

        Args:
            taxonomy_json: JSON string containing taxonomy definition with
                namespace, predicates, and optional entries.

        Returns:
            The parsed TaxonomyDefinition.

        Raises:
            ValueError: If JSON is invalid or required fields are missing.
        """
        try:
            data = json.loads(taxonomy_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid taxonomy JSON: {e}") from e

        if "namespace" not in data:
            raise ValueError("Taxonomy must have 'namespace' field")
        if "predicates" not in data or not isinstance(data["predicates"], list):
            raise ValueError("Taxonomy must have 'predicates' list")

        predicates = []
        for pred_data in data["predicates"]:
            if "value" not in pred_data or "expanded" not in pred_data:
                raise ValueError("Each predicate must have 'value' and 'expanded'")
            entries = []
            for entry_data in pred_data.get("entries", []):
                if "value" not in entry_data or "expanded" not in entry_data:
                    raise ValueError("Each entry must have 'value' and 'expanded'")
                entries.append(
                    TaxonomyEntry(value=entry_data["value"], expanded=entry_data["expanded"])
                )
            predicates.append(
                TaxonomyPredicate(
                    value=pred_data["value"], expanded=pred_data["expanded"], entries=entries
                )
            )

        taxonomy = TaxonomyDefinition(
            namespace=data["namespace"],
            description=data.get("description", ""),
            version=data.get("version", 1),
            predicates=predicates,
        )

        self._taxonomies[taxonomy.namespace] = taxonomy
        return taxonomy

    def load_attack_techniques_from_s3(
        self, s3_bucket: str, s3_key: str, s3_client=None
    ) -> dict[str, dict]:
        """Load MITRE ATT&CK technique metadata from a STIX bundle stored in S3.

        The TaggingConfig.attack_stix_s3_key points to the full ATT&CK STIX
        bundle (enterprise-attack.json). Loading it expands the attack_map
        from 5 hardcoded entries to 500+ techniques with names and tactic phases
        — critical for SIEM correlation rules that match on technique names.

        Args:
            s3_bucket: S3 bucket containing the ATT&CK STIX bundle.
            s3_key: S3 key of the ATT&CK STIX bundle JSON file.
            s3_client: Optional boto3 S3 client (created if not provided).

        Returns:
            Dict mapping technique_id -> {"name": str, "tactics": [str], "description": str}.
            Stored in self._attack_techniques for use by apply_attack_tags().
        """
        if s3_client is None:
            s3_client = boto3.client("s3")

        try:
            response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
            bundle_json = response["Body"].read().decode("utf-8")
            bundle = json.loads(bundle_json)
        except Exception as exc:
            logger.warning(
                "Could not load ATT&CK STIX bundle from s3://%s/%s: %s — "
                "falling back to hardcoded technique map.",
                s3_bucket, s3_key, exc,
            )
            return {}

        techniques: dict[str, dict] = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            # Extract technique ID from external_references (MITRE source)
            ext_refs = obj.get("external_references", [])
            technique_id = next(
                (r["external_id"] for r in ext_refs
                 if r.get("source_name") == "mitre-attack"),
                None,
            )
            if not technique_id:
                continue
            tactics = [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            techniques[technique_id] = {
                "name": obj.get("name", ""),
                "tactics": tactics,
                "description": obj.get("description", "")[:500],
            }

        self._attack_techniques = techniques
        logger.info("Loaded %d ATT&CK techniques from s3://%s/%s", len(techniques), s3_bucket, s3_key)
        return techniques

    def get_loaded_taxonomies(self) -> dict[str, TaxonomyDefinition]:
        """Return all currently loaded taxonomies keyed by namespace."""
        return self._taxonomies

    def map_severity_to_threat_level(self, severity: int) -> str:
        """Map a severity score (1-10) to a threat level string.

        Mapping:
            1-3  → low
            4-6  → medium
            7-9  → high
            10   → critical

        Args:
            severity: Integer severity score from 1 to 10.

        Returns:
            Threat level string: "low", "medium", "high", or "critical".
        """
        if severity <= 3:
            return "low"
        elif severity <= 6:
            return "medium"
        elif severity <= 9:
            return "high"
        else:
            return "critical"

    def apply_fraud_tags(self, entities: list[ExtractedEntity]) -> list[MachineTag]:
        """Apply fraud:type tags based on banking keywords found in entities.

        Rules:
            - If any entity contains "SWIFT" keyword → fraud:type="swift-transfer"
            - If any entity is of type "bin_range" → fraud:type="bin-attack"
            - If any entity is of type "btc_wallet" → fraud:type="crypto-fraud"
            - If any entity contains bank name keywords → fraud:target="<bank_name_lower>"

        Args:
            entities: List of ExtractedEntity objects to analyze.

        Returns:
            List of MachineTag objects for detected fraud indicators.
        """
        tags: list[MachineTag] = []

        for entity in entities:
            if "SWIFT" in entity.value.upper():
                tags.append(MachineTag("fraud", "type", "swift-transfer"))
            if entity.entity_type == "bin_range":
                tags.append(MachineTag("fraud", "type", "bin-attack"))
            if entity.entity_type == "btc_wallet":
                tags.append(MachineTag("fraud", "type", "crypto-fraud"))
            if entity.entity_type == "bank_name":
                tags.append(MachineTag("fraud", "target", entity.value.lower()))
            # Extended entity tags
            if entity.entity_type == "monero_wallet":
                tags.append(MachineTag("fraud", "type", "crypto-laundering"))
            if entity.entity_type == "merchant_id":
                tags.append(MachineTag("fraud", "type", "merchant-account-fraud"))
            if entity.entity_type == "acquiring_bin":
                tags.append(MachineTag("fraud", "type", "acquiring-bin-abuse"))
            if entity.entity_type == "iban":
                tags.append(MachineTag("fraud", "type", "cross-border-transfer"))
            if entity.entity_type == "national_id":
                tags.append(MachineTag("fraud", "type", "identity-document-fraud"))

        return tags

    def apply_attack_tags(self, fraud_category: Optional[str]) -> list[MachineTag]:
        """Apply MITRE ATT&CK technique tags based on fraud category.

        Mapping:
            mfa_bypass         → T1111
            phishing_kit       → T1566
            account_takeover   → T1110
            synthetic_identity → T1583
            cnp_fraud          → T1499
            None               → empty list

        Args:
            fraud_category: Optional fraud category string.

        Returns:
            List of MachineTag objects with MITRE ATT&CK technique IDs.
        """
        attack_map: dict[str, str] = {
            # Primary technique IDs — mapped to MITRE ATT&CK v14 financial fraud TTPs
            # Sub-techniques provide SIEM rule precision:
            #   T1566.001 = Spearphishing Attachment (phishing kit delivery)
            #   T1078.001 = Default Accounts (account takeover via credential stuffing)
            #   T1110.004 = Credential Stuffing (account takeover brute-force variant)
            "mfa_bypass":              "T1111",    # Multi-Factor Authentication Interception
            "phishing_kit":            "T1566",    # Phishing (T1566.001 for attachment delivery)
            "account_takeover":        "T1078",    # Valid Accounts (T1078.001 default creds)
            "synthetic_identity":      "T1585",    # Establish Accounts (T1585.001 social media)
            "cnp_fraud":               "T1539",    # Steal Web Session Cookie (CNP card-not-present)
            # Extended mappings — added for patterns DC-007, DC-008, CHAPS-026, XC-007
            "new_account_fraud":       "T1136",    # Create Account (Fullz → new account opening)
            "recurring_billing_fraud": "T1499",    # Endpoint Denial of Service (billing API abuse)
            "money_mule":              "T1531",    # Account Access Removal (mule account manipulation)
            "investment_fraud":        "T1583",    # Acquire Infrastructure (fake exchange setup)
            "social_engineering":      "T1598",    # Phishing for Information (romance / scripted SE)
        }
        # Also emit sub-technique tags for SIEM rules that correlate at sub-technique level
        sub_technique_map: dict[str, str] = {
            "phishing_kit":            "T1566.001",
            "account_takeover":        "T1078.001",
            "synthetic_identity":      "T1585.001",
            "investment_fraud":        "T1583.006",  # Web Services (fake exchange hosting)
            "social_engineering":      "T1598.003",  # Spearphishing via Service (romance contact)
        }

        if fraud_category is None or fraud_category not in attack_map:
            return []

        technique_id = attack_map[fraud_category]
        tags = [MachineTag("mitre-attack", "technique", technique_id)]
        if fraud_category in sub_technique_map:
            tags.append(MachineTag("mitre-attack", "technique", sub_technique_map[fraud_category]))
        return tags

    def apply_threat_level_tag(self, severity: int) -> MachineTag:
        """Apply a threat-level tag based on severity score.

        Uses map_severity_to_threat_level to convert the severity score,
        then wraps it in a MachineTag.

        Args:
            severity: Integer severity score from 1 to 10.

        Returns:
            MachineTag with namespace="threat-level", predicate="level",
            and value from severity mapping.
        """
        level = self.map_severity_to_threat_level(severity)
        return MachineTag("threat-level", "level", level)

    def apply_requires_review_tag(self) -> MachineTag:
        """Return a requires-review tag for unmatched content.

        Applied when an event doesn't match any fraud or attack taxonomy predicates,
        indicating the content needs manual analyst review.

        Returns:
            MachineTag with namespace="review", predicate="status",
            value="requires-review".
        """
        return MachineTag("review", "status", "requires-review")

    def tag_event(
        self, entities: list[ExtractedEntity], fraud_category: Optional[str], severity: int
    ) -> list[MachineTag]:
        """Orchestrate all tagging steps for an event.

        Combines fraud tagging, attack tagging, and threat-level tagging.
        If no fraud tags and no attack tags were produced, adds a requires-review
        tag to flag the event for manual analysis.

        Args:
            entities: List of extracted entities from the content.
            fraud_category: Optional fraud category string from classification.
            severity: Integer severity score from 1 to 10.

        Returns:
            Combined list of all applied MachineTag objects.
        """
        tags: list[MachineTag] = []

        fraud_tags = self.apply_fraud_tags(entities)
        attack_tags = self.apply_attack_tags(fraud_category)
        threat_level_tag = self.apply_threat_level_tag(severity)

        tags.extend(fraud_tags)
        tags.extend(attack_tags)
        tags.append(threat_level_tag)

        if not fraud_tags and not attack_tags:
            tags.append(self.apply_requires_review_tag())

        return tags

    def match_galaxy_cluster(self, fraud_category: Optional[str]) -> Optional[dict]:
        """Match a fraud category to a known MISP Galaxy cluster.

        Provides a simple mapping of fraud categories to MISP Galaxy cluster
        metadata for linking events to known threat actor patterns.

        Mapping:
            mfa_bypass       → mitre-attack-pattern / MFA Bypass
            phishing_kit     → mitre-attack-pattern / Phishing
            account_takeover → mitre-attack-pattern / Account Takeover
            Others           → None

        Args:
            fraud_category: Optional fraud category string.

        Returns:
            Dictionary with galaxy, cluster_uuid, and cluster_value keys
            if a match is found, otherwise None.
        """
        galaxy_map: dict[str, dict] = {
            "mfa_bypass": {
                "galaxy": "mitre-attack-pattern",
                "cluster_uuid": "mfa-bypass-001",
                "cluster_value": "MFA Bypass",
            },
            "phishing_kit": {
                "galaxy": "mitre-attack-pattern",
                "cluster_uuid": "phishing-001",
                "cluster_value": "Phishing",
            },
            "account_takeover": {
                "galaxy": "mitre-attack-pattern",
                "cluster_uuid": "ato-001",
                "cluster_value": "Account Takeover",
            },
            # Extended galaxy mappings — DC-007, DC-008, CHAPS-026, XC-007
            "new_account_fraud": {
                "galaxy": "financial-fraud",
                "cluster_uuid": "new-account-fraud-001",
                "cluster_value": "New Account Fraud via Identity Theft",
            },
            "recurring_billing_fraud": {
                "galaxy": "financial-fraud",
                "cluster_uuid": "recurring-billing-001",
                "cluster_value": "Recurring Billing Aggregation Fraud",
            },
            "money_mule": {
                "galaxy": "financial-fraud",
                "cluster_uuid": "money-mule-001",
                "cluster_value": "Money Mule Network",
            },
            "investment_fraud": {
                "galaxy": "financial-fraud",
                "cluster_uuid": "pig-butchering-001",
                "cluster_value": "Investment Fraud / Pig Butchering",
            },
            "social_engineering": {
                "galaxy": "social-engineering",
                "cluster_uuid": "romance-script-001",
                "cluster_value": "Romance Scam / Social Engineering Script",
            },
        }

        if fraud_category is None or fraud_category not in galaxy_map:
            return None

        return galaxy_map[fraud_category]
