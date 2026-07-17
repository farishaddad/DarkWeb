

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
    # Input validation
    if not isinstance(event, dict):
        raise ValueError(f"Expected dict event, got {type(event).__name__}")
    missing = [f for f in ["s3_key"] if f not in event]
    if missing:
        raise ValueError(f"Missing required fields: {missing}")

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

    # Apply all tag sets using the new tag() orchestration method
    tag_result = engine.tag(
        entities=[],
        fraud_category=fraud_category,
        severity=severity_score,
    )
    all_tags = tag_result["tags"]
    galaxy_match = tag_result["galaxy_match"]

    tag_strings = [str(t) for t in all_tags]

    # Write tag manifest to S3 alongside the STIX bundle
    s3 = boto3.client("s3")
    tag_manifest_key = stix_bundle_key.replace(".stix.json", ".tags.json")
    s3.put_object(
        Bucket=s3_bucket,
        Key=tag_manifest_key,
        Body=json.dumps({
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
import json
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

        Supports two formats:
        1. Inline entries: predicates contain an "entries" list directly.
        2. MISP format: a top-level "values" array maps entries to predicates
           via a "predicate" key, with entries under an "entry" list.

        Args:
            taxonomy_json: JSON string containing taxonomy definition with
                namespace, predicates, and optional entries/values.

        Returns:
            The parsed TaxonomyDefinition.

        Raises:
            ValueError: If JSON is invalid or required fields are missing.
        """
        try:
            data = json.loads(taxonomy_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid taxonomy JSON: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("Taxonomy JSON must be an object")
        if "namespace" not in data:
            raise ValueError("Taxonomy must have 'namespace' field")
        if "predicates" not in data or not isinstance(data["predicates"], list):
            raise ValueError("Taxonomy must have 'predicates' list")

        # Build a map of predicate value -> entries from the "values" array (MISP format)
        values_map: dict[str, list[TaxonomyEntry]] = {}
        if "values" in data:
            if not isinstance(data["values"], list):
                raise ValueError("Taxonomy 'values' must be a list")
            for values_block in data["values"]:
                if not isinstance(values_block, dict):
                    raise ValueError("Each item in 'values' must be an object")
                pred_ref = values_block.get("predicate")
                if not pred_ref:
                    raise ValueError("Each 'values' item must have a 'predicate' field")
                entries_data = values_block.get("entry", [])
                if not isinstance(entries_data, list):
                    raise ValueError("'entry' in values must be a list")
                entries: list[TaxonomyEntry] = []
                for entry_data in entries_data:
                    if "value" not in entry_data or "expanded" not in entry_data:
                        raise ValueError("Each entry must have 'value' and 'expanded'")
                    entries.append(
                        TaxonomyEntry(value=entry_data["value"], expanded=entry_data["expanded"])
                    )
                values_map[pred_ref] = entries

        predicates: list[TaxonomyPredicate] = []
        for pred_data in data["predicates"]:
            if "value" not in pred_data or "expanded" not in pred_data:
                raise ValueError("Each predicate must have 'value' and 'expanded'")
            # Entries can come from inline "entries" or from the top-level "values" array
            entries: list[TaxonomyEntry] = []
            for entry_data in pred_data.get("entries", []):
                if "value" not in entry_data or "expanded" not in entry_data:
                    raise ValueError("Each entry must have 'value' and 'expanded'")
                entries.append(
                    TaxonomyEntry(value=entry_data["value"], expanded=entry_data["expanded"])
                )
            # Merge entries from MISP-format "values" array
            if pred_data["value"] in values_map:
                entries.extend(values_map[pred_data["value"]])
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
        logger.info(
            "TaggingEngine: loaded taxonomy namespace=%s with %d predicates",
            taxonomy.namespace,
            len(taxonomy.predicates),
        )
        return taxonomy

    def load_taxonomy_from_s3(
        self, s3_bucket: str, s3_key: str, s3_client=None
    ) -> TaxonomyDefinition:
        """Load a taxonomy definition from an S3 object.

        Retrieves the JSON file from S3 and delegates to load_taxonomy() for
        parsing and validation.

        Args:
            s3_bucket: S3 bucket containing the taxonomy file.
            s3_key: S3 key of the taxonomy JSON file.
            s3_client: Optional boto3 S3 client (created if not provided).

        Returns:
            The parsed TaxonomyDefinition.

        Raises:
            RuntimeError: If S3 retrieval fails.
            ValueError: If taxonomy JSON is invalid.
        """
        if s3_client is None:
            s3_client = boto3.client("s3")

        try:
            response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
            taxonomy_json = response["Body"].read().decode("utf-8")
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load taxonomy from s3://{s3_bucket}/{s3_key}: {exc}"
            ) from exc

        return self.load_taxonomy(taxonomy_json)

    def load_taxonomies_from_s3_prefix(
        self, s3_bucket: str, s3_prefix: str, s3_client=None
    ) -> list[TaxonomyDefinition]:
        """Load all taxonomy JSON files under an S3 prefix.

        Lists all objects under the prefix and loads each one that ends with .json.

        Args:
            s3_bucket: S3 bucket containing the taxonomy files.
            s3_prefix: S3 prefix under which taxonomy JSON files reside.
            s3_client: Optional boto3 S3 client (created if not provided).

        Returns:
            List of loaded TaxonomyDefinition objects.

        Raises:
            RuntimeError: If S3 listing fails.
        """
        if s3_client is None:
            s3_client = boto3.client("s3")

        try:
            response = s3_client.list_objects_v2(Bucket=s3_bucket, Prefix=s3_prefix)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to list taxonomy files at s3://{s3_bucket}/{s3_prefix}: {exc}"
            ) from exc

        loaded: list[TaxonomyDefinition] = []
        for obj in response.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".json"):
                continue
            try:
                taxonomy = self.load_taxonomy_from_s3(s3_bucket, key, s3_client=s3_client)
                loaded.append(taxonomy)
            except (ValueError, RuntimeError) as exc:
                logger.warning(
                    "TaggingEngine: skipping invalid taxonomy at s3://%s/%s: %s",
                    s3_bucket, key, exc,
                )

        logger.info(
            "TaggingEngine: loaded %d taxonomies from s3://%s/%s",
            len(loaded), s3_bucket, s3_prefix,
        )
        return loaded

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

    def match_galaxy_cluster(
        self,
        fraud_category: str | None,
        *,
        knowledge_base_id: str | None = None,
        bedrock_client=None,
    ) -> dict | None:
        """Match a fraud category to a MISP Galaxy cluster via Knowledge Base query.

        First queries the AgentCore Managed Knowledge Base (Bedrock Agent Runtime
        Agentic Retriever) for threat actor matching against the fraud category.
        Falls back to a static mapping if the Knowledge Base is unavailable or
        returns no results.

        When a match is found, the event is linked to the corresponding MISP
        Galaxy cluster.

        Args:
            fraud_category: Optional fraud category string to match.
            knowledge_base_id: AgentCore Knowledge Base ID. If None, reads from
                KNOWLEDGE_BASE_ID env var or skips KB query.
            bedrock_client: Optional boto3 bedrock-agent-runtime client
                (created if not provided).

        Returns:
            Dictionary with galaxy, cluster_uuid, cluster_value, and source keys
            if a match is found, otherwise None.
        """
        if fraud_category is None or fraud_category == "":
            return None

        # Attempt Knowledge Base query first
        kb_result = self._query_knowledge_base(
            fraud_category,
            knowledge_base_id=knowledge_base_id,
            bedrock_client=bedrock_client,
        )
        if kb_result is not None:
            return kb_result

        # Fallback to static galaxy mapping
        return self._static_galaxy_lookup(fraud_category)

    def _query_knowledge_base(
        self,
        fraud_category: str,
        *,
        knowledge_base_id: str | None = None,
        bedrock_client=None,
    ) -> dict | None:
        """Query AgentCore Knowledge Base for threat actor matching.

        Uses the Bedrock Agent Runtime retrieve API to search for galaxy
        cluster matches related to the given fraud category.

        Args:
            fraud_category: The fraud category to search for.
            knowledge_base_id: Knowledge Base ID override.
            bedrock_client: Optional boto3 bedrock-agent-runtime client.

        Returns:
            Dict with galaxy cluster info if KB returns a confident match,
            otherwise None.
        """
        kb_id = knowledge_base_id or os.environ.get("KNOWLEDGE_BASE_ID")
        if not kb_id:
            logger.debug(
                "TaggingEngine: no knowledge_base_id configured, skipping KB query"
            )
            return None

        if bedrock_client is None:
            bedrock_client = boto3.client("bedrock-agent-runtime")

        query_text = (
            f"MISP Galaxy cluster for threat actor profile matching "
            f"fraud category: {fraud_category}"
        )

        try:
            response = bedrock_client.retrieve(
                knowledgeBaseId=kb_id,
                retrievalQuery={"text": query_text},
                retrievalConfiguration={
                    "vectorSearchConfiguration": {
                        "numberOfResults": 3,
                    }
                },
            )
        except Exception as exc:
            logger.warning(
                "TaggingEngine: Knowledge Base query failed for category=%s: %s",
                fraud_category,
                exc,
            )
            return None

        results = response.get("retrievalResults", [])
        if not results:
            logger.debug(
                "TaggingEngine: no KB results for category=%s", fraud_category
            )
            return None

        # Parse the top result for galaxy cluster information
        top_result = results[0]
        content = top_result.get("content", {}).get("text", "")
        score = top_result.get("score", 0.0)

        # Require a minimum relevance score to trust the KB result
        if score < 0.5:
            logger.debug(
                "TaggingEngine: KB result score %.2f below threshold for category=%s",
                score,
                fraud_category,
            )
            return None

        # Extract galaxy cluster metadata from the KB response content
        cluster_info = self._parse_kb_galaxy_result(content, fraud_category)
        if cluster_info:
            cluster_info["source"] = "knowledge_base"
            logger.info(
                "TaggingEngine: KB matched galaxy cluster=%s for category=%s",
                cluster_info.get("cluster_value"),
                fraud_category,
            )
        return cluster_info

    def _parse_kb_galaxy_result(self, content: str, fraud_category: str) -> dict | None:
        """Parse Knowledge Base retrieval result into galaxy cluster metadata.

        Attempts to parse JSON from the KB result content. If the content
        contains valid galaxy cluster fields, returns the structured metadata.

        Args:
            content: Text content returned by the Knowledge Base.
            fraud_category: The fraud category for context.

        Returns:
            Dict with galaxy, cluster_uuid, and cluster_value if parseable,
            otherwise None.
        """
        # Try JSON parsing first (KB may store structured galaxy data)
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                galaxy = data.get("galaxy")
                cluster_uuid = data.get("cluster_uuid")
                cluster_value = data.get("cluster_value")
                if galaxy and cluster_uuid and cluster_value:
                    return {
                        "galaxy": galaxy,
                        "cluster_uuid": cluster_uuid,
                        "cluster_value": cluster_value,
                    }
        except (json.JSONDecodeError, TypeError):
            pass

        # If content is unstructured text, attempt keyword extraction
        if "galaxy" in content.lower() and "cluster" in content.lower():
            return {
                "galaxy": "threat-actor",
                "cluster_uuid": f"kb-{fraud_category}-001",
                "cluster_value": content[:100].strip(),
            }

        return None

    def _static_galaxy_lookup(self, fraud_category: str) -> dict | None:
        """Static fallback mapping of fraud categories to MISP Galaxy clusters.

        Used when the Knowledge Base is unavailable or returns no matches.

        Args:
            fraud_category: The fraud category to look up.

        Returns:
            Dict with galaxy, cluster_uuid, cluster_value, and source keys,
            or None if no static mapping exists.
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

        if fraud_category not in galaxy_map:
            return None

        result = galaxy_map[fraud_category].copy()
        result["source"] = "static"
        return result

    def tag(
        self,
        entities: list[ExtractedEntity],
        fraud_category: str | None,
        severity: int,
        *,
        knowledge_base_id: str | None = None,
        bedrock_client=None,
    ) -> dict:
        """Orchestrate all tagging steps for an event.

        Executes the full tagging pipeline:
        1. apply_attack_tags() — MITRE ATT&CK technique mapping
        2. apply_fraud_tags() — banking keyword-based fraud tags
        3. match_galaxy_cluster() — Knowledge Base + static galaxy matching
        4. apply_threat_level_tag() — severity-to-threat-level mapping
        5. Fallback: apply workflow:status="requires-review" if no taxonomy match

        Args:
            entities: List of extracted entities from the content.
            fraud_category: Optional fraud category string from classification.
            severity: Integer severity score from 1 to 10.
            knowledge_base_id: Optional Knowledge Base ID for galaxy matching.
            bedrock_client: Optional boto3 bedrock-agent-runtime client.

        Returns:
            Dict containing:
                - tags: list[MachineTag] — all applied tags
                - galaxy_match: dict | None — galaxy cluster match result
        """
        attack_tags = self.apply_attack_tags(fraud_category)
        fraud_tags = self.apply_fraud_tags(entities)
        galaxy_match = self.match_galaxy_cluster(
            fraud_category,
            knowledge_base_id=knowledge_base_id,
            bedrock_client=bedrock_client,
        )
        threat_level_tag = self.apply_threat_level_tag(severity)

        all_tags: list[MachineTag] = []
        all_tags.extend(attack_tags)
        all_tags.extend(fraud_tags)
        all_tags.append(threat_level_tag)

        # Apply galaxy cluster tag if matched
        if galaxy_match:
            all_tags.append(
                MachineTag(
                    namespace="misp-galaxy",
                    predicate=galaxy_match["galaxy"],
                    value=galaxy_match["cluster_value"],
                )
            )

        # Fallback: if no taxonomy predicate matched, apply requires-review
        if not attack_tags and not fraud_tags and galaxy_match is None:
            all_tags.append(
                MachineTag(
                    namespace="workflow",
                    predicate="status",
                    value="requires-review",
                )
            )
            logger.info(
                "TaggingEngine: no taxonomy match for category=%s, "
                "applied workflow:status=requires-review",
                fraud_category,
            )

        return {
            "tags": all_tags,
            "galaxy_match": galaxy_match,
        }
