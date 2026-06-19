"""Tagging Engine agent for automated intelligence classification."""

import json
from dataclasses import dataclass, field
from typing import Optional

from dark_web_fraud_agent.models.content_analyst import ExtractedEntity
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
            "mfa_bypass": "T1111",
            "phishing_kit": "T1566",
            "account_takeover": "T1110",
            "synthetic_identity": "T1583",
            "cnp_fraud": "T1499",
        }

        if fraud_category is None or fraud_category not in attack_map:
            return []

        technique_id = attack_map[fraud_category]
        return [MachineTag("mitre-attack", "technique", technique_id)]

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
        }

        if fraud_category is None or fraud_category not in galaxy_map:
            return None

        return galaxy_map[fraud_category]
