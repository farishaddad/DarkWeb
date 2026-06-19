"""Data Structurer agent for STIX 2.1 object creation.

This module implements the Data Structurer agent responsible for converting
classified entities from the Content Analyst into valid STIX 2.1 objects:
- SDOs (Domain Objects): Threat Actor, Attack Pattern, Indicator, Malware
- SCOs (Cyber-observable Objects): IPv4Address, URL, EmailAddress, DomainName, Artifact
- SROs (Relationship Objects): linking Threat Actors to Attack Patterns and Indicators
- Bundles: assembling all objects into a STIX 2.1 Bundle

Uses the `stix2` (cti-python-stix2) library for schema-validated object construction.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Optional

import boto3
import stix2

from dark_web_fraud_agent.models.content_analyst import ClassifiedContent, ExtractedEntity
from dark_web_fraud_agent.models.shared import IntelligenceTier, TierLink


@dataclass
class StructurerConfig:
    """Configuration for the Data Structurer agent.

    Attributes:
        opensearch_endpoint: OpenSearch Serverless VECTORSEARCH endpoint.
        opensearch_collection_name: Name of the OpenSearch collection.
        misp_url: URL of the MISP instance.
        misp_secret_arn: AWS Secrets Manager ARN for MISP API key.
        bedrock_embedding_model_id: Bedrock model ID for vector embeddings.
        s3_bucket: S3 bucket for artifact storage.
    """

    opensearch_endpoint: str
    opensearch_collection_name: str
    misp_url: str
    misp_secret_arn: str
    bedrock_embedding_model_id: str
    s3_bucket: str


# Mapping from entity_type to the appropriate STIX SDO creation logic
_SDO_CATEGORY_MAP = {
    "bank_name": "threat-actor",
    "fraud_technique": "attack-pattern",
}

# Mapping from fraud categories to SDO types
_FRAUD_CATEGORY_TO_SDO = {
    "mfa_bypass": "attack-pattern",
    "synthetic_identity": "attack-pattern",
    "phishing_kit": "attack-pattern",
    "cnp_fraud": "attack-pattern",
    "account_takeover": "attack-pattern",
}


class DataStructurer:
    """Data Structurer agent for STIX 2.1 object creation and intelligence structuring.

    Converts classified entities into valid STIX 2.1 objects, manages intelligence
    tier classification, and produces schema-validated Bundles for downstream consumers.
    """

    def __init__(self, config: Optional[StructurerConfig] = None) -> None:
        """Initialize the Data Structurer.

        Args:
            config: Optional configuration for OpenSearch, MISP, and S3 integration.
        """
        self._config = config
        self._opensearch_client = None
        self._bedrock_client = None

    def create_stix_sdo(
        self, entity: ExtractedEntity, category: str
    ) -> stix2.v21.sdo.ThreatActor | stix2.v21.sdo.AttackPattern | stix2.v21.sdo.Indicator | stix2.v21.sdo.Malware:
        """Create a STIX 2.1 Domain Object (SDO) from an extracted entity.

        Maps entities to the appropriate STIX SDO type based on entity_type and category:
        - bank_name / threat actor reference → ThreatActor
        - fraud technique / attack description → AttackPattern
        - detection pattern → Indicator (with STIX pattern)
        - malware reference → Malware

        Args:
            entity: The extracted entity from content analysis.
            category: The fraud category or SDO type hint. Valid values include:
                "threat-actor", "attack-pattern", "indicator", "malware",
                or fraud categories like "mfa_bypass", "account_takeover", etc.

        Returns:
            A STIX 2.1 SDO (ThreatActor, AttackPattern, Indicator, or Malware).

        Raises:
            ValueError: If the category cannot be mapped to a valid SDO type.
        """
        # Resolve the target SDO type
        sdo_type = self._resolve_sdo_type(entity, category)

        if sdo_type == "threat-actor":
            return self._create_threat_actor(entity)
        elif sdo_type == "attack-pattern":
            return self._create_attack_pattern(entity, category)
        elif sdo_type == "indicator":
            return self._create_indicator(entity)
        elif sdo_type == "malware":
            return self._create_malware(entity)
        else:
            raise ValueError(
                f"Cannot map entity_type='{entity.entity_type}' with category='{category}' "
                f"to a valid STIX SDO type. Valid SDO types: threat-actor, attack-pattern, "
                f"indicator, malware."
            )

    def create_stix_sco(self, entity: ExtractedEntity) -> stix2.v21._Observable:
        """Create a STIX 2.1 Cyber-observable Object (SCO) from an extracted entity.

        Maps entities to the appropriate STIX SCO type based on entity_type:
        - ip_address → IPv4Address
        - url → URL
        - email → EmailAddress
        - btc_wallet → Artifact (with custom payload description)
        - domain_name → DomainName (if entity_type extended in future)

        For URL entities that look like domain names (no scheme), creates a DomainName.

        Args:
            entity: The extracted entity from content analysis.

        Returns:
            A STIX 2.1 SCO object.

        Raises:
            ValueError: If the entity type cannot be mapped to a valid SCO type.
        """
        if entity.entity_type == "ip_address":
            return stix2.IPv4Address(value=entity.value)
        elif entity.entity_type == "url":
            return self._create_url_or_domain(entity)
        elif entity.entity_type == "email":
            return stix2.EmailAddress(value=entity.value)
        elif entity.entity_type == "btc_wallet":
            return self._create_btc_artifact(entity)
        else:
            raise ValueError(
                f"Cannot map entity_type='{entity.entity_type}' to a STIX SCO. "
                f"Supported types: ip_address, url, email, btc_wallet."
            )

    def create_stix_relationship(
        self, source_id: str, target_id: str, rel_type: str
    ) -> stix2.Relationship:
        """Create a STIX 2.1 Relationship Object (SRO) linking two STIX objects.

        Common relationship types for this system:
        - "uses": Threat Actor uses Attack Pattern
        - "indicates": Indicator indicates Attack Pattern or Threat Actor
        - "attributed-to": Attack Pattern attributed-to Threat Actor
        - "targets": Threat Actor targets a sector/institution

        Args:
            source_id: The STIX ID of the source object (e.g., "threat-actor--uuid").
            target_id: The STIX ID of the target object (e.g., "attack-pattern--uuid").
            rel_type: The relationship type string (e.g., "uses", "indicates").

        Returns:
            A STIX 2.1 Relationship object.
        """
        return stix2.Relationship(
            source_ref=source_id,
            target_ref=target_id,
            relationship_type=rel_type,
        )

    def build_bundle(self, objects: list) -> stix2.Bundle:
        """Assemble a STIX 2.1 Bundle from a collection of STIX objects.

        Creates a Bundle containing all provided SDOs, SCOs, and SROs.
        The Bundle is schema-validated by the stix2 library on creation.

        Args:
            objects: List of STIX 2.1 objects (SDOs, SCOs, SROs) to include.

        Returns:
            A STIX 2.1 Bundle containing all provided objects.

        Raises:
            ValueError: If objects list is empty.
        """
        if not objects:
            raise ValueError("Cannot build a Bundle with an empty objects list.")

        return stix2.Bundle(objects=objects)

    def serialize_bundle(self, bundle: stix2.Bundle) -> str:
        """Serialize a STIX 2.1 Bundle to a JSON string.

        Uses the stix2 library's built-in serialization to produce JSON conforming
        to the STIX 2.1 JSON serialization format.

        Args:
            bundle: A STIX 2.1 Bundle to serialize.

        Returns:
            A JSON string representation of the Bundle.

        Raises:
            ValueError: If the serialized output is not valid JSON.
        """
        import json

        json_str = bundle.serialize()

        # Validate the output is valid JSON
        try:
            json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Serialized bundle is not valid JSON: {e}") from e

        return json_str

    def deserialize_bundle(self, json_str: str) -> stix2.Bundle:
        """Deserialize a JSON string into a STIX 2.1 Bundle.

        Parses JSON back into a stix2.Bundle using stix2.parse(), reconstructing
        all objects and relationships with their original references intact.

        Args:
            json_str: A JSON string conforming to the STIX 2.1 format.

        Returns:
            A STIX 2.1 Bundle with all objects and relationships reconstructed.

        Raises:
            ValueError: If the JSON string is invalid or does not represent a valid STIX Bundle.
        """
        import json

        # Validate input is valid JSON first
        try:
            json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON input: {e}") from e

        try:
            bundle = stix2.parse(json_str, allow_custom=True)
        except Exception as e:
            raise ValueError(f"Failed to parse STIX Bundle: {e}") from e

        if not isinstance(bundle, stix2.Bundle):
            raise ValueError(
                f"Parsed object is not a STIX Bundle, got type: {type(bundle).__name__}"
            )

        return bundle

    # --- Intelligence Tier Classification ---

    # Entity types that represent purely atomic observables
    _ATOMIC_ENTITY_TYPES = {"ip_address", "url", "email", "btc_wallet"}

    # Fraud categories that describe TTP-level methodology
    _TTP_CATEGORIES = {"mfa_bypass", "synthetic_identity", "phishing_kit", "account_takeover"}

    # Fraud categories that describe indicator-level patterns
    _INDICATOR_CATEGORIES = {"cnp_fraud"}

    def classify_tier(self, content: ClassifiedContent) -> IntelligenceTier:
        """Classify content into an intelligence tier based on its characteristics.

        Classification logic:
        - OBSERVABLE: Content contains only atomic data points (IPs, URLs, emails,
          wallets, hashes) with no behavioral context or fraud category.
        - INDICATOR: Content describes a specific attack pattern with indicators,
          or combines multiple observables with temporal/logical context.
        - TTP: Content describes adversarial behavior methodology (techniques,
          procedures, bypass methods) — maps to MITRE ATT&CK/F3 techniques.

        Args:
            content: The classified content from the Content Analyst.

        Returns:
            The appropriate IntelligenceTier for the content.
        """
        # Check if content describes TTP-level behavior
        if self._is_ttp(content):
            return IntelligenceTier.TTP

        # Check if content describes an indicator-level pattern
        if self._is_indicator(content):
            return IntelligenceTier.INDICATOR

        # Default: atomic observables for blocking
        return IntelligenceTier.OBSERVABLE

    def create_tier_links(
        self, items: list[tuple[str, IntelligenceTier]]
    ) -> list[TierLink]:
        """Create referential links between intelligence items across tiers.

        Establishes the referential chain:
        - Observable → Indicator via "supports" relationship
        - Indicator → TTP via "implements" relationship

        This allows any Observable to trace back to its parent Indicator
        and the TTP it supports.

        Args:
            items: List of (item_id, tier) tuples representing classified items.

        Returns:
            List of TierLink objects connecting items across tiers.
        """
        links: list[TierLink] = []

        # Separate items by tier
        observables = [(id_, tier) for id_, tier in items if tier == IntelligenceTier.OBSERVABLE]
        indicators = [(id_, tier) for id_, tier in items if tier == IntelligenceTier.INDICATOR]
        ttps = [(id_, tier) for id_, tier in items if tier == IntelligenceTier.TTP]

        # Link Observables → Indicators (each observable "supports" each indicator)
        for obs_id, obs_tier in observables:
            for ind_id, ind_tier in indicators:
                links.append(
                    TierLink(
                        source_id=obs_id,
                        source_tier=obs_tier,
                        target_id=ind_id,
                        target_tier=ind_tier,
                        relationship_type="supports",
                    )
                )

        # Link Indicators → TTPs (each indicator "implements" each TTP)
        for ind_id, ind_tier in indicators:
            for ttp_id, ttp_tier in ttps:
                links.append(
                    TierLink(
                        source_id=ind_id,
                        source_tier=ind_tier,
                        target_id=ttp_id,
                        target_tier=ttp_tier,
                        relationship_type="implements",
                    )
                )

        return links

    def _is_ttp(self, content: ClassifiedContent) -> bool:
        """Determine if content represents a TTP (technique/procedure).

        TTP classification criteria:
        - Has a fraud_category that maps to technique methodology
        - Contains high-severity behavioral descriptions
        - Describes adversarial methodology rather than just data points

        Args:
            content: The classified content.

        Returns:
            True if the content is TTP-level intelligence.
        """
        # If the fraud category describes a technique/procedure methodology
        if content.fraud_category in self._TTP_CATEGORIES:
            return True

        # High severity with behavioral context and no purely-atomic entities
        # indicates strategic behavior description
        if content.severity_score >= 8 and content.fraud_category is not None:
            entity_types = {e.entity_type for e in content.entities}
            # If there are non-atomic entities or no entities at all (pure technique desc)
            if not entity_types or not entity_types.issubset(self._ATOMIC_ENTITY_TYPES):
                return True

        return False

    def _is_indicator(self, content: ClassifiedContent) -> bool:
        """Determine if content represents an Indicator (composite attack pattern).

        Indicator classification criteria:
        - Has a fraud_category indicating a specific pattern (e.g., cnp_fraud)
        - Contains multiple entity types suggesting a composite pattern
        - Describes attack patterns with specific indicators

        Args:
            content: The classified content.

        Returns:
            True if the content is Indicator-level intelligence.
        """
        # Explicit indicator-level fraud category
        if content.fraud_category in self._INDICATOR_CATEGORIES:
            return True

        # Multiple diverse entity types suggest a composite pattern
        if len(content.entities) >= 2:
            entity_types = {e.entity_type for e in content.entities}
            # If there are multiple different entity types, it's a composite pattern
            if len(entity_types) >= 2:
                return True

        # Medium-high severity with entities and some behavioral context
        if (
            content.severity_score >= 5
            and content.entities
            and content.fraud_category is not None
            and content.fraud_category not in self._TTP_CATEGORIES
        ):
            return True

        return False

    # --- Private helper methods ---

    def _resolve_sdo_type(self, entity: ExtractedEntity, category: str) -> str:
        """Resolve the target SDO type from entity and category.

        Priority:
        1. Direct category specification ("threat-actor", "attack-pattern", etc.)
        2. Fraud category mapping (e.g., "mfa_bypass" → "attack-pattern")
        3. Entity type mapping (e.g., "bank_name" → "threat-actor")

        Args:
            entity: The extracted entity.
            category: The category hint.

        Returns:
            The resolved STIX SDO type string.
        """
        # Direct SDO type specification
        direct_types = {"threat-actor", "attack-pattern", "indicator", "malware"}
        if category in direct_types:
            return category

        # Fraud category mapping
        if category in _FRAUD_CATEGORY_TO_SDO:
            return _FRAUD_CATEGORY_TO_SDO[category]

        # Entity type mapping
        if entity.entity_type in _SDO_CATEGORY_MAP:
            return _SDO_CATEGORY_MAP[entity.entity_type]

        # Default: use entity_type heuristics
        if entity.entity_type in {"url", "ip_address", "email", "btc_wallet"}:
            return "indicator"

        raise ValueError(
            f"Cannot resolve SDO type for entity_type='{entity.entity_type}', category='{category}'"
        )

    def _create_threat_actor(self, entity: ExtractedEntity) -> stix2.v21.sdo.ThreatActor:
        """Create a STIX ThreatActor SDO from an entity.

        Args:
            entity: Entity representing a threat actor (typically bank_name or actor handle).

        Returns:
            A STIX 2.1 ThreatActor object.
        """
        return stix2.ThreatActor(
            name=entity.value,
            description=f"Threat actor identified from dark web content: {entity.context[:200]}" if entity.context else f"Threat actor: {entity.value}",
            threat_actor_types=["criminal"],
            confidence=int(entity.confidence * 100),
        )

    def _create_attack_pattern(
        self, entity: ExtractedEntity, category: str
    ) -> stix2.v21.sdo.AttackPattern:
        """Create a STIX AttackPattern SDO from an entity.

        Args:
            entity: Entity representing a fraud technique or attack method.
            category: The fraud category for additional context.

        Returns:
            A STIX 2.1 AttackPattern object.
        """
        description = entity.context[:500] if entity.context else f"Attack pattern: {entity.value}"
        name = entity.value

        return stix2.AttackPattern(
            name=name,
            description=f"[{category}] {description}",
        )

    def _create_indicator(self, entity: ExtractedEntity) -> stix2.v21.sdo.Indicator:
        """Create a STIX Indicator SDO from an entity.

        Generates a STIX pattern expression based on the entity type.

        Args:
            entity: Entity representing a detection pattern or observable indicator.

        Returns:
            A STIX 2.1 Indicator object.
        """
        pattern = self._generate_stix_pattern(entity)

        return stix2.Indicator(
            name=f"Indicator: {entity.value}",
            description=f"Detection indicator from dark web intelligence: {entity.context[:200]}" if entity.context else f"Indicator for {entity.entity_type}: {entity.value}",
            pattern=pattern,
            pattern_type="stix",
            valid_from="2024-01-01T00:00:00Z",
        )

    def _create_malware(self, entity: ExtractedEntity) -> stix2.v21.sdo.Malware:
        """Create a STIX Malware SDO from an entity.

        Args:
            entity: Entity representing a malware reference.

        Returns:
            A STIX 2.1 Malware object.
        """
        return stix2.Malware(
            name=entity.value,
            description=f"Malware identified from dark web content: {entity.context[:200]}" if entity.context else f"Malware: {entity.value}",
            malware_types=["trojan"],
            is_family=False,
        )

    def _create_url_or_domain(self, entity: ExtractedEntity) -> stix2.v21._Observable:
        """Create a URL SCO or DomainName SCO depending on the value.

        If the value starts with http:// or https://, creates a URL.
        If it ends with .onion or looks like a domain, creates a DomainName.
        Otherwise defaults to URL.

        Args:
            entity: Entity with type "url".

        Returns:
            A STIX URL or DomainName SCO.
        """
        value = entity.value.strip()

        # If it looks like a domain (no scheme, has dots, or is .onion)
        if not value.startswith(("http://", "https://")) and "." in value:
            return stix2.DomainName(value=value)

        return stix2.URL(value=value)

    def _create_btc_artifact(self, entity: ExtractedEntity) -> stix2.v21.observables.Artifact:
        """Create a STIX Artifact SCO for a Bitcoin wallet address.

        STIX 2.1 doesn't have a native cryptocurrency observable type,
        so we use Artifact with a custom payload description to represent
        BTC wallet addresses.

        Args:
            entity: Entity representing a BTC wallet address.

        Returns:
            A STIX 2.1 Artifact object representing the BTC wallet.
        """
        # Use Artifact with mime_type to indicate cryptocurrency address
        return stix2.Artifact(
            mime_type="application/x-bitcoin-address",
            payload_bin=entity.value.encode("utf-8").hex(),
        )

    def _generate_stix_pattern(self, entity: ExtractedEntity) -> str:
        """Generate a STIX pattern expression for an entity.

        Maps entity types to STIX Cyber-observable patterns:
        - ip_address → [ipv4-addr:value = '<value>']
        - url → [url:value = '<value>']
        - email → [email-addr:value = '<value>']
        - btc_wallet → [artifact:payload_bin = '<hex_encoded>']
        - Others → [artifact:payload_bin = '<hex_encoded>']

        Args:
            entity: The entity to generate a pattern for.

        Returns:
            A valid STIX pattern expression string.
        """
        value = entity.value.replace("'", "\\'")

        if entity.entity_type == "ip_address":
            return f"[ipv4-addr:value = '{value}']"
        elif entity.entity_type == "url":
            return f"[url:value = '{value}']"
        elif entity.entity_type == "email":
            return f"[email-addr:value = '{value}']"
        elif entity.entity_type == "btc_wallet":
            hex_value = entity.value.encode("utf-8").hex()
            return f"[artifact:payload_bin = '{hex_value}']"
        else:
            # Generic pattern for other entity types
            hex_value = entity.value.encode("utf-8").hex()
            return f"[artifact:payload_bin = '{hex_value}']"

    # --- OpenSearch Serverless Vector Indexing ---

    async def index_to_opensearch(self, bundle: stix2.Bundle, metadata: dict) -> list[str]:
        """Index STIX objects into OpenSearch Serverless VECTORSEARCH collection.

        Generates embeddings via Bedrock and indexes each STIX object with
        metadata into the VECTORSEARCH collection for similarity search.

        Args:
            bundle: STIX 2.1 Bundle to index.
            metadata: Additional metadata (tier, severity, fraud_category, tags).

        Returns:
            List of OpenSearch document IDs for indexed objects.
        """
        if self._opensearch_client is None:
            self._opensearch_client = self._create_opensearch_client()

        doc_ids = []
        for obj in bundle.objects:
            doc = {
                "stix_id": obj.id,
                "stix_type": obj.type,
                "tier": metadata.get("tier", "observable"),
                "severity_score": metadata.get("severity_score", 1),
                "confidence": metadata.get("confidence", 0.0),
                "fraud_category": metadata.get("fraud_category"),
                "content_summary": self._get_object_summary(obj),
                "created_at": datetime.now(UTC).isoformat(),
                "intelligence_vector": await self._generate_embedding(obj),
            }

            response = self._opensearch_client.index(
                index=self._config.opensearch_collection_name if self._config else "threat-intel",
                body=doc,
            )
            doc_ids.append(response["_id"])

        return doc_ids

    async def _generate_embedding(self, stix_obj) -> list[float]:
        """Generate vector embedding for a STIX object using Bedrock."""
        if self._bedrock_client is None:
            self._bedrock_client = boto3.client("bedrock-runtime")

        text = self._get_object_summary(stix_obj)
        response = self._bedrock_client.invoke_model(
            modelId=self._config.bedrock_embedding_model_id if self._config else "amazon.titan-embed-text-v2:0",
            body=json.dumps({"inputText": text}),
            contentType="application/json",
        )
        result = json.loads(response["body"].read())
        return result["embedding"]

    def _get_object_summary(self, stix_obj) -> str:
        """Get a text summary of a STIX object for embedding."""
        parts = [f"Type: {stix_obj.type}"]
        if hasattr(stix_obj, "name"):
            parts.append(f"Name: {stix_obj.name}")
        if hasattr(stix_obj, "description"):
            parts.append(f"Description: {stix_obj.description}")
        if hasattr(stix_obj, "value"):
            parts.append(f"Value: {stix_obj.value}")
        return " | ".join(parts)

    def _create_opensearch_client(self):
        """Create OpenSearch client for the VECTORSEARCH collection."""
        from opensearchpy import OpenSearch, RequestsHttpConnection
        from requests_aws4auth import AWS4Auth

        credentials = boto3.Session().get_credentials()
        region = self._config.opensearch_endpoint.split(".")[1] if self._config else "us-east-1"
        awsauth = AWS4Auth(
            credentials.access_key,
            credentials.secret_key,
            region,
            "aoss",
            session_token=credentials.token,
        )

        return OpenSearch(
            hosts=[{"host": self._config.opensearch_endpoint.replace("https://", ""), "port": 443}],
            http_auth=awsauth,
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
        )
