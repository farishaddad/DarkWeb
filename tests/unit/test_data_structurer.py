"""Unit tests for the Data Structurer agent STIX 2.1 object creation.

Tests verify that:
- SDOs are created with correct types and valid properties
- SCOs are created with valid observable values
- Relationships link objects correctly
- Bundles pass STIX 2.1 schema validation
"""

import json

import pytest
import stix2

from dark_web_fraud_agent.agents.data_structurer import DataStructurer, StructurerConfig
from dark_web_fraud_agent.models.content_analyst import ExtractedEntity


@pytest.fixture
def structurer():
    """Create a DataStructurer instance for testing."""
    return DataStructurer()


@pytest.fixture
def structurer_with_config():
    """Create a DataStructurer with full configuration."""
    config = StructurerConfig(
        opensearch_endpoint="https://example.opensearch.amazonaws.com",
        opensearch_collection_name="threat-intel",
        misp_url="https://misp.example.com",
        misp_secret_arn="arn:aws:secretsmanager:us-east-1:123456789:secret:misp-key",
        bedrock_embedding_model_id="amazon.titan-embed-text-v2:0",
        s3_bucket="dark-web-artifacts",
    )
    return DataStructurer(config=config)


# --- SDO Creation Tests ---


class TestCreateStixSDO:
    """Tests for create_stix_sdo() method."""

    def test_create_threat_actor_from_bank_name(self, structurer):
        """A bank_name entity with category 'threat-actor' produces a ThreatActor SDO."""
        entity = ExtractedEntity(
            entity_type="bank_name",
            value="DarkMarketVendor42",
            context="Threat actor selling stolen credentials on dark forum",
            confidence=0.85,
        )

        result = structurer.create_stix_sdo(entity, category="threat-actor")

        assert isinstance(result, stix2.ThreatActor)
        assert result.name == "DarkMarketVendor42"
        assert "criminal" in result.threat_actor_types
        assert result.type == "threat-actor"
        # Validate confidence mapping (0.85 * 100 = 85)
        assert result.confidence == 85

    def test_create_threat_actor_from_entity_type_mapping(self, structurer):
        """A bank_name entity with a non-direct category still maps to ThreatActor via entity_type."""
        entity = ExtractedEntity(
            entity_type="bank_name",
            value="ShadowBanker",
            context="Known threat actor targeting retail banks",
            confidence=0.92,
        )

        result = structurer.create_stix_sdo(entity, category="bank_name")

        assert isinstance(result, stix2.ThreatActor)
        assert result.name == "ShadowBanker"

    def test_create_attack_pattern_from_fraud_category(self, structurer):
        """Fraud category 'mfa_bypass' produces an AttackPattern SDO."""
        entity = ExtractedEntity(
            entity_type="bank_name",
            value="MFA Bypass via SIM Swap",
            context="Technique involves social engineering telecom support to port victim number",
            confidence=0.78,
        )

        result = structurer.create_stix_sdo(entity, category="mfa_bypass")

        assert isinstance(result, stix2.AttackPattern)
        assert result.name == "MFA Bypass via SIM Swap"
        assert "[mfa_bypass]" in result.description
        assert result.type == "attack-pattern"

    def test_create_attack_pattern_direct_category(self, structurer):
        """Direct 'attack-pattern' category produces an AttackPattern SDO."""
        entity = ExtractedEntity(
            entity_type="bank_name",
            value="Credential Stuffing Attack",
            context="Automated login attempts using breached credential databases",
            confidence=0.91,
        )

        result = structurer.create_stix_sdo(entity, category="attack-pattern")

        assert isinstance(result, stix2.AttackPattern)
        assert result.name == "Credential Stuffing Attack"

    def test_create_indicator(self, structurer):
        """An entity with category 'indicator' produces an Indicator SDO with a STIX pattern."""
        entity = ExtractedEntity(
            entity_type="ip_address",
            value="192.168.1.100",
            context="C2 server IP observed in phishing campaign",
            confidence=0.95,
        )

        result = structurer.create_stix_sdo(entity, category="indicator")

        assert isinstance(result, stix2.Indicator)
        assert "192.168.1.100" in result.pattern
        assert result.pattern_type == "stix"
        assert result.type == "indicator"

    def test_create_malware(self, structurer):
        """An entity with category 'malware' produces a Malware SDO."""
        entity = ExtractedEntity(
            entity_type="bank_name",
            value="BankBot v3.2",
            context="Android banking trojan targeting major US banks",
            confidence=0.88,
        )

        result = structurer.create_stix_sdo(entity, category="malware")

        assert isinstance(result, stix2.Malware)
        assert result.name == "BankBot v3.2"
        assert result.is_family is False
        assert "trojan" in result.malware_types
        assert result.type == "malware"

    def test_create_sdo_invalid_category_raises_value_error(self, structurer):
        """An unresolvable category raises ValueError."""
        entity = ExtractedEntity(
            entity_type="bin_range",
            value="411111",
            context="BIN range for Visa cards",
            confidence=0.9,
        )

        with pytest.raises(ValueError, match="Cannot.*SDO"):
            structurer.create_stix_sdo(entity, category="unknown_category")

    def test_all_fraud_categories_map_to_attack_pattern(self, structurer):
        """All valid fraud categories map to AttackPattern."""
        fraud_categories = [
            "mfa_bypass",
            "synthetic_identity",
            "phishing_kit",
            "cnp_fraud",
            "account_takeover",
        ]

        entity = ExtractedEntity(
            entity_type="bank_name",
            value="Test Technique",
            context="Some fraud technique context",
            confidence=0.8,
        )

        for category in fraud_categories:
            result = structurer.create_stix_sdo(entity, category=category)
            assert isinstance(result, stix2.AttackPattern), f"Failed for category: {category}"


# --- SCO Creation Tests ---


class TestCreateStixSCO:
    """Tests for create_stix_sco() method."""

    def test_create_ipv4_address(self, structurer):
        """An ip_address entity produces an IPv4Address SCO."""
        entity = ExtractedEntity(
            entity_type="ip_address",
            value="10.0.0.1",
            context="Proxy server IP found in dark web post",
            confidence=0.99,
        )

        result = structurer.create_stix_sco(entity)

        assert isinstance(result, stix2.IPv4Address)
        assert result.value == "10.0.0.1"
        assert result.type == "ipv4-addr"

    def test_create_url_with_scheme(self, structurer):
        """A url entity with http scheme produces a URL SCO."""
        entity = ExtractedEntity(
            entity_type="url",
            value="http://exampleonion.onion/market",
            context="Dark web marketplace URL",
            confidence=0.97,
        )

        result = structurer.create_stix_sco(entity)

        assert isinstance(result, stix2.URL)
        assert result.value == "http://exampleonion.onion/market"
        assert result.type == "url"

    def test_create_domain_name_from_url_without_scheme(self, structurer):
        """A url entity without scheme but with dots produces a DomainName SCO."""
        entity = ExtractedEntity(
            entity_type="url",
            value="darkforum.onion",
            context="Onion domain for fraud forum",
            confidence=0.85,
        )

        result = structurer.create_stix_sco(entity)

        assert isinstance(result, stix2.DomainName)
        assert result.value == "darkforum.onion"
        assert result.type == "domain-name"

    def test_create_email_address(self, structurer):
        """An email entity produces an EmailAddress SCO."""
        entity = ExtractedEntity(
            entity_type="email",
            value="vendor@darkmail.onion",
            context="Seller contact email on marketplace",
            confidence=0.92,
        )

        result = structurer.create_stix_sco(entity)

        assert isinstance(result, stix2.EmailAddress)
        assert result.value == "vendor@darkmail.onion"
        assert result.type == "email-addr"

    def test_create_btc_wallet_artifact(self, structurer):
        """A btc_wallet entity produces an Artifact SCO with hex-encoded payload."""
        entity = ExtractedEntity(
            entity_type="btc_wallet",
            value="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            context="Bitcoin wallet receiving fraud proceeds",
            confidence=0.98,
        )

        result = structurer.create_stix_sco(entity)

        assert isinstance(result, stix2.Artifact)
        assert result.mime_type == "application/x-bitcoin-address"
        assert result.type == "artifact"
        # Verify the payload_bin contains the hex-encoded wallet address
        expected_hex = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".encode("utf-8").hex()
        assert result.payload_bin == expected_hex

    def test_create_sco_unsupported_type_raises_value_error(self, structurer):
        """An unsupported entity type raises ValueError."""
        entity = ExtractedEntity(
            entity_type="swift_code",
            value="BOFAUS3N",
            context="SWIFT code for Bank of America",
            confidence=0.95,
        )

        with pytest.raises(ValueError, match="Cannot map entity_type.*to a STIX SCO"):
            structurer.create_stix_sco(entity)


# --- Relationship Tests ---


class TestCreateStixRelationship:
    """Tests for create_stix_relationship() method."""

    def test_create_uses_relationship(self, structurer):
        """Creates a 'uses' relationship between threat actor and attack pattern."""
        # Create real STIX objects to get valid IDs
        actor = structurer.create_stix_sdo(
            ExtractedEntity(entity_type="bank_name", value="Actor1", context="ctx", confidence=0.9),
            "threat-actor",
        )
        pattern = structurer.create_stix_sdo(
            ExtractedEntity(entity_type="bank_name", value="Pattern1", context="ctx", confidence=0.8),
            "attack-pattern",
        )

        result = structurer.create_stix_relationship(actor.id, pattern.id, "uses")

        assert isinstance(result, stix2.Relationship)
        assert result.source_ref == actor.id
        assert result.target_ref == pattern.id
        assert result.relationship_type == "uses"
        assert result.type == "relationship"

    def test_create_indicates_relationship(self, structurer):
        """Creates an 'indicates' relationship between indicator and threat actor."""
        indicator = structurer.create_stix_sdo(
            ExtractedEntity(entity_type="ip_address", value="10.0.0.1", context="c2", confidence=0.95),
            "indicator",
        )
        actor = structurer.create_stix_sdo(
            ExtractedEntity(entity_type="bank_name", value="BadGuy", context="ctx", confidence=0.88),
            "threat-actor",
        )

        result = structurer.create_stix_relationship(indicator.id, actor.id, "indicates")

        assert isinstance(result, stix2.Relationship)
        assert result.relationship_type == "indicates"

    def test_create_attributed_to_relationship(self, structurer):
        """Creates an 'attributed-to' relationship."""
        pattern = structurer.create_stix_sdo(
            ExtractedEntity(entity_type="bank_name", value="ATOKit", context="ctx", confidence=0.82),
            "attack-pattern",
        )
        actor = structurer.create_stix_sdo(
            ExtractedEntity(entity_type="bank_name", value="CyberCrook", context="ctx", confidence=0.9),
            "threat-actor",
        )

        result = structurer.create_stix_relationship(pattern.id, actor.id, "attributed-to")

        assert isinstance(result, stix2.Relationship)
        assert result.relationship_type == "attributed-to"

    def test_relationship_has_valid_stix_id(self, structurer):
        """Relationship objects have valid STIX IDs."""
        actor = structurer.create_stix_sdo(
            ExtractedEntity(entity_type="bank_name", value="TestActor", context="ctx", confidence=0.9),
            "threat-actor",
        )
        pattern = structurer.create_stix_sdo(
            ExtractedEntity(entity_type="bank_name", value="TestPattern", context="ctx", confidence=0.8),
            "attack-pattern",
        )

        result = structurer.create_stix_relationship(actor.id, pattern.id, "uses")

        assert result.id.startswith("relationship--")


# --- Bundle Tests ---


class TestBuildBundle:
    """Tests for build_bundle() method."""

    def test_build_bundle_with_single_object(self, structurer):
        """Bundle can be built with a single STIX object."""
        entity = ExtractedEntity(
            entity_type="ip_address",
            value="192.168.1.1",
            context="test",
            confidence=0.9,
        )
        sco = structurer.create_stix_sco(entity)

        bundle = structurer.build_bundle([sco])

        assert isinstance(bundle, stix2.Bundle)
        assert bundle.type == "bundle"
        assert len(bundle.objects) == 1

    def test_build_bundle_with_mixed_objects(self, structurer):
        """Bundle assembles SDOs, SCOs, and SROs together."""
        # Create a threat actor
        actor_entity = ExtractedEntity(
            entity_type="bank_name",
            value="CyberCrook",
            context="Known dark web threat actor",
            confidence=0.88,
        )
        threat_actor = structurer.create_stix_sdo(actor_entity, "threat-actor")

        # Create an attack pattern
        technique_entity = ExtractedEntity(
            entity_type="bank_name",
            value="Phishing Kit v2",
            context="Advanced phishing kit targeting mobile banking",
            confidence=0.82,
        )
        attack_pattern = structurer.create_stix_sdo(technique_entity, "attack-pattern")

        # Create an SCO
        ip_entity = ExtractedEntity(
            entity_type="ip_address",
            value="10.20.30.40",
            context="C2 server",
            confidence=0.95,
        )
        ip_sco = structurer.create_stix_sco(ip_entity)

        # Create a relationship
        relationship = structurer.create_stix_relationship(
            threat_actor.id, attack_pattern.id, "uses"
        )

        # Build bundle
        bundle = structurer.build_bundle([threat_actor, attack_pattern, ip_sco, relationship])

        assert isinstance(bundle, stix2.Bundle)
        assert len(bundle.objects) == 4
        assert bundle.type == "bundle"

    def test_build_bundle_passes_stix_validation(self, structurer):
        """Bundle passes STIX 2.1 schema validation (stix2 library validates on creation)."""
        entity = ExtractedEntity(
            entity_type="bank_name",
            value="TestActor",
            context="Test context",
            confidence=0.75,
        )
        sdo = structurer.create_stix_sdo(entity, "threat-actor")
        bundle = structurer.build_bundle([sdo])

        # Serialize to JSON - stix2 validates on serialization
        json_str = bundle.serialize()
        parsed = json.loads(json_str)

        assert parsed["type"] == "bundle"
        assert "objects" in parsed
        assert len(parsed["objects"]) == 1
        assert parsed["objects"][0]["type"] == "threat-actor"

    def test_build_bundle_empty_raises_value_error(self, structurer):
        """Building a bundle with no objects raises ValueError."""
        with pytest.raises(ValueError, match="Cannot build a Bundle with an empty objects list"):
            structurer.build_bundle([])

    def test_build_bundle_serialization_is_valid_json(self, structurer):
        """Bundle serializes to valid JSON conforming to STIX 2.1 format."""
        entity = ExtractedEntity(
            entity_type="email",
            value="test@darkweb.onion",
            context="Contact email",
            confidence=0.9,
        )
        sco = structurer.create_stix_sco(entity)
        bundle = structurer.build_bundle([sco])

        json_str = bundle.serialize()
        parsed = json.loads(json_str)

        # STIX 2.1 Bundle must have these fields
        assert "type" in parsed
        assert "id" in parsed
        assert "objects" in parsed
        assert parsed["id"].startswith("bundle--")

    def test_build_bundle_full_pipeline_scenario(self, structurer):
        """End-to-end scenario: create multiple objects and assemble into bundle."""
        # Simulate a typical pipeline output
        objects = []

        # Threat Actor
        actor = structurer.create_stix_sdo(
            ExtractedEntity(
                entity_type="bank_name",
                value="FraudKing",
                context="Prolific vendor on dark web forums",
                confidence=0.9,
            ),
            "threat-actor",
        )
        objects.append(actor)

        # Attack Pattern
        technique = structurer.create_stix_sdo(
            ExtractedEntity(
                entity_type="bank_name",
                value="SIM Swap MFA Bypass",
                context="Social engineering telecom to port victim's number",
                confidence=0.85,
            ),
            "mfa_bypass",
        )
        objects.append(technique)

        # Indicator
        indicator = structurer.create_stix_sdo(
            ExtractedEntity(
                entity_type="ip_address",
                value="45.33.32.156",
                context="Known C2 infrastructure",
                confidence=0.95,
            ),
            "indicator",
        )
        objects.append(indicator)

        # SCOs
        ip_sco = structurer.create_stix_sco(
            ExtractedEntity(
                entity_type="ip_address",
                value="45.33.32.156",
                context="C2 IP",
                confidence=0.95,
            )
        )
        objects.append(ip_sco)

        btc_sco = structurer.create_stix_sco(
            ExtractedEntity(
                entity_type="btc_wallet",
                value="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                context="Payment wallet",
                confidence=0.99,
            )
        )
        objects.append(btc_sco)

        # Relationships
        rel1 = structurer.create_stix_relationship(actor.id, technique.id, "uses")
        objects.append(rel1)

        rel2 = structurer.create_stix_relationship(indicator.id, actor.id, "indicates")
        objects.append(rel2)

        # Build and validate bundle
        bundle = structurer.build_bundle(objects)

        assert isinstance(bundle, stix2.Bundle)
        assert len(bundle.objects) == 7

        # Verify serialization
        serialized = bundle.serialize()
        parsed = json.loads(serialized)
        assert parsed["type"] == "bundle"
        assert len(parsed["objects"]) == 7

        # Verify all expected types present
        types_present = {obj["type"] for obj in parsed["objects"]}
        assert "threat-actor" in types_present
        assert "attack-pattern" in types_present
        assert "indicator" in types_present
        assert "ipv4-addr" in types_present
        assert "artifact" in types_present
        assert "relationship" in types_present
