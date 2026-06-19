"""Unit tests for STIX 2.1 serialization and deserialization.

Tests verify:
- Round-trip: serialize then deserialize produces equivalent Bundle
- All object types survive serialization (SDOs, SCOs, SROs)
- Relationships maintain source_ref and target_ref after deserialization
- Invalid JSON raises appropriate error
"""

import json

import pytest
import stix2

from dark_web_fraud_agent.agents.data_structurer import DataStructurer
from dark_web_fraud_agent.models.content_analyst import ExtractedEntity


@pytest.fixture
def structurer():
    """Create a DataStructurer instance for testing."""
    return DataStructurer()


@pytest.fixture
def sample_bundle(structurer):
    """Create a sample Bundle with SDOs, SCOs, and SROs for testing."""
    objects = []

    # SDO: Threat Actor
    actor = structurer.create_stix_sdo(
        ExtractedEntity(
            entity_type="bank_name",
            value="TestActor",
            context="A known threat actor",
            confidence=0.9,
        ),
        "threat-actor",
    )
    objects.append(actor)

    # SDO: Attack Pattern
    pattern = structurer.create_stix_sdo(
        ExtractedEntity(
            entity_type="bank_name",
            value="Phishing Kit",
            context="Advanced phishing kit targeting banking customers",
            confidence=0.85,
        ),
        "attack-pattern",
    )
    objects.append(pattern)

    # SDO: Indicator
    indicator = structurer.create_stix_sdo(
        ExtractedEntity(
            entity_type="ip_address",
            value="192.168.1.100",
            context="C2 server",
            confidence=0.95,
        ),
        "indicator",
    )
    objects.append(indicator)

    # SDO: Malware
    malware = structurer.create_stix_sdo(
        ExtractedEntity(
            entity_type="bank_name",
            value="BankBot",
            context="Android banking trojan",
            confidence=0.88,
        ),
        "malware",
    )
    objects.append(malware)

    # SCO: IPv4Address
    ip_sco = structurer.create_stix_sco(
        ExtractedEntity(
            entity_type="ip_address",
            value="10.0.0.1",
            context="Proxy IP",
            confidence=0.99,
        )
    )
    objects.append(ip_sco)

    # SCO: URL
    url_sco = structurer.create_stix_sco(
        ExtractedEntity(
            entity_type="url",
            value="http://darkmarket.onion/shop",
            context="Marketplace URL",
            confidence=0.97,
        )
    )
    objects.append(url_sco)

    # SCO: EmailAddress
    email_sco = structurer.create_stix_sco(
        ExtractedEntity(
            entity_type="email",
            value="seller@darknet.onion",
            context="Vendor email",
            confidence=0.92,
        )
    )
    objects.append(email_sco)

    # SCO: Artifact (BTC wallet)
    btc_sco = structurer.create_stix_sco(
        ExtractedEntity(
            entity_type="btc_wallet",
            value="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            context="Payment wallet",
            confidence=0.98,
        )
    )
    objects.append(btc_sco)

    # SRO: Relationship (actor uses pattern)
    rel_uses = structurer.create_stix_relationship(actor.id, pattern.id, "uses")
    objects.append(rel_uses)

    # SRO: Relationship (indicator indicates actor)
    rel_indicates = structurer.create_stix_relationship(indicator.id, actor.id, "indicates")
    objects.append(rel_indicates)

    return structurer.build_bundle(objects)


class TestSerializeBundle:
    """Tests for serialize_bundle() method."""

    def test_serialize_produces_valid_json(self, structurer, sample_bundle):
        """Serialized output is valid JSON."""
        result = structurer.serialize_bundle(sample_bundle)

        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert parsed["type"] == "bundle"

    def test_serialize_contains_all_objects(self, structurer, sample_bundle):
        """Serialized JSON contains all objects from the Bundle."""
        result = structurer.serialize_bundle(sample_bundle)
        parsed = json.loads(result)

        assert len(parsed["objects"]) == 10

    def test_serialize_preserves_bundle_id(self, structurer, sample_bundle):
        """Serialized JSON preserves the Bundle ID."""
        result = structurer.serialize_bundle(sample_bundle)
        parsed = json.loads(result)

        assert parsed["id"] == sample_bundle.id
        assert parsed["id"].startswith("bundle--")

    def test_serialize_single_sdo(self, structurer):
        """Serialization works for a Bundle with a single SDO."""
        sdo = structurer.create_stix_sdo(
            ExtractedEntity(
                entity_type="bank_name",
                value="SimpleActor",
                context="test",
                confidence=0.8,
            ),
            "threat-actor",
        )
        bundle = structurer.build_bundle([sdo])

        result = structurer.serialize_bundle(bundle)
        parsed = json.loads(result)

        assert parsed["type"] == "bundle"
        assert len(parsed["objects"]) == 1
        assert parsed["objects"][0]["type"] == "threat-actor"
        assert parsed["objects"][0]["name"] == "SimpleActor"


class TestDeserializeBundle:
    """Tests for deserialize_bundle() method."""

    def test_deserialize_produces_stix_bundle(self, structurer, sample_bundle):
        """Deserialized output is a stix2.Bundle object."""
        json_str = structurer.serialize_bundle(sample_bundle)

        result = structurer.deserialize_bundle(json_str)

        assert isinstance(result, stix2.Bundle)

    def test_deserialize_invalid_json_raises_value_error(self, structurer):
        """Invalid JSON input raises ValueError."""
        with pytest.raises(ValueError, match="Invalid JSON input"):
            structurer.deserialize_bundle("not valid json {{{")

    def test_deserialize_empty_string_raises_value_error(self, structurer):
        """Empty string raises ValueError."""
        with pytest.raises(ValueError, match="Invalid JSON input"):
            structurer.deserialize_bundle("")

    def test_deserialize_non_bundle_json_raises_value_error(self, structurer):
        """JSON that is not a STIX Bundle raises ValueError."""
        non_bundle_json = json.dumps({
            "type": "threat-actor",
            "id": "threat-actor--12345678-1234-1234-1234-123456789012",
            "name": "NotABundle",
            "spec_version": "2.1",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "threat_actor_types": ["criminal"],
        })

        with pytest.raises(ValueError, match="not a STIX Bundle"):
            structurer.deserialize_bundle(non_bundle_json)

    def test_deserialize_malformed_stix_raises_value_error(self, structurer):
        """JSON with invalid STIX structure raises ValueError."""
        malformed_json = json.dumps({
            "type": "bundle",
            "id": "not-a-valid-stix-id",
            "objects": [{"type": "invalid-type"}],
        })

        with pytest.raises(ValueError):
            structurer.deserialize_bundle(malformed_json)


class TestSerializationRoundTrip:
    """Tests for round-trip serialization/deserialization."""

    def test_round_trip_preserves_bundle_id(self, structurer, sample_bundle):
        """Round-trip preserves the Bundle ID."""
        json_str = structurer.serialize_bundle(sample_bundle)
        restored = structurer.deserialize_bundle(json_str)

        assert restored.id == sample_bundle.id

    def test_round_trip_preserves_object_count(self, structurer, sample_bundle):
        """Round-trip preserves the number of objects."""
        json_str = structurer.serialize_bundle(sample_bundle)
        restored = structurer.deserialize_bundle(json_str)

        assert len(restored.objects) == len(sample_bundle.objects)

    def test_round_trip_preserves_all_object_types(self, structurer, sample_bundle):
        """Round-trip preserves all STIX object types (SDOs, SCOs, SROs)."""
        json_str = structurer.serialize_bundle(sample_bundle)
        restored = structurer.deserialize_bundle(json_str)

        original_types = sorted(obj.type for obj in sample_bundle.objects)
        restored_types = sorted(obj.type for obj in restored.objects)

        assert original_types == restored_types

    def test_round_trip_preserves_sdo_properties(self, structurer):
        """Round-trip preserves SDO properties (name, description, etc.)."""
        actor = structurer.create_stix_sdo(
            ExtractedEntity(
                entity_type="bank_name",
                value="RoundTripActor",
                context="Testing round-trip preservation",
                confidence=0.87,
            ),
            "threat-actor",
        )
        bundle = structurer.build_bundle([actor])

        json_str = structurer.serialize_bundle(bundle)
        restored = structurer.deserialize_bundle(json_str)

        restored_actor = restored.objects[0]
        assert restored_actor.name == "RoundTripActor"
        assert restored_actor.type == "threat-actor"
        assert restored_actor.confidence == 87
        assert "criminal" in restored_actor.threat_actor_types

    def test_round_trip_preserves_sco_values(self, structurer):
        """Round-trip preserves SCO observable values."""
        ip_sco = structurer.create_stix_sco(
            ExtractedEntity(
                entity_type="ip_address",
                value="203.0.113.42",
                context="Test IP",
                confidence=0.99,
            )
        )
        email_sco = structurer.create_stix_sco(
            ExtractedEntity(
                entity_type="email",
                value="roundtrip@test.onion",
                context="Test email",
                confidence=0.95,
            )
        )
        bundle = structurer.build_bundle([ip_sco, email_sco])

        json_str = structurer.serialize_bundle(bundle)
        restored = structurer.deserialize_bundle(json_str)

        restored_objects_by_type = {obj.type: obj for obj in restored.objects}

        assert restored_objects_by_type["ipv4-addr"].value == "203.0.113.42"
        assert restored_objects_by_type["email-addr"].value == "roundtrip@test.onion"

    def test_round_trip_preserves_relationship_refs(self, structurer):
        """Round-trip preserves relationship source_ref and target_ref."""
        actor = structurer.create_stix_sdo(
            ExtractedEntity(
                entity_type="bank_name",
                value="Actor1",
                context="ctx",
                confidence=0.9,
            ),
            "threat-actor",
        )
        pattern = structurer.create_stix_sdo(
            ExtractedEntity(
                entity_type="bank_name",
                value="Pattern1",
                context="ctx",
                confidence=0.85,
            ),
            "attack-pattern",
        )
        relationship = structurer.create_stix_relationship(actor.id, pattern.id, "uses")
        bundle = structurer.build_bundle([actor, pattern, relationship])

        json_str = structurer.serialize_bundle(bundle)
        restored = structurer.deserialize_bundle(json_str)

        # Find the relationship in the restored bundle
        restored_rel = next(
            obj for obj in restored.objects if obj.type == "relationship"
        )

        assert restored_rel.source_ref == actor.id
        assert restored_rel.target_ref == pattern.id
        assert restored_rel.relationship_type == "uses"

    def test_round_trip_preserves_multiple_relationships(self, structurer):
        """Round-trip preserves multiple relationship objects with distinct refs."""
        actor = structurer.create_stix_sdo(
            ExtractedEntity(
                entity_type="bank_name",
                value="MultiRelActor",
                context="ctx",
                confidence=0.9,
            ),
            "threat-actor",
        )
        pattern = structurer.create_stix_sdo(
            ExtractedEntity(
                entity_type="bank_name",
                value="MultiRelPattern",
                context="ctx",
                confidence=0.85,
            ),
            "attack-pattern",
        )
        indicator = structurer.create_stix_sdo(
            ExtractedEntity(
                entity_type="ip_address",
                value="10.10.10.10",
                context="ctx",
                confidence=0.95,
            ),
            "indicator",
        )

        rel1 = structurer.create_stix_relationship(actor.id, pattern.id, "uses")
        rel2 = structurer.create_stix_relationship(indicator.id, actor.id, "indicates")
        bundle = structurer.build_bundle([actor, pattern, indicator, rel1, rel2])

        json_str = structurer.serialize_bundle(bundle)
        restored = structurer.deserialize_bundle(json_str)

        restored_rels = [obj for obj in restored.objects if obj.type == "relationship"]
        assert len(restored_rels) == 2

        # Verify each relationship's refs are preserved
        rel_data = {(r.source_ref, r.target_ref, r.relationship_type) for r in restored_rels}
        assert (actor.id, pattern.id, "uses") in rel_data
        assert (indicator.id, actor.id, "indicates") in rel_data

    def test_round_trip_full_bundle_equivalence(self, structurer, sample_bundle):
        """Full round-trip produces semantically equivalent Bundle."""
        json_str = structurer.serialize_bundle(sample_bundle)
        restored = structurer.deserialize_bundle(json_str)

        # Compare by object IDs
        original_ids = sorted(obj.id for obj in sample_bundle.objects)
        restored_ids = sorted(obj.id for obj in restored.objects)
        assert original_ids == restored_ids

        # Compare object types match IDs
        original_type_map = {obj.id: obj.type for obj in sample_bundle.objects}
        restored_type_map = {obj.id: obj.type for obj in restored.objects}
        assert original_type_map == restored_type_map
