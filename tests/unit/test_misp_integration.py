"""Unit tests for MISP integration module."""

import pytest
import stix2
from pymisp import MISPEvent

from dark_web_fraud_agent.agents.misp_integration import (
    MISPIntegration,
    STIX_TO_MISP_TYPE_MAP,
    STIX_TO_MISP_CATEGORY_MAP,
)


@pytest.fixture
def integration():
    """Create a MISPIntegration instance for testing."""
    return MISPIntegration(misp_url="https://misp.test", misp_key="test-key")


class TestTypeMapping:
    """Tests for STIX SCO type to MISP attribute type mapping."""

    def test_ipv4_maps_to_ip_src(self, integration):
        assert integration.map_sco_to_misp_type("ipv4-addr") == "ip-src"

    def test_ipv6_maps_to_ip_src(self, integration):
        assert integration.map_sco_to_misp_type("ipv6-addr") == "ip-src"

    def test_url_maps_to_url(self, integration):
        assert integration.map_sco_to_misp_type("url") == "url"

    def test_email_addr_maps_to_email_src(self, integration):
        assert integration.map_sco_to_misp_type("email-addr") == "email-src"

    def test_domain_name_maps_to_domain(self, integration):
        assert integration.map_sco_to_misp_type("domain-name") == "domain"

    def test_artifact_maps_to_btc(self, integration):
        assert integration.map_sco_to_misp_type("artifact") == "btc"

    def test_unknown_type_maps_to_text(self, integration):
        assert integration.map_sco_to_misp_type("unknown-type") == "text"
        assert integration.map_sco_to_misp_type("file") == "text"

    def test_all_mapped_types_have_categories(self):
        """Every type in the type map should also have a category mapping."""
        for stix_type in STIX_TO_MISP_TYPE_MAP:
            assert stix_type in STIX_TO_MISP_CATEGORY_MAP


class TestStixToMisp:
    """Tests for converting STIX Bundles to MISP events."""

    def test_empty_bundle_produces_event_with_info(self, integration):
        bundle = stix2.Bundle(objects=[])
        event = integration.stix_to_misp(bundle)
        assert isinstance(event, MISPEvent)
        assert "0 STIX objects" in event.info

    def test_ipv4_sco_becomes_attribute(self, integration):
        ipv4 = stix2.IPv4Address(value="192.168.1.1")
        bundle = stix2.Bundle(objects=[ipv4])
        event = integration.stix_to_misp(bundle)

        attrs = event.attributes
        assert len(attrs) == 1
        assert attrs[0].type == "ip-src"
        assert attrs[0].value == "192.168.1.1"
        assert attrs[0].category == "Network activity"

    def test_url_sco_becomes_attribute(self, integration):
        url_obj = stix2.URL(value="http://example.onion/page")
        bundle = stix2.Bundle(objects=[url_obj])
        event = integration.stix_to_misp(bundle)

        attrs = event.attributes
        assert len(attrs) == 1
        assert attrs[0].type == "url"
        assert attrs[0].value == "http://example.onion/page"
        assert attrs[0].category == "Network activity"

    def test_email_sco_becomes_attribute(self, integration):
        email = stix2.EmailAddress(value="attacker@darkweb.org")
        bundle = stix2.Bundle(objects=[email])
        event = integration.stix_to_misp(bundle)

        attrs = event.attributes
        assert len(attrs) == 1
        assert attrs[0].type == "email-src"
        assert attrs[0].value == "attacker@darkweb.org"
        assert attrs[0].category == "Payload delivery"

    def test_domain_sco_becomes_attribute(self, integration):
        domain = stix2.DomainName(value="malicious.example.com")
        bundle = stix2.Bundle(objects=[domain])
        event = integration.stix_to_misp(bundle)

        attrs = event.attributes
        assert len(attrs) == 1
        assert attrs[0].type == "domain"
        assert attrs[0].value == "malicious.example.com"
        assert attrs[0].category == "Network activity"

    def test_threat_actor_sdo_becomes_object(self, integration):
        ta = stix2.ThreatActor(
            name="DarkFraudster",
            description="A threat actor specializing in BIN attacks",
            threat_actor_types=["criminal"],
        )
        bundle = stix2.Bundle(objects=[ta])
        event = integration.stix_to_misp(bundle)

        assert len(event.attributes) == 0
        assert len(event.objects) == 1
        misp_obj = event.objects[0]
        assert misp_obj.name == "threat-actor"

    def test_attack_pattern_sdo_becomes_object(self, integration):
        ap = stix2.AttackPattern(
            name="MFA Bypass Technique",
            description="Method to bypass multi-factor authentication",
        )
        bundle = stix2.Bundle(objects=[ap])
        event = integration.stix_to_misp(bundle)

        assert len(event.objects) == 1
        misp_obj = event.objects[0]
        assert misp_obj.name == "attack-pattern"

    def test_mixed_bundle_processes_all_objects(self, integration):
        ipv4 = stix2.IPv4Address(value="10.0.0.1")
        url_obj = stix2.URL(value="http://dark.onion")
        ta = stix2.ThreatActor(
            name="Actor1",
            threat_actor_types=["criminal"],
        )
        bundle = stix2.Bundle(objects=[ipv4, url_obj, ta])
        event = integration.stix_to_misp(bundle)

        assert len(event.attributes) == 2  # ipv4 + url
        assert len(event.objects) == 1  # threat-actor

    def test_relationship_objects_are_skipped(self, integration):
        ta = stix2.ThreatActor(
            name="Actor1",
            threat_actor_types=["criminal"],
        )
        ap = stix2.AttackPattern(name="Technique1")
        rel = stix2.Relationship(
            relationship_type="uses",
            source_ref=ta.id,
            target_ref=ap.id,
        )
        bundle = stix2.Bundle(objects=[ta, ap, rel])
        event = integration.stix_to_misp(bundle)

        # relationship should not appear as attribute or object
        assert len(event.objects) == 2  # ta + ap
        assert len(event.attributes) == 0

    def test_event_info_contains_object_count(self, integration):
        ipv4 = stix2.IPv4Address(value="1.2.3.4")
        url_obj = stix2.URL(value="http://test.onion")
        bundle = stix2.Bundle(objects=[ipv4, url_obj])
        event = integration.stix_to_misp(bundle)

        assert "2 STIX objects" in event.info

    def test_sdo_description_truncated_to_500_chars(self, integration):
        long_desc = "A" * 1000
        ta = stix2.ThreatActor(
            name="Actor1",
            description=long_desc,
            threat_actor_types=["criminal"],
        )
        bundle = stix2.Bundle(objects=[ta])
        event = integration.stix_to_misp(bundle)

        misp_obj = event.objects[0]
        # Find the description attribute
        desc_attr = None
        for attr in misp_obj.attributes:
            if attr.object_relation == "description":
                desc_attr = attr
                break
        assert desc_attr is not None
        assert len(desc_attr.value) == 500


class TestMISPIntegrationInit:
    """Tests for MISPIntegration initialization."""

    def test_default_init(self):
        integration = MISPIntegration()
        assert integration._misp_url == ""
        assert integration._misp_key == ""
        assert integration._misp_client is None

    def test_init_with_params(self):
        integration = MISPIntegration(
            misp_url="https://misp.example.com",
            misp_key="abc123",
            misp_client="mock_client",
        )
        assert integration._misp_url == "https://misp.example.com"
        assert integration._misp_key == "abc123"
        assert integration._misp_client == "mock_client"
