"""Unit tests for STIX-to-MISP conversion (task 7.1).

Tests the stix_to_misp() function including:
- SCO to MISP attribute type mapping
- SDO to MISP object mapping
- Sensitivity-based distribution level assignment
- Organization context assignment
- Input validation
"""

import pytest
import stix2
from pymisp import MISPEvent

from dark_web_fraud_agent.agents.misp_integration import (
    DISTRIBUTION_ALL,
    DISTRIBUTION_COMMUNITY,
    DISTRIBUTION_CONNECTED,
    DISTRIBUTION_ORG_ONLY,
    MISPIntegration,
    STIX_TO_MISP_CATEGORY_MAP,
    STIX_TO_MISP_TYPE_MAP,
    _DEFAULT_DISTRIBUTION,
    _DEFAULT_ORG,
    _SENSITIVITY_TO_DISTRIBUTION,
)


@pytest.fixture
def integration() -> MISPIntegration:
    """Create a MISPIntegration instance for testing."""
    return MISPIntegration(misp_url="https://misp.test", misp_key="test-key")


class TestStixToMispSCOMapping:
    """Tests for STIX SCO → MISP attribute type mapping in stix_to_misp()."""

    def test_ipv4_addr_maps_to_ip_src(self, integration: MISPIntegration) -> None:
        ipv4 = stix2.IPv4Address(value="192.168.1.1")
        bundle = stix2.Bundle(objects=[ipv4])
        event = integration.stix_to_misp(bundle)

        assert len(event.attributes) == 1
        assert event.attributes[0].type == "ip-src"
        assert event.attributes[0].value == "192.168.1.1"
        assert event.attributes[0].category == "Network activity"

    def test_url_maps_to_url(self, integration: MISPIntegration) -> None:
        url_obj = stix2.URL(value="http://example.onion/phishing")
        bundle = stix2.Bundle(objects=[url_obj])
        event = integration.stix_to_misp(bundle)

        assert len(event.attributes) == 1
        assert event.attributes[0].type == "url"
        assert event.attributes[0].value == "http://example.onion/phishing"
        assert event.attributes[0].category == "Network activity"

    def test_email_addr_maps_to_email_src(self, integration: MISPIntegration) -> None:
        email = stix2.EmailAddress(value="fraud@darkmarket.onion")
        bundle = stix2.Bundle(objects=[email])
        event = integration.stix_to_misp(bundle)

        assert len(event.attributes) == 1
        assert event.attributes[0].type == "email-src"
        assert event.attributes[0].value == "fraud@darkmarket.onion"
        assert event.attributes[0].category == "Payload delivery"

    def test_domain_name_maps_to_domain(self, integration: MISPIntegration) -> None:
        domain = stix2.DomainName(value="phishing-bank.onion")
        bundle = stix2.Bundle(objects=[domain])
        event = integration.stix_to_misp(bundle)

        assert len(event.attributes) == 1
        assert event.attributes[0].type == "domain"
        assert event.attributes[0].value == "phishing-bank.onion"
        assert event.attributes[0].category == "Network activity"

    def test_artifact_btc_maps_to_btc(self, integration: MISPIntegration) -> None:
        btc_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        artifact = stix2.Artifact(
            mime_type="application/x-bitcoin-address",
            payload_bin=btc_address.encode("utf-8").hex(),
        )
        bundle = stix2.Bundle(objects=[artifact])
        event = integration.stix_to_misp(bundle)

        assert len(event.attributes) == 1
        assert event.attributes[0].type == "btc"
        assert event.attributes[0].value == btc_address
        assert event.attributes[0].category == "Financial fraud"

    def test_multiple_scos_all_mapped(self, integration: MISPIntegration) -> None:
        objects = [
            stix2.IPv4Address(value="10.0.0.1"),
            stix2.URL(value="http://dark.onion"),
            stix2.EmailAddress(value="a@b.onion"),
            stix2.DomainName(value="bad.onion"),
        ]
        bundle = stix2.Bundle(objects=objects)
        event = integration.stix_to_misp(bundle)

        assert len(event.attributes) == 4
        attr_types = {a.type for a in event.attributes}
        assert attr_types == {"ip-src", "url", "email-src", "domain"}


class TestStixToMispSDOMapping:
    """Tests for STIX SDO → MISP object mapping."""

    def test_threat_actor_becomes_misp_object(self, integration: MISPIntegration) -> None:
        ta = stix2.ThreatActor(
            name="DarkCarder",
            description="Sells stolen financial data",
            threat_actor_types=["criminal"],
        )
        bundle = stix2.Bundle(objects=[ta])
        event = integration.stix_to_misp(bundle)

        assert len(event.attributes) == 0
        assert len(event.objects) == 1
        assert event.objects[0].name == "threat-actor"

    def test_attack_pattern_becomes_misp_object(self, integration: MISPIntegration) -> None:
        ap = stix2.AttackPattern(
            name="MFA Bypass via SIM Swap",
            description="Social engineering telco to redirect SMS-based MFA",
        )
        bundle = stix2.Bundle(objects=[ap])
        event = integration.stix_to_misp(bundle)

        assert len(event.objects) == 1
        assert event.objects[0].name == "attack-pattern"

    def test_malware_becomes_misp_object(self, integration: MISPIntegration) -> None:
        malware = stix2.Malware(
            name="BankBot",
            is_family=False,
            description="Android banking trojan",
        )
        bundle = stix2.Bundle(objects=[malware])
        event = integration.stix_to_misp(bundle)

        assert len(event.objects) == 1
        assert event.objects[0].name == "malware"

    def test_relationship_objects_are_skipped(self, integration: MISPIntegration) -> None:
        ta = stix2.ThreatActor(name="Actor1", threat_actor_types=["criminal"])
        ap = stix2.AttackPattern(name="Technique1")
        rel = stix2.Relationship(
            relationship_type="uses",
            source_ref=ta.id,
            target_ref=ap.id,
        )
        bundle = stix2.Bundle(objects=[ta, ap, rel])
        event = integration.stix_to_misp(bundle)

        # Relationship should not appear as attribute or object
        assert len(event.objects) == 2
        assert len(event.attributes) == 0

    def test_sdo_description_truncated_to_500(self, integration: MISPIntegration) -> None:
        long_desc = "X" * 1000
        ta = stix2.ThreatActor(
            name="Actor",
            description=long_desc,
            threat_actor_types=["criminal"],
        )
        bundle = stix2.Bundle(objects=[ta])
        event = integration.stix_to_misp(bundle)

        misp_obj = event.objects[0]
        desc_attr = next(
            (a for a in misp_obj.attributes if a.object_relation == "description"),
            None,
        )
        assert desc_attr is not None
        assert len(desc_attr.value) == 500


class TestDistributionLevel:
    """Tests for sensitivity-based distribution level assignment (Req 4.3)."""

    def test_default_distribution_is_org_only(self, integration: MISPIntegration) -> None:
        """Default for sensitive fraud intel is org-only (0)."""
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle)
        assert int(event.distribution) == DISTRIBUTION_ORG_ONLY

    def test_high_sensitivity_maps_to_org_only(self, integration: MISPIntegration) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle, sensitivity="high")
        assert int(event.distribution) == DISTRIBUTION_ORG_ONLY

    def test_medium_sensitivity_maps_to_community(self, integration: MISPIntegration) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle, sensitivity="medium")
        assert int(event.distribution) == DISTRIBUTION_COMMUNITY

    def test_low_sensitivity_maps_to_connected(self, integration: MISPIntegration) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle, sensitivity="low")
        assert int(event.distribution) == DISTRIBUTION_CONNECTED

    def test_explicit_distribution_overrides_sensitivity(
        self, integration: MISPIntegration
    ) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle, sensitivity="high", distribution=3)
        assert int(event.distribution) == DISTRIBUTION_ALL

    def test_explicit_distribution_zero(self, integration: MISPIntegration) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle, distribution=0)
        assert int(event.distribution) == 0

    def test_explicit_distribution_three(self, integration: MISPIntegration) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle, distribution=3)
        assert int(event.distribution) == 3

    def test_invalid_distribution_raises_value_error(
        self, integration: MISPIntegration
    ) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        with pytest.raises(ValueError, match="must be 0-3"):
            integration.stix_to_misp(bundle, distribution=4)

    def test_negative_distribution_raises_value_error(
        self, integration: MISPIntegration
    ) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        with pytest.raises(ValueError, match="must be 0-3"):
            integration.stix_to_misp(bundle, distribution=-1)

    def test_unknown_sensitivity_uses_default(self, integration: MISPIntegration) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle, sensitivity="unknown")
        assert int(event.distribution) == _DEFAULT_DISTRIBUTION

    def test_sensitivity_case_insensitive(self, integration: MISPIntegration) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle, sensitivity="HIGH")
        assert int(event.distribution) == DISTRIBUTION_ORG_ONLY

        event2 = integration.stix_to_misp(bundle, sensitivity="Medium")
        assert int(event2.distribution) == DISTRIBUTION_COMMUNITY


class TestOrganizationContext:
    """Tests for organization context assignment (Req 4.3).

    Note: In newer PyMISP, event.org is read-only (set server-side by API key).
    We verify that the org_name is correctly configured on the integration.
    """

    def test_default_org_assigned(self, integration: MISPIntegration) -> None:
        assert integration._org_name == _DEFAULT_ORG

    def test_custom_org_name(self) -> None:
        custom_integration = MISPIntegration(org_name="FRAUD-TEAM-EU")
        assert custom_integration._org_name == "FRAUD-TEAM-EU"


class TestStixToMispEventMetadata:
    """Tests for MISP event metadata fields."""

    def test_event_info_contains_object_count(self, integration: MISPIntegration) -> None:
        objects = [stix2.IPv4Address(value="1.1.1.1"), stix2.URL(value="http://a.onion")]
        bundle = stix2.Bundle(objects=objects)
        event = integration.stix_to_misp(bundle)
        assert "2 STIX objects" in event.info

    def test_event_threat_level_is_medium(self, integration: MISPIntegration) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle)
        assert int(event.threat_level_id) == 2

    def test_event_analysis_is_ongoing(self, integration: MISPIntegration) -> None:
        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event = integration.stix_to_misp(bundle)
        assert int(event.analysis) == 1

    def test_empty_bundle_produces_valid_event(self, integration: MISPIntegration) -> None:
        bundle = stix2.Bundle(objects=[])
        event = integration.stix_to_misp(bundle)
        assert isinstance(event, MISPEvent)
        assert "0 STIX objects" in event.info
        assert int(event.distribution) == DISTRIBUTION_ORG_ONLY


class TestStixToMispInputValidation:
    """Tests for input validation in stix_to_misp()."""

    def test_non_bundle_input_raises_value_error(self, integration: MISPIntegration) -> None:
        with pytest.raises(ValueError, match="Expected stix2.Bundle"):
            integration.stix_to_misp("not a bundle")  # type: ignore

    def test_none_input_raises_value_error(self, integration: MISPIntegration) -> None:
        with pytest.raises(ValueError, match="Expected stix2.Bundle"):
            integration.stix_to_misp(None)  # type: ignore


class TestMixedBundle:
    """Tests for bundles containing mix of SCOs, SDOs, and relationships."""

    def test_mixed_scos_and_sdos(self, integration: MISPIntegration) -> None:
        ipv4 = stix2.IPv4Address(value="10.0.0.1")
        url_obj = stix2.URL(value="http://marketplace.onion")
        ta = stix2.ThreatActor(name="CardShop", threat_actor_types=["criminal"])
        ap = stix2.AttackPattern(name="CNP Fraud")
        rel = stix2.Relationship(
            relationship_type="uses",
            source_ref=ta.id,
            target_ref=ap.id,
        )
        bundle = stix2.Bundle(objects=[ipv4, url_obj, ta, ap, rel])
        event = integration.stix_to_misp(bundle, sensitivity="medium")

        # SCOs become attributes
        assert len(event.attributes) == 2
        # SDOs become objects (relationship skipped)
        assert len(event.objects) == 2
        # Distribution from sensitivity
        assert int(event.distribution) == DISTRIBUTION_COMMUNITY
