"""Unit tests for MISP-to-STIX export and create_misp_event."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import stix2
from pymisp import MISPEvent, MISPAttribute, MISPObject

from dark_web_fraud_agent.agents.misp_integration import (
    MISPIntegration,
    MISP_TO_STIX_TYPE_MAP,
)


@pytest.fixture
def integration():
    """Create a MISPIntegration instance for testing."""
    return MISPIntegration(misp_url="https://misp.test", misp_key="test-key")


class TestMispToStixTypeMap:
    """Tests for the reverse MISP-to-STIX type mapping."""

    def test_ip_src_maps_to_ipv4(self):
        assert MISP_TO_STIX_TYPE_MAP["ip-src"] == "ipv4-addr"

    def test_ip_dst_maps_to_ipv4(self):
        assert MISP_TO_STIX_TYPE_MAP["ip-dst"] == "ipv4-addr"

    def test_url_maps_to_url(self):
        assert MISP_TO_STIX_TYPE_MAP["url"] == "url"

    def test_email_src_maps_to_email_addr(self):
        assert MISP_TO_STIX_TYPE_MAP["email-src"] == "email-addr"

    def test_domain_maps_to_domain_name(self):
        assert MISP_TO_STIX_TYPE_MAP["domain"] == "domain-name"

    def test_btc_maps_to_artifact(self):
        assert MISP_TO_STIX_TYPE_MAP["btc"] == "artifact"


class TestMispToStix:
    """Tests for converting MISP events back to STIX Bundles."""

    def test_empty_event_produces_empty_bundle(self, integration):
        event = MISPEvent()
        event.info = "Empty event"
        bundle = integration.misp_to_stix(event)
        assert isinstance(bundle, stix2.Bundle)
        assert len(bundle.objects) == 0

    def test_ip_src_attribute_becomes_ipv4_sco(self, integration):
        event = MISPEvent()
        event.info = "Test"
        event.add_attribute("ip-src", "192.168.1.1")
        bundle = integration.misp_to_stix(event)

        assert len(bundle.objects) == 1
        obj = bundle.objects[0]
        assert obj.type == "ipv4-addr"
        assert obj.value == "192.168.1.1"

    def test_ip_dst_attribute_becomes_ipv4_sco(self, integration):
        event = MISPEvent()
        event.info = "Test"
        event.add_attribute("ip-dst", "10.0.0.1")
        bundle = integration.misp_to_stix(event)

        assert len(bundle.objects) == 1
        obj = bundle.objects[0]
        assert obj.type == "ipv4-addr"
        assert obj.value == "10.0.0.1"

    def test_url_attribute_becomes_url_sco(self, integration):
        event = MISPEvent()
        event.info = "Test"
        event.add_attribute("url", "http://dark.onion/page")
        bundle = integration.misp_to_stix(event)

        assert len(bundle.objects) == 1
        obj = bundle.objects[0]
        assert obj.type == "url"
        assert obj.value == "http://dark.onion/page"

    def test_email_src_attribute_becomes_email_sco(self, integration):
        event = MISPEvent()
        event.info = "Test"
        event.add_attribute("email-src", "attacker@dark.org")
        bundle = integration.misp_to_stix(event)

        assert len(bundle.objects) == 1
        obj = bundle.objects[0]
        assert obj.type == "email-addr"
        assert obj.value == "attacker@dark.org"

    def test_domain_attribute_becomes_domain_name_sco(self, integration):
        event = MISPEvent()
        event.info = "Test"
        event.add_attribute("domain", "malicious.example.com")
        bundle = integration.misp_to_stix(event)

        assert len(bundle.objects) == 1
        obj = bundle.objects[0]
        assert obj.type == "domain-name"
        assert obj.value == "malicious.example.com"

    def test_btc_attribute_becomes_artifact_sco(self, integration):
        event = MISPEvent()
        event.info = "Test"
        event.add_attribute("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        bundle = integration.misp_to_stix(event)

        assert len(bundle.objects) == 1
        obj = bundle.objects[0]
        assert obj.type == "artifact"
        assert obj.mime_type == "application/x-bitcoin-address"

    def test_unmapped_attribute_type_skipped(self, integration):
        event = MISPEvent()
        event.info = "Test"
        event.add_attribute("text", "some random text")
        bundle = integration.misp_to_stix(event)

        assert len(bundle.objects) == 0

    def test_threat_actor_object_becomes_sdo(self, integration):
        event = MISPEvent()
        event.info = "Test"
        misp_obj = MISPObject("threat-actor")
        misp_obj.add_attribute("name", value="DarkFraudster")
        misp_obj.add_attribute("description", value="A known threat actor")
        event.add_object(misp_obj)
        bundle = integration.misp_to_stix(event)

        assert len(bundle.objects) == 1
        obj = bundle.objects[0]
        assert obj.type == "threat-actor"
        assert obj.name == "DarkFraudster"
        assert obj.description == "A known threat actor"

    def test_attack_pattern_object_becomes_sdo(self, integration):
        event = MISPEvent()
        event.info = "Test"
        misp_obj = MISPObject("attack-pattern")
        misp_obj.add_attribute("name", value="MFA Bypass")
        event.add_object(misp_obj)
        bundle = integration.misp_to_stix(event)

        assert len(bundle.objects) == 1
        obj = bundle.objects[0]
        assert obj.type == "attack-pattern"
        assert obj.name == "MFA Bypass"

    def test_mixed_event_converts_all(self, integration):
        event = MISPEvent()
        event.info = "Test"
        event.add_attribute("ip-src", "10.0.0.1")
        event.add_attribute("url", "http://test.onion")
        misp_obj = MISPObject("threat-actor")
        misp_obj.add_attribute("name", value="Actor1")
        event.add_object(misp_obj)
        bundle = integration.misp_to_stix(event)

        # 2 SCOs + 1 SDO
        assert len(bundle.objects) == 3
        types = [obj.type for obj in bundle.objects]
        assert "ipv4-addr" in types
        assert "url" in types
        assert "threat-actor" in types

    def test_unknown_object_type_skipped(self, integration):
        event = MISPEvent()
        event.info = "Test"
        misp_obj = MISPObject("unknown-type-xyz")
        misp_obj.add_attribute("name", value="Something")
        event.add_object(misp_obj)
        bundle = integration.misp_to_stix(event)

        assert len(bundle.objects) == 0


class TestCreateMispEvent:
    """Tests for the create_misp_event async method."""

    @pytest.mark.asyncio
    async def test_create_event_with_mocked_client(self, integration):
        """Test that create_misp_event converts bundle and calls add_event."""
        mock_client = MagicMock()
        mock_response = MISPEvent()
        mock_response.id = 42
        mock_client.add_event.return_value = mock_response
        integration._misp_client = mock_client

        ipv4 = stix2.IPv4Address(value="192.168.1.1")
        bundle = stix2.Bundle(objects=[ipv4])

        event_id = await integration.create_misp_event(bundle)

        assert event_id == "42"
        mock_client.add_event.assert_called_once()
        # Verify the event passed to add_event is a MISPEvent
        call_args = mock_client.add_event.call_args
        assert isinstance(call_args[0][0], MISPEvent)

    @pytest.mark.asyncio
    async def test_create_event_returns_id_from_dict_response(self, integration):
        """Test extraction of event ID from dict response."""
        mock_client = MagicMock()
        mock_client.add_event.return_value = {"Event": {"id": "99"}}
        integration._misp_client = mock_client

        bundle = stix2.Bundle(objects=[stix2.URL(value="http://test.onion")])
        event_id = await integration.create_misp_event(bundle)

        assert event_id == "99"

    @pytest.mark.asyncio
    async def test_create_event_retries_on_validation_error(self, integration):
        """Test that validation errors trigger a retry."""
        mock_client = MagicMock()
        # First call returns errors, second call succeeds
        error_response = {"errors": ["Invalid attribute"]}
        success_response = MISPEvent()
        success_response.id = 55
        mock_client.add_event.side_effect = [error_response, success_response]
        integration._misp_client = mock_client

        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.2.3.4")])
        event_id = await integration.create_misp_event(bundle)

        assert event_id == "55"
        assert mock_client.add_event.call_count == 2

    @pytest.mark.asyncio
    async def test_create_event_initializes_client_if_none(self):
        """Test that the client is created if not already set."""
        integration = MISPIntegration(
            misp_url="https://misp.example.com", misp_key="abc123"
        )
        assert integration._misp_client is None

        with patch(
            "dark_web_fraud_agent.agents.misp_integration.PyMISP",
            create=True,
        ) as mock_pymisp_class:
            mock_instance = MagicMock()
            mock_response = MISPEvent()
            mock_response.id = 10
            mock_instance.add_event.return_value = mock_response
            mock_pymisp_class.return_value = mock_instance

            bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="8.8.8.8")])
            event_id = await integration.create_misp_event(bundle)

            mock_pymisp_class.assert_called_once_with(
                "https://misp.example.com", "abc123", ssl=True
            )
            assert event_id == "10"

    @pytest.mark.asyncio
    async def test_create_event_returns_error_string_on_exception(self, integration):
        """Test that exceptions from the client return error-{uuid} string."""
        mock_client = MagicMock()
        mock_client.add_event.side_effect = Exception("Connection refused")
        integration._misp_client = mock_client

        bundle = stix2.Bundle(objects=[stix2.IPv4Address(value="1.1.1.1")])

        result = await integration.create_misp_event(bundle)
        assert result.startswith("error-")
        # Verify it's a valid UUID after the prefix
        uuid_part = result[len("error-"):]
        import uuid as uuid_mod
        uuid_mod.UUID(uuid_part)  # Raises if invalid
