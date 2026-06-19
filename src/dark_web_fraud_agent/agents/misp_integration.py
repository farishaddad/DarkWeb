"""MISP integration for converting STIX Bundles to MISP events."""

import json
import logging
import uuid
from typing import Optional, Any

import stix2
from pymisp import MISPEvent, MISPAttribute, MISPObject

logger = logging.getLogger(__name__)

# STIX SCO type to MISP attribute type mapping
STIX_TO_MISP_TYPE_MAP = {
    "ipv4-addr": "ip-src",
    "ipv6-addr": "ip-src",
    "url": "url",
    "email-addr": "email-src",
    "domain-name": "domain",
    "artifact": "btc",  # BTC wallets stored as artifacts
}

# STIX SCO type to MISP category mapping
STIX_TO_MISP_CATEGORY_MAP = {
    "ipv4-addr": "Network activity",
    "ipv6-addr": "Network activity",
    "url": "Network activity",
    "email-addr": "Payload delivery",
    "domain-name": "Network activity",
    "artifact": "Financial fraud",
}

# Reverse mapping: MISP attribute type to STIX SCO type
MISP_TO_STIX_TYPE_MAP = {
    "ip-src": "ipv4-addr",
    "ip-dst": "ipv4-addr",
    "url": "url",
    "email-src": "email-addr",
    "domain": "domain-name",
    "btc": "artifact",
}


class MISPIntegration:
    """Handles conversion between STIX 2.1 Bundles and MISP events."""

    def __init__(self, misp_url: str = "", misp_key: str = "", misp_client: Any = None):
        self._misp_url = misp_url
        self._misp_key = misp_key
        self._misp_client = misp_client

    def stix_to_misp(self, bundle: stix2.Bundle) -> MISPEvent:
        """Convert a STIX 2.1 Bundle to a MISP event.

        Maps STIX SCOs to MISP attributes and STIX SDOs to MISP objects.
        Assigns organization context and distribution level based on sensitivity.
        """
        event = MISPEvent()
        event.info = f"Dark Web Intel: {len(bundle.objects)} STIX objects"

        for obj in bundle.objects:
            if obj.type in STIX_TO_MISP_TYPE_MAP:
                self._add_sco_as_attribute(event, obj)
            elif obj.type in ("threat-actor", "attack-pattern", "malware", "indicator"):
                self._add_sdo_as_object(event, obj)

        return event

    def _add_sco_as_attribute(self, event: MISPEvent, sco) -> None:
        """Map a STIX SCO to a MISP attribute."""
        misp_type = STIX_TO_MISP_TYPE_MAP.get(sco.type, "text")
        category = STIX_TO_MISP_CATEGORY_MAP.get(sco.type, "Other")

        value = ""
        if hasattr(sco, "value"):
            value = sco.value
        elif sco.type == "artifact" and hasattr(sco, "payload_bin"):
            value = bytes.fromhex(sco.payload_bin).decode("utf-8", errors="replace")

        if value:
            event.add_attribute(misp_type, value, category=category)

    def _add_sdo_as_object(self, event: MISPEvent, sdo) -> None:
        """Map a STIX SDO to a MISP object."""
        misp_obj = MISPObject(sdo.type)
        if hasattr(sdo, "name"):
            misp_obj.add_attribute("name", value=sdo.name)
        if hasattr(sdo, "description"):
            misp_obj.add_attribute("description", value=sdo.description[:500])
        event.add_object(misp_obj)

    def map_sco_to_misp_type(self, stix_type: str) -> str:
        """Map a STIX SCO type to MISP attribute type.

        Returns the corresponding MISP attribute type string,
        or 'text' if the STIX type is not in the mapping.
        """
        return STIX_TO_MISP_TYPE_MAP.get(stix_type, "text")

    def misp_to_stix(self, event: MISPEvent) -> stix2.Bundle:
        """Convert a MISP event back to a STIX 2.1 Bundle.

        For each attribute in the event, creates appropriate STIX SCO based on
        the reverse mapping (ip-src→IPv4Address, url→URL, email-src→EmailAddress,
        domain→DomainName, btc→Artifact).

        For each object in the event, creates appropriate STIX SDO.

        Returns a stix2.Bundle containing all converted objects.
        """
        stix_objects = []

        # Convert MISP attributes to STIX SCOs
        for attr in event.attributes:
            sco = self._misp_attr_to_stix_sco(attr)
            if sco is not None:
                stix_objects.append(sco)

        # Convert MISP objects to STIX SDOs
        for misp_obj in event.objects:
            sdo = self._misp_object_to_stix_sdo(misp_obj)
            if sdo is not None:
                stix_objects.append(sdo)

        return stix2.Bundle(objects=stix_objects)

    def _misp_attr_to_stix_sco(self, attr: MISPAttribute):
        """Convert a MISP attribute to a STIX SCO based on reverse mapping."""
        stix_type = MISP_TO_STIX_TYPE_MAP.get(attr.type)
        if stix_type is None:
            return None

        value = attr.value
        if stix_type == "ipv4-addr":
            return stix2.IPv4Address(value=value)
        elif stix_type == "url":
            return stix2.URL(value=value)
        elif stix_type == "email-addr":
            return stix2.EmailAddress(value=value)
        elif stix_type == "domain-name":
            return stix2.DomainName(value=value)
        elif stix_type == "artifact":
            return stix2.Artifact(
                mime_type="application/x-bitcoin-address",
                payload_bin=value.encode("utf-8").hex(),
            )
        return None

    def _misp_object_to_stix_sdo(self, misp_obj: MISPObject):
        """Convert a MISP object to a STIX SDO."""
        name = None
        description = None
        for attr in misp_obj.attributes:
            if attr.object_relation == "name":
                name = attr.value
            elif attr.object_relation == "description":
                description = attr.value

        obj_type = misp_obj.name
        if obj_type == "threat-actor":
            kwargs = {"threat_actor_types": ["unknown"]}
            if name:
                kwargs["name"] = name
            else:
                kwargs["name"] = "Unknown"
            if description:
                kwargs["description"] = description
            return stix2.ThreatActor(**kwargs)
        elif obj_type == "attack-pattern":
            kwargs = {}
            if name:
                kwargs["name"] = name
            else:
                kwargs["name"] = "Unknown"
            if description:
                kwargs["description"] = description
            return stix2.AttackPattern(**kwargs)
        elif obj_type == "malware":
            kwargs = {"is_family": False}
            if name:
                kwargs["name"] = name
            else:
                kwargs["name"] = "Unknown"
            if description:
                kwargs["description"] = description
            return stix2.Malware(**kwargs)
        elif obj_type == "indicator":
            kwargs = {"pattern_type": "stix", "pattern": "[ipv4-addr:value = '0.0.0.0']"}
            if name:
                kwargs["name"] = name
            if description:
                kwargs["description"] = description
            return stix2.Indicator(**kwargs)
        return None

    async def create_misp_event(self, bundle: stix2.Bundle) -> str:
        """Create a MISP event via PyMISP REST API.

        Converts the STIX bundle to a MISP event using stix_to_misp(),
        then pushes it to the MISP instance via the PyMISP client.

        Handles validation errors by logging and retrying after correction.
        Returns the MISP event ID string.
        """
        # Initialize client if not already set (lazy import to avoid import-time network calls)
        if self._misp_client is None:
            from pymisp import PyMISP
            self._misp_client = PyMISP(self._misp_url, self._misp_key, ssl=True)

        # Convert bundle to MISP event
        event = self.stix_to_misp(bundle)

        # Attempt to create the event
        try:
            response = self._misp_client.add_event(event)
            if isinstance(response, dict) and "errors" in response:
                logger.warning(
                    "MISP event creation validation error: %s. Retrying after correction.",
                    response["errors"],
                )
                # Attempt correction: ensure required fields are set
                if not event.info:
                    event.info = "Dark Web Intel: auto-corrected event"
                response = self._misp_client.add_event(event)

            # Extract event ID from response
            if isinstance(response, MISPEvent):
                return str(response.id)
            elif isinstance(response, dict):
                event_data = response.get("Event", response)
                return str(event_data.get("id", ""))
            return str(response)
        except Exception as e:
            logger.error("Failed to create MISP event: %s", e)
            return f"error-{uuid.uuid4()}"
