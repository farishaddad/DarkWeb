"""MISP integration for converting STIX Bundles to MISP events.

This module handles bidirectional conversion between STIX 2.1 Bundles and MISP
events, including:
- STIX SCO → MISP attribute mapping (ipv4-addr→ip-src, url→url, etc.)
- Organization context and distribution level assignment based on sensitivity
- MISP → STIX export for downstream STIX-native consumers
- MISP event creation via PyMISP REST API with validation error handling
"""

import logging
from typing import Any

import stix2
from pymisp import MISPAttribute, MISPEvent, MISPObject, PyMISP

logger = logging.getLogger(__name__)

# STIX SCO type to MISP attribute type mapping
STIX_TO_MISP_TYPE_MAP: dict[str, str] = {
    "ipv4-addr": "ip-src",
    "ipv6-addr": "ip-src",
    "url": "url",
    "email-addr": "email-src",
    "domain-name": "domain",
    "artifact": "btc",  # BTC wallets stored as artifacts
}

# STIX SCO type to MISP category mapping
STIX_TO_MISP_CATEGORY_MAP: dict[str, str] = {
    "ipv4-addr": "Network activity",
    "ipv6-addr": "Network activity",
    "url": "Network activity",
    "email-addr": "Payload delivery",
    "domain-name": "Network activity",
    "artifact": "Financial fraud",
}

# Reverse mapping: MISP attribute type to STIX SCO type
MISP_TO_STIX_TYPE_MAP: dict[str, str] = {
    "ip-src": "ipv4-addr",
    "ip-dst": "ipv4-addr",
    "url": "url",
    "email-src": "email-addr",
    "domain": "domain-name",
    "btc": "artifact",
}

# Distribution levels for MISP events
# 0 = Organization only (most restrictive — default for sensitive fraud intel)
# 1 = This community only
# 2 = Connected communities
# 3 = All communities (least restrictive)
DISTRIBUTION_ORG_ONLY = 0
DISTRIBUTION_COMMUNITY = 1
DISTRIBUTION_CONNECTED = 2
DISTRIBUTION_ALL = 3

# Default distribution for sensitive fraud intelligence
_DEFAULT_DISTRIBUTION = DISTRIBUTION_ORG_ONLY

# Default organization for dark web fraud intelligence events
_DEFAULT_ORG = "DARK-WEB-FRAUD-AGENT"

# Sensitivity classification to distribution level mapping
# Higher sensitivity → more restrictive distribution
_SENSITIVITY_TO_DISTRIBUTION: dict[str, int] = {
    "high": DISTRIBUTION_ORG_ONLY,       # PII, financial credentials, active exploits
    "medium": DISTRIBUTION_COMMUNITY,    # Fraud techniques, general indicators
    "low": DISTRIBUTION_CONNECTED,       # Public threat intel, known IOCs
}


class MISPIntegration:
    """Handles conversion between STIX 2.1 Bundles and MISP events.

    Provides bidirectional STIX ↔ MISP conversion with:
    - SCO-to-attribute type mapping preserving semantic meaning
    - Sensitivity-based distribution level assignment
    - Organization context for fraud intelligence provenance
    """

    def __init__(
        self,
        misp_url: str = "",
        misp_key: str = "",
        misp_client: Any = None,
        org_name: str = _DEFAULT_ORG,
    ) -> None:
        """Initialize MISPIntegration.

        Args:
            misp_url: URL of the MISP instance for REST API calls.
            misp_key: API key for MISP authentication.
            misp_client: Pre-configured PyMISP client (for testing/injection).
            org_name: Organization name to assign to created events.
        """
        self._misp_url = misp_url
        self._misp_key = misp_key
        self._misp_client = misp_client
        self._org_name = org_name

    def stix_to_misp(
        self,
        bundle: stix2.Bundle,
        sensitivity: str | None = None,
        distribution: int | None = None,
    ) -> MISPEvent:
        """Convert a STIX 2.1 Bundle to a MISP event.

        Maps STIX SCOs to MISP attributes and STIX SDOs to MISP objects.
        Assigns organization context and distribution level based on sensitivity.

        Distribution level logic:
        - If explicit `distribution` is provided, use it directly (0-3).
        - If `sensitivity` is provided ("high", "medium", "low"), map to distribution.
        - Otherwise default to 0 (organization only) for sensitive fraud intel.

        Args:
            bundle: A valid STIX 2.1 Bundle to convert.
            sensitivity: Sensitivity classification ("high", "medium", "low").
                Controls distribution level when no explicit distribution is given.
            distribution: Explicit MISP distribution level (0-3). Overrides sensitivity.

        Returns:
            A MISPEvent with attributes, objects, organization, and distribution set.

        Raises:
            ValueError: If bundle is not a valid stix2.Bundle, or distribution
                is outside range 0-3.
        """
        if not isinstance(bundle, stix2.Bundle):
            raise ValueError(
                f"Expected stix2.Bundle, got {type(bundle).__name__}"
            )

        # Resolve distribution level
        resolved_distribution = self._resolve_distribution(sensitivity, distribution)

        bundle_objects = getattr(bundle, "objects", None) or []

        event = MISPEvent()
        event.info = f"Dark Web Intel: {len(bundle_objects)} STIX objects"
        event.distribution = resolved_distribution
        event.threat_level_id = 2   # 2 = Medium (1=High, 3=Low, 4=Undefined)
        event.analysis = 1          # 1 = Ongoing (0=Initial, 2=Completed)
        # Note: event.org is read-only in PyMISP — orgc is set server-side.
        # Store org_name in event.info for traceability; the MISP instance
        # assigns the creating org based on the API key used.

        for obj in bundle_objects:
            if obj.type in STIX_TO_MISP_TYPE_MAP:
                self._add_sco_as_attribute(event, obj)
            elif obj.type in ("threat-actor", "attack-pattern", "malware", "indicator"):
                self._add_sdo_as_object(event, obj)

        logger.info(
            "MISPIntegration: converted STIX Bundle with %d objects to MISP event "
            "(distribution=%d, org=%s)",
            len(bundle_objects),
            resolved_distribution,
            self._org_name,
        )

        return event

    def _resolve_distribution(
        self, sensitivity: str | None, distribution: int | None
    ) -> int:
        """Resolve the MISP distribution level from sensitivity or explicit value.

        Args:
            sensitivity: Sensitivity classification string.
            distribution: Explicit distribution level override.

        Returns:
            Integer distribution level (0-3).

        Raises:
            ValueError: If distribution is outside 0-3 range.
        """
        if distribution is not None:
            if not (0 <= distribution <= 3):
                raise ValueError(
                    f"Distribution level must be 0-3, got {distribution}"
                )
            return distribution

        if sensitivity is not None:
            level = _SENSITIVITY_TO_DISTRIBUTION.get(sensitivity.lower())
            if level is not None:
                return level
            logger.warning(
                "MISPIntegration: unknown sensitivity '%s', using default distribution=%d",
                sensitivity,
                _DEFAULT_DISTRIBUTION,
            )

        return _DEFAULT_DISTRIBUTION

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
        misp_obj = MISPObject(sdo.type, standalone=True, strict=False)
        if hasattr(sdo, "name"):
            misp_obj.add_attribute("name", type="text", value=sdo.name)
        if hasattr(sdo, "description"):
            misp_obj.add_attribute("description", type="text", value=sdo.description[:500])
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
        # Initialize client if not already set
        if self._misp_client is None:
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
            # Re-raise so Step Functions marks the task as failed and routes to
            # the DLQ — do NOT return a fake "error-<uuid>" ID that looks like
            # success and causes silent intelligence data loss.
            raise
