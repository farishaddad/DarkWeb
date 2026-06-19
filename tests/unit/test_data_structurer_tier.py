"""Unit tests for intelligence tier classification in DataStructurer.

Tests cover:
- classify_tier(): Observable, Indicator, and TTP classification logic
- create_tier_links(): referential link creation between tiers
"""

import pytest

from dark_web_fraud_agent.agents.data_structurer import DataStructurer
from dark_web_fraud_agent.models.content_analyst import ClassifiedContent, ExtractedEntity
from dark_web_fraud_agent.models.shared import IntelligenceTier, TierLink


@pytest.fixture
def structurer() -> DataStructurer:
    """Create a DataStructurer instance for testing."""
    return DataStructurer()


# --- Helper factories ---


def _make_entity(entity_type: str = "ip_address", value: str = "192.168.1.1") -> ExtractedEntity:
    """Create an ExtractedEntity with defaults."""
    return ExtractedEntity(
        entity_type=entity_type,
        value=value,
        context="test context",
        confidence=0.9,
    )


def _make_content(
    entities: list[ExtractedEntity] | None = None,
    fraud_category: str | None = None,
    severity_score: int = 5,
) -> ClassifiedContent:
    """Create a ClassifiedContent with defaults."""
    return ClassifiedContent(
        source_ref="s3://bucket/test-artifact",
        is_fraud_relevant=True,
        confidence=0.85,
        requires_manual_review=False,
        severity_score=severity_score,
        fraud_category=fraud_category,
        entities=entities or [],
        raw_text_snippet="Test content snippet",
        bedrock_guardrail_result="PASSED",
    )


# --- classify_tier() tests ---


class TestClassifyTierObservable:
    """Tests for Observable tier classification."""

    def test_single_ip_address_is_observable(self, structurer: DataStructurer) -> None:
        """A single IP address with no fraud category is an Observable."""
        content = _make_content(
            entities=[_make_entity("ip_address", "10.0.0.1")],
            fraud_category=None,
            severity_score=3,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.OBSERVABLE

    def test_single_url_is_observable(self, structurer: DataStructurer) -> None:
        """A single URL with no fraud category is an Observable."""
        content = _make_content(
            entities=[_make_entity("url", "http://example.onion")],
            fraud_category=None,
            severity_score=2,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.OBSERVABLE

    def test_single_email_is_observable(self, structurer: DataStructurer) -> None:
        """A single email with no fraud category is an Observable."""
        content = _make_content(
            entities=[_make_entity("email", "bad@evil.com")],
            fraud_category=None,
            severity_score=4,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.OBSERVABLE

    def test_single_btc_wallet_is_observable(self, structurer: DataStructurer) -> None:
        """A single BTC wallet with no fraud category is an Observable."""
        content = _make_content(
            entities=[_make_entity("btc_wallet", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")],
            fraud_category=None,
            severity_score=3,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.OBSERVABLE

    def test_no_entities_no_category_is_observable(self, structurer: DataStructurer) -> None:
        """Content with no entities and no fraud category is an Observable."""
        content = _make_content(entities=[], fraud_category=None, severity_score=2)
        assert structurer.classify_tier(content) == IntelligenceTier.OBSERVABLE

    def test_single_atomic_entity_low_severity_is_observable(self, structurer: DataStructurer) -> None:
        """Low-severity content with a single atomic entity is an Observable."""
        content = _make_content(
            entities=[_make_entity("ip_address", "172.16.0.1")],
            fraud_category=None,
            severity_score=1,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.OBSERVABLE


class TestClassifyTierIndicator:
    """Tests for Indicator tier classification."""

    def test_cnp_fraud_category_is_indicator(self, structurer: DataStructurer) -> None:
        """Content with cnp_fraud category is an Indicator."""
        content = _make_content(
            entities=[_make_entity("ip_address", "10.0.0.1")],
            fraud_category="cnp_fraud",
            severity_score=5,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.INDICATOR

    def test_multiple_diverse_entity_types_is_indicator(self, structurer: DataStructurer) -> None:
        """Content with multiple diverse entity types is an Indicator (composite pattern)."""
        content = _make_content(
            entities=[
                _make_entity("ip_address", "10.0.0.1"),
                _make_entity("email", "fraud@dark.net"),
            ],
            fraud_category=None,
            severity_score=4,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.INDICATOR

    def test_three_different_entity_types_is_indicator(self, structurer: DataStructurer) -> None:
        """Content with three different entity types is an Indicator."""
        content = _make_content(
            entities=[
                _make_entity("ip_address", "10.0.0.1"),
                _make_entity("url", "http://evil.onion"),
                _make_entity("btc_wallet", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            ],
            fraud_category=None,
            severity_score=4,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.INDICATOR


class TestClassifyTierTTP:
    """Tests for TTP tier classification."""

    def test_mfa_bypass_is_ttp(self, structurer: DataStructurer) -> None:
        """Content with mfa_bypass fraud category is a TTP."""
        content = _make_content(
            entities=[_make_entity("url", "http://bypass-tool.onion")],
            fraud_category="mfa_bypass",
            severity_score=8,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.TTP

    def test_synthetic_identity_is_ttp(self, structurer: DataStructurer) -> None:
        """Content with synthetic_identity fraud category is a TTP."""
        content = _make_content(
            entities=[],
            fraud_category="synthetic_identity",
            severity_score=7,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.TTP

    def test_phishing_kit_is_ttp(self, structurer: DataStructurer) -> None:
        """Content with phishing_kit fraud category is a TTP."""
        content = _make_content(
            entities=[_make_entity("url", "http://phish.onion")],
            fraud_category="phishing_kit",
            severity_score=9,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.TTP

    def test_account_takeover_is_ttp(self, structurer: DataStructurer) -> None:
        """Content with account_takeover fraud category is a TTP."""
        content = _make_content(
            entities=[_make_entity("email", "victim@bank.com")],
            fraud_category="account_takeover",
            severity_score=8,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.TTP

    def test_high_severity_with_non_atomic_entities_is_ttp(self, structurer: DataStructurer) -> None:
        """High-severity content with non-atomic entities and a fraud category is a TTP."""
        content = _make_content(
            entities=[_make_entity("bank_name", "Chase Bank")],
            fraud_category="cnp_fraud",
            severity_score=8,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.TTP


class TestClassifyTierEdgeCases:
    """Edge case tests for tier classification."""

    def test_returns_exactly_one_tier(self, structurer: DataStructurer) -> None:
        """classify_tier always returns exactly one IntelligenceTier value."""
        content = _make_content(
            entities=[_make_entity("ip_address", "1.2.3.4")],
            fraud_category=None,
            severity_score=5,
        )
        result = structurer.classify_tier(content)
        assert isinstance(result, IntelligenceTier)
        assert result in {IntelligenceTier.OBSERVABLE, IntelligenceTier.INDICATOR, IntelligenceTier.TTP}

    def test_ttp_takes_priority_over_indicator(self, structurer: DataStructurer) -> None:
        """TTP classification takes priority when both TTP and Indicator criteria match."""
        # This has mfa_bypass (TTP) AND multiple entity types (Indicator)
        content = _make_content(
            entities=[
                _make_entity("ip_address", "10.0.0.1"),
                _make_entity("email", "attacker@dark.net"),
            ],
            fraud_category="mfa_bypass",
            severity_score=9,
        )
        assert structurer.classify_tier(content) == IntelligenceTier.TTP


# --- create_tier_links() tests ---


class TestCreateTierLinks:
    """Tests for create_tier_links() referential link creation."""

    def test_empty_items_returns_empty_links(self, structurer: DataStructurer) -> None:
        """No items produce no links."""
        links = structurer.create_tier_links([])
        assert links == []

    def test_single_observable_no_links(self, structurer: DataStructurer) -> None:
        """A single observable with no indicators/TTPs produces no links."""
        items = [("obs-1", IntelligenceTier.OBSERVABLE)]
        links = structurer.create_tier_links(items)
        assert links == []

    def test_observable_to_indicator_link(self, structurer: DataStructurer) -> None:
        """Observable → Indicator creates a 'supports' link."""
        items = [
            ("obs-1", IntelligenceTier.OBSERVABLE),
            ("ind-1", IntelligenceTier.INDICATOR),
        ]
        links = structurer.create_tier_links(items)
        assert len(links) == 1
        assert links[0].source_id == "obs-1"
        assert links[0].source_tier == IntelligenceTier.OBSERVABLE
        assert links[0].target_id == "ind-1"
        assert links[0].target_tier == IntelligenceTier.INDICATOR
        assert links[0].relationship_type == "supports"

    def test_indicator_to_ttp_link(self, structurer: DataStructurer) -> None:
        """Indicator → TTP creates an 'implements' link."""
        items = [
            ("ind-1", IntelligenceTier.INDICATOR),
            ("ttp-1", IntelligenceTier.TTP),
        ]
        links = structurer.create_tier_links(items)
        assert len(links) == 1
        assert links[0].source_id == "ind-1"
        assert links[0].source_tier == IntelligenceTier.INDICATOR
        assert links[0].target_id == "ttp-1"
        assert links[0].target_tier == IntelligenceTier.TTP
        assert links[0].relationship_type == "implements"

    def test_full_chain_observable_indicator_ttp(self, structurer: DataStructurer) -> None:
        """Full chain: Observable → Indicator → TTP creates both links."""
        items = [
            ("obs-1", IntelligenceTier.OBSERVABLE),
            ("ind-1", IntelligenceTier.INDICATOR),
            ("ttp-1", IntelligenceTier.TTP),
        ]
        links = structurer.create_tier_links(items)
        assert len(links) == 2

        # Observable → Indicator
        supports_links = [l for l in links if l.relationship_type == "supports"]
        assert len(supports_links) == 1
        assert supports_links[0].source_id == "obs-1"
        assert supports_links[0].target_id == "ind-1"

        # Indicator → TTP
        implements_links = [l for l in links if l.relationship_type == "implements"]
        assert len(implements_links) == 1
        assert implements_links[0].source_id == "ind-1"
        assert implements_links[0].target_id == "ttp-1"

    def test_multiple_observables_to_one_indicator(self, structurer: DataStructurer) -> None:
        """Multiple observables each link to a single indicator."""
        items = [
            ("obs-1", IntelligenceTier.OBSERVABLE),
            ("obs-2", IntelligenceTier.OBSERVABLE),
            ("ind-1", IntelligenceTier.INDICATOR),
        ]
        links = structurer.create_tier_links(items)
        assert len(links) == 2
        source_ids = {l.source_id for l in links}
        assert source_ids == {"obs-1", "obs-2"}
        assert all(l.target_id == "ind-1" for l in links)
        assert all(l.relationship_type == "supports" for l in links)

    def test_multiple_indicators_to_one_ttp(self, structurer: DataStructurer) -> None:
        """Multiple indicators each link to a single TTP."""
        items = [
            ("ind-1", IntelligenceTier.INDICATOR),
            ("ind-2", IntelligenceTier.INDICATOR),
            ("ttp-1", IntelligenceTier.TTP),
        ]
        links = structurer.create_tier_links(items)
        assert len(links) == 2
        source_ids = {l.source_id for l in links}
        assert source_ids == {"ind-1", "ind-2"}
        assert all(l.target_id == "ttp-1" for l in links)
        assert all(l.relationship_type == "implements" for l in links)

    def test_many_to_many_links(self, structurer: DataStructurer) -> None:
        """Multiple items at each tier create a full mesh of links."""
        items = [
            ("obs-1", IntelligenceTier.OBSERVABLE),
            ("obs-2", IntelligenceTier.OBSERVABLE),
            ("ind-1", IntelligenceTier.INDICATOR),
            ("ind-2", IntelligenceTier.INDICATOR),
            ("ttp-1", IntelligenceTier.TTP),
        ]
        links = structurer.create_tier_links(items)
        # 2 obs × 2 ind = 4 "supports" links + 2 ind × 1 ttp = 2 "implements" links
        assert len(links) == 6
        supports = [l for l in links if l.relationship_type == "supports"]
        implements = [l for l in links if l.relationship_type == "implements"]
        assert len(supports) == 4
        assert len(implements) == 2

    def test_only_ttps_no_links(self, structurer: DataStructurer) -> None:
        """Only TTP items produce no links (no cross-tier connections)."""
        items = [
            ("ttp-1", IntelligenceTier.TTP),
            ("ttp-2", IntelligenceTier.TTP),
        ]
        links = structurer.create_tier_links(items)
        assert links == []

    def test_link_objects_are_tier_link_instances(self, structurer: DataStructurer) -> None:
        """All returned links are TierLink instances."""
        items = [
            ("obs-1", IntelligenceTier.OBSERVABLE),
            ("ind-1", IntelligenceTier.INDICATOR),
            ("ttp-1", IntelligenceTier.TTP),
        ]
        links = structurer.create_tier_links(items)
        for link in links:
            assert isinstance(link, TierLink)
