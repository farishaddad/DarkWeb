"""Unit tests for extended EntityType and VALID_FRAUD_CATEGORIES.

Covers the 6 new entity types and 5 new fraud categories added to support
fraud patterns DC-007, DC-008, CHAPS-026, PS-001, and XC-007.
"""

import pytest

from dark_web_fraud_agent.models.content_analyst import (
    VALID_FRAUD_CATEGORIES,
    ClassifiedContent,
    EntityType,
    ExtractedEntity,
)


# ---------------------------------------------------------------------------
# EntityType — new members
# ---------------------------------------------------------------------------

class TestExtendedEntityTypes:
    """Verify the 6 new entity types are present and usable."""

    NEW_ENTITY_TYPES = {
        "merchant_id",
        "acquiring_bin",
        "national_id",
        "sort_code",
        "iban",
        "monero_wallet",
    }

    def test_new_entity_types_present_in_enum(self):
        """All 6 new entity types must be members of EntityType."""
        actual = {e.value for e in EntityType}
        missing = self.NEW_ENTITY_TYPES - actual
        assert missing == set(), f"Missing EntityType members: {missing}"

    def test_total_entity_type_count(self):
        """EntityType should now have 13 members (7 original + 6 new)."""
        assert len(EntityType) == 13

    @pytest.mark.parametrize("value", [
        "merchant_id",
        "acquiring_bin",
        "national_id",
        "sort_code",
        "iban",
        "monero_wallet",
    ])
    def test_new_entity_type_constructable_from_value(self, value):
        """Each new entity type is constructable from its string value."""
        et = EntityType(value)
        assert et.value == value

    @pytest.mark.parametrize("value", [
        "merchant_id",
        "acquiring_bin",
        "national_id",
        "sort_code",
        "iban",
        "monero_wallet",
    ])
    def test_new_entity_type_usable_in_extracted_entity(self, value):
        """ExtractedEntity accepts each new entity type without raising."""
        entity = ExtractedEntity(
            entity_type=value,
            value="test_value_123",
            context="surrounding context text",
            confidence=0.8,
        )
        assert entity.entity_type == value

    def test_merchant_id_enum_name(self):
        assert EntityType.MERCHANT_ID.value == "merchant_id"

    def test_monero_wallet_enum_name(self):
        assert EntityType.MONERO_WALLET.value == "monero_wallet"

    def test_iban_enum_name(self):
        assert EntityType.IBAN.value == "iban"

    def test_original_entity_types_preserved(self):
        """Adding new members must not remove any of the original 7."""
        original = {"bank_name", "bin_range", "swift_code", "btc_wallet",
                    "email", "url", "ip_address"}
        actual = {e.value for e in EntityType}
        assert original <= actual


# ---------------------------------------------------------------------------
# VALID_FRAUD_CATEGORIES — new entries
# ---------------------------------------------------------------------------

NEW_CATEGORIES = (
    "new_account_fraud",
    "recurring_billing_fraud",
    "money_mule",
    "investment_fraud",
    "social_engineering",
)

ORIGINAL_CATEGORIES = (
    "mfa_bypass",
    "synthetic_identity",
    "phishing_kit",
    "cnp_fraud",
    "account_takeover",
)


class TestExtendedFraudCategories:
    """Verify the 5 new fraud categories are present and accepted."""

    def test_total_category_count(self):
        """Should have 10 categories total (5 original + 5 new)."""
        assert len(VALID_FRAUD_CATEGORIES) == 10

    @pytest.mark.parametrize("category", NEW_CATEGORIES)
    def test_new_category_in_valid_list(self, category):
        assert category in VALID_FRAUD_CATEGORIES

    @pytest.mark.parametrize("category", ORIGINAL_CATEGORIES)
    def test_original_categories_preserved(self, category):
        assert category in VALID_FRAUD_CATEGORIES

    @pytest.mark.parametrize("category", NEW_CATEGORIES)
    def test_classified_content_accepts_new_category(self, category):
        """ClassifiedContent __post_init__ must accept every new category."""
        content = ClassifiedContent(
            source_ref="s3://bucket/test",
            is_fraud_relevant=True,
            confidence=0.9,
            requires_manual_review=False,
            severity_score=5,
            fraud_category=category,
        )
        assert content.fraud_category == category

    def test_invalid_category_still_raises(self):
        """Post-extension, unknown categories must still be rejected."""
        with pytest.raises(ValueError, match="fraud_category must be one of"):
            ClassifiedContent(
                source_ref="s3://bucket/test",
                is_fraud_relevant=True,
                confidence=0.9,
                requires_manual_review=False,
                severity_score=5,
                fraud_category="romance_scam",  # not a valid value
            )


# ---------------------------------------------------------------------------
# Pattern-grounded entity creation
# ---------------------------------------------------------------------------

class TestPatternEntityCreation:
    """Smoke tests grounded in the five annotated fraud patterns."""

    def test_dc007_fullz_entities(self):
        """DC-007: Fullz listing produces national_id, sort_code, bank_name entities."""
        entities = [
            ExtractedEntity("national_id", "AB123456C", "NI: AB123456C", 0.9),
            ExtractedEntity("sort_code", "20-00-00", "Sort: 20-00-00", 0.85),
            ExtractedEntity("bank_name", "Barclays", "targeting Barclays", 0.95),
            ExtractedEntity("bin_range", "453900", "BIN 453900", 0.9),
        ]
        content = ClassifiedContent(
            source_ref="s3://bucket/dc007",
            is_fraud_relevant=True,
            confidence=0.95,
            requires_manual_review=False,
            severity_score=8,
            fraud_category="new_account_fraud",
            entities=entities,
        )
        assert len(content.entities) == 4
        types = {e.entity_type for e in content.entities}
        assert "national_id" in types
        assert "sort_code" in types

    def test_dc008_card_dump_entities(self):
        """DC-008: Card dump listing produces bin_range and bank_name entities."""
        entities = [
            ExtractedEntity("bin_range", "453200", "BIN 453200 HSBC", 0.92),
            ExtractedEntity("bank_name", "HSBC", "HSBC debit", 0.9),
        ]
        content = ClassifiedContent(
            source_ref="s3://bucket/dc008",
            is_fraud_relevant=True,
            confidence=0.93,
            requires_manual_review=False,
            severity_score=8,  # post-record-count boost from 6
            fraud_category="recurring_billing_fraud",
            entities=entities,
        )
        assert content.severity_score == 8
        assert content.fraud_category == "recurring_billing_fraud"

    def test_chaps026_mule_entities(self):
        """CHAPS-026: Credential listing produces bank_name + iban entities."""
        entities = [
            ExtractedEntity("bank_name", "HSBC", "CHAPS-enabled HSBC account", 0.9),
            ExtractedEntity("iban", "GB29NWBK60161331926819", "IBAN GB29...", 0.8),
            ExtractedEntity("swift_code", "HBUKGB4B", "BIC HBUKGB4B", 0.88),
        ]
        content = ClassifiedContent(
            source_ref="s3://bucket/chaps026",
            is_fraud_relevant=True,
            confidence=0.91,
            requires_manual_review=False,
            severity_score=9,
            fraud_category="money_mule",
            entities=entities,
        )
        assert "iban" in {e.entity_type for e in content.entities}

    def test_ps001_merchant_entities(self):
        """PS-001: Purchase scam listing produces merchant_id and acquiring_bin."""
        entities = [
            ExtractedEntity("merchant_id", "529910000000001", "MID: 529910000000001", 0.7),
            ExtractedEntity("acquiring_bin", "529910", "acquiring BIN 529910", 0.75),
            ExtractedEntity("url", "https://scam-store.example.com", "storefront URL", 0.9),
        ]
        content = ClassifiedContent(
            source_ref="s3://bucket/ps001",
            is_fraud_relevant=True,
            confidence=0.88,
            requires_manual_review=False,
            severity_score=7,
            fraud_category="phishing_kit",
            entities=entities,
        )
        types = {e.entity_type for e in content.entities}
        assert "merchant_id" in types
        assert "acquiring_bin" in types

    def test_xc007_pig_butchering_entities(self):
        """XC-007: Pig-butchering laundering chain produces monero_wallet entity."""
        entities = [
            ExtractedEntity(
                "monero_wallet",
                "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
                "wash via XMR wallet 44AFF...",
                0.85,
            ),
            ExtractedEntity("btc_wallet", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                            "initial USDT converted via", 0.9),
        ]
        content = ClassifiedContent(
            source_ref="s3://bucket/xc007",
            is_fraud_relevant=True,
            confidence=0.87,
            requires_manual_review=False,
            severity_score=7,
            fraud_category="investment_fraud",
            entities=entities,
        )
        assert "monero_wallet" in {e.entity_type for e in content.entities}
        assert content.fraud_category == "investment_fraud"
