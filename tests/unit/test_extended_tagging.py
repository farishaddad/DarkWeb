"""Unit tests for extended tagging engine coverage.

Covers the 5 new ATT&CK mappings, new entity fraud tags (merchant_id,
monero_wallet, iban), extended MISP Galaxy clusters, and sub-technique
tags for investment_fraud (T1583.006) and social_engineering (T1598.003).
"""

import pytest

from dark_web_fraud_agent.agents.tagging_engine import MachineTag, TaggingEngine
from dark_web_fraud_agent.models.content_analyst import EntityType, ExtractedEntity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine() -> TaggingEngine:
    return TaggingEngine()


def _entity(etype: str, value: str = "test_value") -> ExtractedEntity:
    return ExtractedEntity(
        entity_type=etype,
        value=value,
        context="surrounding context",
        confidence=0.8,
    )


# ---------------------------------------------------------------------------
# apply_attack_tags — new categories
# ---------------------------------------------------------------------------

class TestExtendedAttackTags:
    """apply_attack_tags produces correct ATT&CK technique tags for new categories."""

    @pytest.mark.parametrize("category,expected_technique", [
        ("new_account_fraud",       "T1136"),
        ("recurring_billing_fraud", "T1499"),
        ("money_mule",              "T1531"),
        ("investment_fraud",        "T1583"),
        ("social_engineering",      "T1598"),
    ])
    def test_new_category_maps_to_technique(self, category, expected_technique):
        engine = _engine()
        tags = engine.apply_attack_tags(category)
        tag_strings = [str(t) for t in tags]
        assert any(expected_technique in s for s in tag_strings), (
            f"Expected {expected_technique} in tags for {category}: {tag_strings}"
        )

    def test_investment_fraud_has_sub_technique(self):
        """investment_fraud should emit T1583.006 sub-technique tag."""
        engine = _engine()
        tags = engine.apply_attack_tags("investment_fraud")
        tag_strings = [str(t) for t in tags]
        assert any("T1583.006" in s for s in tag_strings), (
            f"Expected T1583.006 sub-technique for investment_fraud: {tag_strings}"
        )

    def test_social_engineering_has_sub_technique(self):
        """social_engineering should emit T1598.003 sub-technique tag."""
        engine = _engine()
        tags = engine.apply_attack_tags("social_engineering")
        tag_strings = [str(t) for t in tags]
        assert any("T1598.003" in s for s in tag_strings), (
            f"Expected T1598.003 sub-technique for social_engineering: {tag_strings}"
        )

    def test_new_account_fraud_no_sub_technique(self):
        """new_account_fraud has no sub-technique — should not emit T1136.xxx."""
        engine = _engine()
        tags = engine.apply_attack_tags("new_account_fraud")
        tag_strings = [str(t) for t in tags]
        sub_tech = [s for s in tag_strings if "T1136." in s]
        assert sub_tech == [], f"Unexpected sub-technique tags: {sub_tech}"

    def test_original_categories_unaffected(self):
        """Adding new categories must not change output for existing ones."""
        engine = _engine()
        mfa_tags = [str(t) for t in engine.apply_attack_tags("mfa_bypass")]
        assert any("T1111" in t for t in mfa_tags)


# ---------------------------------------------------------------------------
# apply_fraud_tags — new entity types
# ---------------------------------------------------------------------------

class TestExtendedEntityFraudTags:
    """New entity types produce the correct fraud: taxonomy tags."""

    @pytest.mark.parametrize("entity_type,expected_tag_fragment", [
        ("monero_wallet",  "crypto-laundering"),
        ("merchant_id",    "merchant-account-fraud"),
        ("acquiring_bin",  "acquiring-bin-abuse"),
        ("iban",           "cross-border-transfer"),
        ("national_id",    "identity-document-fraud"),
    ])
    def test_new_entity_produces_fraud_tag(self, entity_type, expected_tag_fragment):
        engine = _engine()
        entities = [_entity(entity_type)]
        tags = engine.apply_fraud_tags(entities)
        tag_strings = [str(t) for t in tags]
        assert any(expected_tag_fragment in s for s in tag_strings), (
            f"Expected {expected_tag_fragment!r} for entity_type={entity_type}: {tag_strings}"
        )

    def test_monero_wallet_produces_crypto_laundering_not_crypto_fraud(self):
        """Monero must produce crypto-laundering, not the existing crypto-fraud tag."""
        engine = _engine()
        tags = engine.apply_fraud_tags([_entity("monero_wallet")])
        tag_strings = [str(t) for t in tags]
        assert any("crypto-laundering" in t for t in tag_strings)
        # crypto-fraud is for BTC wallets; Monero should NOT produce it
        assert not any("crypto-fraud" in t for t in tag_strings)

    def test_btc_wallet_still_produces_crypto_fraud(self):
        """Existing btc_wallet → crypto-fraud tag must be preserved."""
        engine = _engine()
        tags = engine.apply_fraud_tags([_entity("btc_wallet", "bc1qtest")])
        tag_strings = [str(t) for t in tags]
        assert any("crypto-fraud" in t for t in tag_strings)

    def test_bank_name_still_produces_target_tag(self):
        """Existing bank_name → fraud:target tag must be preserved."""
        engine = _engine()
        tags = engine.apply_fraud_tags([_entity("bank_name", "HSBC")])
        tag_strings = [str(t) for t in tags]
        assert any('fraud:target="hsbc"' in t for t in tag_strings)

    def test_mixed_entities_produce_multiple_tags(self):
        """A signal with monero_wallet + merchant_id produces both new tags."""
        engine = _engine()
        entities = [
            _entity("monero_wallet"),
            _entity("merchant_id", "529910000000001"),
        ]
        tags = engine.apply_fraud_tags(entities)
        tag_strings = [str(t) for t in tags]
        assert any("crypto-laundering" in t for t in tag_strings)
        assert any("merchant-account-fraud" in t for t in tag_strings)


# ---------------------------------------------------------------------------
# match_galaxy_cluster — new categories
# ---------------------------------------------------------------------------

class TestExtendedGalaxyCluster:
    """match_galaxy_cluster returns correct galaxy entries for new categories."""

    @pytest.mark.parametrize("category,expected_cluster_fragment", [
        ("new_account_fraud",       "New Account Fraud"),
        ("recurring_billing_fraud", "Recurring Billing"),
        ("money_mule",              "Money Mule"),
        ("investment_fraud",        "Pig Butchering"),
        ("social_engineering",      "Romance Scam"),
    ])
    def test_new_category_has_galaxy_entry(self, category, expected_cluster_fragment):
        engine = _engine()
        match = engine.match_galaxy_cluster(category)
        assert match is not None, f"No galaxy match for {category}"
        assert expected_cluster_fragment in match["cluster_value"], (
            f"Expected {expected_cluster_fragment!r} in cluster_value for {category}: "
            f"{match['cluster_value']!r}"
        )

    def test_investment_fraud_galaxy_is_financial_fraud(self):
        engine = _engine()
        match = engine.match_galaxy_cluster("investment_fraud")
        assert match["galaxy"] == "financial-fraud"

    def test_social_engineering_galaxy_is_social_engineering(self):
        engine = _engine()
        match = engine.match_galaxy_cluster("social_engineering")
        assert match["galaxy"] == "social-engineering"

    def test_original_categories_galaxy_unaffected(self):
        """Existing mfa_bypass galaxy entry must still resolve correctly."""
        engine = _engine()
        match = engine.match_galaxy_cluster("mfa_bypass")
        assert match is not None
        assert match["cluster_value"] == "MFA Bypass"

    def test_unknown_category_returns_none(self):
        engine = _engine()
        assert engine.match_galaxy_cluster("unknown_category") is None


# ---------------------------------------------------------------------------
# New regex patterns
# ---------------------------------------------------------------------------

class TestNewRegexPatterns:
    """Verify _MONERO_PATTERN, _MID_PATTERN, _IBAN_PATTERN, _SORT_CODE_PATTERN exist."""

    def test_monero_pattern_imported(self):
        from dark_web_fraud_agent.agents.content_analyst import _MONERO_PATTERN
        assert _MONERO_PATTERN is not None

    def test_mid_pattern_imported(self):
        from dark_web_fraud_agent.agents.content_analyst import _MID_PATTERN
        assert _MID_PATTERN is not None

    def test_iban_pattern_imported(self):
        from dark_web_fraud_agent.agents.content_analyst import _IBAN_PATTERN
        assert _IBAN_PATTERN is not None

    def test_sort_code_pattern_imported(self):
        from dark_web_fraud_agent.agents.content_analyst import _SORT_CODE_PATTERN
        assert _SORT_CODE_PATTERN is not None

    def test_monero_pattern_matches_valid_address(self):
        from dark_web_fraud_agent.agents.content_analyst import _MONERO_PATTERN
        # Standard 95-char Monero address starting with 4
        addr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
        assert len(addr) == 95
        match = _MONERO_PATTERN.search(addr)
        assert match is not None

    def test_iban_pattern_matches_uk_iban(self):
        from dark_web_fraud_agent.agents.content_analyst import _IBAN_PATTERN
        match = _IBAN_PATTERN.search("account IBAN: GB29NWBK60161331926819 confirmed")
        assert match is not None
        assert "GB29" in match.group(0)

    def test_sort_code_pattern_matches_hyphenated(self):
        from dark_web_fraud_agent.agents.content_analyst import _SORT_CODE_PATTERN
        match = _SORT_CODE_PATTERN.search("sort code 20-00-00 for Barclays")
        assert match is not None

    def test_mid_pattern_matches_15_digits(self):
        from dark_web_fraud_agent.agents.content_analyst import _MID_PATTERN
        match = _MID_PATTERN.search("MID: 529910000000001 registered")
        assert match is not None
        assert match.group(1) == "529910000000001"
