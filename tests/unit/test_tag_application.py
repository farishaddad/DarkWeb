"""Unit tests for tag application methods in the Tagging Engine."""

import pytest

from dark_web_fraud_agent.agents.tagging_engine import MachineTag, TaggingEngine
from dark_web_fraud_agent.models.content_analyst import ExtractedEntity


class TestApplyFraudTags:
    """Tests for apply_fraud_tags method."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def test_swift_keyword_in_value_produces_swift_transfer_tag(self):
        """Entity value containing 'SWIFT' triggers swift-transfer tag."""
        entities = [
            ExtractedEntity(
                entity_type="swift_code",
                value="SWIFT DEUTDEFF",
                context="Transfer via SWIFT network",
                confidence=0.9,
            )
        ]
        tags = self.engine.apply_fraud_tags(entities)
        assert MachineTag("fraud", "type", "swift-transfer") in tags

    def test_swift_keyword_case_insensitive(self):
        """SWIFT detection is case-insensitive (matches 'swift' in value)."""
        entities = [
            ExtractedEntity(
                entity_type="swift_code",
                value="swift code BOFAUS3N",
                context="International transfer",
                confidence=0.85,
            )
        ]
        tags = self.engine.apply_fraud_tags(entities)
        assert MachineTag("fraud", "type", "swift-transfer") in tags

    def test_bin_range_entity_produces_bin_attack_tag(self):
        """Entity of type bin_range triggers bin-attack tag."""
        entities = [
            ExtractedEntity(
                entity_type="bin_range",
                value="411111",
                context="Visa BIN range for sale",
                confidence=0.95,
            )
        ]
        tags = self.engine.apply_fraud_tags(entities)
        assert MachineTag("fraud", "type", "bin-attack") in tags

    def test_btc_wallet_entity_produces_crypto_fraud_tag(self):
        """Entity of type btc_wallet triggers crypto-fraud tag."""
        entities = [
            ExtractedEntity(
                entity_type="btc_wallet",
                value="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                context="Payment address for stolen cards",
                confidence=0.92,
            )
        ]
        tags = self.engine.apply_fraud_tags(entities)
        assert MachineTag("fraud", "type", "crypto-fraud") in tags

    def test_bank_name_entity_produces_fraud_target_tag(self):
        """Entity of type bank_name triggers fraud:target with lowercased value."""
        entities = [
            ExtractedEntity(
                entity_type="bank_name",
                value="Chase Bank",
                context="Targeting Chase Bank customers",
                confidence=0.88,
            )
        ]
        tags = self.engine.apply_fraud_tags(entities)
        assert MachineTag("fraud", "target", "chase bank") in tags

    def test_multiple_entities_produce_multiple_tags(self):
        """Multiple matching entities produce corresponding tags."""
        entities = [
            ExtractedEntity(
                entity_type="bin_range",
                value="523456",
                context="Mastercard BIN",
                confidence=0.9,
            ),
            ExtractedEntity(
                entity_type="btc_wallet",
                value="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                context="BTC wallet for payment",
                confidence=0.85,
            ),
            ExtractedEntity(
                entity_type="bank_name",
                value="Wells Fargo",
                context="Targeted institution",
                confidence=0.91,
            ),
        ]
        tags = self.engine.apply_fraud_tags(entities)
        assert MachineTag("fraud", "type", "bin-attack") in tags
        assert MachineTag("fraud", "type", "crypto-fraud") in tags
        assert MachineTag("fraud", "target", "wells fargo") in tags

    def test_empty_entities_returns_empty_list(self):
        """Empty entities list returns empty tags list."""
        tags = self.engine.apply_fraud_tags([])
        assert tags == []

    def test_non_matching_entity_returns_empty_list(self):
        """Entity not matching any rule returns no tags."""
        entities = [
            ExtractedEntity(
                entity_type="email",
                value="user@example.com",
                context="Contact email",
                confidence=0.8,
            )
        ]
        tags = self.engine.apply_fraud_tags(entities)
        assert tags == []


class TestApplyAttackTags:
    """Tests for apply_attack_tags method."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def test_mfa_bypass_maps_to_t1111(self):
        tags = self.engine.apply_attack_tags("mfa_bypass")
        assert tags == [MachineTag("mitre-attack", "technique", "T1111")]

    def test_phishing_kit_maps_to_t1566_with_sub_technique(self):
        tags = self.engine.apply_attack_tags("phishing_kit")
        assert MachineTag("mitre-attack", "technique", "T1566") in tags
        assert MachineTag("mitre-attack", "technique", "T1566.001") in tags

    def test_account_takeover_maps_to_t1078_with_sub_technique(self):
        tags = self.engine.apply_attack_tags("account_takeover")
        assert MachineTag("mitre-attack", "technique", "T1078") in tags
        assert MachineTag("mitre-attack", "technique", "T1078.001") in tags

    def test_synthetic_identity_maps_to_t1585_with_sub_technique(self):
        tags = self.engine.apply_attack_tags("synthetic_identity")
        assert MachineTag("mitre-attack", "technique", "T1585") in tags
        assert MachineTag("mitre-attack", "technique", "T1585.001") in tags

    def test_cnp_fraud_maps_to_t1539(self):
        tags = self.engine.apply_attack_tags("cnp_fraud")
        assert tags == [MachineTag("mitre-attack", "technique", "T1539")]

    def test_none_returns_empty_list(self):
        tags = self.engine.apply_attack_tags(None)
        assert tags == []

    def test_unknown_category_returns_empty_list(self):
        tags = self.engine.apply_attack_tags("unknown_category")
        assert tags == []


class TestApplyThreatLevelTag:
    """Tests for apply_threat_level_tag method."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def test_severity_1_produces_low_tag(self):
        tag = self.engine.apply_threat_level_tag(1)
        assert tag == MachineTag("threat-level", "level", "low")

    def test_severity_3_produces_low_tag(self):
        tag = self.engine.apply_threat_level_tag(3)
        assert tag == MachineTag("threat-level", "level", "low")

    def test_severity_4_produces_medium_tag(self):
        tag = self.engine.apply_threat_level_tag(4)
        assert tag == MachineTag("threat-level", "level", "medium")

    def test_severity_6_produces_medium_tag(self):
        tag = self.engine.apply_threat_level_tag(6)
        assert tag == MachineTag("threat-level", "level", "medium")

    def test_severity_7_produces_high_tag(self):
        tag = self.engine.apply_threat_level_tag(7)
        assert tag == MachineTag("threat-level", "level", "high")

    def test_severity_9_produces_high_tag(self):
        tag = self.engine.apply_threat_level_tag(9)
        assert tag == MachineTag("threat-level", "level", "high")

    def test_severity_10_produces_critical_tag(self):
        tag = self.engine.apply_threat_level_tag(10)
        assert tag == MachineTag("threat-level", "level", "critical")

    def test_tag_format(self):
        """Verify the string representation of the tag."""
        tag = self.engine.apply_threat_level_tag(7)
        assert str(tag) == 'threat-level:level="high"'
