"""Unit tests for Tagging Engine - galaxy cluster matching, requires-review, and tag_event orchestration."""

import pytest

from dark_web_fraud_agent.agents.tagging_engine import MachineTag, TaggingEngine
from dark_web_fraud_agent.models.content_analyst import ExtractedEntity


class TestApplyRequiresReviewTag:
    """Tests for apply_requires_review_tag."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def test_returns_machine_tag(self):
        """apply_requires_review_tag returns a MachineTag instance."""
        tag = self.engine.apply_requires_review_tag()
        assert isinstance(tag, MachineTag)

    def test_tag_namespace_is_review(self):
        """The requires-review tag has namespace 'review'."""
        tag = self.engine.apply_requires_review_tag()
        assert tag.namespace == "review"

    def test_tag_predicate_is_status(self):
        """The requires-review tag has predicate 'status'."""
        tag = self.engine.apply_requires_review_tag()
        assert tag.predicate == "status"

    def test_tag_value_is_requires_review(self):
        """The requires-review tag has value 'requires-review'."""
        tag = self.engine.apply_requires_review_tag()
        assert tag.value == "requires-review"

    def test_tag_str_format(self):
        """The requires-review tag renders correctly as a string."""
        tag = self.engine.apply_requires_review_tag()
        assert str(tag) == 'review:status="requires-review"'


class TestMatchGalaxyCluster:
    """Tests for match_galaxy_cluster."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def test_mfa_bypass_maps_to_galaxy(self):
        """mfa_bypass maps to MFA Bypass galaxy cluster via static fallback."""
        result = self.engine.match_galaxy_cluster("mfa_bypass")
        assert result is not None
        assert result["galaxy"] == "mitre-attack-pattern"
        assert result["cluster_uuid"] == "mfa-bypass-001"
        assert result["cluster_value"] == "MFA Bypass"
        assert result["source"] == "static"

    def test_phishing_kit_maps_to_galaxy(self):
        """phishing_kit maps to Phishing galaxy cluster."""
        result = self.engine.match_galaxy_cluster("phishing_kit")
        assert result is not None
        assert result["galaxy"] == "mitre-attack-pattern"
        assert result["cluster_uuid"] == "phishing-001"
        assert result["cluster_value"] == "Phishing"

    def test_account_takeover_maps_to_galaxy(self):
        """account_takeover maps to Account Takeover galaxy cluster."""
        result = self.engine.match_galaxy_cluster("account_takeover")
        assert result is not None
        assert result["galaxy"] == "mitre-attack-pattern"
        assert result["cluster_uuid"] == "ato-001"
        assert result["cluster_value"] == "Account Takeover"

    def test_none_category_returns_none(self):
        """None fraud_category returns None (no galaxy match)."""
        result = self.engine.match_galaxy_cluster(None)
        assert result is None

    def test_unknown_category_returns_none(self):
        """An unmapped fraud category returns None."""
        result = self.engine.match_galaxy_cluster("some_unknown_category")
        assert result is None

    def test_cnp_fraud_returns_none(self):
        """cnp_fraud is not in the galaxy map and returns None."""
        result = self.engine.match_galaxy_cluster("cnp_fraud")
        assert result is None

    def test_empty_string_returns_none(self):
        """Empty string returns None."""
        result = self.engine.match_galaxy_cluster("")
        assert result is None


class TestTagEvent:
    """Tests for tag_event orchestration method."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def _make_entity(self, entity_type: str, value: str) -> ExtractedEntity:
        """Helper to create an ExtractedEntity with defaults."""
        return ExtractedEntity(
            entity_type=entity_type,
            value=value,
            context="test context",
            confidence=0.9,
        )

    def test_with_fraud_entities_and_category(self):
        """tag_event produces fraud + attack + threat-level tags when both match."""
        entities = [self._make_entity("bin_range", "411111")]
        tags = self.engine.tag_event(entities, "phishing_kit", severity=7)

        # Should have fraud tag (bin-attack), attack tag (T1566), and threat-level tag
        namespaces = [t.namespace for t in tags]
        assert "fraud" in namespaces
        assert "mitre-attack" in namespaces
        assert "threat-level" in namespaces
        # Should NOT have requires-review since we have fraud and attack tags
        assert not any(t.value == "requires-review" for t in tags)

    def test_with_no_fraud_entities_and_no_category_adds_review_tag(self):
        """tag_event adds requires-review when no fraud or attack tags match."""
        entities = [self._make_entity("email", "test@example.com")]
        tags = self.engine.tag_event(entities, None, severity=3)

        # email entity doesn't produce fraud tags, None category produces no attack tags
        assert any(t.value == "requires-review" for t in tags)
        # Should still have threat-level tag
        assert any(t.namespace == "threat-level" for t in tags)

    def test_with_fraud_entities_but_no_category(self):
        """tag_event does NOT add requires-review if fraud tags exist (even without attack tags)."""
        entities = [self._make_entity("btc_wallet", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")]
        tags = self.engine.tag_event(entities, None, severity=5)

        # btc_wallet produces fraud tag but no attack tag (None category)
        assert any(t.namespace == "fraud" for t in tags)
        assert not any(t.value == "requires-review" for t in tags)

    def test_with_no_fraud_entities_but_has_category(self):
        """tag_event does NOT add requires-review if attack tags exist (even without fraud tags)."""
        entities = [self._make_entity("email", "hacker@dark.net")]
        tags = self.engine.tag_event(entities, "mfa_bypass", severity=8)

        # email doesn't produce fraud tags, but mfa_bypass produces attack tag
        assert any(t.namespace == "mitre-attack" for t in tags)
        assert not any(t.value == "requires-review" for t in tags)

    def test_threat_level_always_present(self):
        """tag_event always includes a threat-level tag regardless of other matches."""
        entities = []
        tags = self.engine.tag_event(entities, None, severity=10)

        threat_tags = [t for t in tags if t.namespace == "threat-level"]
        assert len(threat_tags) == 1
        assert threat_tags[0].value == "critical"

    def test_severity_mapping_in_tag_event(self):
        """tag_event correctly maps severity through threat-level tag."""
        entities = [self._make_entity("bin_range", "522345")]
        tags = self.engine.tag_event(entities, "account_takeover", severity=4)

        threat_tags = [t for t in tags if t.namespace == "threat-level"]
        assert len(threat_tags) == 1
        assert threat_tags[0].value == "medium"

    def test_empty_entities_and_none_category(self):
        """tag_event with empty entities and None category produces review tag."""
        tags = self.engine.tag_event([], None, severity=1)

        assert any(t.value == "requires-review" for t in tags)
        threat_tags = [t for t in tags if t.namespace == "threat-level"]
        assert threat_tags[0].value == "low"

    def test_returns_list_of_machine_tags(self):
        """tag_event always returns a list of MachineTag instances."""
        tags = self.engine.tag_event([], None, severity=5)
        assert isinstance(tags, list)
        assert all(isinstance(t, MachineTag) for t in tags)

    def test_multiple_fraud_entities(self):
        """tag_event handles multiple entities producing multiple fraud tags."""
        entities = [
            self._make_entity("bin_range", "411111"),
            self._make_entity("btc_wallet", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            self._make_entity("bank_name", "Chase"),
        ]
        tags = self.engine.tag_event(entities, "cnp_fraud", severity=9)

        fraud_tags = [t for t in tags if t.namespace == "fraud"]
        # bin_range -> bin-attack, btc_wallet -> crypto-fraud, bank_name -> target
        assert len(fraud_tags) >= 3
        assert not any(t.value == "requires-review" for t in tags)
