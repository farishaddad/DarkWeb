"""Unit tests for galaxy cluster matching via Knowledge Base and tag() orchestration."""

import json
from unittest.mock import MagicMock, patch

import pytest

from dark_web_fraud_agent.agents.tagging_engine import MachineTag, TaggingEngine
from dark_web_fraud_agent.models.content_analyst import ExtractedEntity


class TestMatchGalaxyClusterWithKnowledgeBase:
    """Tests for match_galaxy_cluster with Bedrock Agent Runtime KB querying."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def test_kb_query_returns_structured_json_match(self):
        """When KB returns structured JSON with galaxy fields, uses that result."""
        mock_client = MagicMock()
        kb_content = json.dumps({
            "galaxy": "threat-actor",
            "cluster_uuid": "ta-fin7-001",
            "cluster_value": "FIN7 MFA Bypass Campaign",
        })
        mock_client.retrieve.return_value = {
            "retrievalResults": [
                {
                    "content": {"text": kb_content},
                    "score": 0.85,
                }
            ]
        }

        result = self.engine.match_galaxy_cluster(
            "mfa_bypass",
            knowledge_base_id="kb-test-123",
            bedrock_client=mock_client,
        )

        assert result is not None
        assert result["galaxy"] == "threat-actor"
        assert result["cluster_uuid"] == "ta-fin7-001"
        assert result["cluster_value"] == "FIN7 MFA Bypass Campaign"
        assert result["source"] == "knowledge_base"

    def test_kb_query_called_with_correct_params(self):
        """Verifies the retrieve API is called with the right parameters."""
        mock_client = MagicMock()
        mock_client.retrieve.return_value = {"retrievalResults": []}

        self.engine.match_galaxy_cluster(
            "phishing_kit",
            knowledge_base_id="kb-abc-456",
            bedrock_client=mock_client,
        )

        mock_client.retrieve.assert_called_once_with(
            knowledgeBaseId="kb-abc-456",
            retrievalQuery={
                "text": "MISP Galaxy cluster for threat actor profile matching "
                        "fraud category: phishing_kit"
            },
            retrievalConfiguration={
                "vectorSearchConfiguration": {
                    "numberOfResults": 3,
                }
            },
        )

    def test_kb_query_low_score_falls_back_to_static(self):
        """When KB result score is below 0.5, falls back to static map."""
        mock_client = MagicMock()
        mock_client.retrieve.return_value = {
            "retrievalResults": [
                {
                    "content": {"text": "some irrelevant content"},
                    "score": 0.3,
                }
            ]
        }

        result = self.engine.match_galaxy_cluster(
            "mfa_bypass",
            knowledge_base_id="kb-test-123",
            bedrock_client=mock_client,
        )

        assert result is not None
        assert result["source"] == "static"
        assert result["cluster_value"] == "MFA Bypass"

    def test_kb_query_empty_results_falls_back_to_static(self):
        """When KB returns no results, falls back to static map."""
        mock_client = MagicMock()
        mock_client.retrieve.return_value = {"retrievalResults": []}

        result = self.engine.match_galaxy_cluster(
            "account_takeover",
            knowledge_base_id="kb-test-123",
            bedrock_client=mock_client,
        )

        assert result is not None
        assert result["source"] == "static"
        assert result["cluster_value"] == "Account Takeover"

    def test_kb_query_exception_falls_back_to_static(self):
        """When KB query raises exception, falls back to static map."""
        mock_client = MagicMock()
        mock_client.retrieve.side_effect = Exception("Bedrock timeout")

        result = self.engine.match_galaxy_cluster(
            "phishing_kit",
            knowledge_base_id="kb-test-123",
            bedrock_client=mock_client,
        )

        assert result is not None
        assert result["source"] == "static"
        assert result["cluster_value"] == "Phishing"

    def test_kb_query_exception_unknown_category_returns_none(self):
        """When KB fails and category not in static map, returns None."""
        mock_client = MagicMock()
        mock_client.retrieve.side_effect = Exception("Service unavailable")

        result = self.engine.match_galaxy_cluster(
            "cnp_fraud",
            knowledge_base_id="kb-test-123",
            bedrock_client=mock_client,
        )

        assert result is None

    def test_no_knowledge_base_id_skips_kb_query(self):
        """When no knowledge_base_id and no env var, skips KB and uses static."""
        with patch.dict("os.environ", {}, clear=True):
            result = self.engine.match_galaxy_cluster("mfa_bypass")

        assert result is not None
        assert result["source"] == "static"

    def test_kb_returns_unstructured_text_with_galaxy_keyword(self):
        """When KB returns unstructured text with galaxy keywords, extracts info."""
        mock_client = MagicMock()
        mock_client.retrieve.return_value = {
            "retrievalResults": [
                {
                    "content": {
                        "text": "Galaxy cluster: FIN8 Phishing Infrastructure"
                    },
                    "score": 0.75,
                }
            ]
        }

        result = self.engine.match_galaxy_cluster(
            "phishing_kit",
            knowledge_base_id="kb-test-123",
            bedrock_client=mock_client,
        )

        assert result is not None
        assert result["source"] == "knowledge_base"
        assert result["galaxy"] == "threat-actor"
        assert "kb-phishing_kit-001" in result["cluster_uuid"]

    def test_kb_returns_unparseable_content_falls_back(self):
        """When KB content is not JSON and has no galaxy keywords, falls back."""
        mock_client = MagicMock()
        mock_client.retrieve.return_value = {
            "retrievalResults": [
                {
                    "content": {"text": "random unrelated text about cooking"},
                    "score": 0.6,
                }
            ]
        }

        result = self.engine.match_galaxy_cluster(
            "mfa_bypass",
            knowledge_base_id="kb-test-123",
            bedrock_client=mock_client,
        )

        # Should fall back to static since KB content is unparseable
        assert result is not None
        assert result["source"] == "static"

    @patch.dict("os.environ", {"KNOWLEDGE_BASE_ID": "kb-from-env"})
    def test_reads_knowledge_base_id_from_env_var(self):
        """When knowledge_base_id not passed, reads from KNOWLEDGE_BASE_ID env."""
        mock_client = MagicMock()
        mock_client.retrieve.return_value = {"retrievalResults": []}

        self.engine.match_galaxy_cluster(
            "mfa_bypass",
            bedrock_client=mock_client,
        )

        mock_client.retrieve.assert_called_once()
        call_args = mock_client.retrieve.call_args
        assert call_args.kwargs["knowledgeBaseId"] == "kb-from-env"


class TestTagOrchestration:
    """Tests for the tag() orchestration method."""

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

    def test_returns_dict_with_tags_and_galaxy_match(self):
        """tag() returns a dict with 'tags' and 'galaxy_match' keys."""
        result = self.engine.tag([], None, severity=5)

        assert "tags" in result
        assert "galaxy_match" in result
        assert isinstance(result["tags"], list)

    def test_all_tags_are_machine_tag_instances(self):
        """All items in the tags list are MachineTag instances."""
        result = self.engine.tag([], "mfa_bypass", severity=7)

        for tag in result["tags"]:
            assert isinstance(tag, MachineTag)

    def test_includes_attack_tags_when_category_matches(self):
        """tag() includes MITRE ATT&CK tags when fraud_category is known."""
        result = self.engine.tag([], "phishing_kit", severity=5)

        attack_tags = [t for t in result["tags"] if t.namespace == "mitre-attack"]
        assert len(attack_tags) >= 1
        assert any(t.value == "T1566" for t in attack_tags)

    def test_includes_fraud_tags_when_entities_match(self):
        """tag() includes fraud tags when entities contain banking keywords."""
        entities = [self._make_entity("bin_range", "411111")]
        result = self.engine.tag(entities, None, severity=3)

        fraud_tags = [t for t in result["tags"] if t.namespace == "fraud"]
        assert any(t.value == "bin-attack" for t in fraud_tags)

    def test_includes_threat_level_tag(self):
        """tag() always includes a threat-level tag."""
        result = self.engine.tag([], "mfa_bypass", severity=9)

        threat_tags = [t for t in result["tags"] if t.namespace == "threat-level"]
        assert len(threat_tags) == 1
        assert threat_tags[0].value == "high"

    def test_includes_galaxy_tag_when_matched(self):
        """tag() adds a misp-galaxy tag when galaxy cluster matches."""
        result = self.engine.tag([], "mfa_bypass", severity=7)

        galaxy_tags = [t for t in result["tags"] if t.namespace == "misp-galaxy"]
        assert len(galaxy_tags) == 1
        assert galaxy_tags[0].predicate == "mitre-attack-pattern"
        assert galaxy_tags[0].value == "MFA Bypass"

    def test_galaxy_match_included_in_result(self):
        """tag() includes galaxy_match dict in result when matched."""
        result = self.engine.tag([], "phishing_kit", severity=5)

        assert result["galaxy_match"] is not None
        assert result["galaxy_match"]["cluster_value"] == "Phishing"

    def test_no_match_applies_requires_review_tag(self):
        """tag() applies workflow:status=requires-review when nothing matches."""
        entities = [self._make_entity("email", "test@example.com")]
        result = self.engine.tag(entities, None, severity=3)

        review_tags = [
            t for t in result["tags"]
            if t.namespace == "workflow" and t.value == "requires-review"
        ]
        assert len(review_tags) == 1
        assert review_tags[0].predicate == "status"

    def test_no_requires_review_when_attack_tags_exist(self):
        """tag() does NOT apply requires-review when attack tags exist."""
        result = self.engine.tag([], "account_takeover", severity=5)

        review_tags = [
            t for t in result["tags"]
            if t.namespace == "workflow" and t.value == "requires-review"
        ]
        assert len(review_tags) == 0

    def test_no_requires_review_when_fraud_tags_exist(self):
        """tag() does NOT apply requires-review when fraud tags exist."""
        entities = [self._make_entity("btc_wallet", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")]
        result = self.engine.tag(entities, None, severity=5)

        review_tags = [
            t for t in result["tags"]
            if t.namespace == "workflow" and t.value == "requires-review"
        ]
        assert len(review_tags) == 0

    def test_no_requires_review_when_galaxy_matches(self):
        """tag() does NOT apply requires-review when galaxy cluster matches."""
        # mfa_bypass has a galaxy match even though entities are empty
        result = self.engine.tag([], "mfa_bypass", severity=5)

        review_tags = [
            t for t in result["tags"]
            if t.namespace == "workflow" and t.value == "requires-review"
        ]
        assert len(review_tags) == 0

    def test_galaxy_match_none_when_no_match(self):
        """tag() returns galaxy_match=None when no cluster matches."""
        entities = [self._make_entity("email", "test@dark.net")]
        result = self.engine.tag(entities, None, severity=2)

        assert result["galaxy_match"] is None

    def test_kb_client_passed_through(self):
        """tag() passes knowledge_base_id and bedrock_client to match_galaxy_cluster."""
        mock_client = MagicMock()
        kb_content = json.dumps({
            "galaxy": "apt-group",
            "cluster_uuid": "apt-fin7-001",
            "cluster_value": "FIN7",
        })
        mock_client.retrieve.return_value = {
            "retrievalResults": [
                {"content": {"text": kb_content}, "score": 0.9}
            ]
        }

        result = self.engine.tag(
            [],
            "mfa_bypass",
            severity=8,
            knowledge_base_id="kb-test-xyz",
            bedrock_client=mock_client,
        )

        assert result["galaxy_match"] is not None
        assert result["galaxy_match"]["source"] == "knowledge_base"
        assert result["galaxy_match"]["cluster_value"] == "FIN7"

    def test_full_pipeline_with_all_matches(self):
        """tag() produces complete tag set when everything matches."""
        entities = [
            self._make_entity("bin_range", "411111"),
            self._make_entity("bank_name", "HSBC"),
        ]
        result = self.engine.tag(entities, "phishing_kit", severity=10)

        tags = result["tags"]
        namespaces = {t.namespace for t in tags}

        assert "mitre-attack" in namespaces
        assert "fraud" in namespaces
        assert "threat-level" in namespaces
        assert "misp-galaxy" in namespaces
        # No requires-review because everything matched
        assert not any(
            t.namespace == "workflow" and t.value == "requires-review"
            for t in tags
        )

    def test_requires_review_tag_string_format(self):
        """The workflow requires-review tag renders correctly as string."""
        entities = [self._make_entity("email", "user@test.com")]
        result = self.engine.tag(entities, None, severity=3)

        review_tags = [
            t for t in result["tags"]
            if t.namespace == "workflow" and t.value == "requires-review"
        ]
        assert len(review_tags) == 1
        assert str(review_tags[0]) == 'workflow:status="requires-review"'
