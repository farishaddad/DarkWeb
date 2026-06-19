"""Unit tests for the Content Analyst agent.

Tests fraud relevance classification with mocked Bedrock invoke_model responses,
guardrail behavior, confidence threshold logic, and response parsing.
"""

import io
import json
from unittest.mock import MagicMock, patch

import pytest

from dark_web_fraud_agent.agents.content_analyst import (
    CLASSIFICATION_PROMPT,
    ContentAnalyst,
)
from dark_web_fraud_agent.config.settings import AnalystConfig


@pytest.fixture
def analyst_config():
    """Create a valid AnalystConfig for testing."""
    return AnalystConfig(
        bedrock_model_id="anthropic.claude-opus-4-8-20260601-v1:0",
        guardrail_id="test-guardrail-id-123",
        knowledge_base_id="test-kb-id-456",
        confidence_threshold=0.7,
        s3_bucket="test-analyst-bucket",
    )


@pytest.fixture
def mock_bedrock_client():
    """Create a mocked bedrock-runtime client."""
    return MagicMock()


@pytest.fixture
def analyst(analyst_config, mock_bedrock_client):
    """Create a ContentAnalyst instance with mocked Bedrock client."""
    return ContentAnalyst(config=analyst_config, bedrock_client=mock_bedrock_client)


def _make_bedrock_response(is_fraud_relevant: bool, confidence: float, reasoning: str = "test") -> dict:
    """Helper to create a mock Bedrock invoke_model response.

    Args:
        is_fraud_relevant: Whether content is fraud-relevant.
        confidence: Classification confidence score.
        reasoning: Brief reasoning text.

    Returns:
        Dict structured like a Bedrock invoke_model response.
    """
    response_json = json.dumps({
        "is_fraud_relevant": is_fraud_relevant,
        "confidence": confidence,
        "reasoning": reasoning,
    })
    body_content = json.dumps({
        "content": [{"type": "text", "text": response_json}],
        "model": "anthropic.claude-opus-4-8-20260601-v1:0",
        "stop_reason": "end_turn",
    })
    return {"body": io.BytesIO(body_content.encode("utf-8"))}


def _make_guardrail_response() -> dict:
    """Helper to create a Bedrock response where guardrails intervened."""
    body_content = json.dumps({
        "amazon-bedrock-guardrailAction": "GUARDRAIL_INTERVENED",
        "content": [{"type": "text", "text": "I cannot process this content."}],
    })
    return {"body": io.BytesIO(body_content.encode("utf-8"))}


class TestContentAnalystInit:
    """Tests for ContentAnalyst initialization."""

    def test_init_with_config(self, analyst_config, mock_bedrock_client):
        """ContentAnalyst initializes with AnalystConfig."""
        analyst = ContentAnalyst(config=analyst_config, bedrock_client=mock_bedrock_client)
        assert analyst.analyst_config == analyst_config
        assert analyst.config.agent_id == "content-analyst"
        assert analyst.config.agent_name == "Content Analyst"
        assert analyst.config.s3_bucket == "test-analyst-bucket"

    def test_init_inherits_agent_base(self, analyst):
        """ContentAnalyst is an instance of AgentBase."""
        from dark_web_fraud_agent.models.shared import AgentBase
        assert isinstance(analyst, AgentBase)

    def test_get_health_returns_agent_health(self, analyst):
        """get_health() returns a valid AgentHealth instance."""
        from dark_web_fraud_agent.models.shared import AgentHealth
        health = analyst.get_health()
        assert isinstance(health, AgentHealth)
        assert health.agent_id == "content-analyst"
        assert health.status == "healthy"

    def test_creates_default_bedrock_client_when_none_provided(self, analyst_config):
        """ContentAnalyst creates a boto3 bedrock-runtime client if none is passed."""
        with patch("dark_web_fraud_agent.agents.content_analyst.boto3.client") as mock_boto3:
            mock_boto3.return_value = MagicMock()
            analyst = ContentAnalyst(config=analyst_config)
            mock_boto3.assert_called_once_with("bedrock-runtime")


class TestClassifyRelevance:
    """Tests for classify_relevance() method."""

    def test_classifies_fraud_relevant_content(self, analyst, mock_bedrock_client):
        """Returns (True, high confidence) for clearly fraud-relevant content."""
        mock_bedrock_client.invoke_model.return_value = _make_bedrock_response(
            is_fraud_relevant=True, confidence=0.95, reasoning="Contains BIN data and phishing kit references"
        )

        is_relevant, confidence = analyst.classify_relevance(
            "Selling premium phishing kit targeting Chase Bank. BIN 411111 available."
        )

        assert is_relevant is True
        assert confidence == 0.95

    def test_classifies_non_fraud_content(self, analyst, mock_bedrock_client):
        """Returns (False, high confidence) for clearly non-fraud content."""
        mock_bedrock_client.invoke_model.return_value = _make_bedrock_response(
            is_fraud_relevant=False, confidence=0.92, reasoning="General discussion unrelated to banking"
        )

        is_relevant, confidence = analyst.classify_relevance(
            "Discussion about cryptocurrency mining hardware comparison."
        )

        assert is_relevant is False
        assert confidence == 0.92

    def test_low_confidence_classification(self, analyst, mock_bedrock_client):
        """Returns low confidence for ambiguous content."""
        mock_bedrock_client.invoke_model.return_value = _make_bedrock_response(
            is_fraud_relevant=True, confidence=0.55, reasoning="Mentions banks but unclear context"
        )

        is_relevant, confidence = analyst.classify_relevance(
            "Some general news about banks and technology."
        )

        assert is_relevant is True
        assert confidence == 0.55

    def test_invokes_bedrock_with_guardrails(self, analyst, mock_bedrock_client):
        """invoke_model is called with guardrailIdentifier and guardrailVersion."""
        mock_bedrock_client.invoke_model.return_value = _make_bedrock_response(
            is_fraud_relevant=False, confidence=0.8
        )

        analyst.classify_relevance("test content")

        call_kwargs = mock_bedrock_client.invoke_model.call_args[1]
        assert call_kwargs["guardrailIdentifier"] == "test-guardrail-id-123"
        assert call_kwargs["guardrailVersion"] == "DRAFT"
        assert call_kwargs["modelId"] == "anthropic.claude-opus-4-8-20260601-v1:0"

    def test_invokes_bedrock_with_correct_body_format(self, analyst, mock_bedrock_client):
        """invoke_model body contains proper Anthropic Messages API format."""
        mock_bedrock_client.invoke_model.return_value = _make_bedrock_response(
            is_fraud_relevant=False, confidence=0.5
        )

        analyst.classify_relevance("some content to classify")

        call_kwargs = mock_bedrock_client.invoke_model.call_args[1]
        body = json.loads(call_kwargs["body"])
        assert body["anthropic_version"] == "bedrock-2023-05-31"
        assert body["max_tokens"] == 512
        assert len(body["messages"]) == 1
        assert body["messages"][0]["role"] == "user"
        assert "some content to classify" in body["messages"][0]["content"]

    def test_guardrails_intervention_returns_not_relevant(self, analyst, mock_bedrock_client):
        """When guardrails intervene, returns (False, 0.0)."""
        mock_bedrock_client.invoke_model.return_value = _make_guardrail_response()

        is_relevant, confidence = analyst.classify_relevance(
            "Content that triggers guardrail intervention"
        )

        assert is_relevant is False
        assert confidence == 0.0

    def test_bedrock_invocation_failure_raises_runtime_error(self, analyst, mock_bedrock_client):
        """RuntimeError is raised when Bedrock invocation fails."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        with pytest.raises(RuntimeError, match="Bedrock invocation failed"):
            analyst.classify_relevance("test content")

    def test_empty_response_raises_value_error(self, analyst, mock_bedrock_client):
        """ValueError is raised when response has empty content blocks."""
        body_content = json.dumps({"content": []})
        mock_bedrock_client.invoke_model.return_value = {
            "body": io.BytesIO(body_content.encode("utf-8"))
        }

        with pytest.raises(ValueError, match="Empty response from Bedrock model"):
            analyst.classify_relevance("test content")

    def test_malformed_json_response_raises_value_error(self, analyst, mock_bedrock_client):
        """ValueError is raised when Claude returns non-JSON text."""
        body_content = json.dumps({
            "content": [{"type": "text", "text": "This is not JSON at all"}],
        })
        mock_bedrock_client.invoke_model.return_value = {
            "body": io.BytesIO(body_content.encode("utf-8"))
        }

        with pytest.raises(ValueError, match="Failed to parse classification response"):
            analyst.classify_relevance("test content")

    def test_confidence_clamped_to_max_one(self, analyst, mock_bedrock_client):
        """Confidence values above 1.0 are clamped to 1.0."""
        mock_bedrock_client.invoke_model.return_value = _make_bedrock_response(
            is_fraud_relevant=True, confidence=1.5
        )

        _, confidence = analyst.classify_relevance("test")
        assert confidence == 1.0

    def test_confidence_clamped_to_min_zero(self, analyst, mock_bedrock_client):
        """Confidence values below 0.0 are clamped to 0.0."""
        mock_bedrock_client.invoke_model.return_value = _make_bedrock_response(
            is_fraud_relevant=False, confidence=-0.3
        )

        _, confidence = analyst.classify_relevance("test")
        assert confidence == 0.0

    def test_json_embedded_in_extra_text(self, analyst, mock_bedrock_client):
        """Parser extracts JSON even when Claude wraps it with extra text."""
        response_text = (
            'Here is my analysis:\n'
            '{"is_fraud_relevant": true, "confidence": 0.88, "reasoning": "BIN data found"}\n'
            'Let me know if you need more details.'
        )
        body_content = json.dumps({
            "content": [{"type": "text", "text": response_text}],
        })
        mock_bedrock_client.invoke_model.return_value = {
            "body": io.BytesIO(body_content.encode("utf-8"))
        }

        is_relevant, confidence = analyst.classify_relevance("test content")
        assert is_relevant is True
        assert confidence == 0.88


class TestShouldRequireManualReview:
    """Tests for the confidence threshold manual review logic."""

    def test_low_confidence_requires_review(self, analyst):
        """Confidence below 0.7 threshold requires manual review."""
        assert analyst.should_require_manual_review(0.5) is True
        assert analyst.should_require_manual_review(0.69) is True
        assert analyst.should_require_manual_review(0.0) is True

    def test_high_confidence_does_not_require_review(self, analyst):
        """Confidence at or above 0.7 threshold does not require manual review."""
        assert analyst.should_require_manual_review(0.7) is False
        assert analyst.should_require_manual_review(0.95) is False
        assert analyst.should_require_manual_review(1.0) is False

    def test_exact_threshold_does_not_require_review(self, analyst):
        """Confidence exactly at threshold does not trigger review."""
        assert analyst.should_require_manual_review(0.7) is False

    def test_custom_threshold(self, mock_bedrock_client):
        """Custom confidence threshold is respected."""
        config = AnalystConfig(
            bedrock_model_id="anthropic.claude-opus-4-8-20260601-v1:0",
            guardrail_id="guardrail-id",
            knowledge_base_id="kb-id",
            confidence_threshold=0.85,
            s3_bucket="test-bucket",
        )
        analyst = ContentAnalyst(config=config, bedrock_client=mock_bedrock_client)

        # 0.8 is below 0.85 threshold
        assert analyst.should_require_manual_review(0.8) is True
        # 0.85 is at threshold
        assert analyst.should_require_manual_review(0.85) is False
        # 0.9 is above threshold
        assert analyst.should_require_manual_review(0.9) is False


class TestClassificationPrompt:
    """Tests for the classification prompt template."""

    def test_prompt_includes_content_placeholder(self):
        """CLASSIFICATION_PROMPT contains the {text} placeholder."""
        assert "{text}" in CLASSIFICATION_PROMPT

    def test_prompt_mentions_fraud_criteria(self):
        """Prompt includes fraud-relevant classification criteria."""
        assert "MFA" in CLASSIFICATION_PROMPT
        assert "phishing" in CLASSIFICATION_PROMPT.lower()
        assert "BIN" in CLASSIFICATION_PROMPT
        assert "SWIFT" in CLASSIFICATION_PROMPT

    def test_prompt_mentions_confidence_threshold(self):
        """Prompt instructs LLM about the 0.7 confidence threshold."""
        assert "0.7" in CLASSIFICATION_PROMPT

    def test_prompt_formats_correctly_with_content(self):
        """Prompt template formats with the provided text."""
        formatted = CLASSIFICATION_PROMPT.format(text="test dark web content here")
        assert "test dark web content here" in formatted
        assert "<content>" in formatted
        assert "</content>" in formatted


class TestClassifyRelevanceIntegration:
    """Integration-style tests verifying the full classify flow with mocked Bedrock."""

    def test_full_flow_fraud_relevant(self, analyst, mock_bedrock_client):
        """Full classification flow for fraud-relevant content."""
        mock_bedrock_client.invoke_model.return_value = _make_bedrock_response(
            is_fraud_relevant=True,
            confidence=0.92,
            reasoning="Contains stolen credit card BINs and phishing tools",
        )

        is_relevant, confidence = analyst.classify_relevance(
            "New phishing kit for sale. Works with Chase, BofA. "
            "Includes BIN checker for 411111 range. $500 BTC."
        )

        assert is_relevant is True
        assert confidence == 0.92
        assert analyst.should_require_manual_review(confidence) is False

    def test_full_flow_not_relevant(self, analyst, mock_bedrock_client):
        """Full classification flow for non-fraud content."""
        mock_bedrock_client.invoke_model.return_value = _make_bedrock_response(
            is_fraud_relevant=False,
            confidence=0.88,
            reasoning="Discussion about VPN setup for privacy",
        )

        is_relevant, confidence = analyst.classify_relevance(
            "Best VPN for privacy in 2024? I need good speed for streaming."
        )

        assert is_relevant is False
        assert confidence == 0.88
        assert analyst.should_require_manual_review(confidence) is False

    def test_full_flow_low_confidence_triggers_review(self, analyst, mock_bedrock_client):
        """Low-confidence classification triggers manual review flag."""
        mock_bedrock_client.invoke_model.return_value = _make_bedrock_response(
            is_fraud_relevant=True,
            confidence=0.55,
            reasoning="Mentions banks but context is unclear",
        )

        is_relevant, confidence = analyst.classify_relevance(
            "Big news about banks today. Changes coming soon to accounts."
        )

        assert is_relevant is True
        assert confidence == 0.55
        assert analyst.should_require_manual_review(confidence) is True


class TestAssignSeverity:
    """Tests for assign_severity() method."""

    def test_base_score_for_minimal_fraud_content(self, analyst):
        """Base score is 3 for fraud-relevant content with no boosting factors."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,  # placeholder, assign_severity computes the real one
            fraud_category="phishing_kit",
            entities=[],
        )
        score = analyst.assign_severity(classification)
        assert score == 3

    def test_institution_entities_add_to_score(self, analyst):
        """Each bank_name entity adds +1, capped at +3."""
        from dark_web_fraud_agent.models.content_analyst import (
            ClassifiedContent,
            ExtractedEntity,
        )

        # One institution: base 3 + 1 = 4
        entities_1 = [
            ExtractedEntity(entity_type="bank_name", value="Chase", context="ctx", confidence=0.9),
        ]
        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="phishing_kit",
            entities=entities_1,
        )
        assert analyst.assign_severity(classification) == 4

    def test_institution_entities_capped_at_three(self, analyst):
        """Institution bonus is capped at +3 even with more bank_name entities."""
        from dark_web_fraud_agent.models.content_analyst import (
            ClassifiedContent,
            ExtractedEntity,
        )

        # Five institutions: base 3 + 3 (capped) = 6
        entities = [
            ExtractedEntity(entity_type="bank_name", value=f"Bank{i}", context="ctx", confidence=0.9)
            for i in range(5)
        ]
        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="phishing_kit",
            entities=entities,
        )
        assert analyst.assign_severity(classification) == 6

    def test_high_severity_category_account_takeover(self, analyst):
        """account_takeover category adds +1."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="account_takeover",
            entities=[],
        )
        # base 3 + 1 (category) = 4
        assert analyst.assign_severity(classification) == 4

    def test_high_severity_category_mfa_bypass(self, analyst):
        """mfa_bypass category adds +1."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="mfa_bypass",
            entities=[],
        )
        # base 3 + 1 (category) = 4
        assert analyst.assign_severity(classification) == 4

    def test_medium_category_phishing_kit_no_bonus(self, analyst):
        """phishing_kit does NOT add the high-severity category bonus."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="phishing_kit",
            entities=[],
        )
        # base 3, no category bonus
        assert analyst.assign_severity(classification) == 3

    def test_high_confidence_adds_one(self, analyst):
        """Confidence > 0.8 adds +1."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.85,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="phishing_kit",
            entities=[],
        )
        # base 3 + 1 (confidence) = 4
        assert analyst.assign_severity(classification) == 4

    def test_confidence_exactly_0_8_no_bonus(self, analyst):
        """Confidence exactly 0.8 does NOT add the bonus (must be > 0.8)."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.8,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="phishing_kit",
            entities=[],
        )
        # base 3, no confidence bonus
        assert analyst.assign_severity(classification) == 3

    def test_multiple_entity_types_adds_one(self, analyst):
        """Multiple distinct entity types present adds +1."""
        from dark_web_fraud_agent.models.content_analyst import (
            ClassifiedContent,
            ExtractedEntity,
        )

        entities = [
            ExtractedEntity(entity_type="bank_name", value="Chase", context="ctx", confidence=0.9),
            ExtractedEntity(entity_type="btc_wallet", value="bc1qtest", context="ctx", confidence=0.9),
        ]
        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="phishing_kit",
            entities=entities,
        )
        # base 3 + 1 (institution) + 1 (multiple types) = 5
        assert analyst.assign_severity(classification) == 5

    def test_single_entity_type_no_multiple_type_bonus(self, analyst):
        """Single entity type (even multiple instances) does NOT add the type diversity bonus."""
        from dark_web_fraud_agent.models.content_analyst import (
            ClassifiedContent,
            ExtractedEntity,
        )

        entities = [
            ExtractedEntity(entity_type="bank_name", value="Chase", context="ctx", confidence=0.9),
            ExtractedEntity(entity_type="bank_name", value="BofA", context="ctx", confidence=0.9),
        ]
        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="phishing_kit",
            entities=entities,
        )
        # base 3 + 2 (institutions) + 0 (only 1 type) = 5
        assert analyst.assign_severity(classification) == 5

    def test_all_bonuses_combined(self, analyst):
        """All scoring bonuses applied together."""
        from dark_web_fraud_agent.models.content_analyst import (
            ClassifiedContent,
            ExtractedEntity,
        )

        entities = [
            ExtractedEntity(entity_type="bank_name", value="Chase", context="ctx", confidence=0.9),
            ExtractedEntity(entity_type="bank_name", value="BofA", context="ctx", confidence=0.9),
            ExtractedEntity(entity_type="bank_name", value="Wells Fargo", context="ctx", confidence=0.9),
            ExtractedEntity(entity_type="btc_wallet", value="bc1qtest", context="ctx", confidence=0.9),
            ExtractedEntity(entity_type="email", value="x@test.com", context="ctx", confidence=0.9),
        ]
        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.95,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="account_takeover",
            entities=entities,
        )
        # base 3 + 3 (institutions capped) + 1 (category) + 1 (confidence) + 1 (multiple types) = 9
        assert analyst.assign_severity(classification) == 9

    def test_score_clamped_to_max_10(self, analyst):
        """Score never exceeds 10 even with maximum bonuses.
        
        Max possible: 3 + 3 + 1 + 1 + 1 = 9, which doesn't exceed 10.
        But this test ensures the clamp logic works if rules ever change.
        """
        from dark_web_fraud_agent.models.content_analyst import (
            ClassifiedContent,
            ExtractedEntity,
        )

        entities = [
            ExtractedEntity(entity_type="bank_name", value=f"Bank{i}", context="ctx", confidence=0.9)
            for i in range(10)
        ] + [
            ExtractedEntity(entity_type="btc_wallet", value="bc1q", context="ctx", confidence=0.9),
            ExtractedEntity(entity_type="email", value="x@t.com", context="ctx", confidence=0.9),
            ExtractedEntity(entity_type="url", value="http://x.onion", context="ctx", confidence=0.9),
        ]
        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.99,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="mfa_bypass",
            entities=entities,
        )
        score = analyst.assign_severity(classification)
        assert score <= 10

    def test_score_clamped_to_min_1(self, analyst):
        """Score never goes below 1 (base is 3 so this is theoretical)."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=False,
            confidence=0.3,
            requires_manual_review=True,
            severity_score=1,
            fraud_category=None,
            entities=[],
        )
        score = analyst.assign_severity(classification)
        assert score >= 1

    def test_no_fraud_category_no_category_bonus(self, analyst):
        """None fraud_category does not add the high-severity bonus."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category=None,
            entities=[],
        )
        # base 3, nothing else
        assert analyst.assign_severity(classification) == 3

    def test_cnp_fraud_category_no_bonus(self, analyst):
        """cnp_fraud is not a high-severity category, no bonus."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="cnp_fraud",
            entities=[],
        )
        assert analyst.assign_severity(classification) == 3

    def test_synthetic_identity_category_no_bonus(self, analyst):
        """synthetic_identity is not a high-severity category, no bonus."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="synthetic_identity",
            entities=[],
        )
        assert analyst.assign_severity(classification) == 3

    def test_empty_entities_no_entity_bonuses(self, analyst):
        """Empty entities list results in no entity-related bonuses."""
        from dark_web_fraud_agent.models.content_analyst import ClassifiedContent

        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.95,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="account_takeover",
            entities=[],
        )
        # base 3 + 0 (no institutions) + 1 (category) + 1 (confidence) + 0 (no types) = 5
        assert analyst.assign_severity(classification) == 5

    def test_non_institution_entities_only_give_type_diversity(self, analyst):
        """Non-bank_name entities don't add institution bonus but can add type diversity."""
        from dark_web_fraud_agent.models.content_analyst import (
            ClassifiedContent,
            ExtractedEntity,
        )

        entities = [
            ExtractedEntity(entity_type="btc_wallet", value="bc1q", context="ctx", confidence=0.9),
            ExtractedEntity(entity_type="ip_address", value="1.2.3.4", context="ctx", confidence=0.9),
        ]
        classification = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=True,
            confidence=0.75,
            requires_manual_review=False,
            severity_score=1,
            fraud_category="phishing_kit",
            entities=entities,
        )
        # base 3 + 0 (no bank_name) + 0 (phishing_kit not high) + 0 (confidence <= 0.8) + 1 (multiple types) = 4
        assert analyst.assign_severity(classification) == 4
