"""Unit tests for the coached-secrecy keyword override (XC-007 pattern).

The override forces fraud_category = "social_engineering" when any phrase
from _COACHED_SECRECY_KEYWORDS appears in the raw content, regardless of
what Claude returns. This is a safety-net for pig-butchering detection.
"""

import json
import io
import pytest
from unittest.mock import MagicMock

from dark_web_fraud_agent.agents.content_analyst import (
    ContentAnalyst,
    _COACHED_SECRECY_KEYWORDS,
)
from dark_web_fraud_agent.config.settings import AnalystConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analyst() -> ContentAnalyst:
    """Return a ContentAnalyst with a mock Bedrock client."""
    config = AnalystConfig(
        model_id="anthropic.claude-opus-4-8-20260601-v1:0",
        guardrail_id="test-guardrail",
        knowledge_base_id="test-kb",
        confidence_threshold=0.7,
        s3_bucket="test-bucket",
    )
    client = MagicMock()
    return ContentAnalyst(config=config, bedrock_client=client)


def _bedrock_combined_response(category: str | None, confidence: float = 0.85) -> dict:
    """Build a mock Bedrock combined-analysis response payload."""
    body = json.dumps({
        "is_fraud_relevant": True,
        "confidence": confidence,
        "reasoning": "test",
        "entities": [],
        "affected_institutions": [],
        "estimated_record_count": None,
        "fraud_category": category,
    }).encode()
    return {"body": io.BytesIO(body)}


# ---------------------------------------------------------------------------
# _COACHED_SECRECY_KEYWORDS constant
# ---------------------------------------------------------------------------

class TestCoachedSecrecyKeywords:
    """Verify the keyword list exists and contains expected phrases."""

    def test_keywords_tuple_is_non_empty(self):
        assert len(_COACHED_SECRECY_KEYWORDS) > 0

    def test_dont_tell_your_bank_present(self):
        assert "don't tell your bank" in _COACHED_SECRECY_KEYWORDS

    def test_pig_butcher_variant_present(self):
        assert "pig butcher" in _COACHED_SECRECY_KEYWORDS

    def test_sha_zhu_pan_present(self):
        assert "sha zhu pan" in _COACHED_SECRECY_KEYWORDS

    def test_all_keywords_are_lowercase(self):
        """All keywords should be lowercase so case-folded matching works."""
        for kw in _COACHED_SECRECY_KEYWORDS:
            assert kw == kw.lower(), f"Keyword not lowercase: {repr(kw)}"


# ---------------------------------------------------------------------------
# Override logic inside classify_and_extract_combined
# ---------------------------------------------------------------------------

class TestCoachedSecrecyOverride:
    """Verify that coached-secrecy phrases override the LLM fraud_category."""

    def setup_method(self):
        self.analyst = _make_analyst()

    @pytest.mark.parametrize("keyword", [
        "don't tell your bank",
        "pig butcher",
        "sha zhu pan",
        "romance script",
        "wrong number text",
    ])
    def test_keyword_forces_social_engineering(self, keyword):
        """Any coached-secrecy keyword in content forces social_engineering category."""
        # LLM returns cnp_fraud — the override should change it
        self.analyst._bedrock_client.invoke_model.return_value = (
            _bedrock_combined_response("cnp_fraud")
        )
        text = f"Here is a guide. {keyword.upper()} is what to say. Full tutorial."
        result = self.analyst.classify_and_extract_combined(text)
        assert result["fraud_category"] == "social_engineering", (
            f"Expected social_engineering for keyword {repr(keyword)}, "
            f"got {result['fraud_category']!r}"
        )

    def test_keyword_forces_is_fraud_relevant_true(self):
        """Coached-secrecy content is always marked as fraud-relevant."""
        self.analyst._bedrock_client.invoke_model.return_value = (
            _bedrock_combined_response(None, confidence=0.3)
        )
        text = "investment protection scheme — send more before you can withdraw"
        result = self.analyst.classify_and_extract_combined(text)
        assert result["is_fraud_relevant"] is True

    def test_keyword_boosts_low_confidence(self):
        """Coached-secrecy override raises confidence to at least 0.85."""
        self.analyst._bedrock_client.invoke_model.return_value = (
            _bedrock_combined_response("social_engineering", confidence=0.5)
        )
        text = "don't tell your bank about the investment or they will block it"
        result = self.analyst.classify_and_extract_combined(text)
        assert result["confidence"] >= 0.85

    def test_keyword_does_not_lower_existing_high_confidence(self):
        """If confidence is already ≥ 0.85, the override must not reduce it."""
        self.analyst._bedrock_client.invoke_model.return_value = (
            _bedrock_combined_response("social_engineering", confidence=0.97)
        )
        text = "pig butcher scheme complete instructions"
        result = self.analyst.classify_and_extract_combined(text)
        assert result["confidence"] == pytest.approx(0.97)

    def test_no_keyword_leaves_category_unchanged(self):
        """Content without any coached-secrecy keyword is not overridden."""
        self.analyst._bedrock_client.invoke_model.return_value = (
            _bedrock_combined_response("phishing_kit", confidence=0.9)
        )
        text = "selling premium phishing kit targeting Barclays login page"
        result = self.analyst.classify_and_extract_combined(text)
        assert result["fraud_category"] == "phishing_kit"

    def test_case_insensitive_matching(self):
        """Keyword matching is case-insensitive (content is lowercased before check)."""
        self.analyst._bedrock_client.invoke_model.return_value = (
            _bedrock_combined_response("cnp_fraud")
        )
        text = "SHA ZHU PAN SCHEME — full romance arc script included"
        result = self.analyst.classify_and_extract_combined(text)
        assert result["fraud_category"] == "social_engineering"

    def test_partial_word_not_matched(self):
        """Substring of a keyword that doesn't form the full phrase is not matched."""
        self.analyst._bedrock_client.invoke_model.return_value = (
            _bedrock_combined_response("cnp_fraud")
        )
        # "pig" alone is not in the keyword list — only "pig butcher"
        text = "the guinea pig experiment was successful"
        result = self.analyst.classify_and_extract_combined(text)
        # Should remain cnp_fraud — no override
        assert result["fraud_category"] == "cnp_fraud"
