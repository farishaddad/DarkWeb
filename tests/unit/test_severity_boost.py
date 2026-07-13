"""Unit tests for the record-count severity boost (DC-007 / DC-008 patterns).

adjust_severity_for_record_count() boosts severity when a listing specifies
a large-scale dump. This ensures DC-008's 10,000-card dump reaches the
immediate-alert threshold (≥7) without waiting for campaign convergence.
"""

import pytest
from unittest.mock import MagicMock

from dark_web_fraud_agent.agents.content_analyst import ContentAnalyst
from dark_web_fraud_agent.config.settings import AnalystConfig


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_analyst() -> ContentAnalyst:
    config = AnalystConfig(
        model_id="anthropic.claude-opus-4-8-20260601-v1:0",
        guardrail_id="test-guardrail",
        knowledge_base_id="test-kb",
        confidence_threshold=0.7,
        s3_bucket="test-bucket",
    )
    return ContentAnalyst(config=config, bedrock_client=MagicMock())


# ---------------------------------------------------------------------------
# No-op cases
# ---------------------------------------------------------------------------

class TestSeverityBoostNoOp:
    """Cases where no boost should be applied."""

    def setup_method(self):
        self.analyst = _make_analyst()

    def test_none_record_count_unchanged(self):
        assert self.analyst.adjust_severity_for_record_count(6, None) == 6

    def test_zero_record_count_unchanged(self):
        assert self.analyst.adjust_severity_for_record_count(6, 0) == 6

    def test_small_count_under_1000_unchanged(self):
        assert self.analyst.adjust_severity_for_record_count(5, 999) == 5

    def test_exactly_999_unchanged(self):
        assert self.analyst.adjust_severity_for_record_count(4, 999) == 4


# ---------------------------------------------------------------------------
# Medium boost (+1 for 1,000–4,999 records)
# ---------------------------------------------------------------------------

class TestSeverityBoostMedium:
    """Exactly +1 for dumps of 1,000–4,999 records."""

    def setup_method(self):
        self.analyst = _make_analyst()

    def test_exactly_1000_gets_plus_one(self):
        assert self.analyst.adjust_severity_for_record_count(5, 1_000) == 6

    def test_4999_gets_plus_one(self):
        assert self.analyst.adjust_severity_for_record_count(5, 4_999) == 6

    def test_2500_gets_plus_one(self):
        assert self.analyst.adjust_severity_for_record_count(4, 2_500) == 5

    def test_medium_boost_does_not_exceed_10(self):
        assert self.analyst.adjust_severity_for_record_count(10, 2_000) == 10


# ---------------------------------------------------------------------------
# High boost (+2 for ≥5,000 records)
# ---------------------------------------------------------------------------

class TestSeverityBoostHigh:
    """Exactly +2 for dumps of 5,000+ records."""

    def setup_method(self):
        self.analyst = _make_analyst()

    def test_exactly_5000_gets_plus_two(self):
        assert self.analyst.adjust_severity_for_record_count(5, 5_000) == 7

    def test_10000_gets_plus_two(self):
        """DC-008 pattern: 10k card dump base severity 6 → 8 (immediate alert)."""
        assert self.analyst.adjust_severity_for_record_count(6, 10_000) == 8

    def test_500000_gets_plus_two(self):
        assert self.analyst.adjust_severity_for_record_count(5, 500_000) == 7

    def test_high_boost_clamps_at_10(self):
        assert self.analyst.adjust_severity_for_record_count(9, 10_000) == 10

    def test_already_at_10_stays_at_10(self):
        assert self.analyst.adjust_severity_for_record_count(10, 10_000) == 10


# ---------------------------------------------------------------------------
# Boundary conditions
# ---------------------------------------------------------------------------

class TestSeverityBoostBoundaries:
    """Boundary values around the two thresholds."""

    def setup_method(self):
        self.analyst = _make_analyst()

    @pytest.mark.parametrize("count,base,expected", [
        (999,   5, 5),   # just below medium threshold — no boost
        (1_000, 5, 6),   # at medium threshold — +1
        (4_999, 5, 6),   # just below high threshold — +1
        (5_000, 5, 7),   # at high threshold — +2
        (5_001, 5, 7),   # just above high threshold — +2
    ])
    def test_boundary_matrix(self, count, base, expected):
        result = self.analyst.adjust_severity_for_record_count(base, count)
        assert result == expected, (
            f"count={count}, base={base}: expected {expected}, got {result}"
        )


# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------

class TestThresholdConstants:
    """Verify threshold constants are accessible and have correct values."""

    def test_high_threshold_constant(self):
        assert ContentAnalyst._RECORD_COUNT_HIGH_THRESHOLD == 5_000

    def test_med_threshold_constant(self):
        assert ContentAnalyst._RECORD_COUNT_MED_THRESHOLD == 1_000

    def test_high_threshold_greater_than_med(self):
        assert ContentAnalyst._RECORD_COUNT_HIGH_THRESHOLD > ContentAnalyst._RECORD_COUNT_MED_THRESHOLD
