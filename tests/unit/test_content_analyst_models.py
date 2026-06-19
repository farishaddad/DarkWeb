"""Unit tests for Content Analyst data models."""

import pytest

from dark_web_fraud_agent.models.content_analyst import (
    VALID_FRAUD_CATEGORIES,
    ClassifiedContent,
    EntityType,
    ExtractedEntity,
)


class TestEntityType:
    """Tests for EntityType string enum."""

    def test_all_entity_types_defined(self):
        expected = {
            "bank_name",
            "bin_range",
            "swift_code",
            "btc_wallet",
            "email",
            "url",
            "ip_address",
        }
        actual = {e.value for e in EntityType}
        assert actual == expected

    def test_entity_type_count(self):
        assert len(EntityType) == 7

    def test_entity_type_is_string_enum(self):
        """EntityType values can be used as plain strings."""
        assert EntityType.BANK_NAME == "bank_name"
        assert EntityType.BTC_WALLET == "btc_wallet"

    def test_entity_type_from_value(self):
        assert EntityType("bank_name") == EntityType.BANK_NAME
        assert EntityType("ip_address") == EntityType.IP_ADDRESS

    def test_invalid_entity_type_raises(self):
        with pytest.raises(ValueError):
            EntityType("invalid_type")


class TestExtractedEntity:
    """Tests for ExtractedEntity dataclass."""

    def test_create_valid_entity(self):
        entity = ExtractedEntity(
            entity_type="btc_wallet",
            value="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            context="Payment to wallet 1A1zP1... for phishing kit",
            confidence=0.95,
        )
        assert entity.entity_type == "btc_wallet"
        assert entity.value == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        assert entity.context == "Payment to wallet 1A1zP1... for phishing kit"
        assert entity.confidence == 0.95

    def test_create_entity_with_each_type(self):
        """Verify each entity type can be used."""
        for entity_type in EntityType:
            entity = ExtractedEntity(
                entity_type=entity_type.value,
                value="test_value",
                context="test context",
                confidence=0.8,
            )
            assert entity.entity_type == entity_type.value

    def test_invalid_entity_type_raises(self):
        with pytest.raises(ValueError, match="entity_type must be one of"):
            ExtractedEntity(
                entity_type="unknown_type",
                value="some_value",
                context="context",
                confidence=0.5,
            )

    def test_empty_value_raises(self):
        with pytest.raises(ValueError, match="value must be a non-empty string"):
            ExtractedEntity(
                entity_type="email",
                value="",
                context="context",
                confidence=0.5,
            )

    def test_confidence_below_zero_raises(self):
        with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
            ExtractedEntity(
                entity_type="email",
                value="test@example.com",
                context="context",
                confidence=-0.1,
            )

    def test_confidence_above_one_raises(self):
        with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
            ExtractedEntity(
                entity_type="email",
                value="test@example.com",
                context="context",
                confidence=1.1,
            )

    def test_confidence_boundary_zero(self):
        entity = ExtractedEntity(
            entity_type="url",
            value="http://example.onion",
            context="link found",
            confidence=0.0,
        )
        assert entity.confidence == 0.0

    def test_confidence_boundary_one(self):
        entity = ExtractedEntity(
            entity_type="url",
            value="http://example.onion",
            context="link found",
            confidence=1.0,
        )
        assert entity.confidence == 1.0


class TestClassifiedContent:
    """Tests for ClassifiedContent dataclass."""

    def test_create_valid_classified_content(self):
        entities = [
            ExtractedEntity(
                entity_type="bank_name",
                value="Chase Bank",
                context="targeting Chase Bank customers",
                confidence=0.9,
            ),
        ]
        content = ClassifiedContent(
            source_ref="s3://bucket/artifacts/2026/06/15/abc123.json",
            is_fraud_relevant=True,
            confidence=0.92,
            requires_manual_review=False,
            severity_score=7,
            fraud_category="phishing_kit",
            entities=entities,
            raw_text_snippet="Selling premium phishing kit targeting Chase Bank...",
            bedrock_guardrail_result="PASSED",
        )
        assert content.source_ref == "s3://bucket/artifacts/2026/06/15/abc123.json"
        assert content.is_fraud_relevant is True
        assert content.confidence == 0.92
        assert content.requires_manual_review is False
        assert content.severity_score == 7
        assert content.fraud_category == "phishing_kit"
        assert len(content.entities) == 1
        assert content.entities[0].value == "Chase Bank"
        assert content.raw_text_snippet.startswith("Selling premium")
        assert content.bedrock_guardrail_result == "PASSED"

    def test_create_minimal_classified_content(self):
        """Test with only required fields (optional fields use defaults)."""
        content = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=False,
            confidence=0.3,
            requires_manual_review=True,
            severity_score=1,
        )
        assert content.fraud_category is None
        assert content.entities == []
        assert content.raw_text_snippet == ""
        assert content.bedrock_guardrail_result == "PASSED"

    def test_empty_source_ref_raises(self):
        with pytest.raises(ValueError, match="source_ref must be a non-empty string"):
            ClassifiedContent(
                source_ref="",
                is_fraud_relevant=False,
                confidence=0.5,
                requires_manual_review=False,
                severity_score=3,
            )

    def test_confidence_out_of_range_raises(self):
        with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
            ClassifiedContent(
                source_ref="s3://bucket/key",
                is_fraud_relevant=True,
                confidence=1.5,
                requires_manual_review=False,
                severity_score=5,
            )

    def test_severity_score_below_one_raises(self):
        with pytest.raises(ValueError, match="severity_score must be between 1 and 10"):
            ClassifiedContent(
                source_ref="s3://bucket/key",
                is_fraud_relevant=True,
                confidence=0.8,
                requires_manual_review=False,
                severity_score=0,
            )

    def test_severity_score_above_ten_raises(self):
        with pytest.raises(ValueError, match="severity_score must be between 1 and 10"):
            ClassifiedContent(
                source_ref="s3://bucket/key",
                is_fraud_relevant=True,
                confidence=0.8,
                requires_manual_review=False,
                severity_score=11,
            )

    def test_severity_score_boundaries(self):
        """Verify boundary values 1 and 10 are accepted."""
        for score in (1, 10):
            content = ClassifiedContent(
                source_ref="s3://bucket/key",
                is_fraud_relevant=True,
                confidence=0.8,
                requires_manual_review=False,
                severity_score=score,
            )
            assert content.severity_score == score

    def test_valid_fraud_categories(self):
        """Verify all valid fraud categories are accepted."""
        for category in VALID_FRAUD_CATEGORIES:
            content = ClassifiedContent(
                source_ref="s3://bucket/key",
                is_fraud_relevant=True,
                confidence=0.9,
                requires_manual_review=False,
                severity_score=5,
                fraud_category=category,
            )
            assert content.fraud_category == category

    def test_invalid_fraud_category_raises(self):
        with pytest.raises(ValueError, match="fraud_category must be one of"):
            ClassifiedContent(
                source_ref="s3://bucket/key",
                is_fraud_relevant=True,
                confidence=0.9,
                requires_manual_review=False,
                severity_score=5,
                fraud_category="invalid_category",
            )

    def test_fraud_category_none_accepted(self):
        content = ClassifiedContent(
            source_ref="s3://bucket/key",
            is_fraud_relevant=False,
            confidence=0.4,
            requires_manual_review=True,
            severity_score=2,
            fraud_category=None,
        )
        assert content.fraud_category is None

    def test_valid_guardrail_results(self):
        """Verify all valid guardrail result values are accepted."""
        for result in ("PASSED", "FILTERED", "FLAGGED"):
            content = ClassifiedContent(
                source_ref="s3://bucket/key",
                is_fraud_relevant=True,
                confidence=0.8,
                requires_manual_review=False,
                severity_score=5,
                bedrock_guardrail_result=result,
            )
            assert content.bedrock_guardrail_result == result

    def test_invalid_guardrail_result_raises(self):
        with pytest.raises(ValueError, match="bedrock_guardrail_result must be one of"):
            ClassifiedContent(
                source_ref="s3://bucket/key",
                is_fraud_relevant=True,
                confidence=0.8,
                requires_manual_review=False,
                severity_score=5,
                bedrock_guardrail_result="UNKNOWN",
            )

    def test_content_with_multiple_entities(self):
        entities = [
            ExtractedEntity(
                entity_type="bank_name",
                value="Chase Bank",
                context="targeting Chase",
                confidence=0.9,
            ),
            ExtractedEntity(
                entity_type="bin_range",
                value="411111",
                context="BIN 411111 for Chase Visa",
                confidence=0.85,
            ),
            ExtractedEntity(
                entity_type="btc_wallet",
                value="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                context="send payment to bc1q...",
                confidence=0.95,
            ),
        ]
        content = ClassifiedContent(
            source_ref="s3://bucket/artifacts/item-456",
            is_fraud_relevant=True,
            confidence=0.88,
            requires_manual_review=False,
            severity_score=8,
            fraud_category="cnp_fraud",
            entities=entities,
            raw_text_snippet="Premium BIN list for Chase Visa cards...",
            bedrock_guardrail_result="PASSED",
        )
        assert len(content.entities) == 3
        assert content.entities[0].entity_type == "bank_name"
        assert content.entities[1].entity_type == "bin_range"
        assert content.entities[2].entity_type == "btc_wallet"
