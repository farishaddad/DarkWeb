"""Unit tests for entity extraction and technique categorization.

Tests extract_entities() and categorize_technique() methods on ContentAnalyst
with mocked Bedrock invoke_model responses and regex fallback extraction.
"""

import io
import json
from unittest.mock import MagicMock

import pytest

from dark_web_fraud_agent.agents.content_analyst import ContentAnalyst
from dark_web_fraud_agent.config.settings import AnalystConfig
from dark_web_fraud_agent.models.content_analyst import ExtractedEntity, VALID_FRAUD_CATEGORIES


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


def _make_entity_extraction_response(entities: list[dict], affected_institutions: list[str] = None, estimated_record_count: int = None) -> dict:
    """Helper to create a mock Bedrock response for entity extraction."""
    response_json = json.dumps({
        "entities": entities,
        "affected_institutions": affected_institutions or [],
        "estimated_record_count": estimated_record_count,
    })
    body_content = json.dumps({
        "content": [{"type": "text", "text": response_json}],
        "model": "anthropic.claude-opus-4-8-20260601-v1:0",
        "stop_reason": "end_turn",
    })
    return {"body": io.BytesIO(body_content.encode("utf-8"))}


def _make_categorization_response(category: str, reasoning: str = "test") -> dict:
    """Helper to create a mock Bedrock response for technique categorization."""
    response_json = json.dumps({
        "category": category,
        "reasoning": reasoning,
    })
    body_content = json.dumps({
        "content": [{"type": "text", "text": response_json}],
        "model": "anthropic.claude-opus-4-8-20260601-v1:0",
        "stop_reason": "end_turn",
    })
    return {"body": io.BytesIO(body_content.encode("utf-8"))}


class TestExtractEntitiesLLM:
    """Tests for LLM-based entity extraction."""

    def test_extracts_bank_name(self, analyst, mock_bedrock_client):
        """LLM extraction returns bank name entities."""
        mock_bedrock_client.invoke_model.return_value = _make_entity_extraction_response(
            entities=[
                {"entity_type": "bank_name", "value": "Chase Bank", "context": "targeting Chase Bank customers", "confidence": 0.95}
            ]
        )

        result = analyst.extract_entities("Phishing kit targeting Chase Bank customers")

        bank_entities = [e for e in result if e.entity_type == "bank_name"]
        assert len(bank_entities) >= 1
        assert bank_entities[0].value == "Chase Bank"
        assert bank_entities[0].confidence == 0.95

    def test_extracts_multiple_entity_types(self, analyst, mock_bedrock_client):
        """LLM extraction returns multiple entity types."""
        mock_bedrock_client.invoke_model.return_value = _make_entity_extraction_response(
            entities=[
                {"entity_type": "bank_name", "value": "Wells Fargo", "context": "Wells Fargo BIN", "confidence": 0.9},
                {"entity_type": "bin_range", "value": "411111", "context": "BIN 411111 for Visa", "confidence": 0.85},
                {"entity_type": "btc_wallet", "value": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "context": "send BTC to 1A1z...", "confidence": 0.92},
            ]
        )

        result = analyst.extract_entities("Wells Fargo BIN 411111 for Visa. Send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

        entity_types = {e.entity_type for e in result}
        assert "bank_name" in entity_types
        assert "bin_range" in entity_types
        assert "btc_wallet" in entity_types

    def test_returns_empty_list_for_no_entities(self, analyst, mock_bedrock_client):
        """LLM extraction returns empty list when no entities found."""
        mock_bedrock_client.invoke_model.return_value = _make_entity_extraction_response(entities=[])

        result = analyst.extract_entities("General discussion about weather.")
        assert result == []

    def test_bedrock_call_uses_correct_model(self, analyst, mock_bedrock_client):
        """Entity extraction invokes Bedrock with the configured model ID."""
        mock_bedrock_client.invoke_model.return_value = _make_entity_extraction_response(entities=[])

        analyst.extract_entities("test content")

        call_kwargs = mock_bedrock_client.invoke_model.call_args[1]
        assert call_kwargs["modelId"] == "anthropic.claude-opus-4-8-20260601-v1:0"

    def test_skips_invalid_entities_from_llm(self, analyst, mock_bedrock_client):
        """Invalid entities from LLM are skipped without crashing."""
        mock_bedrock_client.invoke_model.return_value = _make_entity_extraction_response(
            entities=[
                {"entity_type": "bank_name", "value": "Chase Bank", "context": "ctx", "confidence": 0.9},
                {"entity_type": "invalid_type", "value": "bad", "context": "ctx", "confidence": 0.5},
                {"entity_type": "email", "value": "", "context": "ctx", "confidence": 0.8},
            ]
        )

        result = analyst.extract_entities("Chase Bank email test")
        # Only the valid bank_name entity should be returned from LLM
        llm_valid = [e for e in result if e.entity_type == "bank_name"]
        assert len(llm_valid) >= 1

    def test_all_extracted_entities_are_valid(self, analyst, mock_bedrock_client):
        """All returned entities have valid entity_type and non-empty values."""
        mock_bedrock_client.invoke_model.return_value = _make_entity_extraction_response(
            entities=[
                {"entity_type": "ip_address", "value": "192.168.1.1", "context": "IP 192.168.1.1", "confidence": 0.88},
                {"entity_type": "email", "value": "test@evil.com", "context": "contact test@evil.com", "confidence": 0.91},
            ]
        )

        result = analyst.extract_entities("IP 192.168.1.1 and contact test@evil.com")

        from dark_web_fraud_agent.models.content_analyst import EntityType
        valid_types = {e.value for e in EntityType}
        for entity in result:
            assert entity.entity_type in valid_types
            assert entity.value != ""
            assert 0.0 <= entity.confidence <= 1.0


class TestExtractEntitiesRegexFallback:
    """Tests for regex-based fallback entity extraction."""

    def test_fallback_extracts_btc_base58_wallet(self, analyst, mock_bedrock_client):
        """Regex fallback extracts Base58 Bitcoin wallets."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        text = "Send payment to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa for the kit"
        result = analyst.extract_entities(text)

        btc_entities = [e for e in result if e.entity_type == "btc_wallet"]
        assert len(btc_entities) >= 1
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in [e.value for e in btc_entities]

    def test_fallback_extracts_btc_bech32_wallet(self, analyst, mock_bedrock_client):
        """Regex fallback extracts Bech32 Bitcoin wallets."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        text = "Payment address: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
        result = analyst.extract_entities(text)

        btc_entities = [e for e in result if e.entity_type == "btc_wallet"]
        assert len(btc_entities) >= 1
        assert "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" in [e.value for e in btc_entities]

    def test_fallback_extracts_ipv4_address(self, analyst, mock_bedrock_client):
        """Regex fallback extracts valid IPv4 addresses."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        text = "C2 server at 192.168.1.100 and 10.0.0.1 for exfil"
        result = analyst.extract_entities(text)

        ip_entities = [e for e in result if e.entity_type == "ip_address"]
        assert len(ip_entities) >= 2
        values = {e.value for e in ip_entities}
        assert "192.168.1.100" in values
        assert "10.0.0.1" in values

    def test_fallback_rejects_invalid_ipv4(self, analyst, mock_bedrock_client):
        """Regex fallback does not extract invalid IPv4 (octets > 255)."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        text = "Address 999.999.999.999 is not valid"
        result = analyst.extract_entities(text)

        ip_entities = [e for e in result if e.entity_type == "ip_address"]
        assert len(ip_entities) == 0

    def test_fallback_extracts_email(self, analyst, mock_bedrock_client):
        """Regex fallback extracts email addresses."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        text = "Contact seller at fraudster@darkweb.onion for details"
        result = analyst.extract_entities(text)

        email_entities = [e for e in result if e.entity_type == "email"]
        assert len(email_entities) >= 1
        assert "fraudster@darkweb.onion" in [e.value for e in email_entities]

    def test_fallback_extracts_url(self, analyst, mock_bedrock_client):
        """Regex fallback extracts URLs including onion links."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        text = "Visit http://example.com/phish and ab2cdef3gh4i.onion/market for tools"
        result = analyst.extract_entities(text)

        url_entities = [e for e in result if e.entity_type == "url"]
        assert len(url_entities) >= 1

    def test_fallback_extracts_swift_code(self, analyst, mock_bedrock_client):
        """Regex fallback extracts SWIFT/BIC codes."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        text = "Wire transfer via SWIFT code CHASUS33XXX to receive funds"
        result = analyst.extract_entities(text)

        swift_entities = [e for e in result if e.entity_type == "swift_code"]
        assert len(swift_entities) >= 1
        assert "CHASUS33XXX" in [e.value for e in swift_entities]

    def test_fallback_extracts_bin_in_financial_context(self, analyst, mock_bedrock_client):
        """Regex fallback extracts BINs when in a financial context."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        text = "New card dump: BIN 411111 Visa credit cards from Chase Bank"
        result = analyst.extract_entities(text)

        bin_entities = [e for e in result if e.entity_type == "bin_range"]
        assert len(bin_entities) >= 1
        assert "411111" in [e.value for e in bin_entities]

    def test_fallback_ignores_bin_without_financial_context(self, analyst, mock_bedrock_client):
        """Regex fallback does NOT treat random 6-digit numbers as BINs."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        text = "The population of the town is 123456 people, and they have 654321 dogs."
        result = analyst.extract_entities(text)

        bin_entities = [e for e in result if e.entity_type == "bin_range"]
        assert len(bin_entities) == 0


class TestExtractEntitiesDeduplication:
    """Tests for deduplication between LLM and regex entities."""

    def test_no_duplicate_entities(self, analyst, mock_bedrock_client):
        """Same entity from LLM and regex should not appear twice."""
        mock_bedrock_client.invoke_model.return_value = _make_entity_extraction_response(
            entities=[
                {"entity_type": "ip_address", "value": "192.168.1.1", "context": "server at 192.168.1.1", "confidence": 0.95}
            ]
        )

        text = "C2 server at 192.168.1.1 for data exfiltration"
        result = analyst.extract_entities(text)

        ip_entities = [e for e in result if e.entity_type == "ip_address" and e.value == "192.168.1.1"]
        assert len(ip_entities) == 1

    def test_supplements_llm_with_regex_findings(self, analyst, mock_bedrock_client):
        """Regex adds entities the LLM missed."""
        mock_bedrock_client.invoke_model.return_value = _make_entity_extraction_response(
            entities=[
                {"entity_type": "bank_name", "value": "Chase Bank", "context": "Chase Bank accounts", "confidence": 0.9}
            ]
        )

        text = "Chase Bank accounts leaked. Contact admin@evil.com for info. Server 10.0.0.5"
        result = analyst.extract_entities(text)

        entity_types = {e.entity_type for e in result}
        assert "bank_name" in entity_types
        assert "email" in entity_types
        assert "ip_address" in entity_types


class TestCategorizeTechnique:
    """Tests for categorize_technique() method."""

    def test_categorizes_mfa_bypass(self, analyst, mock_bedrock_client):
        """Correctly categorizes MFA bypass technique."""
        mock_bedrock_client.invoke_model.return_value = _make_categorization_response(
            category="mfa_bypass",
            reasoning="Describes SIM swapping to intercept OTP codes",
        )

        result = analyst.categorize_technique(
            "New SIM swap method to intercept bank OTP codes. Works on all carriers."
        )

        assert result == "mfa_bypass"

    def test_categorizes_synthetic_identity(self, analyst, mock_bedrock_client):
        """Correctly categorizes synthetic identity creation."""
        mock_bedrock_client.invoke_model.return_value = _make_categorization_response(
            category="synthetic_identity",
            reasoning="Describes creating fake identities with real SSNs",
        )

        result = analyst.categorize_technique(
            "Combining real SSNs with fabricated names to create synthetic identities for bank applications."
        )

        assert result == "synthetic_identity"

    def test_categorizes_phishing_kit(self, analyst, mock_bedrock_client):
        """Correctly categorizes phishing kit."""
        mock_bedrock_client.invoke_model.return_value = _make_categorization_response(
            category="phishing_kit",
            reasoning="Selling phishing templates for bank login pages",
        )

        result = analyst.categorize_technique(
            "Premium phishing kit: Chase, BofA, Wells Fargo templates. Real-time credential capture."
        )

        assert result == "phishing_kit"

    def test_categorizes_cnp_fraud(self, analyst, mock_bedrock_client):
        """Correctly categorizes card-not-present fraud."""
        mock_bedrock_client.invoke_model.return_value = _make_categorization_response(
            category="cnp_fraud",
            reasoning="Describes using stolen card details for online purchases",
        )

        result = analyst.categorize_technique(
            "Using fresh fullz with BIN 411111 for online shopping. Anti-fraud bypass included."
        )

        assert result == "cnp_fraud"

    def test_categorizes_account_takeover(self, analyst, mock_bedrock_client):
        """Correctly categorizes account takeover."""
        mock_bedrock_client.invoke_model.return_value = _make_categorization_response(
            category="account_takeover",
            reasoning="Credential stuffing attack on banking portals",
        )

        result = analyst.categorize_technique(
            "Automated credential stuffing tool for bank login portals. 100k combos included."
        )

        assert result == "account_takeover"

    def test_returns_none_for_non_bypass_content(self, analyst, mock_bedrock_client):
        """Returns None when content is not a bypass technique."""
        mock_bedrock_client.invoke_model.return_value = _make_categorization_response(
            category=None,
            reasoning="Not a bypass technique",
        )

        result = analyst.categorize_technique(
            "General discussion about VPN privacy features and streaming."
        )

        assert result is None

    def test_returns_none_for_invalid_category_from_llm(self, analyst, mock_bedrock_client):
        """Returns None when LLM returns an invalid category string."""
        mock_bedrock_client.invoke_model.return_value = _make_categorization_response(
            category="invalid_category_name",
            reasoning="bad category",
        )

        result = analyst.categorize_technique("some text")
        assert result is None

    def test_returns_none_when_bedrock_returns_empty_content(self, analyst, mock_bedrock_client):
        """Returns None when Bedrock returns empty content blocks."""
        body_content = json.dumps({"content": []})
        mock_bedrock_client.invoke_model.return_value = {
            "body": io.BytesIO(body_content.encode("utf-8"))
        }

        result = analyst.categorize_technique("test content")
        assert result is None

    def test_raises_runtime_error_on_bedrock_failure(self, analyst, mock_bedrock_client):
        """RuntimeError raised when Bedrock invocation fails."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Service unavailable")

        with pytest.raises(RuntimeError, match="Bedrock invocation failed"):
            analyst.categorize_technique("test content")

    def test_returns_none_for_malformed_json(self, analyst, mock_bedrock_client):
        """Returns None when LLM returns non-JSON text."""
        body_content = json.dumps({
            "content": [{"type": "text", "text": "I cannot classify this content properly."}],
        })
        mock_bedrock_client.invoke_model.return_value = {
            "body": io.BytesIO(body_content.encode("utf-8"))
        }

        result = analyst.categorize_technique("test content")
        assert result is None

    def test_exactly_one_category_returned(self, analyst, mock_bedrock_client):
        """The method returns exactly one category string, not a list."""
        mock_bedrock_client.invoke_model.return_value = _make_categorization_response(
            category="phishing_kit",
            reasoning="Clear phishing kit content",
        )

        result = analyst.categorize_technique("Premium phishing kit for sale")

        assert isinstance(result, str)
        assert result in VALID_FRAUD_CATEGORIES

    def test_all_five_categories_are_valid_returns(self, analyst, mock_bedrock_client):
        """Each of the 5 fraud categories can be returned."""
        for category in VALID_FRAUD_CATEGORIES:
            mock_bedrock_client.invoke_model.return_value = _make_categorization_response(
                category=category,
                reasoning=f"Test for {category}",
            )
            result = analyst.categorize_technique(f"Content about {category}")
            assert result == category

    def test_uses_correct_model_id(self, analyst, mock_bedrock_client):
        """Categorization uses the configured Bedrock model ID."""
        mock_bedrock_client.invoke_model.return_value = _make_categorization_response(
            category="mfa_bypass"
        )

        analyst.categorize_technique("test")

        call_kwargs = mock_bedrock_client.invoke_model.call_args[1]
        assert call_kwargs["modelId"] == "anthropic.claude-opus-4-8-20260601-v1:0"


class TestExtractEntitiesAffectedInstitutions:
    """Tests for extraction of affected institutions and record counts from Fullz/dumps."""

    def test_extracts_affected_institutions(self, analyst, mock_bedrock_client):
        """LLM extraction includes affected institutions from credential dumps."""
        mock_bedrock_client.invoke_model.return_value = _make_entity_extraction_response(
            entities=[
                {"entity_type": "bank_name", "value": "Chase Bank", "context": "Chase fullz dump", "confidence": 0.92},
                {"entity_type": "bank_name", "value": "Bank of America", "context": "BofA credentials", "confidence": 0.88},
            ],
            affected_institutions=["Chase Bank", "Bank of America"],
            estimated_record_count=50000,
        )

        result = analyst.extract_entities(
            "Fresh fullz dump: 50k records from Chase Bank and Bank of America. Full SSN + DOB included."
        )

        bank_entities = [e for e in result if e.entity_type == "bank_name"]
        assert len(bank_entities) >= 2
        bank_names = {e.value for e in bank_entities}
        assert "Chase Bank" in bank_names
        assert "Bank of America" in bank_names
