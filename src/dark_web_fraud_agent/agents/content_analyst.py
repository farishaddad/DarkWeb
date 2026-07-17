"""Content Analyst agent for fraud relevance classification.

This module implements the ContentAnalyst agent that:
- Classifies dark web content for fraud relevance using Claude Opus 4.8 via Bedrock
- Applies Bedrock Guardrails (prompt injection, harmful content, sensitive data detection)
- Returns (is_fraud_relevant, confidence) tuples
- Flags low-confidence results for manual review
- Extracts structured entities (BINs, SWIFT codes, wallets, emails, IPs, URLs, bank names)
- Categorizes bypass techniques into fraud categories
"""

import json
import logging
import os
import re
from typing import Any, Optional

import boto3

from dark_web_fraud_agent.config.settings import AnalystConfig
from dark_web_fraud_agent.models.content_analyst import (
    ClassifiedContent,
    ExtractedEntity,
    VALID_FRAUD_CATEGORIES,
)
from dark_web_fraud_agent.models.shared import AgentBase, AgentConfig, AgentHealth

logger = logging.getLogger(__name__)

# Classification prompt template for fraud relevance analysis
CLASSIFICATION_PROMPT = """You are a banking fraud intelligence analyst. Analyze the following dark web content and determine if it is relevant to banking fraud.

Content to analyze:
<content>
{text}
</content>

Respond ONLY with a JSON object in the following format:
{{
  "is_fraud_relevant": true or false,
  "confidence": a float between 0.0 and 1.0,
  "reasoning": "brief explanation of your determination"
}}

Classification criteria for fraud-relevant content:
- Discussions about bypassing bank security controls (MFA, 2FA, OTP)
- Stolen credential dumps, Fullz, or card data listings
- Phishing kits targeting financial institutions
- Account takeover techniques or tools
- Synthetic identity creation methods
- Card-not-present (CNP) fraud techniques
- BIN lists, SWIFT codes, or bank routing information
- Cryptocurrency wallets used for fraud proceeds
- Tutorials or guides for financial fraud

Content that is NOT fraud-relevant:
- General dark web discussion unrelated to banking
- Drug marketplace listings
- Non-financial hacking discussions
- Political content or activism
- Personal communications without fraud context

Provide your confidence score based on how clearly the content matches fraud indicators.
A score below 0.7 indicates uncertainty and the content should be flagged for manual review."""


# Entity extraction prompt template
ENTITY_EXTRACTION_PROMPT = """You are a banking fraud intelligence analyst specializing in entity extraction from dark web content.

Analyze the following text and extract ALL structured entities you can identify:

<content>
{text}
</content>

Extract entities of these types:
- bank_name: Names of banks or financial institutions
- bin_range: Bank Identification Numbers (first 6 digits of payment cards)
- swift_code: SWIFT/BIC codes (8-11 character bank identifiers)
- btc_wallet: Bitcoin wallet addresses (Base58 or Bech32 format)
- email: Email addresses
- url: URLs or onion links
- ip_address: IPv4 addresses
- merchant_id: Merchant IDs (MID) — typically 15-digit numeric strings in payment fraud context
- acquiring_bin: Acquiring bank BINs — 6-digit codes identifying payment processors
- national_id: National identity numbers (UK NI format AA999999A, US SSN format NNN-NN-NNNN)
- sort_code: UK bank sort codes (format NN-NN-NN or NNNNNN)
- iban: International Bank Account Numbers (format CCddBBBBBBBBBBBBBBB)
- monero_wallet: Monero wallet addresses (95-character strings starting with 4 or 8)

For each entity, provide:
- entity_type: one of the types listed above
- value: the extracted value
- context: surrounding text (up to 50 characters each side) providing context
- confidence: your confidence in the extraction (0.0 to 1.0)

Also extract:
- affected_institutions: list of institution names if this is a credential dump or Fullz listing
- estimated_record_count: estimated number of records if mentioned

Respond ONLY with a JSON object in the following format:
{{
  "entities": [
    {{"entity_type": "...", "value": "...", "context": "...", "confidence": 0.95}},
    ...
  ],
  "affected_institutions": ["Bank A", "Bank B"],
  "estimated_record_count": null
}}

If no entities are found, return an empty entities list."""

# Technique categorization prompt template
CATEGORIZATION_PROMPT = """You are a banking fraud intelligence analyst. Classify the following dark web content into exactly ONE fraud technique category.

<content>
{text}
</content>

Categories:
1. mfa_bypass - Techniques for bypassing multi-factor authentication (2FA, OTP interception, SIM swapping for MFA)
2. synthetic_identity - Creating fake identities using real and fabricated data (Fullz manipulation, synthetic SSNs)
3. phishing_kit - Phishing tools, kits, or templates targeting financial institutions
4. cnp_fraud - Card-not-present fraud techniques (stolen card data, BIN attacks, online transaction fraud)
5. account_takeover - Methods for taking over existing bank accounts (credential stuffing, session hijacking)
6. new_account_fraud - Opening accounts using stolen Fullz or fabricated identities to commit fraud
7. recurring_billing_fraud - Enrolling stolen cards in recurring subscriptions or small-amount billing schemes
8. money_mule - Mule recruitment, reverse money mule schemes, unwitting account holders forwarding fraud proceeds
9. investment_fraud - Fake investment platforms, pig-butchering schemes, fake crypto exchanges, HYIP scams
10. social_engineering - Romance scripts, coached-secrecy guides, mule recruitment scripts, social manipulation

If the content does NOT describe any of the above fraud types, respond with:
{{"category": null, "reasoning": "Not a fraud technique"}}

Otherwise respond ONLY with a JSON object:
{{
  "category": "one_of_the_five_categories",
  "reasoning": "brief explanation"
}}"""

# ---------------------------------------------------------------------------
# COMBINED prompt — single Bedrock call returning all analysis (replaces 3x calls)
# Use this in production; the individual prompts above are kept for unit tests.
# ---------------------------------------------------------------------------
COMBINED_ANALYSIS_PROMPT = """You are a banking fraud intelligence analyst. Analyse the following dark web content and return a single JSON response covering ALL of: fraud relevance, entity extraction, and technique categorisation.

Content:
<content>
{text}
</content>

Respond ONLY with this JSON structure:
{{
  "is_fraud_relevant": true or false,
  "confidence": float 0.0-1.0,
  "reasoning": "brief explanation",
  "entities": [
    {{"entity_type": "bank_name|bin_range|swift_code|btc_wallet|email|url|ip_address",
      "value": "...", "context": "surrounding 50 chars", "confidence": float}}
  ],
  "affected_institutions": ["Bank A", "Bank B"],
  "estimated_record_count": null,
  "fraud_category": "mfa_bypass|synthetic_identity|phishing_kit|cnp_fraud|account_takeover|new_account_fraud|recurring_billing_fraud|money_mule|investment_fraud|social_engineering|null"
}}

Fraud relevance criteria: MFA bypass, stolen credentials/Fullz, phishing kits, account takeover,
synthetic identity, CNP fraud, BIN/SWIFT data, crypto wallets used for fraud proceeds,
fake investment platforms, romance/pig-butchering scripts, mule recruitment, recurring billing abuse.
Fraud categories: mfa_bypass, synthetic_identity, phishing_kit, cnp_fraud, account_takeover,
new_account_fraud, recurring_billing_fraud, money_mule, investment_fraud, social_engineering.
Entity types: bank_name, bin_range, swift_code, btc_wallet, email, url, ip_address,
merchant_id, acquiring_bin, national_id, sort_code, iban, monero_wallet.
If content is not fraud-relevant, entities and fraud_category should be empty/null.
Confidence < 0.7 indicates uncertainty — flag for manual review."""



# ---------------------------------------------------------------------------
# Coached-secrecy keyword override (XC-007 pig-butchering detection)
# ---------------------------------------------------------------------------
# When these phrases are present, force fraud_category = "social_engineering"
# regardless of LLM classification — they are unambiguous pig-butchering markers.
_COACHED_SECRECY_KEYWORDS = (
    "don't tell your bank",
    "dont tell your bank",
    "they'll freeze your funds",
    "they will freeze your funds",
    "investment protection scheme",
    "authorized push payment",
    "tell them it's for",
    "tell them its for",
    "romance script",
    "pig butcher",
    "sha zhu pan",
    "wrong number text",
)


# Regex patterns for fallback entity extraction
_BIN_PATTERN = re.compile(r'\b([3-6]\d{5})\b')
_SWIFT_PATTERN = re.compile(r'\b([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b')
_BTC_BASE58_PATTERN = re.compile(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
_BTC_BECH32_PATTERN = re.compile(r'\b(bc1[a-z0-9]{39,59})\b')
_MONERO_PATTERN = re.compile(r'\b([48][0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b')   # XMR standard address (95 chars)
_IBAN_PATTERN = re.compile(r'\b([A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}(?:[A-Z0-9]?)*)\b')
_SORT_CODE_PATTERN = re.compile(r'\b(\d{2}-\d{2}-\d{2}|\d{6})\b')
_MID_PATTERN = re.compile(r'\b(\d{15})\b')                                   # ISO 8583 MID format
_IPV4_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_EMAIL_PATTERN = re.compile(r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b')
_URL_PATTERN = re.compile(r'(https?://[^\s<>"]+|[a-z0-9\-]+\.onion(?:/[^\s<>"]*)?)')


class ContentAnalyst(AgentBase):
    """AgentCore agent for classifying dark web content for banking fraud relevance.

    Uses Claude Opus 4.8 via Amazon Bedrock with Bedrock Guardrails for content safety.
    Classifies content as fraud-relevant or irrelevant, assigns confidence scores,
    and flags low-confidence items for manual review.
    """

    def __init__(
        self,
        config: AnalystConfig,
        bedrock_client: Optional[Any] = None,
    ) -> None:
        """Initialize the Content Analyst agent.

        Args:
            config: AnalystConfig with Bedrock model ID, guardrail ID,
                    knowledge base ID, and confidence threshold.
            bedrock_client: Optional boto3 bedrock-runtime client
                           (created if not provided).
        """
        # Create base AgentConfig from AnalystConfig
        agent_config = AgentConfig(
            agent_id="content-analyst",
            agent_name="Content Analyst",
            s3_bucket=config.s3_bucket,
        )
        super().__init__(agent_config)
        self._analyst_config = config
        self._bedrock_client = bedrock_client or boto3.client("bedrock-runtime")

    @property
    def analyst_config(self) -> AnalystConfig:
        """Return the analyst-specific configuration."""
        return self._analyst_config

    def get_health(self) -> AgentHealth:
        """Return the current health status of the Content Analyst agent."""
        return self._health

    def classify_relevance(self, text: str) -> tuple[bool, float]:
        """Classify dark web content for banking fraud relevance.

        Invokes Claude Opus 4.8 via Bedrock with Guardrails applied for
        content safety (prompt injection, harmful content, sensitive data).

        Args:
            text: Raw text content from the Crawling Engine to classify.

        Returns:
            Tuple of (is_fraud_relevant, confidence) where:
            - is_fraud_relevant: True if content is relevant to banking fraud
            - confidence: Float in [0.0, 1.0] indicating classification confidence

        Raises:
            ValueError: If the LLM response cannot be parsed.
            RuntimeError: If Bedrock invocation fails.
        """
        # Build the prompt
        prompt = CLASSIFICATION_PROMPT.format(text=text)

        # Prepare the request body for Claude on Bedrock
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 512,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "temperature": 0.1,
        }

        # Invoke Bedrock with Guardrails
        try:
            response = self._bedrock_client.invoke_model(
                modelId=self._analyst_config.bedrock_model_id,
                body=json.dumps(request_body),
                contentType="application/json",
                accept="application/json",
                guardrailIdentifier=self._analyst_config.guardrail_id,
                # "DRAFT" is only valid during development; production must pin a
                # published version number. Injected via GUARDRAIL_VERSION env var.
                guardrailVersion=os.environ.get("GUARDRAIL_VERSION", "1"),
            )
        except Exception as e:
            logger.error(f"Bedrock invocation failed: {e}")
            raise RuntimeError(f"Bedrock invocation failed: {e}") from e

        # Parse the response
        response_body = json.loads(response["body"].read())

        # Check for guardrail intervention
        guardrail_action = response_body.get("amazon-bedrock-guardrailAction")
        if guardrail_action == "GUARDRAIL_INTERVENED":
            logger.warning("Bedrock Guardrails intervened on content classification")
            # Return as not fraud-relevant with low confidence when guardrails block
            return (False, 0.0)

        # Extract the text content from Claude's response
        content_blocks = response_body.get("content", [])
        if not content_blocks:
            raise ValueError("Empty response from Bedrock model")

        response_text = content_blocks[0].get("text", "")

        # Parse the JSON response from Claude
        return self._parse_classification_response(response_text)

    def _parse_classification_response(self, response_text: str) -> tuple[bool, float]:
        """Parse the classification JSON response from Claude.

        Extracts is_fraud_relevant and confidence from the LLM output.
        Handles common response format variations.

        Args:
            response_text: Raw text response from Claude.

        Returns:
            Tuple of (is_fraud_relevant, confidence).

        Raises:
            ValueError: If the response cannot be parsed into the expected format.
        """
        try:
            # Try to find JSON in the response (Claude may include extra text)
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start == -1 or json_end == 0:
                raise ValueError("No JSON object found in response")

            json_str = response_text[json_start:json_end]
            result = json.loads(json_str)

            is_fraud_relevant = bool(result.get("is_fraud_relevant", False))
            confidence = float(result.get("confidence", 0.0))

            # Clamp confidence to [0.0, 1.0]
            confidence = max(0.0, min(1.0, confidence))

            return (is_fraud_relevant, confidence)

        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.error(f"Failed to parse classification response: {response_text}")
            raise ValueError(
                f"Failed to parse classification response: {e}"
            ) from e

    def classify_and_extract_combined(self, text: str) -> dict:
        """Single Bedrock invocation combining classify, extract, and categorise.

        Replaces the 3-call pattern (classify_relevance + extract_entities +
        categorize_technique) with a single prompt returning all outputs as JSON.
        Reduces Bedrock cost by ~3x and latency by ~2x.

        Returns a dict with keys: is_fraud_relevant, confidence, entities,
        fraud_category, affected_institutions, estimated_record_count.
        On guardrail intervention returns is_fraud_relevant=False, confidence=0.0.
        """
        prompt = COMBINED_ANALYSIS_PROMPT.format(text=text)
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        }
        try:
            response = self._bedrock_client.invoke_model(
                modelId=self._analyst_config.bedrock_model_id,
                body=__import__("json").dumps(request_body),
                contentType="application/json",
                accept="application/json",
                guardrailIdentifier=self._analyst_config.guardrail_id,
                guardrailVersion=os.environ.get("GUARDRAIL_VERSION", "1"),
            )
        except Exception as e:
            logger.error("Combined Bedrock call failed: %s", e)
            raise RuntimeError(f"Bedrock invocation failed: {e}") from e

        body = __import__("json").loads(response["body"].read())
        if body.get("amazon-bedrock-guardrailAction") == "GUARDRAIL_INTERVENED":
            logger.warning("Guardrails intervened on combined analysis")
            return {"is_fraud_relevant": False, "confidence": 0.0,
                    "entities": [], "fraud_category": None,
                    "affected_institutions": [], "estimated_record_count": None}

        text_out = (body.get("content") or [{}])[0].get("text", "{}")
        # Strip markdown code fences if Claude wraps in ```json
        text_out = text_out.strip()
        if text_out.startswith("```"):
            text_out = text_out.split("```")[1]
            if text_out.startswith("json"):
                text_out = text_out[4:]
        try:
            result = __import__("json").loads(text_out)
        except Exception:
            logger.warning("Failed to parse combined response, falling back to 3-call path")
            is_rel, conf = self.classify_relevance(text)
            ents = self.extract_entities(text) if is_rel else []
            cat = self.categorize_technique(text) if is_rel else None
            return {"is_fraud_relevant": is_rel, "confidence": conf,
                    "entities": ents, "fraud_category": cat,
                    "affected_institutions": [], "estimated_record_count": None}

        # Hydrate entity dicts into ExtractedEntity objects
        raw_entities = result.get("entities") or []
        hydrated = []
        for e in raw_entities:
            try:
                hydrated.append(ExtractedEntity(
                    entity_type=e.get("entity_type", "url"),
                    value=e.get("value", ""),
                    context=e.get("context", ""),
                    confidence=float(e.get("confidence", 0.8)),
                ))
            except (ValueError, KeyError):
                pass
        result["entities"] = hydrated

        # Coached-secrecy keyword override: force social_engineering classification
        # regardless of LLM output when unambiguous pig-butchering markers are present.
        raw_snippet = text.lower()
        if any(kw in raw_snippet for kw in _COACHED_SECRECY_KEYWORDS):
            result["fraud_category"] = "social_engineering"
            result["is_fraud_relevant"] = True
            # Ensure confidence is high enough to skip manual-review flag
            if result.get("confidence", 0.0) < 0.85:
                result["confidence"] = 0.85

        return result

    def should_require_manual_review(self, confidence: float) -> bool:
        """Determine if content should be flagged for manual review.

        Args:
            confidence: Classification confidence score.

        Returns:
            True if confidence is below the configured threshold (default 0.7).
        """
        return confidence < self._analyst_config.confidence_threshold

    def extract_entities(self, text: str) -> list[ExtractedEntity]:
        """Extract structured entities from dark web content using LLM + regex fallback.

        Uses Claude Opus 4.8 via Bedrock for intelligent entity extraction (NER + LLM).
        Falls back to regex-based extraction for structured identifiers if LLM fails
        or as a supplement to LLM results.

        Args:
            text: Raw text content to extract entities from.

        Returns:
            List of ExtractedEntity instances with type, value, context, and confidence.

        Raises:
            RuntimeError: If Bedrock invocation fails and regex fallback also produces no results.
        """
        entities: list[ExtractedEntity] = []

        # Try LLM-based extraction first
        try:
            llm_entities = self._extract_entities_via_llm(text)
            entities.extend(llm_entities)
        except (RuntimeError, ValueError) as e:
            logger.warning(f"LLM entity extraction failed, using regex fallback: {e}")

        # Always supplement with regex-based fallback extraction
        regex_entities = self._extract_entities_via_regex(text)

        # Merge: add regex entities that aren't duplicates of LLM entities
        existing_values = {(e.entity_type, e.value) for e in entities}
        for entity in regex_entities:
            if (entity.entity_type, entity.value) not in existing_values:
                entities.append(entity)
                existing_values.add((entity.entity_type, entity.value))

        return entities

    def _extract_entities_via_llm(self, text: str) -> list[ExtractedEntity]:
        """Extract entities using Claude Opus 4.8 via Bedrock.

        Args:
            text: Raw text to extract entities from.

        Returns:
            List of ExtractedEntity instances from LLM extraction.

        Raises:
            RuntimeError: If Bedrock invocation fails.
            ValueError: If the LLM response cannot be parsed.
        """
        prompt = ENTITY_EXTRACTION_PROMPT.format(text=text)

        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 2048,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "temperature": 0.1,
        }

        try:
            response = self._bedrock_client.invoke_model(
                modelId=self._analyst_config.bedrock_model_id,
                body=json.dumps(request_body),
                contentType="application/json",
                accept="application/json",
            )
        except Exception as e:
            logger.error(f"Bedrock invocation failed for entity extraction: {e}")
            raise RuntimeError(f"Bedrock invocation failed: {e}") from e

        response_body = json.loads(response["body"].read())
        content_blocks = response_body.get("content", [])
        if not content_blocks:
            raise ValueError("Empty response from Bedrock model")

        response_text = content_blocks[0].get("text", "")
        return self._parse_entity_extraction_response(response_text)

    def _parse_entity_extraction_response(self, response_text: str) -> list[ExtractedEntity]:
        """Parse the entity extraction JSON response from Claude.

        Args:
            response_text: Raw text response from Claude.

        Returns:
            List of validated ExtractedEntity instances.

        Raises:
            ValueError: If the response cannot be parsed.
        """
        try:
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start == -1 or json_end == 0:
                raise ValueError("No JSON object found in response")

            json_str = response_text[json_start:json_end]
            result = json.loads(json_str)

            entities: list[ExtractedEntity] = []
            for entity_data in result.get("entities", []):
                try:
                    entity = ExtractedEntity(
                        entity_type=entity_data.get("entity_type", ""),
                        value=entity_data.get("value", ""),
                        context=entity_data.get("context", ""),
                        confidence=float(entity_data.get("confidence", 0.0)),
                    )
                    entities.append(entity)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Skipping invalid entity from LLM: {e}")
                    continue

            return entities

        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.error(f"Failed to parse entity extraction response: {response_text}")
            raise ValueError(f"Failed to parse entity extraction response: {e}") from e

    def _extract_entities_via_regex(self, text: str) -> list[ExtractedEntity]:
        """Extract entities using regex patterns as fallback.

        Provides reliable extraction for structured identifiers that have
        well-defined patterns (BINs, SWIFT codes, BTC wallets, IPs, emails, URLs).

        Args:
            text: Raw text to extract entities from.

        Returns:
            List of ExtractedEntity instances from regex extraction.
        """
        entities: list[ExtractedEntity] = []

        # Extract BIN ranges (6-digit sequences in context of financial content)
        for match in _BIN_PATTERN.finditer(text):
            value = match.group(1)
            # Only consider as BIN if in a financial context
            context = self._get_surrounding_context(text, match.start(), match.end())
            if self._is_likely_bin(value, context):
                entities.append(ExtractedEntity(
                    entity_type="bin_range",
                    value=value,
                    context=context,
                    confidence=0.7,
                ))

        # Extract SWIFT codes (8-11 uppercase chars matching bank code format)
        for match in _SWIFT_PATTERN.finditer(text):
            value = match.group(1)
            if len(value) in (8, 11):
                context = self._get_surrounding_context(text, match.start(), match.end())
                entities.append(ExtractedEntity(
                    entity_type="swift_code",
                    value=value,
                    context=context,
                    confidence=0.8,
                ))

        # Extract BTC wallets (Base58 and Bech32)
        for pattern in (_BTC_BASE58_PATTERN, _BTC_BECH32_PATTERN):
            for match in pattern.finditer(text):
                value = match.group(1)
                context = self._get_surrounding_context(text, match.start(), match.end())
                entities.append(ExtractedEntity(
                    entity_type="btc_wallet",
                    value=value,
                    context=context,
                    confidence=0.9,
                ))

        # Extract IPv4 addresses
        for match in _IPV4_PATTERN.finditer(text):
            value = match.group(1)
            # Validate each octet is 0-255
            octets = value.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                context = self._get_surrounding_context(text, match.start(), match.end())
                entities.append(ExtractedEntity(
                    entity_type="ip_address",
                    value=value,
                    context=context,
                    confidence=0.85,
                ))

        # Extract email addresses
        for match in _EMAIL_PATTERN.finditer(text):
            value = match.group(1)
            context = self._get_surrounding_context(text, match.start(), match.end())
            entities.append(ExtractedEntity(
                entity_type="email",
                value=value,
                context=context,
                confidence=0.9,
            ))

        # Extract URLs
        for match in _URL_PATTERN.finditer(text):
            value = match.group(0)
            context = self._get_surrounding_context(text, match.start(), match.end())
            entities.append(ExtractedEntity(
                entity_type="url",
                value=value,
                context=context,
                confidence=0.85,
            ))

        # Extract Monero wallets (XMR — used in pig-butchering laundering chains)
        for match in _MONERO_PATTERN.finditer(text):
            value = match.group(1)
            context = self._get_surrounding_context(text, match.start(), match.end())
            entities.append(ExtractedEntity(
                entity_type="monero_wallet",
                value=value,
                context=context,
                confidence=0.85,
            ))

        # Extract IBANs (CHAPS-026 cross-border credential listings)
        for match in _IBAN_PATTERN.finditer(text):
            value = match.group(1)
            if len(value) >= 15:  # Minimum valid IBAN length
                context = self._get_surrounding_context(text, match.start(), match.end())
                entities.append(ExtractedEntity(
                    entity_type="iban",
                    value=value,
                    context=context,
                    confidence=0.80,
                ))

        # Extract UK sort codes (Fullz / CHAPS credential listings — DC-007, CHAPS-026)
        for match in _SORT_CODE_PATTERN.finditer(text):
            value = match.group(1)
            context = self._get_surrounding_context(text, match.start(), match.end())
            # Only flag as sort_code when financial keywords are in context
            if any(kw in context.lower() for kw in ("sort", "account", "bank", "fullz", "chaps")):
                entities.append(ExtractedEntity(
                    entity_type="sort_code",
                    value=value,
                    context=context,
                    confidence=0.75,
                ))

        # Extract merchant IDs (PS-001 purchase scam MID watchlist anchor)
        for match in _MID_PATTERN.finditer(text):
            value = match.group(1)
            context = self._get_surrounding_context(text, match.start(), match.end())
            if any(kw in context.lower() for kw in ("mid", "merchant", "mid:", "acquir")):
                entities.append(ExtractedEntity(
                    entity_type="merchant_id",
                    value=value,
                    context=context,
                    confidence=0.70,
                ))

        return entities

    @staticmethod
    def _get_surrounding_context(text: str, start: int, end: int, window: int = 50) -> str:
        """Get surrounding text context for an entity match.

        Args:
            text: Full text content.
            start: Start index of the match.
            end: End index of the match.
            window: Number of characters to include on each side.

        Returns:
            Surrounding context string.
        """
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        return text[ctx_start:ctx_end]

    @staticmethod
    def _is_likely_bin(value: str, context: str) -> bool:
        """Determine if a 6-digit number is likely a BIN.

        Checks surrounding context for financial indicators.

        Args:
            value: The 6-digit string.
            context: Surrounding text context.

        Returns:
            True if the context suggests this is a BIN.
        """
        financial_keywords = (
            "bin", "card", "visa", "mastercard", "amex", "credit",
            "debit", "bank", "issuer", "payment", "fullz", "dump",
        )
        context_lower = context.lower()
        return any(keyword in context_lower for keyword in financial_keywords)

    def categorize_technique(self, text: str) -> Optional[str]:
        """Classify bypass technique into exactly one of 5 fraud categories.

        Uses Claude Opus 4.8 via Bedrock to classify the technique described
        in the text into one of: mfa_bypass, synthetic_identity, phishing_kit,
        cnp_fraud, or account_takeover.

        Args:
            text: Raw text describing a potential bypass technique.

        Returns:
            One of the 5 fraud category strings, or None if the text does not
            describe a bypass technique.

        Raises:
            RuntimeError: If Bedrock invocation fails.
        """
        prompt = CATEGORIZATION_PROMPT.format(text=text)

        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 512,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "temperature": 0.1,
        }

        try:
            response = self._bedrock_client.invoke_model(
                modelId=self._analyst_config.bedrock_model_id,
                body=json.dumps(request_body),
                contentType="application/json",
                accept="application/json",
            )
        except Exception as e:
            logger.error(f"Bedrock invocation failed for technique categorization: {e}")
            raise RuntimeError(f"Bedrock invocation failed: {e}") from e

        response_body = json.loads(response["body"].read())
        content_blocks = response_body.get("content", [])
        if not content_blocks:
            return None

        response_text = content_blocks[0].get("text", "")
        return self._parse_categorization_response(response_text)

    def _parse_categorization_response(self, response_text: str) -> Optional[str]:
        """Parse the technique categorization JSON response from Claude.

        Args:
            response_text: Raw text response from Claude.

        Returns:
            A valid fraud category string, or None if not a bypass technique.
        """
        try:
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start == -1 or json_end == 0:
                return None

            json_str = response_text[json_start:json_end]
            result = json.loads(json_str)

            category = result.get("category")
            if category is None:
                return None

            # Validate the category is one of the allowed values
            if category in VALID_FRAUD_CATEGORIES:
                return category

            logger.warning(f"LLM returned invalid category: {category}")
            return None

        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.warning(f"Failed to parse categorization response: {e}")
            return None

    # High-severity fraud categories that indicate more immediate threats
    _HIGH_SEVERITY_CATEGORIES = {"account_takeover", "mfa_bypass"}

    def assign_severity(self, classification: ClassifiedContent) -> int:
        """Calculate a severity score from 1-10 based on threat immediacy and scale.

        Scoring algorithm:
        - Base score 3 for any fraud-relevant content
        - +1 for each institution entity (bank_name), capped at +3
        - +1 for high-severity categories (account_takeover, mfa_bypass)
        - +1 if confidence > 0.8
        - +1 if multiple entity types present (indicating complete intelligence)
        - Final result clamped to [1, 10]

        Args:
            classification: A ClassifiedContent instance with entities,
                fraud_category, and confidence already populated.

        Returns:
            Integer severity score in [1, 10].
        """
        score = 3  # Base score for any fraud-relevant content

        # +1 for each institution entity (bank_name), capped at +3
        institution_count = sum(
            1 for entity in classification.entities
            if entity.entity_type == "bank_name"
        )
        score += min(institution_count, 3)

        # +1 for high-severity categories
        if classification.fraud_category in self._HIGH_SEVERITY_CATEGORIES:
            score += 1

        # +1 if confidence > 0.8
        if classification.confidence > 0.8:
            score += 1

        # +1 if multiple entity types present (indicating complete intelligence)
        entity_types = {entity.entity_type for entity in classification.entities}
        if len(entity_types) > 1:
            score += 1

        # Clamp to [1, 10]
        return max(1, min(10, score))

    # Record-count severity boost constants
    _RECORD_COUNT_HIGH_THRESHOLD = 5_000   # +2 severity
    _RECORD_COUNT_MED_THRESHOLD  = 1_000   # +1 severity

    def adjust_severity_for_record_count(
        self, severity: int, estimated_record_count: int | None
    ) -> int:
        """Boost severity score when a large-scale data dump is detected.

        High-volume card dumps (DC-008) or large Fullz batches (DC-007) warrant
        an immediate alert rather than waiting for campaign convergence.
        A 10,000-card dump at DC-008 severity 6 becomes severity 8 (immediate alert).

        Args:
            severity: Base severity score from assign_severity().
            estimated_record_count: Record count extracted from the listing, or None.

        Returns:
            Adjusted severity score clamped to [1, 10].
        """
        if estimated_record_count is None:
            return severity
        if estimated_record_count >= self._RECORD_COUNT_HIGH_THRESHOLD:
            return min(10, severity + 2)
        if estimated_record_count >= self._RECORD_COUNT_MED_THRESHOLD:
            return min(10, severity + 1)
        return severity


# ---------------------------------------------------------------------------
# Lambda entry point — invoked by Step Functions LambdaInvoke task state
# ---------------------------------------------------------------------------

# Module-level boto3 client — reused across warm Lambda invocations (connection pooling)
_bedrock_client = boto3.client("bedrock-runtime")


def handler(event: dict, context) -> dict:
    """Lambda handler for the Content Analyst pipeline step.

    Receives an event from Step Functions containing an S3 artifact key,
    runs the full analysis pipeline (classify → extract entities → categorise),
    and returns structured output for the Data Structurer step.

    Expected input:
        {
            "s3_key": "crawl-artifacts/2026/01/15/abc123/xyz.txt",
            "execution_id": "arn:aws:states:..."
        }

    Returns a dict consumed as input by the next Step Functions state.
    """
    # Input validation
    if not isinstance(event, dict):
        raise ValueError(f"Expected dict event, got {type(event).__name__}")
    missing = [f for f in ["s3_key"] if f not in event]
    if missing:
        raise ValueError(f"Missing required fields: {missing}")

    s3_key = event["s3_key"]
    execution_id = event.get("execution_id", "unknown")

    config = AnalystConfig(
        bedrock_model_id=os.environ["BEDROCK_MODEL_ID"],
        guardrail_id=os.environ["GUARDRAIL_ID"],
        knowledge_base_id=os.environ.get("KNOWLEDGE_BASE_ID", ""),
        confidence_threshold=float(os.environ.get("CONFIDENCE_THRESHOLD", "0.7")),
        s3_bucket=os.environ["S3_BUCKET"],
    )
    analyst = ContentAnalyst(config, bedrock_client=_bedrock_client)

    # Fetch raw artifact from S3
    s3 = boto3.client("s3")
    obj = s3.get_object(Bucket=config.s3_bucket, Key=s3_key)
    text = obj["Body"].read().decode("utf-8", errors="replace")

    # Single combined Bedrock call (1x instead of 3x) — ~3x cheaper, ~2x faster
    result = analyst.classify_and_extract_combined(text)
    is_relevant = result["is_fraud_relevant"]
    confidence = result["confidence"]
    requires_review = analyst.should_require_manual_review(confidence)
    entities = result["entities"]
    fraud_category = result["fraud_category"]

    # Build ClassifiedContent to compute severity score
    classification = ClassifiedContent(
        source_ref=s3_key,
        is_fraud_relevant=is_relevant,
        confidence=confidence,
        requires_manual_review=requires_review,
        severity_score=1,  # placeholder — overwritten below
        fraud_category=fraud_category,
        entities=entities,
        raw_text_snippet=text[:500],
    )
    classification.severity_score = analyst.assign_severity(classification)
    # Boost severity for large-volume dumps (DC-007/DC-008)
    classification.severity_score = analyst.adjust_severity_for_record_count(
        classification.severity_score,
        result.get("estimated_record_count"),
    )

    analyst.update_health(
        items_processed=1 if is_relevant else 0,
        errors=0,
        bedrock_tokens=0,  # TODO: extract from Bedrock response metadata
    )
    logger.info(
        "ContentAnalyst",
        extra={
            "s3_key": s3_key,
            "execution_id": execution_id,
            "is_fraud_relevant": is_relevant,
            "confidence": confidence,
            "fraud_category": fraud_category,
            "severity_score": classification.severity_score,
            "entity_count": len(entities),
        },
    )

    return {
        "s3_key": s3_key,
        "execution_id": execution_id,
        "is_fraud_relevant": is_relevant,
        "confidence": confidence,
        "requires_manual_review": requires_review,
        "fraud_category": fraud_category,
        "severity_score": classification.severity_score,
        "entities": [
            {
                "entity_type": e.entity_type,
                "value": e.value,
                "context": e.context,
                "confidence": e.confidence,
            }
            for e in entities
        ],
        "raw_text_snippet": text[:500],
    }
