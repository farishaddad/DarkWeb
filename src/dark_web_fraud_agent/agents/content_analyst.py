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

If the content does NOT describe a bank security bypass technique, respond with:
{{"category": null, "reasoning": "Not a bypass technique"}}

Otherwise respond ONLY with a JSON object:
{{
  "category": "one_of_the_five_categories",
  "reasoning": "brief explanation"
}}"""

# Regex patterns for fallback entity extraction
_BIN_PATTERN = re.compile(r'\b([3-6]\d{5})\b')
_SWIFT_PATTERN = re.compile(r'\b([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b')
_BTC_BASE58_PATTERN = re.compile(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
_BTC_BECH32_PATTERN = re.compile(r'\b(bc1[a-z0-9]{39,59})\b')
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
                guardrailVersion="DRAFT",
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
