"""Content Analyst data models.

This module defines the data structures produced by the Content Analyst agent:
- EntityType: enum of recognized entity types for extraction
- FraudCategory: valid fraud category values
- ExtractedEntity: a single extracted entity with type, value, context, and confidence
- ClassifiedContent: the full classification result for a piece of crawled content
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EntityType(str, Enum):
    """Recognized entity types for extraction from dark web content.

    Each value represents a specific financial or technical entity that
    the Content Analyst can identify in raw text.
    """

    BANK_NAME = "bank_name"
    BIN_RANGE = "bin_range"
    SWIFT_CODE = "swift_code"
    BTC_WALLET = "btc_wallet"
    EMAIL = "email"
    URL = "url"
    IP_ADDRESS = "ip_address"


# Valid fraud category values for ClassifiedContent.fraud_category
VALID_FRAUD_CATEGORIES = (
    "mfa_bypass",
    "synthetic_identity",
    "phishing_kit",
    "cnp_fraud",
    "account_takeover",
)


@dataclass
class ExtractedEntity:
    """A single entity extracted from dark web content.

    Attributes:
        entity_type: The type of entity (from EntityType enum values).
        value: The extracted entity value (e.g., the actual BTC address or IP).
        context: Surrounding text providing context for the extraction.
        confidence: Confidence score for the extraction, between 0.0 and 1.0.
    """

    entity_type: str  # One of EntityType values
    value: str
    context: str
    confidence: float

    def __post_init__(self) -> None:
        """Validate field constraints after initialization."""
        # Validate entity_type is a known value
        valid_types = {e.value for e in EntityType}
        if self.entity_type not in valid_types:
            raise ValueError(
                f"entity_type must be one of {sorted(valid_types)}, got '{self.entity_type}'"
            )
        # Validate value is non-empty
        if not self.value:
            raise ValueError("value must be a non-empty string")
        # Validate confidence is in [0.0, 1.0]
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )


@dataclass
class ClassifiedContent:
    """The full classification result for a piece of crawled content.

    Produced by the Content Analyst agent after processing raw text from
    the Crawling Engine. Contains fraud relevance determination, entity
    extractions, severity assessment, and guardrail status.

    Attributes:
        source_ref: S3 artifact key reference to the original crawled content.
        is_fraud_relevant: Whether the content is relevant to banking fraud.
        confidence: Confidence score for the classification, between 0.0 and 1.0.
        requires_manual_review: Whether the content needs human review (True when confidence < 0.7).
        severity_score: Threat severity from 1 (lowest) to 10 (highest).
        fraud_category: Optional category of fraud technique identified.
        entities: List of extracted entities found in the content.
        raw_text_snippet: First 500 characters of raw content for context.
        bedrock_guardrail_result: Result from Bedrock Guardrails check ("PASSED", "FILTERED", or "FLAGGED").
    """

    source_ref: str
    is_fraud_relevant: bool
    confidence: float
    requires_manual_review: bool
    severity_score: int
    fraud_category: Optional[str] = None
    entities: list[ExtractedEntity] = field(default_factory=list)
    raw_text_snippet: str = ""
    bedrock_guardrail_result: str = "PASSED"

    def __post_init__(self) -> None:
        """Validate field constraints after initialization."""
        # Validate source_ref is non-empty
        if not self.source_ref:
            raise ValueError("source_ref must be a non-empty string")
        # Validate confidence is in [0.0, 1.0]
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )
        # Validate severity_score is in [1, 10]
        if not (1 <= self.severity_score <= 10):
            raise ValueError(
                f"severity_score must be between 1 and 10, got {self.severity_score}"
            )
        # Validate fraud_category if provided
        if self.fraud_category is not None and self.fraud_category not in VALID_FRAUD_CATEGORIES:
            raise ValueError(
                f"fraud_category must be one of {VALID_FRAUD_CATEGORIES}, got '{self.fraud_category}'"
            )
        # Validate bedrock_guardrail_result
        valid_guardrail_results = ("PASSED", "FILTERED", "FLAGGED")
        if self.bedrock_guardrail_result not in valid_guardrail_results:
            raise ValueError(
                f"bedrock_guardrail_result must be one of {valid_guardrail_results}, "
                f"got '{self.bedrock_guardrail_result}'"
            )
