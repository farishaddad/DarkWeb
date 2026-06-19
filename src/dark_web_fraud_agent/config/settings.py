"""Configuration models with Pydantic validation for all agents."""

from datetime import timedelta
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class SourceType(str, Enum):
    """Supported dark web source types."""

    ONION = "onion"
    I2P = "i2p"
    TELEGRAM = "telegram"
    CLEARNET = "clearnet"


class SourceDefinition(BaseModel):
    """Definition of a dark web source to crawl.

    Validates source configuration including URL, type, category,
    crawl interval, and optional authentication settings.
    """

    url: str = Field(..., min_length=1, description="Source URL to crawl")
    source_type: SourceType = Field(..., description="Type of dark web source")
    category: str = Field(..., min_length=1, description="Source category (forum, marketplace, paste, telegram)")
    crawl_interval_seconds: int = Field(..., gt=0, description="Crawl interval in seconds")
    requires_auth: bool = Field(default=False, description="Whether source requires authentication")
    secret_arn: Optional[str] = Field(default=None, description="AWS Secrets Manager ARN for auth credentials")

    @model_validator(mode="after")
    def validate_auth_requires_secret(self) -> "SourceDefinition":
        """Ensure secret_arn is provided when auth is required."""
        if self.requires_auth and not self.secret_arn:
            raise ValueError("secret_arn must be provided when requires_auth is True")
        return self

    @field_validator("url")
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        """Basic URL validation."""
        if not v.startswith(("http://", "https://", "socks5://", "t.me/", "tg://")):
            # Allow onion and i2p URLs which may not have standard prefixes
            if not (v.endswith(".onion") or v.endswith(".i2p") or "." in v):
                raise ValueError("url must be a valid URL or hostname")
        return v


class CrawlConfig(BaseModel):
    """Configuration for the Crawling Engine agent.

    Validates crawl parameters including source definitions, Tor proxy ports,
    retry settings, and AWS resource references.
    """

    sources: list[SourceDefinition] = Field(
        default_factory=list, description="List of source definitions to crawl"
    )
    tor_socks_port: int = Field(default=9050, gt=0, le=65535, description="Tor SOCKS5 proxy port")
    tor_control_port: int = Field(default=9051, gt=0, le=65535, description="Tor control port")
    max_retries: int = Field(default=3, ge=1, le=10, description="Maximum retry attempts per source")
    circuit_rotation_interval: int = Field(
        default=300, gt=0, description="Seconds between Tor circuit rotations"
    )
    request_timeout: int = Field(default=30, gt=0, description="HTTP request timeout in seconds")
    s3_bucket: str = Field(..., min_length=3, max_length=63, description="S3 bucket for artifact storage")
    dynamodb_table: str = Field(..., min_length=3, max_length=255, description="DynamoDB table for state tracking")
    secrets_manager_prefix: str = Field(
        ..., min_length=1, description="Prefix for credential ARNs in Secrets Manager"
    )

    @field_validator("tor_socks_port", "tor_control_port")
    @classmethod
    def validate_ports_not_equal(cls, v: int, info) -> int:
        """Validate port values are in valid range."""
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v

    @field_validator("s3_bucket")
    @classmethod
    def validate_s3_bucket_name(cls, v: str) -> str:
        """Validate S3 bucket naming conventions."""
        if not v.replace("-", "").replace(".", "").isalnum():
            raise ValueError("S3 bucket name must contain only alphanumeric characters, hyphens, and dots")
        if v.startswith("-") or v.startswith(".") or v.endswith("-") or v.endswith("."):
            raise ValueError("S3 bucket name must not start or end with a hyphen or dot")
        return v


class AnalystConfig(BaseModel):
    """Configuration for the Content Analyst agent.

    Validates Bedrock model settings, guardrail configuration,
    and confidence thresholds for fraud classification.
    """

    bedrock_model_id: str = Field(
        ..., min_length=1, description="Bedrock model ID (e.g., anthropic.claude-opus-4-8-20260601-v1:0)"
    )
    guardrail_id: str = Field(..., min_length=1, description="Bedrock Guardrail ID or ARN")
    knowledge_base_id: str = Field(..., min_length=1, description="AgentCore Managed Knowledge Base ID")
    confidence_threshold: float = Field(
        default=0.7, ge=0.0, le=1.0, description="Confidence threshold for manual review flagging"
    )
    s3_bucket: str = Field(..., min_length=3, max_length=63, description="S3 bucket for analyst artifacts")

    @field_validator("s3_bucket")
    @classmethod
    def validate_s3_bucket_name(cls, v: str) -> str:
        """Validate S3 bucket naming conventions."""
        if not v.replace("-", "").replace(".", "").isalnum():
            raise ValueError("S3 bucket name must contain only alphanumeric characters, hyphens, and dots")
        if v.startswith("-") or v.startswith(".") or v.endswith("-") or v.endswith("."):
            raise ValueError("S3 bucket name must not start or end with a hyphen or dot")
        return v


class StructurerConfig(BaseModel):
    """Configuration for the Data Structurer agent.

    Validates OpenSearch, MISP, and Bedrock embedding settings
    for intelligence structuring and indexing.
    """

    opensearch_endpoint: str = Field(..., min_length=1, description="OpenSearch Serverless VECTORSEARCH endpoint")
    opensearch_collection_name: str = Field(
        ..., min_length=3, max_length=32, description="OpenSearch collection name"
    )
    misp_url: str = Field(..., min_length=1, description="MISP instance URL")
    misp_secret_arn: str = Field(..., min_length=1, description="Secrets Manager ARN for MISP API key")
    bedrock_embedding_model_id: str = Field(
        ..., min_length=1, description="Bedrock embedding model ID for vector generation"
    )
    s3_bucket: str = Field(..., min_length=3, max_length=63, description="S3 bucket for structured data")

    @field_validator("opensearch_endpoint")
    @classmethod
    def validate_opensearch_endpoint(cls, v: str) -> str:
        """Validate OpenSearch endpoint format."""
        if not v.startswith("https://"):
            raise ValueError("OpenSearch endpoint must start with https://")
        return v

    @field_validator("misp_url")
    @classmethod
    def validate_misp_url(cls, v: str) -> str:
        """Validate MISP URL format."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("MISP URL must start with http:// or https://")
        return v

    @field_validator("s3_bucket")
    @classmethod
    def validate_s3_bucket_name(cls, v: str) -> str:
        """Validate S3 bucket naming conventions."""
        if not v.replace("-", "").replace(".", "").isalnum():
            raise ValueError("S3 bucket name must contain only alphanumeric characters, hyphens, and dots")
        if v.startswith("-") or v.startswith(".") or v.endswith("-") or v.endswith("."):
            raise ValueError("S3 bucket name must not start or end with a hyphen or dot")
        return v


class TaggingConfig(BaseModel):
    """Configuration for the Tagging Engine agent.

    Validates knowledge base, MISP, and taxonomy settings
    for automated intelligence tagging and classification.
    """

    knowledge_base_id: str = Field(..., min_length=1, description="AgentCore Managed Knowledge Base ID")
    misp_url: str = Field(..., min_length=1, description="MISP instance URL")
    misp_secret_arn: str = Field(..., min_length=1, description="Secrets Manager ARN for MISP API key")
    taxonomy_s3_prefix: str = Field(
        ..., min_length=1, description="S3 prefix for custom taxonomy JSON files"
    )
    attack_stix_s3_key: str = Field(
        ..., min_length=1, description="S3 key for MITRE ATT&CK STIX data"
    )

    @field_validator("misp_url")
    @classmethod
    def validate_misp_url(cls, v: str) -> str:
        """Validate MISP URL format."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("MISP URL must start with http:// or https://")
        return v


class AlertConfig(BaseModel):
    """Configuration for the Alert Generator agent.

    Validates campaign convergence settings, alert thresholds,
    and AWS resource references for alert distribution.
    """

    campaign_convergence_window: timedelta = Field(
        ..., description="Time window for campaign convergence detection (e.g., 24 hours)"
    )
    summary_digest_period: timedelta = Field(
        ..., description="Period for summary digest generation (e.g., 7 days)"
    )
    high_severity_threshold: int = Field(
        ..., ge=1, le=10, description="Severity score >= this triggers immediate alert"
    )
    opensearch_endpoint: str = Field(
        ..., min_length=1, description="OpenSearch endpoint for campaign vector similarity queries"
    )
    sns_topic_arn: str = Field(..., min_length=1, description="SNS topic ARN for alert distribution")
    dynamodb_table: str = Field(
        ..., min_length=3, max_length=255, description="DynamoDB table for convergence tracking"
    )
    s3_bucket: str = Field(..., min_length=3, max_length=63, description="S3 bucket for alert artifacts")

    @field_validator("opensearch_endpoint")
    @classmethod
    def validate_opensearch_endpoint(cls, v: str) -> str:
        """Validate OpenSearch endpoint format."""
        if not v.startswith("https://"):
            raise ValueError("OpenSearch endpoint must start with https://")
        return v

    @field_validator("sns_topic_arn")
    @classmethod
    def validate_sns_topic_arn(cls, v: str) -> str:
        """Validate SNS topic ARN format."""
        if not v.startswith("arn:aws:sns:"):
            raise ValueError("SNS topic ARN must start with arn:aws:sns:")
        return v

    @field_validator("campaign_convergence_window", "summary_digest_period")
    @classmethod
    def validate_positive_timedelta(cls, v: timedelta) -> timedelta:
        """Validate timedelta is positive."""
        if v.total_seconds() <= 0:
            raise ValueError("Duration must be positive")
        return v

    @field_validator("s3_bucket")
    @classmethod
    def validate_s3_bucket_name(cls, v: str) -> str:
        """Validate S3 bucket naming conventions."""
        if not v.replace("-", "").replace(".", "").isalnum():
            raise ValueError("S3 bucket name must contain only alphanumeric characters, hyphens, and dots")
        if v.startswith("-") or v.startswith(".") or v.endswith("-") or v.endswith("."):
            raise ValueError("S3 bucket name must not start or end with a hyphen or dot")
        return v
