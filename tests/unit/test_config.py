"""Unit tests for configuration management and validation."""

from datetime import timedelta

import pytest
from pydantic import ValidationError

from dark_web_fraud_agent.config import (
    AlertConfig,
    AnalystConfig,
    CrawlConfig,
    SourceDefinition,
    SourceType,
    StructurerConfig,
    TaggingConfig,
)


class TestSourceDefinition:
    """Tests for SourceDefinition validation."""

    def test_valid_onion_source(self):
        source = SourceDefinition(
            url="http://example.onion",
            source_type=SourceType.ONION,
            category="forum",
            crawl_interval_seconds=3600,
        )
        assert source.url == "http://example.onion"
        assert source.source_type == SourceType.ONION
        assert source.requires_auth is False
        assert source.secret_arn is None

    def test_valid_telegram_source(self):
        source = SourceDefinition(
            url="t.me/fraud_channel",
            source_type=SourceType.TELEGRAM,
            category="telegram",
            crawl_interval_seconds=600,
        )
        assert source.source_type == SourceType.TELEGRAM

    def test_valid_i2p_source(self):
        source = SourceDefinition(
            url="http://example.i2p",
            source_type=SourceType.I2P,
            category="marketplace",
            crawl_interval_seconds=1800,
        )
        assert source.source_type == SourceType.I2P

    def test_valid_clearnet_source(self):
        source = SourceDefinition(
            url="https://paste.example.com",
            source_type=SourceType.CLEARNET,
            category="paste",
            crawl_interval_seconds=300,
        )
        assert source.source_type == SourceType.CLEARNET

    def test_valid_source_with_auth(self):
        source = SourceDefinition(
            url="http://protected.onion",
            source_type=SourceType.ONION,
            category="marketplace",
            crawl_interval_seconds=3600,
            requires_auth=True,
            secret_arn="arn:aws:secretsmanager:us-east-1:123456789:secret:tor-creds",
        )
        assert source.requires_auth is True
        assert source.secret_arn is not None

    def test_invalid_source_type(self):
        with pytest.raises(ValidationError):
            SourceDefinition(
                url="http://example.onion",
                source_type="invalid_type",  # type: ignore
                category="forum",
                crawl_interval_seconds=3600,
            )

    def test_missing_secret_arn_when_auth_required(self):
        with pytest.raises(ValidationError, match="secret_arn must be provided"):
            SourceDefinition(
                url="http://protected.onion",
                source_type=SourceType.ONION,
                category="marketplace",
                crawl_interval_seconds=3600,
                requires_auth=True,
            )

    def test_invalid_crawl_interval_zero(self):
        with pytest.raises(ValidationError):
            SourceDefinition(
                url="http://example.onion",
                source_type=SourceType.ONION,
                category="forum",
                crawl_interval_seconds=0,
            )

    def test_invalid_crawl_interval_negative(self):
        with pytest.raises(ValidationError):
            SourceDefinition(
                url="http://example.onion",
                source_type=SourceType.ONION,
                category="forum",
                crawl_interval_seconds=-100,
            )

    def test_empty_url_rejected(self):
        with pytest.raises(ValidationError):
            SourceDefinition(
                url="",
                source_type=SourceType.ONION,
                category="forum",
                crawl_interval_seconds=3600,
            )

    def test_empty_category_rejected(self):
        with pytest.raises(ValidationError):
            SourceDefinition(
                url="http://example.onion",
                source_type=SourceType.ONION,
                category="",
                crawl_interval_seconds=3600,
            )


class TestCrawlConfig:
    """Tests for CrawlConfig validation."""

    def test_valid_config_with_defaults(self):
        config = CrawlConfig(
            s3_bucket="my-crawl-bucket",
            dynamodb_table="crawl-state-table",
            secrets_manager_prefix="darkweb/tor",
        )
        assert config.tor_socks_port == 9050
        assert config.tor_control_port == 9051
        assert config.max_retries == 3
        assert config.circuit_rotation_interval == 300
        assert config.request_timeout == 30
        assert config.sources == []

    def test_valid_config_with_sources(self):
        sources = [
            SourceDefinition(
                url="http://example.onion",
                source_type=SourceType.ONION,
                category="forum",
                crawl_interval_seconds=3600,
            )
        ]
        config = CrawlConfig(
            sources=sources,
            s3_bucket="my-crawl-bucket",
            dynamodb_table="crawl-state-table",
            secrets_manager_prefix="darkweb/tor",
        )
        assert len(config.sources) == 1

    def test_valid_custom_ports(self):
        config = CrawlConfig(
            tor_socks_port=19050,
            tor_control_port=19051,
            s3_bucket="my-bucket",
            dynamodb_table="my-table",
            secrets_manager_prefix="prefix",
        )
        assert config.tor_socks_port == 19050
        assert config.tor_control_port == 19051

    def test_invalid_port_zero(self):
        with pytest.raises(ValidationError):
            CrawlConfig(
                tor_socks_port=0,
                s3_bucket="my-bucket",
                dynamodb_table="my-table",
                secrets_manager_prefix="prefix",
            )

    def test_invalid_port_too_high(self):
        with pytest.raises(ValidationError):
            CrawlConfig(
                tor_socks_port=70000,
                s3_bucket="my-bucket",
                dynamodb_table="my-table",
                secrets_manager_prefix="prefix",
            )

    def test_invalid_max_retries_zero(self):
        with pytest.raises(ValidationError):
            CrawlConfig(
                max_retries=0,
                s3_bucket="my-bucket",
                dynamodb_table="my-table",
                secrets_manager_prefix="prefix",
            )

    def test_invalid_s3_bucket_too_short(self):
        with pytest.raises(ValidationError):
            CrawlConfig(
                s3_bucket="ab",
                dynamodb_table="my-table",
                secrets_manager_prefix="prefix",
            )

    def test_invalid_s3_bucket_special_chars(self):
        with pytest.raises(ValidationError):
            CrawlConfig(
                s3_bucket="my_bucket!",
                dynamodb_table="my-table",
                secrets_manager_prefix="prefix",
            )

    def test_invalid_s3_bucket_starts_with_hyphen(self):
        with pytest.raises(ValidationError):
            CrawlConfig(
                s3_bucket="-my-bucket",
                dynamodb_table="my-table",
                secrets_manager_prefix="prefix",
            )

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            CrawlConfig()  # type: ignore


class TestAnalystConfig:
    """Tests for AnalystConfig validation."""

    def test_valid_config(self):
        config = AnalystConfig(
            bedrock_model_id="anthropic.claude-opus-4-8-20260601-v1:0",
            guardrail_id="arn:aws:bedrock:us-east-1:123456789:guardrail/abc123",
            knowledge_base_id="kb-12345",
            s3_bucket="analyst-bucket",
        )
        assert config.confidence_threshold == 0.7
        assert config.bedrock_model_id == "anthropic.claude-opus-4-8-20260601-v1:0"

    def test_custom_confidence_threshold(self):
        config = AnalystConfig(
            bedrock_model_id="anthropic.claude-opus-4-8-20260601-v1:0",
            guardrail_id="guardrail-123",
            knowledge_base_id="kb-12345",
            confidence_threshold=0.85,
            s3_bucket="analyst-bucket",
        )
        assert config.confidence_threshold == 0.85

    def test_invalid_confidence_above_one(self):
        with pytest.raises(ValidationError):
            AnalystConfig(
                bedrock_model_id="model-id",
                guardrail_id="guardrail-123",
                knowledge_base_id="kb-12345",
                confidence_threshold=1.5,
                s3_bucket="analyst-bucket",
            )

    def test_invalid_confidence_negative(self):
        with pytest.raises(ValidationError):
            AnalystConfig(
                bedrock_model_id="model-id",
                guardrail_id="guardrail-123",
                knowledge_base_id="kb-12345",
                confidence_threshold=-0.1,
                s3_bucket="analyst-bucket",
            )

    def test_confidence_boundary_zero(self):
        config = AnalystConfig(
            bedrock_model_id="model-id",
            guardrail_id="guardrail-123",
            knowledge_base_id="kb-12345",
            confidence_threshold=0.0,
            s3_bucket="analyst-bucket",
        )
        assert config.confidence_threshold == 0.0

    def test_confidence_boundary_one(self):
        config = AnalystConfig(
            bedrock_model_id="model-id",
            guardrail_id="guardrail-123",
            knowledge_base_id="kb-12345",
            confidence_threshold=1.0,
            s3_bucket="analyst-bucket",
        )
        assert config.confidence_threshold == 1.0

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            AnalystConfig()  # type: ignore


class TestStructurerConfig:
    """Tests for StructurerConfig validation."""

    def test_valid_config(self):
        config = StructurerConfig(
            opensearch_endpoint="https://search-my-collection.us-east-1.aoss.amazonaws.com",
            opensearch_collection_name="threat-intel",
            misp_url="https://misp.internal.example.com",
            misp_secret_arn="arn:aws:secretsmanager:us-east-1:123456789:secret:misp-key",
            bedrock_embedding_model_id="amazon.titan-embed-text-v2:0",
            s3_bucket="structurer-bucket",
        )
        assert config.opensearch_endpoint.startswith("https://")

    def test_invalid_opensearch_endpoint_http(self):
        with pytest.raises(ValidationError, match="must start with https://"):
            StructurerConfig(
                opensearch_endpoint="http://insecure-endpoint.com",
                opensearch_collection_name="collection",
                misp_url="https://misp.example.com",
                misp_secret_arn="arn:aws:secretsmanager:us-east-1:123456789:secret:key",
                bedrock_embedding_model_id="amazon.titan-embed-text-v2:0",
                s3_bucket="my-bucket",
            )

    def test_invalid_misp_url_no_scheme(self):
        with pytest.raises(ValidationError, match="MISP URL must start with"):
            StructurerConfig(
                opensearch_endpoint="https://endpoint.com",
                opensearch_collection_name="collection",
                misp_url="misp.example.com",
                misp_secret_arn="arn:aws:secretsmanager:us-east-1:123456789:secret:key",
                bedrock_embedding_model_id="amazon.titan-embed-text-v2:0",
                s3_bucket="my-bucket",
            )

    def test_collection_name_too_short(self):
        with pytest.raises(ValidationError):
            StructurerConfig(
                opensearch_endpoint="https://endpoint.com",
                opensearch_collection_name="ab",
                misp_url="https://misp.example.com",
                misp_secret_arn="arn",
                bedrock_embedding_model_id="model",
                s3_bucket="my-bucket",
            )


class TestTaggingConfig:
    """Tests for TaggingConfig validation."""

    def test_valid_config(self):
        config = TaggingConfig(
            knowledge_base_id="kb-tagging-12345",
            misp_url="https://misp.internal.example.com",
            misp_secret_arn="arn:aws:secretsmanager:us-east-1:123456789:secret:misp-key",
            taxonomy_s3_prefix="taxonomies/custom/",
            attack_stix_s3_key="stix/enterprise-attack.json",
        )
        assert config.knowledge_base_id == "kb-tagging-12345"
        assert config.taxonomy_s3_prefix == "taxonomies/custom/"

    def test_invalid_misp_url(self):
        with pytest.raises(ValidationError, match="MISP URL must start with"):
            TaggingConfig(
                knowledge_base_id="kb-12345",
                misp_url="ftp://misp.example.com",
                misp_secret_arn="arn",
                taxonomy_s3_prefix="prefix/",
                attack_stix_s3_key="key",
            )

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            TaggingConfig()  # type: ignore


class TestAlertConfig:
    """Tests for AlertConfig validation."""

    def test_valid_config(self):
        config = AlertConfig(
            campaign_convergence_window=timedelta(hours=24),
            summary_digest_period=timedelta(days=7),
            high_severity_threshold=7,
            opensearch_endpoint="https://search-alerts.us-east-1.aoss.amazonaws.com",
            sns_topic_arn="arn:aws:sns:us-east-1:123456789:fraud-alerts",
            dynamodb_table="campaign-convergence",
            s3_bucket="alert-bucket",
        )
        assert config.campaign_convergence_window == timedelta(hours=24)
        assert config.summary_digest_period == timedelta(days=7)
        assert config.high_severity_threshold == 7

    def test_invalid_severity_threshold_zero(self):
        with pytest.raises(ValidationError):
            AlertConfig(
                campaign_convergence_window=timedelta(hours=24),
                summary_digest_period=timedelta(days=7),
                high_severity_threshold=0,
                opensearch_endpoint="https://endpoint.com",
                sns_topic_arn="arn:aws:sns:us-east-1:123456789:topic",
                dynamodb_table="table",
                s3_bucket="my-bucket",
            )

    def test_invalid_severity_threshold_above_ten(self):
        with pytest.raises(ValidationError):
            AlertConfig(
                campaign_convergence_window=timedelta(hours=24),
                summary_digest_period=timedelta(days=7),
                high_severity_threshold=11,
                opensearch_endpoint="https://endpoint.com",
                sns_topic_arn="arn:aws:sns:us-east-1:123456789:topic",
                dynamodb_table="table",
                s3_bucket="my-bucket",
            )

    def test_invalid_sns_topic_arn_format(self):
        with pytest.raises(ValidationError, match="SNS topic ARN must start with"):
            AlertConfig(
                campaign_convergence_window=timedelta(hours=24),
                summary_digest_period=timedelta(days=7),
                high_severity_threshold=7,
                opensearch_endpoint="https://endpoint.com",
                sns_topic_arn="not-a-valid-arn",
                dynamodb_table="table",
                s3_bucket="my-bucket",
            )

    def test_invalid_opensearch_endpoint(self):
        with pytest.raises(ValidationError, match="must start with https://"):
            AlertConfig(
                campaign_convergence_window=timedelta(hours=24),
                summary_digest_period=timedelta(days=7),
                high_severity_threshold=7,
                opensearch_endpoint="http://insecure.com",
                sns_topic_arn="arn:aws:sns:us-east-1:123456789:topic",
                dynamodb_table="table",
                s3_bucket="my-bucket",
            )

    def test_invalid_negative_convergence_window(self):
        with pytest.raises(ValidationError, match="Duration must be positive"):
            AlertConfig(
                campaign_convergence_window=timedelta(seconds=-1),
                summary_digest_period=timedelta(days=7),
                high_severity_threshold=7,
                opensearch_endpoint="https://endpoint.com",
                sns_topic_arn="arn:aws:sns:us-east-1:123456789:topic",
                dynamodb_table="table",
                s3_bucket="my-bucket",
            )

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            AlertConfig()  # type: ignore
