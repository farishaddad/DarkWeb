"""Unit tests for FraudIntelPipeline orchestration."""

import pytest
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

from dark_web_fraud_agent.agents.alert_generator import AlertGenerator
from dark_web_fraud_agent.agents.content_analyst import ContentAnalyst
from dark_web_fraud_agent.agents.crawling_engine import CrawlingEngine, CrawlResult
from dark_web_fraud_agent.agents.data_structurer import DataStructurer
from dark_web_fraud_agent.agents.tagging_engine import TaggingEngine, MachineTag
from dark_web_fraud_agent.config.settings import SourceDefinition
from dark_web_fraud_agent.infrastructure.fault_isolation import FaultIsolator
from dark_web_fraud_agent.models.content_analyst import (
    ClassifiedContent,
    ExtractedEntity,
)
from dark_web_fraud_agent.models.shared import IntelligenceTier
from dark_web_fraud_agent.pipeline import FraudIntelPipeline


@pytest.fixture
def source():
    """Create a test SourceDefinition."""
    return SourceDefinition(
        url="http://example.onion",
        source_type="onion",
        category="forum",
        crawl_interval_seconds=300,
    )


@pytest.fixture
def crawl_result():
    """Create a test CrawlResult."""
    return CrawlResult(
        source_url="http://example.onion",
        source_category="forum",
        raw_content="Selling BIN 411111 fullz with MFA bypass tools",
        crawl_timestamp=datetime(2024, 6, 1, tzinfo=UTC),
        proxy_identity="1.2.3.4",
        response_status=200,
        content_hash="abc123",
        s3_artifact_key="crawl-artifacts/2024/06/01/abc123/test.txt",
        s3_annotation_id="ann-test123",
    )


@pytest.fixture
def mock_crawling_engine(crawl_result):
    """Create a mocked CrawlingEngine."""
    engine = MagicMock(spec=CrawlingEngine)
    engine.crawl_source = AsyncMock(return_value=crawl_result)
    return engine


@pytest.fixture
def extracted_entities():
    """Create test extracted entities."""
    return [
        ExtractedEntity(
            entity_type="bin_range",
            value="411111",
            context="Selling BIN 411111 fullz",
            confidence=0.9,
        ),
        ExtractedEntity(
            entity_type="ip_address",
            value="192.168.1.1",
            context="connect to 192.168.1.1 for drops",
            confidence=0.85,
        ),
    ]


@pytest.fixture
def mock_content_analyst(extracted_entities):
    """Create a mocked ContentAnalyst."""
    analyst = MagicMock(spec=ContentAnalyst)
    analyst.classify_relevance = MagicMock(return_value=(True, 0.92))
    analyst.extract_entities = MagicMock(return_value=extracted_entities)
    analyst.categorize_technique = MagicMock(return_value="mfa_bypass")
    analyst.should_require_manual_review = MagicMock(return_value=False)
    analyst.assign_severity = MagicMock(return_value=7)
    return analyst


@pytest.fixture
def mock_data_structurer():
    """Create a mocked DataStructurer."""
    structurer = MagicMock(spec=DataStructurer)

    # SCO and SDO creation returns mock STIX objects with IDs
    mock_sco = MagicMock()
    mock_sco.id = "ipv4-addr--fake-id-1"
    structurer.create_stix_sco = MagicMock(return_value=mock_sco)

    mock_sdo = MagicMock()
    mock_sdo.id = "attack-pattern--fake-id-2"
    structurer.create_stix_sdo = MagicMock(return_value=mock_sdo)

    mock_bundle = MagicMock()
    mock_bundle.objects = [mock_sco, mock_sdo]
    structurer.build_bundle = MagicMock(return_value=mock_bundle)

    structurer.classify_tier = MagicMock(return_value=IntelligenceTier.INDICATOR)
    return structurer


@pytest.fixture
def mock_tagging_engine():
    """Create a mocked TaggingEngine."""
    engine = MagicMock(spec=TaggingEngine)
    engine.tag_event = MagicMock(
        return_value=[
            MachineTag("fraud", "type", "bin-attack"),
            MachineTag("mitre-attack", "technique", "T1111"),
            MachineTag("threat-level", "level", "high"),
        ]
    )
    return engine


@pytest.fixture
def mock_alert_generator():
    """Create a mocked AlertGenerator."""
    generator = MagicMock(spec=AlertGenerator)
    generator.track_item = MagicMock()
    generator.check_campaign_convergence = MagicMock(return_value=None)
    return generator


@pytest.fixture
def pipeline(
    mock_crawling_engine,
    mock_content_analyst,
    mock_data_structurer,
    mock_tagging_engine,
    mock_alert_generator,
):
    """Create a FraudIntelPipeline with all mocked agents."""
    return FraudIntelPipeline(
        crawling_engine=mock_crawling_engine,
        content_analyst=mock_content_analyst,
        data_structurer=mock_data_structurer,
        tagging_engine=mock_tagging_engine,
        alert_generator=mock_alert_generator,
    )


class TestFraudIntelPipelineInit:
    """Tests for pipeline initialization."""

    def test_pipeline_accepts_all_agents(
        self,
        mock_crawling_engine,
        mock_content_analyst,
        mock_data_structurer,
        mock_tagging_engine,
        mock_alert_generator,
    ):
        """Pipeline should accept all 5 agents in __init__."""
        pipeline = FraudIntelPipeline(
            crawling_engine=mock_crawling_engine,
            content_analyst=mock_content_analyst,
            data_structurer=mock_data_structurer,
            tagging_engine=mock_tagging_engine,
            alert_generator=mock_alert_generator,
        )
        assert pipeline is not None
        assert pipeline.fault_isolator is not None

    def test_pipeline_accepts_custom_fault_isolator(
        self,
        mock_crawling_engine,
        mock_content_analyst,
        mock_data_structurer,
        mock_tagging_engine,
        mock_alert_generator,
    ):
        """Pipeline should accept a custom FaultIsolator."""
        isolator = FaultIsolator(max_consecutive_failures=3)
        pipeline = FraudIntelPipeline(
            crawling_engine=mock_crawling_engine,
            content_analyst=mock_content_analyst,
            data_structurer=mock_data_structurer,
            tagging_engine=mock_tagging_engine,
            alert_generator=mock_alert_generator,
            fault_isolator=isolator,
        )
        assert pipeline.fault_isolator is isolator


class TestPipelineHappyPath:
    """Tests for the full pipeline happy path."""

    @pytest.mark.asyncio
    async def test_process_source_returns_results_for_relevant_content(
        self, pipeline, source
    ):
        """Pipeline should return results dict when content is fraud-relevant."""
        result = await pipeline.process_source(source)

        assert result is not None
        assert "correlation_id" in result
        assert result["classification"]["is_relevant"] is True
        assert result["classification"]["confidence"] == 0.92
        assert result["classification"]["fraud_category"] == "mfa_bypass"
        assert result["intelligence_tier"] == "indicator"
        assert result["stix_bundle"] is not None
        assert len(result["tags"]) > 0

    @pytest.mark.asyncio
    async def test_process_source_calls_crawling_engine(
        self, pipeline, source, mock_crawling_engine
    ):
        """Step 1: Pipeline should call crawl_source."""
        await pipeline.process_source(source)
        mock_crawling_engine.crawl_source.assert_called_once_with(source)

    @pytest.mark.asyncio
    async def test_process_source_calls_content_analyst(
        self, pipeline, source, mock_content_analyst, crawl_result
    ):
        """Step 2: Pipeline should call classify, extract, and categorize."""
        await pipeline.process_source(source)
        mock_content_analyst.classify_relevance.assert_called_once_with(
            crawl_result.raw_content
        )
        mock_content_analyst.extract_entities.assert_called_once_with(
            crawl_result.raw_content
        )
        mock_content_analyst.categorize_technique.assert_called_once_with(
            crawl_result.raw_content
        )

    @pytest.mark.asyncio
    async def test_process_source_calls_data_structurer(
        self, pipeline, source, mock_data_structurer
    ):
        """Step 3: Pipeline should create STIX objects and classify tier."""
        await pipeline.process_source(source)
        # Should call create_stix_sco for ip_address entity
        assert mock_data_structurer.create_stix_sco.called
        # Should call create_stix_sdo for attack pattern
        assert mock_data_structurer.create_stix_sdo.called
        # Should build bundle
        mock_data_structurer.build_bundle.assert_called_once()
        # Should classify tier
        mock_data_structurer.classify_tier.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_source_calls_tagging_engine(
        self, pipeline, source, mock_tagging_engine, extracted_entities
    ):
        """Step 4: Pipeline should call tag_event."""
        await pipeline.process_source(source)
        mock_tagging_engine.tag_event.assert_called_once_with(
            extracted_entities, "mfa_bypass", 7
        )

    @pytest.mark.asyncio
    async def test_process_source_calls_alert_generator(
        self, pipeline, source, mock_alert_generator
    ):
        """Step 5: Pipeline should track items and check convergence."""
        await pipeline.process_source(source)
        assert mock_alert_generator.track_item.called
        mock_alert_generator.check_campaign_convergence.assert_called_once_with(
            "mfa_bypass"
        )


class TestPipelineIrrelevantContent:
    """Tests for pipeline behavior when content is not fraud-relevant."""

    @pytest.mark.asyncio
    async def test_returns_none_for_irrelevant_content(
        self, pipeline, source, mock_content_analyst
    ):
        """Pipeline should return None when content is not fraud-relevant."""
        mock_content_analyst.classify_relevance.return_value = (False, 0.85)

        result = await pipeline.process_source(source)

        assert result is None

    @pytest.mark.asyncio
    async def test_does_not_call_downstream_agents_for_irrelevant(
        self,
        pipeline,
        source,
        mock_content_analyst,
        mock_data_structurer,
        mock_tagging_engine,
        mock_alert_generator,
    ):
        """Pipeline should not call downstream agents when content is irrelevant."""
        mock_content_analyst.classify_relevance.return_value = (False, 0.3)

        await pipeline.process_source(source)

        mock_content_analyst.extract_entities.assert_not_called()
        mock_content_analyst.categorize_technique.assert_not_called()
        mock_data_structurer.create_stix_sco.assert_not_called()
        mock_tagging_engine.tag_event.assert_not_called()
        mock_alert_generator.track_item.assert_not_called()


class TestPipelineFaultIsolation:
    """Tests for fault isolation behavior."""

    @pytest.mark.asyncio
    async def test_crawling_failure_is_recorded(
        self, pipeline, source, mock_crawling_engine
    ):
        """Crawling failures should be recorded in the fault isolator."""
        mock_crawling_engine.crawl_source = AsyncMock(
            side_effect=RuntimeError("Tor connection failed")
        )

        with pytest.raises(RuntimeError, match="Tor connection failed"):
            await pipeline.process_source(source)

        history = pipeline.fault_isolator.get_failure_history("crawling-engine")
        assert len(history) == 1
        assert history[0].error_type == "RuntimeError"

    @pytest.mark.asyncio
    async def test_content_analyst_failure_is_recorded(
        self, pipeline, source, mock_content_analyst
    ):
        """Content analyst failures should be recorded."""
        mock_content_analyst.classify_relevance.side_effect = RuntimeError(
            "Bedrock unavailable"
        )

        with pytest.raises(RuntimeError, match="Bedrock unavailable"):
            await pipeline.process_source(source)

        history = pipeline.fault_isolator.get_failure_history("content-analyst")
        assert len(history) == 1

    @pytest.mark.asyncio
    async def test_data_structurer_failure_is_recorded(
        self, pipeline, source, mock_data_structurer
    ):
        """Data structurer failures should be recorded."""
        mock_data_structurer.create_stix_sco.side_effect = ValueError(
            "Invalid entity type"
        )

        with pytest.raises(ValueError, match="Invalid entity type"):
            await pipeline.process_source(source)

        history = pipeline.fault_isolator.get_failure_history("data-structurer")
        assert len(history) == 1

    @pytest.mark.asyncio
    async def test_tagging_failure_is_recorded(
        self, pipeline, source, mock_tagging_engine
    ):
        """Tagging engine failures should be recorded."""
        mock_tagging_engine.tag_event.side_effect = Exception("Taxonomy error")

        with pytest.raises(Exception, match="Taxonomy error"):
            await pipeline.process_source(source)

        history = pipeline.fault_isolator.get_failure_history("tagging-engine")
        assert len(history) == 1

    @pytest.mark.asyncio
    async def test_alert_generator_failure_is_recorded(
        self, pipeline, source, mock_alert_generator
    ):
        """Alert generator failures should be recorded."""
        mock_alert_generator.track_item.side_effect = Exception("DynamoDB error")

        with pytest.raises(Exception, match="DynamoDB error"):
            await pipeline.process_source(source)

        history = pipeline.fault_isolator.get_failure_history("alert-generator")
        assert len(history) == 1

    @pytest.mark.asyncio
    async def test_success_resets_failure_count(self, pipeline, source):
        """Successful processing should reset failure counters."""
        await pipeline.process_source(source)

        # All agents should have 0 failures after success
        for agent_id in [
            "crawling-engine",
            "content-analyst",
            "data-structurer",
            "tagging-engine",
            "alert-generator",
        ]:
            history = pipeline.fault_isolator.get_failure_history(agent_id)
            assert len(history) == 0


class TestPipelineCampaignDetection:
    """Tests for campaign convergence detection in the pipeline."""

    @pytest.mark.asyncio
    async def test_campaign_alert_generated_on_convergence(
        self, pipeline, source, mock_alert_generator
    ):
        """Pipeline should generate campaign alert when convergence is detected."""
        converged_ids = ["stix-1", "stix-2", "stix-3"]
        mock_alert_generator.check_campaign_convergence.return_value = converged_ids

        mock_alert = MagicMock()
        mock_alert.alert_type = "campaign_alert"
        mock_alert_generator.generate_campaign_alert.return_value = mock_alert

        result = await pipeline.process_source(source)

        assert result is not None
        assert result["campaign_alert"] is mock_alert
        mock_alert_generator.generate_campaign_alert.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_campaign_alert_without_convergence(
        self, pipeline, source, mock_alert_generator
    ):
        """Pipeline should not generate campaign alert without convergence."""
        mock_alert_generator.check_campaign_convergence.return_value = None

        result = await pipeline.process_source(source)

        assert result is not None
        assert result["campaign_alert"] is None
        mock_alert_generator.generate_campaign_alert.assert_not_called()
