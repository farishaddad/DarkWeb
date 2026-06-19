"""Main pipeline orchestration wiring all agents together.

This module implements the FraudIntelPipeline class that orchestrates the
5-agent pipeline: Crawling Engine → Content Analyst → Data Structurer →
Tagging Engine → Alert Generator.

Each agent step is wrapped with FaultIsolator for error handling and
automatic agent isolation after repeated failures.
"""

import logging
import uuid
from typing import Any, Optional

from dark_web_fraud_agent.agents.alert_generator import AlertGenerator
from dark_web_fraud_agent.agents.content_analyst import ContentAnalyst
from dark_web_fraud_agent.agents.crawling_engine import CrawlingEngine
from dark_web_fraud_agent.agents.data_structurer import DataStructurer
from dark_web_fraud_agent.agents.tagging_engine import TaggingEngine
from dark_web_fraud_agent.config.settings import SourceDefinition
from dark_web_fraud_agent.infrastructure.fault_isolation import FaultIsolator
from dark_web_fraud_agent.models.content_analyst import ClassifiedContent, ExtractedEntity

logger = logging.getLogger(__name__)


class FraudIntelPipeline:
    """Orchestrates the full fraud intelligence pipeline across all 5 agents.

    Pipeline flow:
        1. crawl_source → raw content from dark web
        2. classify_relevance + extract_entities + categorize_technique → analysis
        3. create STIX objects + classify_tier → structured intelligence
        4. tag_event → machine-readable tags
        5. track for convergence + check campaign → alerts

    Uses FaultIsolator for per-agent error handling and isolation.
    """

    def __init__(
        self,
        crawling_engine: CrawlingEngine,
        content_analyst: ContentAnalyst,
        data_structurer: DataStructurer,
        tagging_engine: TaggingEngine,
        alert_generator: AlertGenerator,
        fault_isolator: Optional[FaultIsolator] = None,
    ) -> None:
        """Initialize the pipeline with all 5 agents.

        Args:
            crawling_engine: Agent for dark web content collection.
            content_analyst: Agent for fraud relevance classification.
            data_structurer: Agent for STIX 2.1 object creation.
            tagging_engine: Agent for automated intelligence tagging.
            alert_generator: Agent for campaign convergence and alerting.
            fault_isolator: Optional FaultIsolator instance (created if not provided).
        """
        self._crawling_engine = crawling_engine
        self._content_analyst = content_analyst
        self._data_structurer = data_structurer
        self._tagging_engine = tagging_engine
        self._alert_generator = alert_generator
        self._fault_isolator = fault_isolator or FaultIsolator()

    @property
    def fault_isolator(self) -> FaultIsolator:
        """Return the pipeline's fault isolator."""
        return self._fault_isolator

    async def process_source(self, source: SourceDefinition) -> Optional[dict[str, Any]]:
        """Run the full pipeline for a single source.

        Steps:
            1. Crawl source via CrawlingEngine
            2. Classify relevance, extract entities, categorize technique via ContentAnalyst
            3. Create STIX objects and classify intelligence tier via DataStructurer
            4. Tag the event via TaggingEngine
            5. Track for convergence and check campaign via AlertGenerator

        Returns None if the content is not fraud-relevant.

        Args:
            source: SourceDefinition describing the dark web source to process.

        Returns:
            Dictionary with pipeline results, or None if content is irrelevant.

        Raises:
            Exception: Re-raises exceptions from isolated agents.
        """
        correlation_id = str(uuid.uuid4())

        # Step 1: Crawl source
        try:
            crawl_result = await self._crawling_engine.crawl_source(source)
            self._fault_isolator.record_success("crawling-engine")
        except Exception as e:
            self._fault_isolator.record_failure(
                "crawling-engine", e, correlation_id=correlation_id
            )
            raise

        # Step 2: Content analysis (classify + extract + categorize)
        try:
            is_relevant, confidence = self._content_analyst.classify_relevance(
                crawl_result.raw_content
            )

            # Early return if not fraud-relevant
            if not is_relevant:
                self._fault_isolator.record_success("content-analyst")
                return None

            entities = self._content_analyst.extract_entities(crawl_result.raw_content)
            fraud_category = self._content_analyst.categorize_technique(
                crawl_result.raw_content
            )
            self._fault_isolator.record_success("content-analyst")
        except Exception as e:
            self._fault_isolator.record_failure(
                "content-analyst", e, correlation_id=correlation_id
            )
            raise

        # Build ClassifiedContent for downstream agents
        requires_review = self._content_analyst.should_require_manual_review(confidence)
        classified = ClassifiedContent(
            source_ref=crawl_result.s3_artifact_key,
            is_fraud_relevant=True,
            confidence=confidence,
            requires_manual_review=requires_review,
            severity_score=1,  # Placeholder, will be computed below
            fraud_category=fraud_category,
            entities=entities,
            raw_text_snippet=crawl_result.raw_content[:500],
        )
        # Compute severity using the content analyst
        classified.severity_score = self._content_analyst.assign_severity(classified)

        # Step 3: STIX object creation + tier classification
        try:
            stix_objects = []
            for entity in entities:
                # Create SCOs for observable-type entities
                if entity.entity_type in ("ip_address", "url", "email", "btc_wallet"):
                    sco = self._data_structurer.create_stix_sco(entity)
                    stix_objects.append(sco)
                # Create SDOs for entities that can be mapped
                elif entity.entity_type == "bank_name" and fraud_category:
                    sdo = self._data_structurer.create_stix_sdo(entity, "threat-actor")
                    stix_objects.append(sdo)

            # Create an attack pattern SDO if we have a fraud category
            if fraud_category and entities:
                attack_entity = entities[0]  # Use first entity as representative
                attack_sdo = self._data_structurer.create_stix_sdo(
                    ExtractedEntity(
                        entity_type="bank_name",
                        value=fraud_category,
                        context=crawl_result.raw_content[:100],
                        confidence=confidence,
                    ),
                    fraud_category,
                )
                stix_objects.append(attack_sdo)

            # Build bundle if we have objects
            bundle = None
            if stix_objects:
                bundle = self._data_structurer.build_bundle(stix_objects)

            # Classify tier
            tier = self._data_structurer.classify_tier(classified)

            self._fault_isolator.record_success("data-structurer")
        except Exception as e:
            self._fault_isolator.record_failure(
                "data-structurer", e, correlation_id=correlation_id
            )
            raise

        # Step 4: Tagging
        try:
            tags = self._tagging_engine.tag_event(
                entities, fraud_category, classified.severity_score
            )
            self._fault_isolator.record_success("tagging-engine")
        except Exception as e:
            self._fault_isolator.record_failure(
                "tagging-engine", e, correlation_id=correlation_id
            )
            raise

        # Step 5: Convergence tracking + campaign check
        try:
            campaign_alert = None
            if bundle and fraud_category:
                # Track each STIX object for convergence
                for obj in stix_objects:
                    if hasattr(obj, "id"):
                        self._alert_generator.track_item(
                            stix_id=obj.id,
                            ttp_reference=fraud_category,
                            tier=tier.value,
                        )

                # Check for campaign convergence
                converged_ids = self._alert_generator.check_campaign_convergence(
                    fraud_category
                )
                if converged_ids:
                    # Get affected institutions from entities
                    institutions = [
                        e.value for e in entities if e.entity_type == "bank_name"
                    ]
                    campaign_alert = self._alert_generator.generate_campaign_alert(
                        ttp_reference=fraud_category,
                        ttp_description=f"Campaign detected: {fraud_category}",
                        affected_institutions=institutions,
                        related_ids=converged_ids,
                        source_url=source.url,
                        crawl_timestamp=crawl_result.crawl_timestamp,
                    )

            self._fault_isolator.record_success("alert-generator")
        except Exception as e:
            self._fault_isolator.record_failure(
                "alert-generator", e, correlation_id=correlation_id
            )
            raise

        return {
            "correlation_id": correlation_id,
            "crawl_result": crawl_result,
            "classification": {
                "is_relevant": True,
                "confidence": confidence,
                "fraud_category": fraud_category,
                "severity_score": classified.severity_score,
                "requires_manual_review": requires_review,
            },
            "entities": entities,
            "stix_bundle": bundle,
            "intelligence_tier": tier.value,
            "tags": [str(tag) for tag in tags],
            "campaign_alert": campaign_alert,
        }
