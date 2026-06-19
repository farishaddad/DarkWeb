"""Shared data models and interfaces for the Dark Web Fraud Agent system.

This module defines the core data structures used across all agents in the pipeline:
- AgentHealth: monitoring and health status for each agent
- StepFunctionsPipelineState: tracks pipeline execution state
- IntelligenceTier: classification tier enum
- TierLink: referential links between intelligence tiers
- AgentConfig: base configuration for all agents
- AgentBase: abstract base class for all pipeline agents
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Optional


class IntelligenceTier(Enum):
    """Classification tier for intelligence items.

    - OBSERVABLE: Atomic data points (IP, URL, hash, wallet, email) — immediate blocking
    - INDICATOR: Attack patterns with temporal/logical operators — real-time detection rules
    - TTP: Strategic adversarial behavior methodology — long-term detection logic
    """

    OBSERVABLE = "observable"
    INDICATOR = "indicator"
    TTP = "ttp"


@dataclass
class AgentHealth:
    """Health status for a pipeline agent.

    Captures monitoring fields for agent operational status including
    throughput, error rates, queue depth, and Bedrock-specific metrics.
    """

    agent_id: str
    status: str  # "healthy" | "degraded" | "failed"
    processing_throughput: float  # items/minute
    error_rate: float  # errors/total in last window
    queue_depth: int  # Step Functions pending executions
    last_heartbeat: datetime
    uptime_seconds: float
    bedrock_token_count: int  # Tokens consumed (from Bedrock CloudWatch Metrics)
    bedrock_error_rate: float  # Client error rate from Bedrock


@dataclass
class StepFunctionsPipelineState:
    """Tracks the pipeline execution state in Step Functions.

    Each execution through the agent pipeline is tracked with a correlation ID
    that follows the item from crawl through to alert generation.
    """

    execution_arn: str
    current_step: str  # Which agent is currently processing
    correlation_id: str  # Tracks item through full pipeline
    started_at: datetime
    items_processed: int
    errors: list[dict] = field(default_factory=list)


@dataclass
class TierLink:
    """Referential link between intelligence items across tiers.

    Maintains the chain: Observable → Indicator → TTP so that any Observable
    can trace back to its parent Indicator and the TTP it supports.
    """

    source_id: str
    source_tier: IntelligenceTier
    target_id: str
    target_tier: IntelligenceTier
    relationship_type: str  # "derived-from" | "supports" | "indicates"


@dataclass
class AgentConfig:
    """Base configuration shared by all agents.

    Each agent extends this with agent-specific configuration fields.
    """

    agent_id: str
    agent_name: str
    s3_bucket: Optional[str] = None
    dynamodb_table: Optional[str] = None


class AgentBase(ABC):
    """Abstract base class for all pipeline agents.

    All agents in the pipeline (Crawling Engine, Content Analyst, Data Structurer,
    Tagging Engine, Alert Generator) must implement this interface.
    """

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._health = AgentHealth(
            agent_id=config.agent_id,
            status="healthy",
            processing_throughput=0.0,
            error_rate=0.0,
            queue_depth=0,
            last_heartbeat=datetime.now(UTC),
            uptime_seconds=0.0,
            bedrock_token_count=0,
            bedrock_error_rate=0.0,
        )

    @property
    def config(self) -> AgentConfig:
        """Return the agent's configuration."""
        return self._config

    @abstractmethod
    def get_health(self) -> AgentHealth:
        """Return the current health status of the agent.

        Must be implemented by each agent to provide real-time health metrics
        including processing throughput, error rate, and queue depth.
        """
        ...
