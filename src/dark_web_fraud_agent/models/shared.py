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

    def update_health(
        self,
        *,
        items_processed: int = 0,
        errors: int = 0,
        bedrock_tokens: int = 0,
        bedrock_errors: int = 0,
        window_seconds: float = 300.0,
    ) -> None:
        """Update health metrics and emit CloudWatch Embedded Metric Format logs.

        Call this at the end of each agent invocation from the Lambda handler.
        EMF logs are written to stdout and automatically converted to CloudWatch
        custom metrics by the Lambda runtime — zero additional API calls.

        Args:
            items_processed: Number of items successfully processed this invocation.
            errors: Number of errors encountered this invocation.
            bedrock_tokens: Bedrock tokens consumed (from invoke_model response).
            bedrock_errors: Number of Bedrock throttle/error responses.
            window_seconds: Length of the measurement window in seconds.
        """
        now = datetime.now(UTC)
        elapsed = (now - self._health.last_heartbeat).total_seconds() or window_seconds

        # Update throughput (items per minute) as exponential moving average
        throughput = (items_processed / elapsed) * 60.0
        alpha = 0.3  # EMA smoothing factor
        self._health.processing_throughput = (
            alpha * throughput + (1 - alpha) * self._health.processing_throughput
        )

        total = items_processed + errors
        if total > 0:
            self._health.error_rate = errors / total
        self._health.bedrock_token_count += bedrock_tokens
        self._health.bedrock_error_rate = (
            alpha * (bedrock_errors / max(1, items_processed + bedrock_errors))
            + (1 - alpha) * self._health.bedrock_error_rate
        )
        self._health.last_heartbeat = now
        self._health.status = "healthy" if self._health.error_rate < 0.1 else "degraded"

        # Emit CloudWatch Embedded Metric Format — Lambda runtime converts to metrics
        import sys, json as _json
        emf = {
            "_aws": {
                "Timestamp": int(now.timestamp() * 1000),
                "CloudWatchMetrics": [{
                    "Namespace": "dark-web-fraud",
                    "Dimensions": [["agent_id"]],
                    "Metrics": [
                        {"Name": "ItemsProcessed",       "Unit": "Count"},
                        {"Name": "Errors",               "Unit": "Count"},
                        {"Name": "ProcessingThroughput", "Unit": "Count/Second"},
                        {"Name": "BedrockTokens",        "Unit": "Count"},
                        {"Name": "ErrorRate",            "Unit": "None"},
                    ],
                }],
            },
            "agent_id":             self._health.agent_id,
            "ItemsProcessed":       items_processed,
            "Errors":               errors,
            "ProcessingThroughput": throughput,
            "BedrockTokens":        bedrock_tokens,
            "ErrorRate":            self._health.error_rate,
        }
        print(_json.dumps(emf), file=sys.stdout)

    @abstractmethod
    def get_health(self) -> AgentHealth:
        """Return the current health status of the agent.

        Must be implemented by each agent to provide real-time health metrics
        including processing throughput, error rate, and queue depth.
        """
        ...
