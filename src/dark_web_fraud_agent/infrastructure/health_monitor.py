"""Pipeline health monitoring and fault isolation utilities.

Provides:
- PipelineHealthMonitor: collects AgentHealth from all agents and exposes
  pipeline-level status (healthy/degraded/critical).
- RetryConfig: exponential-backoff retry configuration with configurable
  max_retries, base_delay, and backoff_factor.
- DeadLetterQueueRouter: routes failed items to an SQS dead-letter queue.
"""

import json
import logging
import math
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Optional

import boto3

from dark_web_fraud_agent.models.shared import AgentHealth

logger = logging.getLogger(__name__)

# Pipeline agents classified as core — if any of these is unhealthy, pipeline is critical
_CORE_AGENT_IDS = frozenset({
    "crawling_engine",
    "content_analyst",
    "data_structurer",
})


@dataclass
class RetryConfig:
    """Configuration for exponential-backoff retry logic.

    Attributes:
        max_retries: Maximum number of retry attempts. Defaults to 3.
        base_delay: Base delay in seconds before the first retry. Defaults to 2.
        backoff_factor: Multiplier applied to delay for each successive retry.
            Delay for attempt n = base_delay * (backoff_factor ** n). Defaults to 2.
        max_delay: Optional ceiling for the computed delay. Defaults to 60 seconds.
    """

    max_retries: int = 3
    base_delay: float = 2.0
    backoff_factor: float = 2.0
    max_delay: float = 60.0

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.base_delay <= 0:
            raise ValueError("base_delay must be positive")
        if self.backoff_factor < 1:
            raise ValueError("backoff_factor must be >= 1")

    def delay_for_attempt(self, attempt: int) -> float:
        """Calculate the delay in seconds for a given retry attempt (0-indexed).

        Args:
            attempt: The retry attempt number (0 = first retry).

        Returns:
            Delay in seconds, capped by max_delay.
        """
        delay = self.base_delay * (self.backoff_factor ** attempt)
        return min(delay, self.max_delay)


class DeadLetterQueueRouter:
    """Routes failed pipeline items to an SQS dead-letter queue.

    Each failed item is serialized as JSON and sent to the configured DLQ
    with message attributes describing the failure.

    Args:
        dlq_url: The SQS queue URL of the dead-letter queue.
        sqs_client: Optional pre-configured boto3 SQS client.
    """

    def __init__(
        self,
        dlq_url: str,
        sqs_client: Optional[Any] = None,
    ) -> None:
        self._dlq_url = dlq_url
        self._sqs_client = sqs_client or boto3.client("sqs")

    @property
    def dlq_url(self) -> str:
        """Return the configured DLQ URL."""
        return self._dlq_url

    def route_to_dlq(self, item: dict, error: Exception) -> str:
        """Route a failed item to the dead-letter queue.

        Args:
            item: The pipeline item that failed processing. Must be JSON-serializable.
            error: The exception that caused the failure.

        Returns:
            The SQS MessageId of the enqueued message.

        Raises:
            RuntimeError: If the SQS send_message call fails.
        """
        message_body = json.dumps(
            {
                "item": item,
                "error_type": type(error).__name__,
                "error_message": str(error),
                "failed_at": datetime.now(UTC).isoformat(),
            },
            default=str,
        )

        try:
            response = self._sqs_client.send_message(
                QueueUrl=self._dlq_url,
                MessageBody=message_body,
                MessageAttributes={
                    "ErrorType": {
                        "DataType": "String",
                        "StringValue": type(error).__name__,
                    },
                    "FailedAt": {
                        "DataType": "String",
                        "StringValue": datetime.now(UTC).isoformat(),
                    },
                },
            )
            message_id = response["MessageId"]
            logger.info(
                "PipelineHealthMonitor: routed failed item to DLQ, MessageId=%s",
                message_id,
            )
            return message_id
        except Exception as exc:
            logger.error(
                "PipelineHealthMonitor: failed to route item to DLQ: %s", exc
            )
            raise RuntimeError(f"Failed to route item to DLQ: {exc}") from exc


class PipelineHealthMonitor:
    """Collects AgentHealth from all agents and exposes pipeline-level status.

    Aggregates per-agent health reports to derive an overall pipeline status:
    - "healthy": all registered agents report healthy status
    - "degraded": some non-core agents are unhealthy or isolated
    - "critical": a core agent is down or isolated

    Also provides DLQ routing for failed items and retry configuration.

    Args:
        dlq_url: SQS URL for the dead-letter queue.
        retry_config: Retry configuration. Defaults to RetryConfig().
        sqs_client: Optional pre-configured boto3 SQS client.
        core_agent_ids: Optional override for core agent IDs.
    """

    def __init__(
        self,
        dlq_url: str = "",
        retry_config: RetryConfig | None = None,
        sqs_client: Optional[Any] = None,
        core_agent_ids: frozenset[str] | None = None,
    ) -> None:
        self._retry_config = retry_config or RetryConfig()
        self._core_agent_ids = core_agent_ids or _CORE_AGENT_IDS
        self._agent_healths: dict[str, AgentHealth] = {}
        self._dlq_router: DeadLetterQueueRouter | None = None
        if dlq_url:
            self._dlq_router = DeadLetterQueueRouter(
                dlq_url=dlq_url, sqs_client=sqs_client
            )

    @property
    def retry_config(self) -> RetryConfig:
        """Return the retry configuration."""
        return self._retry_config

    def register_agent_health(self, health: AgentHealth) -> None:
        """Register or update an agent's health report.

        Args:
            health: The AgentHealth report for the agent.
        """
        self._agent_healths[health.agent_id] = health

    def get_agent_health(self, agent_id: str) -> AgentHealth | None:
        """Get the latest health report for a specific agent.

        Args:
            agent_id: The agent to look up.

        Returns:
            The AgentHealth report, or None if not registered.
        """
        return self._agent_healths.get(agent_id)

    def aggregate_health(self) -> str:
        """Aggregate pipeline-level status from all registered agent health reports.

        Returns:
            One of "healthy", "degraded", or "critical".
        """
        if not self._agent_healths:
            return "healthy"

        all_healths = list(self._agent_healths.values())
        healthy_count = sum(1 for h in all_healths if h.status == "healthy")
        total = len(all_healths)

        # Check if any core agent is unhealthy
        core_agent_down = any(
            h.status != "healthy"
            for h in all_healths
            if h.agent_id in self._core_agent_ids
        )

        if core_agent_down:
            return "critical"
        elif healthy_count == total:
            return "healthy"
        else:
            return "degraded"

    def get_health_summary(self) -> dict[str, Any]:
        """Get a full health summary including per-agent details.

        Returns:
            Dictionary with pipeline_status, healthy_count, total_count,
            and per_agent breakdown.
        """
        all_healths = list(self._agent_healths.values())
        healthy_count = sum(1 for h in all_healths if h.status == "healthy")

        return {
            "pipeline_status": self.aggregate_health(),
            "healthy_count": healthy_count,
            "total_count": len(all_healths),
            "per_agent": {
                h.agent_id: {
                    "status": h.status,
                    "throughput": h.processing_throughput,
                    "error_rate": h.error_rate,
                    "queue_depth": h.queue_depth,
                }
                for h in all_healths
            },
        }

    def route_to_dlq(self, item: dict, error: Exception) -> str:
        """Route a failed item to the dead-letter queue.

        Args:
            item: The pipeline item that failed processing.
            error: The exception that caused the failure.

        Returns:
            The SQS MessageId of the enqueued message.

        Raises:
            RuntimeError: If DLQ routing is not configured or send fails.
        """
        if self._dlq_router is None:
            raise RuntimeError("DLQ routing is not configured (no dlq_url provided)")
        return self._dlq_router.route_to_dlq(item, error)
