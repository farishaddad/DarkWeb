"""Agent fault isolation and health monitoring.

Provides the FaultIsolator class for tracking agent failures, isolating
misbehaving agents after consecutive failures, and aggregating pipeline health.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Optional

from dark_web_fraud_agent.models.shared import AgentHealth


@dataclass
class AgentFailure:
    """Records a single agent failure event.

    Attributes:
        agent_id: Identifier of the agent that failed.
        error_message: Human-readable error description.
        error_type: The exception class name (e.g. "TimeoutError").
        timestamp: When the failure occurred (defaults to now).
        correlation_id: Optional pipeline correlation ID for tracing.
        recoverable: Whether the failure is considered recoverable.
    """

    agent_id: str
    error_message: str
    error_type: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    correlation_id: Optional[str] = None
    recoverable: bool = True


class FaultIsolator:
    """Tracks agent failures and isolates agents after repeated consecutive failures.

    The isolator monitors each agent independently. When an agent accumulates
    max_consecutive_failures without a success, it is marked as isolated and
    should be excluded from pipeline processing until manually restored.

    Args:
        max_consecutive_failures: Number of consecutive failures before isolation.
            Defaults to 5.
    """

    def __init__(self, max_consecutive_failures: int = 5) -> None:
        self._max_consecutive_failures = max_consecutive_failures
        self._failure_counts: dict[str, int] = {}
        self._isolated_agents: set[str] = set()
        self._failure_history: list[AgentFailure] = []

    def record_failure(
        self,
        agent_id: str,
        error: Exception,
        correlation_id: Optional[str] = None,
    ) -> AgentFailure:
        """Record a failure for an agent and check if it should be isolated.

        Args:
            agent_id: The agent that experienced the failure.
            error: The exception that was raised.
            correlation_id: Optional correlation ID for pipeline tracing.

        Returns:
            The AgentFailure record created for this event.
        """
        failure = AgentFailure(
            agent_id=agent_id,
            error_message=str(error),
            error_type=type(error).__name__,
            correlation_id=correlation_id,
        )
        self._failure_history.append(failure)

        # Increment consecutive failure count
        self._failure_counts[agent_id] = self._failure_counts.get(agent_id, 0) + 1

        # Check if agent should be isolated
        if self._failure_counts[agent_id] >= self._max_consecutive_failures:
            self._isolated_agents.add(agent_id)

        return failure

    def record_success(self, agent_id: str) -> None:
        """Record a success for an agent, resetting its consecutive failure count.

        Args:
            agent_id: The agent that succeeded.
        """
        self._failure_counts[agent_id] = 0

    def is_isolated(self, agent_id: str) -> bool:
        """Check whether an agent is currently isolated.

        Args:
            agent_id: The agent to check.

        Returns:
            True if the agent has been isolated due to consecutive failures.
        """
        return agent_id in self._isolated_agents

    def restore_agent(self, agent_id: str) -> None:
        """Restore an isolated agent, allowing it to process again.

        Also resets the consecutive failure counter for the agent.

        Args:
            agent_id: The agent to restore.
        """
        self._isolated_agents.discard(agent_id)
        self._failure_counts[agent_id] = 0

    def get_failure_history(
        self, agent_id: Optional[str] = None
    ) -> list[AgentFailure]:
        """Get the failure history, optionally filtered by agent.

        Args:
            agent_id: If provided, only return failures for this agent.

        Returns:
            List of AgentFailure records in chronological order.
        """
        if agent_id is None:
            return list(self._failure_history)
        return [f for f in self._failure_history if f.agent_id == agent_id]

    def get_pipeline_health(
        self, agent_healths: list[AgentHealth]
    ) -> dict[str, Any]:
        """Aggregate pipeline-level health from individual agent health reports.

        Determines overall pipeline status:
        - "healthy": all agents report healthy status
        - "degraded": some agents are unhealthy or isolated
        - "failed": all agents are unhealthy

        Args:
            agent_healths: List of AgentHealth reports from each agent.

        Returns:
            Dictionary with pipeline health summary including status,
            healthy/total agent counts, isolated agents list, and total failures.
        """
        total = len(agent_healths)
        healthy_count = sum(1 for h in agent_healths if h.status == "healthy")
        isolated = [
            aid for aid in self._isolated_agents
        ]

        if total == 0:
            status = "healthy"
        elif healthy_count == total:
            status = "healthy"
        elif healthy_count == 0:
            status = "failed"
        else:
            status = "degraded"

        return {
            "status": status,
            "healthy_agents": healthy_count,
            "total_agents": total,
            "isolated_agents": isolated,
            "total_failures": len(self._failure_history),
        }
