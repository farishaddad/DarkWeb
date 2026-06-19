"""EventBridge scheduler and agent initialization for the pipeline.

Provides:
- PipelineScheduler: Wraps boto3 EventBridge client to enable/disable/query
  an EventBridge rule that triggers Step Functions pipeline executions.
- AgentInitializer: Initializes pipeline agents in dependency order
  (crawling → content → data → tagging → alert), verifying connectivity
  via get_health() on each agent before proceeding.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import boto3

from dark_web_fraud_agent.models.shared import AgentBase, AgentHealth

logger = logging.getLogger(__name__)


@dataclass
class ScheduleStatus:
    """Status of an EventBridge rule.

    Attributes:
        rule_name: Name of the EventBridge rule.
        state: Current rule state ('ENABLED' or 'DISABLED').
        schedule_expression: Cron or rate expression for the rule.
        description: Human-readable description of the rule.
    """

    rule_name: str
    state: str
    schedule_expression: str
    description: str = ""


class PipelineScheduler:
    """Wraps boto3 EventBridge client to manage a pipeline trigger rule.

    Enables, disables, and queries the state of an EventBridge rule that
    triggers the Step Functions pipeline on a schedule.
    """

    def __init__(
        self,
        rule_name: str,
        events_client: Optional[Any] = None,
    ) -> None:
        """Initialize the pipeline scheduler.

        Args:
            rule_name: Name of the EventBridge rule to manage.
            events_client: Optional pre-configured boto3 EventBridge client
                (useful for testing). If None, creates a default client.
        """
        self._rule_name = rule_name
        self._events_client = events_client or boto3.client("events")

    @property
    def rule_name(self) -> str:
        """Return the managed EventBridge rule name."""
        return self._rule_name

    def enable(self) -> None:
        """Enable the EventBridge rule to start triggering the pipeline.

        Raises:
            botocore.exceptions.ClientError: If the enable call fails.
        """
        logger.info(f"Enabling EventBridge rule: {self._rule_name}")
        self._events_client.enable_rule(Name=self._rule_name)

    def disable(self) -> None:
        """Disable the EventBridge rule to stop triggering the pipeline.

        Raises:
            botocore.exceptions.ClientError: If the disable call fails.
        """
        logger.info(f"Disabling EventBridge rule: {self._rule_name}")
        self._events_client.disable_rule(Name=self._rule_name)

    def get_status(self) -> ScheduleStatus:
        """Query the current state of the EventBridge rule.

        Returns:
            ScheduleStatus with rule name, state, schedule expression,
            and description.

        Raises:
            botocore.exceptions.ClientError: If the describe call fails.
        """
        response = self._events_client.describe_rule(Name=self._rule_name)

        return ScheduleStatus(
            rule_name=response["Name"],
            state=response.get("State", "UNKNOWN"),
            schedule_expression=response.get("ScheduleExpression", ""),
            description=response.get("Description", ""),
        )

    def is_enabled(self) -> bool:
        """Check if the EventBridge rule is currently enabled.

        Returns:
            True if the rule state is 'ENABLED', False otherwise.
        """
        status = self.get_status()
        return status.state == "ENABLED"


@dataclass
class InitializationResult:
    """Result of agent initialization.

    Attributes:
        agent_id: Identifier of the agent.
        success: Whether the agent initialized successfully.
        health: AgentHealth if initialization succeeded, None otherwise.
        error: Error message if initialization failed.
    """

    agent_id: str
    success: bool
    health: Optional[AgentHealth] = None
    error: Optional[str] = None


class AgentInitializer:
    """Initializes pipeline agents in dependency order and verifies connectivity.

    The pipeline agents must be initialized in this order:
    1. Crawling Engine
    2. Content Analyst
    3. Data Structurer
    4. Tagging Engine
    5. Alert Generator

    Each agent's connectivity is verified via get_health() after initialization.
    If any agent fails health check, initialization stops and reports the failure.
    """

    def __init__(self, agents: list[AgentBase]) -> None:
        """Initialize with the ordered list of pipeline agents.

        Args:
            agents: List of AgentBase instances in initialization order
                (crawling → content → data → tagging → alert).
        """
        self._agents = agents
        self._results: list[InitializationResult] = []

    @property
    def agents(self) -> list[AgentBase]:
        """Return the ordered list of agents."""
        return self._agents

    @property
    def results(self) -> list[InitializationResult]:
        """Return initialization results from the last run."""
        return self._results

    def initialize_all(self) -> list[InitializationResult]:
        """Initialize all agents in order and verify connectivity.

        Calls get_health() on each agent to verify it responds correctly.
        Stops on the first failure and returns results for all attempted agents.

        Returns:
            List of InitializationResult for each agent attempted.
        """
        self._results = []

        for agent in self._agents:
            result = self._initialize_agent(agent)
            self._results.append(result)

            if not result.success:
                logger.error(
                    f"Agent initialization failed at {result.agent_id}: "
                    f"{result.error}. Stopping pipeline initialization."
                )
                break

        return self._results

    def _initialize_agent(self, agent: AgentBase) -> InitializationResult:
        """Initialize a single agent and verify its health.

        Args:
            agent: The agent to initialize.

        Returns:
            InitializationResult with success status and health or error.
        """
        agent_id = agent.config.agent_id
        logger.info(f"Initializing agent: {agent_id}")

        try:
            health = agent.get_health()

            if health.status in ("healthy", "degraded"):
                logger.info(
                    f"Agent {agent_id} initialized successfully "
                    f"(status: {health.status})"
                )
                return InitializationResult(
                    agent_id=agent_id,
                    success=True,
                    health=health,
                )
            else:
                error_msg = f"Agent {agent_id} health check returned status: {health.status}"
                logger.warning(error_msg)
                return InitializationResult(
                    agent_id=agent_id,
                    success=False,
                    health=health,
                    error=error_msg,
                )

        except Exception as e:
            error_msg = f"Agent {agent_id} health check raised: {e}"
            logger.error(error_msg)
            return InitializationResult(
                agent_id=agent_id,
                success=False,
                error=error_msg,
            )

    def all_healthy(self) -> bool:
        """Check if all agents were initialized successfully.

        Returns:
            True if all initialization results are successful.
        """
        return all(r.success for r in self._results) and len(self._results) == len(
            self._agents
        )
