"""EventBridge scheduler and agent initialization for the pipeline.

Provides:
- PipelineScheduler: Wraps boto3 EventBridge client to create/enable/disable/query
  an EventBridge rule that triggers Step Functions pipeline executions.
- AgentInitializer: Initializes pipeline agents in dependency order
  (crawling → content → data → tagging → alert), verifying connectivity
  via get_health() on each agent before proceeding.
- MapStateConfig: Configuration for Step Functions Map state that processes
  crawl results in parallel with bounded concurrency.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import boto3

from dark_web_fraud_agent.models.shared import AgentBase, AgentHealth

logger = logging.getLogger(__name__)

# Default schedule: every 6 hours
_DEFAULT_SCHEDULE_EXPRESSION = "rate(6 hours)"
_DEFAULT_RULE_NAME = "dark-web-fraud-crawl-schedule"
_DEFAULT_RULE_DESCRIPTION = (
    "Triggers the dark web fraud intelligence crawl pipeline every 6 hours"
)
_DEFAULT_MAX_CONCURRENCY = 10


@dataclass
class ScheduleStatus:
    """Status of an EventBridge rule.

    Attributes:
        rule_name: Name of the EventBridge rule.
        state: Current rule state ('ENABLED' or 'DISABLED').
        schedule_expression: Cron or rate expression for the rule.
        description: Human-readable description of the rule.
        target_arn: ARN of the rule's target (e.g. Step Functions state machine).
    """

    rule_name: str
    state: str
    schedule_expression: str
    description: str = ""
    target_arn: str = ""


@dataclass
class MapStateConfig:
    """Configuration for Step Functions Map state parallel processing.

    Defines the parameters for the Map state that processes crawl results
    in parallel with bounded concurrency.

    Attributes:
        max_concurrency: Maximum parallel executions (default 10).
        items_path: JSONPath to the array of items in the state input.
        result_path: JSONPath where Map state results are written.
        retry_max_attempts: Max retry attempts per item on failure.
        retry_backoff_rate: Exponential backoff rate for retries.
        retry_interval_seconds: Initial retry interval in seconds.
    """

    max_concurrency: int = _DEFAULT_MAX_CONCURRENCY
    items_path: str = "$.crawlResults"
    result_path: str = "$.processedResults"
    retry_max_attempts: int = 3
    retry_backoff_rate: float = 2.0
    retry_interval_seconds: int = 5

    def __post_init__(self) -> None:
        if self.max_concurrency < 1:
            raise ValueError(
                f"max_concurrency must be >= 1, got {self.max_concurrency}"
            )
        if self.retry_max_attempts < 0:
            raise ValueError(
                f"retry_max_attempts must be >= 0, got {self.retry_max_attempts}"
            )
        if self.retry_backoff_rate < 1.0:
            raise ValueError(
                f"retry_backoff_rate must be >= 1.0, got {self.retry_backoff_rate}"
            )

    def to_state_definition(self) -> dict[str, Any]:
        """Generate the Step Functions Map state definition as a dictionary.

        Returns:
            Dictionary conforming to the ASL Map state specification, suitable
            for inclusion in a Step Functions state machine definition.
        """
        return {
            "Type": "Map",
            "ItemsPath": self.items_path,
            "ResultPath": self.result_path,
            "MaxConcurrency": self.max_concurrency,
            "Iterator": {
                "StartAt": "AnalyzeContent",
                "States": {
                    "AnalyzeContent": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::bedrock-agent:invoke",
                        "Parameters": {
                            "AgentId.$": "$.contentAnalystAgentId",
                            "InputText.$": "$.rawContent",
                        },
                        "Next": "CheckFraudRelevance",
                        "Retry": [
                            {
                                "ErrorEquals": ["States.TaskFailed"],
                                "MaxAttempts": self.retry_max_attempts,
                                "IntervalSeconds": self.retry_interval_seconds,
                                "BackoffRate": self.retry_backoff_rate,
                            }
                        ],
                    },
                    "CheckFraudRelevance": {
                        "Type": "Choice",
                        "Choices": [
                            {
                                "Variable": "$.isFraudRelevant",
                                "BooleanEquals": True,
                                "Next": "StructureData",
                            }
                        ],
                        "Default": "DiscardIrrelevant",
                    },
                    "StructureData": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::bedrock-agent:invoke",
                        "Parameters": {
                            "AgentId.$": "$.dataStructurerAgentId",
                        },
                        "Next": "TagIntelligence",
                        "Retry": [
                            {
                                "ErrorEquals": ["States.TaskFailed"],
                                "MaxAttempts": self.retry_max_attempts,
                                "IntervalSeconds": self.retry_interval_seconds,
                                "BackoffRate": self.retry_backoff_rate,
                            }
                        ],
                    },
                    "TagIntelligence": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::bedrock-agent:invoke",
                        "Parameters": {
                            "AgentId.$": "$.taggingEngineAgentId",
                        },
                        "Next": "GenerateAlerts",
                        "Retry": [
                            {
                                "ErrorEquals": ["States.TaskFailed"],
                                "MaxAttempts": self.retry_max_attempts,
                                "IntervalSeconds": self.retry_interval_seconds,
                                "BackoffRate": self.retry_backoff_rate,
                            }
                        ],
                    },
                    "GenerateAlerts": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::bedrock-agent:invoke",
                        "Parameters": {
                            "AgentId.$": "$.alertGeneratorAgentId",
                        },
                        "End": True,
                        "Retry": [
                            {
                                "ErrorEquals": ["States.TaskFailed"],
                                "MaxAttempts": self.retry_max_attempts,
                                "IntervalSeconds": self.retry_interval_seconds,
                                "BackoffRate": self.retry_backoff_rate,
                            }
                        ],
                    },
                    "DiscardIrrelevant": {"Type": "Succeed"},
                },
            },
        }


class PipelineScheduler:
    """Wraps boto3 EventBridge client to manage a pipeline trigger rule.

    Creates, enables, disables, and queries the state of an EventBridge rule
    that triggers the Step Functions pipeline on a cron/rate schedule.
    """

    def __init__(
        self,
        rule_name: str = _DEFAULT_RULE_NAME,
        events_client: Optional[Any] = None,
        region: str = "eu-west-2",
    ) -> None:
        """Initialize the pipeline scheduler.

        Args:
            rule_name: Name of the EventBridge rule to manage.
            events_client: Optional pre-configured boto3 EventBridge client
                (useful for testing). If None, creates a default client.
            region: AWS region for the EventBridge client.
        """
        self._rule_name = rule_name
        self._region = region
        self._events_client = events_client or boto3.client(
            "events", region_name=region
        )

    @property
    def rule_name(self) -> str:
        """Return the managed EventBridge rule name."""
        return self._rule_name

    def create_schedule(
        self,
        state_machine_arn: str,
        role_arn: str,
        schedule_expression: str = _DEFAULT_SCHEDULE_EXPRESSION,
        description: str = _DEFAULT_RULE_DESCRIPTION,
        enabled: bool = True,
    ) -> str:
        """Create or update the EventBridge rule and set Step Functions as target.

        Creates the EventBridge rule with the given schedule expression and
        adds the Step Functions state machine as the target.

        Args:
            state_machine_arn: ARN of the Step Functions state machine to trigger.
            role_arn: IAM role ARN that EventBridge assumes to invoke Step Functions.
            schedule_expression: Cron or rate expression (default: rate(6 hours)).
            description: Human-readable description of the rule.
            enabled: Whether to create the rule in ENABLED state.

        Returns:
            The rule ARN.

        Raises:
            ValueError: If state_machine_arn or role_arn are empty.
            botocore.exceptions.ClientError: If the AWS API call fails.
        """
        if not state_machine_arn:
            raise ValueError("state_machine_arn must not be empty")
        if not role_arn:
            raise ValueError("role_arn must not be empty")

        logger.info(
            "PipelineScheduler: creating rule=%s schedule=%s target=%s",
            self._rule_name,
            schedule_expression,
            state_machine_arn,
        )

        # Create or update the rule
        response = self._events_client.put_rule(
            Name=self._rule_name,
            ScheduleExpression=schedule_expression,
            State="ENABLED" if enabled else "DISABLED",
            Description=description,
        )
        rule_arn = response["RuleArn"]

        # Set the Step Functions state machine as the target
        self._events_client.put_targets(
            Rule=self._rule_name,
            Targets=[
                {
                    "Id": "step-functions-pipeline",
                    "Arn": state_machine_arn,
                    "RoleArn": role_arn,
                    "Input": json.dumps(
                        {
                            "source": "eventbridge-schedule",
                            "rule_name": self._rule_name,
                            "schedule_expression": schedule_expression,
                        }
                    ),
                }
            ],
        )

        logger.info(
            "PipelineScheduler: rule created successfully, arn=%s", rule_arn
        )
        return rule_arn

    def delete_schedule(self) -> None:
        """Remove the EventBridge rule and its targets.

        First removes all targets from the rule, then deletes the rule itself.

        Raises:
            botocore.exceptions.ClientError: If the AWS API call fails.
        """
        logger.info("PipelineScheduler: deleting rule=%s", self._rule_name)

        # Remove targets first (required before rule deletion)
        self._events_client.remove_targets(
            Rule=self._rule_name,
            Ids=["step-functions-pipeline"],
        )

        self._events_client.delete_rule(Name=self._rule_name)
        logger.info("PipelineScheduler: rule deleted successfully")

    def update_schedule(self, schedule_expression: str) -> str:
        """Update the schedule expression of an existing rule.

        Args:
            schedule_expression: New cron or rate expression.

        Returns:
            The rule ARN.

        Raises:
            botocore.exceptions.ClientError: If the AWS API call fails.
        """
        logger.info(
            "PipelineScheduler: updating schedule for rule=%s to %s",
            self._rule_name,
            schedule_expression,
        )

        response = self._events_client.put_rule(
            Name=self._rule_name,
            ScheduleExpression=schedule_expression,
        )
        return response["RuleArn"]

    def enable(self) -> None:
        """Enable the EventBridge rule to start triggering the pipeline.

        Raises:
            botocore.exceptions.ClientError: If the enable call fails.
        """
        logger.info("PipelineScheduler: enabling rule=%s", self._rule_name)
        self._events_client.enable_rule(Name=self._rule_name)

    def disable(self) -> None:
        """Disable the EventBridge rule to stop triggering the pipeline.

        Raises:
            botocore.exceptions.ClientError: If the disable call fails.
        """
        logger.info("PipelineScheduler: disabling rule=%s", self._rule_name)
        self._events_client.disable_rule(Name=self._rule_name)

    def get_status(self) -> ScheduleStatus:
        """Query the current state of the EventBridge rule.

        Returns:
            ScheduleStatus with rule name, state, schedule expression,
            description, and target ARN.

        Raises:
            botocore.exceptions.ClientError: If the describe call fails.
        """
        response = self._events_client.describe_rule(Name=self._rule_name)

        # Fetch target ARN
        target_arn = ""
        try:
            targets_response = self._events_client.list_targets_by_rule(
                Rule=self._rule_name
            )
            targets = targets_response.get("Targets", [])
            if targets:
                target_arn = targets[0].get("Arn", "")
        except Exception:
            logger.debug(
                "PipelineScheduler: could not list targets for rule=%s",
                self._rule_name,
            )

        return ScheduleStatus(
            rule_name=response["Name"],
            state=response.get("State", "UNKNOWN"),
            schedule_expression=response.get("ScheduleExpression", ""),
            description=response.get("Description", ""),
            target_arn=target_arn,
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
