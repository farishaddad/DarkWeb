"""AWS Step Functions pipeline orchestrator for the agent pipeline.

Provides the PipelineOrchestrator class that wraps boto3 Step Functions client calls
to manage pipeline execution lifecycle: starting executions, querying status,
and handling human approval task callbacks.
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Optional

import boto3

from dark_web_fraud_agent.models.shared import StepFunctionsPipelineState


@dataclass
class PipelineMessage:
    """Inter-agent message passed through the Step Functions pipeline.

    Each message carries a correlation_id that tracks the item through
    the full pipeline (Crawl -> Analyze -> Structure -> Tag -> Alert),
    along with a payload containing the agent output data.
    """

    correlation_id: str
    source_agent: str
    target_agent: str
    payload: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize message to a dictionary for Step Functions input/output."""
        return {
            "correlation_id": self.correlation_id,
            "source_agent": self.source_agent,
            "target_agent": self.target_agent,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PipelineMessage":
        """Deserialize a message from a dictionary."""
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        elif timestamp is None:
            timestamp = datetime.now(UTC)

        return cls(
            correlation_id=data["correlation_id"],
            source_agent=data["source_agent"],
            target_agent=data["target_agent"],
            payload=data.get("payload", {}),
            timestamp=timestamp,
            metadata=data.get("metadata", {}),
        )


class PipelineOrchestrator:
    """AWS Step Functions state machine managing the agent pipeline.

    Wraps boto3 Step Functions client calls to start executions, query
    execution status, and handle human approval callbacks via task tokens.
    Tracks correlation_id through pipeline execution.
    """

    def __init__(
        self,
        state_machine_arn: str,
        sfn_client: Optional[Any] = None,
    ) -> None:
        """Initialize the pipeline orchestrator.

        Args:
            state_machine_arn: ARN of the Step Functions state machine.
            sfn_client: Optional pre-configured boto3 Step Functions client
                (useful for testing). If None, creates a default client.
        """
        self._state_machine_arn = state_machine_arn
        self._sfn_client = sfn_client or boto3.client("stepfunctions")

    @property
    def state_machine_arn(self) -> str:
        """Return the state machine ARN."""
        return self._state_machine_arn

    async def start_execution(
        self,
        input_payload: dict,
        correlation_id: Optional[str] = None,
    ) -> str:
        """Start a new Step Functions execution.

        Args:
            input_payload: The input data for the state machine execution.
            correlation_id: Optional correlation ID to track the execution.
                If not provided, a new UUID is generated.

        Returns:
            The execution ARN of the started execution.

        Raises:
            botocore.exceptions.ClientError: If the execution fails to start.
        """
        if correlation_id is None:
            correlation_id = str(uuid.uuid4())

        # Embed correlation_id into the input payload
        execution_input = {
            "correlationId": correlation_id,
            **input_payload,
        }

        response = self._sfn_client.start_execution(
            stateMachineArn=self._state_machine_arn,
            name=f"pipeline-{correlation_id}",
            input=json.dumps(execution_input, default=str),
        )

        return response["executionArn"]

    async def get_execution_status(
        self, execution_arn: str
    ) -> StepFunctionsPipelineState:
        """Query the current status of a pipeline execution.

        Args:
            execution_arn: The ARN of the execution to query.

        Returns:
            A StepFunctionsPipelineState with execution details.

        Raises:
            botocore.exceptions.ClientError: If the describe call fails.
        """
        response = self._sfn_client.describe_execution(
            executionArn=execution_arn,
        )

        # Parse the input to extract correlation_id
        execution_input = json.loads(response.get("input", "{}"))
        correlation_id = execution_input.get("correlationId", "")

        # Determine current step from status
        status = response.get("status", "UNKNOWN")
        started_at = response.get("startDate", datetime.now(UTC))

        # Build errors list from execution output if failed
        errors: list[dict] = []
        if status == "FAILED":
            error_info = {
                "error": response.get("error", "Unknown"),
                "cause": response.get("cause", "Unknown"),
            }
            errors.append(error_info)

        return StepFunctionsPipelineState(
            execution_arn=execution_arn,
            current_step=status,
            correlation_id=correlation_id,
            started_at=started_at,
            items_processed=0,
            errors=errors,
        )

    async def signal_human_approval(
        self, task_token: str, approved: bool
    ) -> None:
        """Handle a human approval callback for a manual review gate.

        When the pipeline reaches a human approval step, Step Functions
        pauses and issues a task token. This method sends the approval
        decision back to resume execution.

        Args:
            task_token: The task token issued by Step Functions.
            approved: Whether the human approved the item.

        Raises:
            botocore.exceptions.ClientError: If the callback fails.
        """
        if approved:
            self._sfn_client.send_task_success(
                taskToken=task_token,
                output=json.dumps({"approved": True, "timestamp": datetime.now(UTC).isoformat()}),
            )
        else:
            self._sfn_client.send_task_failure(
                taskToken=task_token,
                error="HumanRejection",
                cause="Item rejected during manual review",
            )
