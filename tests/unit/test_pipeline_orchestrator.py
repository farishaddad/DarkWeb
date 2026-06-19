"""Unit tests for the PipelineOrchestrator and PipelineMessage classes."""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from dark_web_fraud_agent.infrastructure.pipeline_orchestrator import (
    PipelineMessage,
    PipelineOrchestrator,
)
from dark_web_fraud_agent.models.shared import StepFunctionsPipelineState


class TestPipelineMessage:
    """Tests for the PipelineMessage dataclass."""

    def test_create_message_with_defaults(self):
        """PipelineMessage can be created with minimal required fields."""
        msg = PipelineMessage(
            correlation_id="test-123",
            source_agent="crawling_engine",
            target_agent="content_analyst",
        )
        assert msg.correlation_id == "test-123"
        assert msg.source_agent == "crawling_engine"
        assert msg.target_agent == "content_analyst"
        assert msg.payload == {}
        assert msg.metadata == {}
        assert isinstance(msg.timestamp, datetime)

    def test_create_message_with_payload(self):
        """PipelineMessage carries arbitrary payload data."""
        payload = {"raw_content": "test data", "source_url": "http://example.onion"}
        msg = PipelineMessage(
            correlation_id="corr-456",
            source_agent="crawling_engine",
            target_agent="content_analyst",
            payload=payload,
        )
        assert msg.payload == payload

    def test_to_dict_serialization(self):
        """to_dict produces a valid dictionary with all fields."""
        msg = PipelineMessage(
            correlation_id="corr-789",
            source_agent="data_structurer",
            target_agent="tagging_engine",
            payload={"stix_bundle": "{}"},
            metadata={"retry_count": 0},
        )
        result = msg.to_dict()
        assert result["correlation_id"] == "corr-789"
        assert result["source_agent"] == "data_structurer"
        assert result["target_agent"] == "tagging_engine"
        assert result["payload"] == {"stix_bundle": "{}"}
        assert result["metadata"] == {"retry_count": 0}
        assert "timestamp" in result

    def test_from_dict_deserialization(self):
        """from_dict reconstructs a PipelineMessage from a dictionary."""
        data = {
            "correlation_id": "corr-abc",
            "source_agent": "tagging_engine",
            "target_agent": "alert_generator",
            "payload": {"tagged_event_id": "evt-1"},
            "timestamp": "2024-01-15T10:30:00+00:00",
            "metadata": {"priority": "high"},
        }
        msg = PipelineMessage.from_dict(data)
        assert msg.correlation_id == "corr-abc"
        assert msg.source_agent == "tagging_engine"
        assert msg.target_agent == "alert_generator"
        assert msg.payload == {"tagged_event_id": "evt-1"}
        assert msg.metadata == {"priority": "high"}

    def test_round_trip_serialization(self):
        """to_dict followed by from_dict preserves all fields."""
        original = PipelineMessage(
            correlation_id="round-trip-id",
            source_agent="content_analyst",
            target_agent="data_structurer",
            payload={"entities": ["ip-1", "url-2"]},
            metadata={"version": "1.0"},
        )
        serialized = original.to_dict()
        restored = PipelineMessage.from_dict(serialized)
        assert restored.correlation_id == original.correlation_id
        assert restored.source_agent == original.source_agent
        assert restored.target_agent == original.target_agent
        assert restored.payload == original.payload
        assert restored.metadata == original.metadata

    def test_from_dict_missing_optional_fields(self):
        """from_dict handles missing optional fields gracefully."""
        data = {
            "correlation_id": "minimal-id",
            "source_agent": "crawling_engine",
            "target_agent": "content_analyst",
        }
        msg = PipelineMessage.from_dict(data)
        assert msg.payload == {}
        assert msg.metadata == {}
        assert isinstance(msg.timestamp, datetime)


class TestPipelineOrchestrator:
    """Tests for the PipelineOrchestrator class with mocked sfn_client."""

    @pytest.fixture
    def mock_sfn_client(self):
        """Create a mock Step Functions client."""
        return MagicMock()

    @pytest.fixture
    def orchestrator(self, mock_sfn_client):
        """Create a PipelineOrchestrator with a mocked client."""
        return PipelineOrchestrator(
            state_machine_arn="arn:aws:states:us-east-1:123456789012:stateMachine:DarkWebPipeline",
            sfn_client=mock_sfn_client,
        )

    def test_init_stores_state_machine_arn(self, orchestrator):
        """Orchestrator stores the state machine ARN."""
        assert orchestrator.state_machine_arn == (
            "arn:aws:states:us-east-1:123456789012:stateMachine:DarkWebPipeline"
        )

    @pytest.mark.asyncio
    async def test_start_execution_returns_execution_arn(
        self, orchestrator, mock_sfn_client
    ):
        """start_execution returns the execution ARN from Step Functions."""
        mock_sfn_client.start_execution.return_value = {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:DarkWebPipeline:pipeline-test-id",
            "startDate": datetime(2024, 1, 15, 10, 0, 0),
        }

        result = await orchestrator.start_execution(
            input_payload={"sources": ["http://example.onion"]},
            correlation_id="test-id",
        )

        assert (
            result
            == "arn:aws:states:us-east-1:123456789012:execution:DarkWebPipeline:pipeline-test-id"
        )

    @pytest.mark.asyncio
    async def test_start_execution_passes_correlation_id(
        self, orchestrator, mock_sfn_client
    ):
        """start_execution embeds correlation_id in the execution input."""
        mock_sfn_client.start_execution.return_value = {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:test",
            "startDate": datetime(2024, 1, 15, 10, 0, 0),
        }

        await orchestrator.start_execution(
            input_payload={"key": "value"},
            correlation_id="my-corr-id",
        )

        call_kwargs = mock_sfn_client.start_execution.call_args[1]
        input_json = json.loads(call_kwargs["input"])
        assert input_json["correlationId"] == "my-corr-id"
        assert input_json["key"] == "value"

    @pytest.mark.asyncio
    async def test_start_execution_generates_correlation_id_if_none(
        self, orchestrator, mock_sfn_client
    ):
        """start_execution generates a UUID correlation_id when none provided."""
        mock_sfn_client.start_execution.return_value = {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:test",
            "startDate": datetime(2024, 1, 15, 10, 0, 0),
        }

        await orchestrator.start_execution(input_payload={"data": "test"})

        call_kwargs = mock_sfn_client.start_execution.call_args[1]
        input_json = json.loads(call_kwargs["input"])
        assert "correlationId" in input_json
        assert len(input_json["correlationId"]) == 36  # UUID format

    @pytest.mark.asyncio
    async def test_start_execution_uses_correct_state_machine_arn(
        self, orchestrator, mock_sfn_client
    ):
        """start_execution calls the configured state machine ARN."""
        mock_sfn_client.start_execution.return_value = {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:test",
            "startDate": datetime(2024, 1, 15, 10, 0, 0),
        }

        await orchestrator.start_execution(
            input_payload={}, correlation_id="corr-1"
        )

        call_kwargs = mock_sfn_client.start_execution.call_args[1]
        assert call_kwargs["stateMachineArn"] == (
            "arn:aws:states:us-east-1:123456789012:stateMachine:DarkWebPipeline"
        )

    @pytest.mark.asyncio
    async def test_get_execution_status_returns_pipeline_state(
        self, orchestrator, mock_sfn_client
    ):
        """get_execution_status returns a StepFunctionsPipelineState."""
        exec_arn = "arn:aws:states:us-east-1:123456789012:execution:DarkWebPipeline:pipeline-abc"
        start_date = datetime(2024, 1, 15, 10, 0, 0)
        mock_sfn_client.describe_execution.return_value = {
            "executionArn": exec_arn,
            "stateMachineArn": "arn:aws:states:us-east-1:123456789012:stateMachine:DarkWebPipeline",
            "name": "pipeline-abc",
            "status": "RUNNING",
            "startDate": start_date,
            "input": json.dumps({"correlationId": "abc-123", "sources": []}),
        }

        result = await orchestrator.get_execution_status(exec_arn)

        assert isinstance(result, StepFunctionsPipelineState)
        assert result.execution_arn == exec_arn
        assert result.current_step == "RUNNING"
        assert result.correlation_id == "abc-123"
        assert result.started_at == start_date
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_get_execution_status_captures_errors_on_failure(
        self, orchestrator, mock_sfn_client
    ):
        """get_execution_status captures error info when execution is FAILED."""
        exec_arn = "arn:aws:states:us-east-1:123456789012:execution:DarkWebPipeline:pipeline-fail"
        mock_sfn_client.describe_execution.return_value = {
            "executionArn": exec_arn,
            "status": "FAILED",
            "startDate": datetime(2024, 1, 15, 10, 0, 0),
            "input": json.dumps({"correlationId": "fail-id"}),
            "error": "TorConnectivityError",
            "cause": "Could not connect to Tor network",
        }

        result = await orchestrator.get_execution_status(exec_arn)

        assert result.current_step == "FAILED"
        assert len(result.errors) == 1
        assert result.errors[0]["error"] == "TorConnectivityError"
        assert result.errors[0]["cause"] == "Could not connect to Tor network"

    @pytest.mark.asyncio
    async def test_signal_human_approval_approved(
        self, orchestrator, mock_sfn_client
    ):
        """signal_human_approval sends task success when approved."""
        await orchestrator.signal_human_approval(
            task_token="token-xyz-123", approved=True
        )

        mock_sfn_client.send_task_success.assert_called_once()
        call_kwargs = mock_sfn_client.send_task_success.call_args[1]
        assert call_kwargs["taskToken"] == "token-xyz-123"
        output = json.loads(call_kwargs["output"])
        assert output["approved"] is True

    @pytest.mark.asyncio
    async def test_signal_human_approval_rejected(
        self, orchestrator, mock_sfn_client
    ):
        """signal_human_approval sends task failure when rejected."""
        await orchestrator.signal_human_approval(
            task_token="token-reject-456", approved=False
        )

        mock_sfn_client.send_task_failure.assert_called_once()
        call_kwargs = mock_sfn_client.send_task_failure.call_args[1]
        assert call_kwargs["taskToken"] == "token-reject-456"
        assert call_kwargs["error"] == "HumanRejection"
        assert "rejected" in call_kwargs["cause"].lower()

    @pytest.mark.asyncio
    async def test_start_execution_name_includes_correlation_id(
        self, orchestrator, mock_sfn_client
    ):
        """start_execution uses correlation_id in the execution name."""
        mock_sfn_client.start_execution.return_value = {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:test",
            "startDate": datetime(2024, 1, 15, 10, 0, 0),
        }

        await orchestrator.start_execution(
            input_payload={}, correlation_id="named-execution"
        )

        call_kwargs = mock_sfn_client.start_execution.call_args[1]
        assert call_kwargs["name"] == "pipeline-named-execution"

    def test_init_creates_default_client_when_none_provided(self):
        """PipelineOrchestrator creates a boto3 client when none is provided."""
        with patch("dark_web_fraud_agent.infrastructure.pipeline_orchestrator.boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock()
            orch = PipelineOrchestrator(
                state_machine_arn="arn:aws:states:us-east-1:123456789012:stateMachine:Test"
            )
            mock_boto.assert_called_once_with("stepfunctions")
