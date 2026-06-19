"""Unit tests for the CDK pipeline orchestration stack."""

import pytest

try:
    import aws_cdk as cdk
    from aws_cdk import assertions

    from dark_web_fraud_agent.infrastructure.cdk_pipeline_stack import DarkWebFraudPipelineStack

    CDK_AVAILABLE = True
except ImportError:
    CDK_AVAILABLE = False


pytestmark = pytest.mark.skipif(not CDK_AVAILABLE, reason="aws-cdk-lib not installed")


@pytest.fixture
def template():
    """Synthesize the stack and return a CloudFormation template assertion wrapper."""
    app = cdk.App()
    stack = DarkWebFraudPipelineStack(app, "TestPipelineStack")
    return assertions.Template.from_stack(stack)


class TestSNSResources:
    """Tests for SNS topic configuration."""

    def test_sns_topic_created(self, template):
        """SNS topic for alert distribution exists."""
        template.resource_count_is("AWS::SNS::Topic", 1)

    def test_sns_topic_display_name(self, template):
        """SNS topic has the expected display name."""
        template.has_resource_properties("AWS::SNS::Topic", {
            "DisplayName": "Dark Web Fraud Intelligence Alerts",
        })


class TestSQSResources:
    """Tests for SQS queue configuration."""

    def test_dlq_created(self, template):
        """Dead-letter queue exists with correct retention."""
        template.has_resource_properties("AWS::SQS::Queue", {
            "QueueName": "dark-web-fraud-dlq",
            "MessageRetentionPeriod": 1209600,  # 14 days in seconds
        })

    def test_alert_queue_created(self, template):
        """Alert queue exists with correct visibility timeout and DLQ redrive."""
        template.has_resource_properties("AWS::SQS::Queue", {
            "QueueName": "dark-web-fraud-alerts",
            "VisibilityTimeout": 300,
        })

    def test_sqs_queue_count(self, template):
        """Exactly 2 SQS queues are created (alert queue + DLQ)."""
        template.resource_count_is("AWS::SQS::Queue", 2)

    def test_sns_subscription_to_sqs(self, template):
        """SNS subscription routes alerts to the SQS queue."""
        template.resource_count_is("AWS::SNS::Subscription", 1)
        template.has_resource_properties("AWS::SNS::Subscription", {
            "Protocol": "sqs",
        })


class TestStepFunctionsResources:
    """Tests for Step Functions state machine configuration."""

    def test_state_machine_created(self, template):
        """Step Functions state machine exists."""
        template.resource_count_is("AWS::StepFunctions::StateMachine", 1)

    def test_state_machine_name(self, template):
        """State machine has expected name."""
        template.has_resource_properties("AWS::StepFunctions::StateMachine", {
            "StateMachineName": "dark-web-fraud-pipeline",
        })


class TestEventBridgeResources:
    """Tests for EventBridge scheduled rule."""

    def test_eventbridge_rule_created(self, template):
        """EventBridge rule for scheduled crawling exists."""
        template.has_resource_properties("AWS::Events::Rule", {
            "Name": "dark-web-fraud-crawl-schedule",
            "ScheduleExpression": "rate(5 minutes)",
        })

    def test_eventbridge_targets_state_machine(self, template):
        """EventBridge rule has a target (Step Functions state machine)."""
        template.has_resource_properties("AWS::Events::Rule", {
            "Name": "dark-web-fraud-crawl-schedule",
            "State": "ENABLED",
        })


class TestCloudWatchAlarms:
    """Tests for CloudWatch alarm configuration."""

    def test_alarm_count(self, template):
        """Two CloudWatch alarms are created (pipeline failures + DLQ depth)."""
        template.resource_count_is("AWS::CloudWatch::Alarm", 2)

    def test_pipeline_failure_alarm(self, template):
        """Pipeline failure alarm has correct threshold."""
        template.has_resource_properties("AWS::CloudWatch::Alarm", {
            "Threshold": 3,
            "EvaluationPeriods": 1,
            "AlarmDescription": "Alert when pipeline has more than 3 failures per evaluation period",
        })

    def test_dlq_depth_alarm(self, template):
        """DLQ depth alarm has correct threshold."""
        template.has_resource_properties("AWS::CloudWatch::Alarm", {
            "Threshold": 10,
            "EvaluationPeriods": 1,
            "AlarmDescription": "Alert when DLQ has more than 10 messages",
        })


class TestStackOutputs:
    """Tests for CloudFormation outputs."""

    def test_state_machine_arn_output(self, template):
        """Stack exports the state machine ARN."""
        template.has_output("StateMachineArn", {})

    def test_alert_topic_arn_output(self, template):
        """Stack exports the SNS topic ARN."""
        template.has_output("AlertTopicArn", {})

    def test_dlq_url_output(self, template):
        """Stack exports the DLQ URL."""
        template.has_output("DLQUrl", {})
