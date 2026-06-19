#!/usr/bin/env python3
"""CDK app entry point for the Dark Web Fraud Agent infrastructure."""
import aws_cdk as cdk

from dark_web_fraud_agent.infrastructure.cdk_core_stack import DarkWebFraudCoreStack
from dark_web_fraud_agent.infrastructure.cdk_intelligence_stack import DarkWebFraudIntelligenceStack
from dark_web_fraud_agent.infrastructure.cdk_pipeline_stack import DarkWebFraudPipelineStack

app = cdk.App()

core = DarkWebFraudCoreStack(app, "DarkWebFraudCore",
    description="Core infrastructure: VPC, S3, DynamoDB, Secrets Manager, IAM",
)
intelligence = DarkWebFraudIntelligenceStack(app, "DarkWebFraudIntelligence",
    description="Intelligence infrastructure: OpenSearch Serverless VECTORSEARCH",
)
pipeline = DarkWebFraudPipelineStack(app, "DarkWebFraudPipeline",
    description="Pipeline orchestration: Step Functions, EventBridge, SNS/SQS, CloudWatch",
)

app.synth()
