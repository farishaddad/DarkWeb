#!/usr/bin/env python3
"""CDK app entry point for the Dark Web Fraud Agent infrastructure.

Stack dependency order (each stack depends on the one before it):
  1. DarkWebFraudCoreStack        — VPC, KMS, S3, DynamoDB, Secrets Manager
  2. DarkWebFraudIntelligenceStack — OpenSearch Serverless (depends on VPC endpoints from Core)
  3. DarkWebFraudComputeStack     — ECR, ECS/Fargate, Lambda, IAM roles (depends on Core + Intelligence)
  4. DarkWebFraudPipelineStack    — Step Functions, EventBridge, SNS/SQS (depends on Core + Compute)

Deploy order:
  cdk deploy DarkWebFraudCore
  cdk deploy DarkWebFraudIntelligence
  cdk deploy DarkWebFraudCompute
  cdk deploy DarkWebFraudPipeline

Or in one command (CDK resolves order from addDependency):
  cdk deploy --all
"""
import aws_cdk as cdk

from dark_web_fraud_agent.infrastructure.cdk_core_stack import DarkWebFraudCoreStack
from dark_web_fraud_agent.infrastructure.cdk_compute_stack import DarkWebFraudComputeStack
from dark_web_fraud_agent.infrastructure.cdk_intelligence_stack import DarkWebFraudIntelligenceStack
from dark_web_fraud_agent.infrastructure.cdk_pipeline_stack import DarkWebFraudPipelineStack

app = cdk.App()

# 1. Core — must deploy first (VPC endpoints needed by Intelligence + Compute)
core = DarkWebFraudCoreStack(
    app,
    "DarkWebFraudCore",
    description="Core infrastructure: VPC (2 NAT GWs), KMS CMK, S3, DynamoDB, Secrets Manager",
)

# 2. Intelligence — depends on VPC Interface Endpoint from Core
intelligence = DarkWebFraudIntelligenceStack(
    app,
    "DarkWebFraudIntelligence",
    core_stack=core,
    description="Intelligence infrastructure: OpenSearch Serverless VECTORSEARCH (VPC-scoped)",
)
intelligence.add_dependency(core)

# 3. Compute — depends on Core (bucket/tables/secrets) + Intelligence (OpenSearch endpoint)
compute = DarkWebFraudComputeStack(
    app,
    "DarkWebFraudCompute",
    core_stack=core,
    intelligence_stack=intelligence,
    description="Compute: ECR, ECS/Fargate (Tor sidecar), Lambda agents, per-agent IAM roles",
)
compute.add_dependency(intelligence)

# 4. Pipeline — depends on Core (SNS key) + Compute (Lambda ARNs, ECS cluster)
pipeline = DarkWebFraudPipelineStack(
    app,
    "DarkWebFraudPipeline",
    core_stack=core,
    compute_stack=compute,
    description="Orchestration: Step Functions Express, EventBridge Scheduler, SNS/SQS, CloudWatch",
)
pipeline.add_dependency(compute)

app.synth()
