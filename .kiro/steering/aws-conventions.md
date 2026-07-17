# AWS Conventions — DarkWeb Fraud Intelligence Agent

## Stack Architecture
- **4 CDK stacks** deployed in order: Core → Intelligence → Compute → Pipeline
- **Anti-cycle pattern**: `from_*_arn()` + SSM StringParameter for cross-stack ARN passing
- **No L2 cross-stack construct references** — causes CDK DependencyCycle errors

## Lambda
- Runtime: Python 3.12 (upgrading to 3.13)
- Architecture: x86_64 (upgrading to ARM64)
- NOT in VPC — reaches AWS services via public HTTPS + IAM SigV4
- Module-level boto3 clients for connection reuse across warm invocations
- Handler convention: `dark_web_fraud_agent.agents.<module>.handler`
- All handlers call `update_health()` at end for CloudWatch EMF metrics

## ECS Fargate
- Crawling Engine runs as Fargate task (Private subnet, NAT Gateway for Tor egress)
- Two containers: app (crawling-engine) + sidecar (tor-socks-proxy)
- App waits for sidecar HEALTHY before starting
- ECR repo: `dark-web-fraud/crawling-engine`

## Step Functions
- Express Workflow (not Standard) — high-frequency 5-min cadence
- ECS launch via `CallAwsService` SDK integration (not L2 EcsRunTask)
- Lambda invocation via `LambdaInvoke` task states
- Cluster ARN, Task Def ARN, Lambda ARNs passed via SSM

## Messaging
- FIFO SNS topic → FIFO SQS queue (ordered, exactly-once alert delivery)
- SNS topic lives in ComputeStack (same stack as AlertGenerator Lambda)
- PipelineStack imports topic ARN via SSM StringParameter

## DynamoDB
- On-Demand billing (bursty access pattern)
- CMK encryption at rest
- Convergence table: DynamoDB Streams (NEW_AND_OLD_IMAGES) triggers AlertGenerator
- TTL on convergence items (auto-expire after 24h window)

## Security
- KMS CMK with annual rotation for all data at rest
- S3: enforce_ssl, block_public_access, Object Lock, bucket_key_enabled
- Per-agent IAM roles with least-privilege (scoping in progress)
- Secrets Manager for Tor + MISP credentials

## DO NOT
- Add Lambda VPC placement (causes CDK dependency cycles)
- Use L2 EcsRunTask from PipelineStack (creates cross-stack construct refs)
- Change from FIFO to Standard messaging (ordered delivery required)
- Change DynamoDB to Provisioned (access pattern is bursty)
- Remove S3 Object Lock (forensic integrity requirement)
