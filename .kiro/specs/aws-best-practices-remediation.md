# AWS Best Practices Remediation

**Priority:** P1 — No blocking issues; all items are optimisation/hardening improvements.  
**Reviewed:** 17 July 2026  
**Rating before:** PRODUCTION READY (41/57)  
**Target after:** EXCELLENT (57/57)  

---

## Quick Reference: Files to Modify

| File | Changes |
|---|---|
| `src/dark_web_fraud_agent/infrastructure/cdk_compute_stack.py` | ARM64, SnapStart, Fargate Spot, Python 3.13, scoped IAM |
| `src/dark_web_fraud_agent/infrastructure/cdk_pipeline_stack.py` | Lambda duration alarm, Bedrock throttle alarm, EventBridge Scheduler |
| `src/dark_web_fraud_agent/infrastructure/cdk_core_stack.py` | Secrets rotation, GuardDuty, Security Hub |
| `src/dark_web_fraud_agent/infrastructure/cdk_intelligence_stack.py` | OpenSearch Serverless standby config |
| `src/dark_web_fraud_agent/agents/alert_generator.py` | SNS MessageDeduplicationId, DynamoDB ConditionExpression |
| `src/dark_web_fraud_agent/agents/content_analyst.py` | Input validation |
| `src/dark_web_fraud_agent/agents/data_structurer.py` | Input validation |
| `src/dark_web_fraud_agent/agents/tagging_engine.py` | Input validation |
| `cdk.json` | Cross-stack reference strength flag |
| `.dockerignore` | NEW FILE |

---

## Task 1: Lambda ARM64 + Python 3.13 + SnapStart

**File:** `src/dark_web_fraud_agent/infrastructure/cdk_compute_stack.py`

**What to change:**

Find `common_lambda_kwargs`:
```python
common_lambda_kwargs = dict(
    runtime=lambda_.Runtime.PYTHON_3_12,
    code=lambda_.Code.from_asset("src"),
    tracing=lambda_.Tracing.ACTIVE,
)
```

Replace with:
```python
common_lambda_kwargs = dict(
    runtime=lambda_.Runtime.PYTHON_3_13,
    architecture=lambda_.Architecture.ARM_64,
    code=lambda_.Code.from_asset("src"),
    tracing=lambda_.Tracing.ACTIVE,
    snap_start=lambda_.SnapStartConf.ON_PUBLISHED_VERSIONS,
)
```

**Why:**
- ARM64 (Graviton2): 20% cheaper, up to 34% better price-performance for Python
- Python 3.13: GA on Lambda since Dec 2025, better stdlib + performance
- SnapStart: cold start drops from ~2–3s to <200ms (critical since stix2/pymisp are heavy imports)

**Acceptance criteria:**
- `cdk synth` produces ARM64 architecture in all 4 Lambda function CloudFormation resources
- Runtime shows `python3.13`
- SnapStart configuration is present

---

## Task 2: Fargate Spot for Crawling Engine

**File:** `src/dark_web_fraud_agent/infrastructure/cdk_compute_stack.py`

**What to change:**

Find the ECS Cluster definition:
```python
self.cluster = ecs.Cluster(
    self,
    "FraudAgentCluster",
    cluster_name="dark-web-fraud-agents",
    vpc=vpc,
    container_insights_v2=ecs.ContainerInsights.ENHANCED,
)
```

Add Fargate Spot capacity provider AFTER the cluster definition:
```python
self.cluster.enable_fargate_capacity_providers()
```

Then update the CallAwsService parameters in `cdk_pipeline_stack.py` where the ECS RunTask is defined, adding to the parameters dict:
```python
"CapacityProviderStrategy": [{
    "CapacityProvider": "FARGATE_SPOT",
    "Weight": 2,
    "Base": 0
}, {
    "CapacityProvider": "FARGATE",
    "Weight": 1,
    "Base": 1  # At least 1 task on regular Fargate as fallback
}]
```

**Why:** Crawl jobs are retryable (circuit breaker already handles failures). Fargate Spot saves 50–70% on compute costs.

**Acceptance criteria:**
- ECS cluster has FARGATE_SPOT capacity provider enabled
- RunTask parameters include CapacityProviderStrategy preferring Spot

---

## Task 3: Scope IAM Wildcards

**File:** `src/dark_web_fraud_agent/infrastructure/cdk_compute_stack.py`

**What to change:**

Replace all `resources=["*"]` with scoped ARNs where possible:

1. **Bedrock InvokeModel** (AnalystRole + StructurerRole):
```python
# OLD
resources=["*"],

# NEW — scope to specific model ARNs
resources=[
    f"arn:aws:bedrock:{Stack.of(self).region}::foundation-model/anthropic.claude-*",
    f"arn:aws:bedrock:{Stack.of(self).region}::foundation-model/amazon.titan-embed-*",
],
```

2. **KMS** (all roles) — use SSM to pass the CMK ARN:
```python
# OLD
resources=["*"],  # KMS key — cross-stack ARN removed to avoid dep cycle

# NEW — read CMK ARN from SSM
resources=[
    ssm.StringParameter.value_for_string_parameter(
        self, "/dark-web-fraud/kms-key-arn"
    )
],
```
(Also add a KMS ARN SSM export to `cdk_core_stack.py`)

3. **X-Ray and SNS** — these legitimately need `*`:
```python
# X-Ray: resources=["*"] is CORRECT — X-Ray doesn't support resource-level policies
# SNS: scoped via env var but SSM import would require circular reference — leave as "*"
```

4. **AgentCore/Bedrock** (AnalystRole):
```python
# OLD
resources=["*"],

# NEW
resources=[
    f"arn:aws:bedrock-agentcore:{Stack.of(self).region}:{Stack.of(self).account}:*"
],
```

**Acceptance criteria:**
- Only X-Ray and SNS still use `resources=["*"]`
- Bedrock scoped to model family ARN pattern
- KMS scoped to specific CMK ARN via SSM

---

## Task 4: SNS MessageDeduplicationId

**File:** `src/dark_web_fraud_agent/agents/alert_generator.py`

**What to change:**

Find the `publish_alert` method's `sns_client.publish()` call:
```python
response = sns_client.publish(
    TopicArn=sns_topic_arn,
    Message=message_body,
    Subject=f"FraudAlert [{alert.severity.upper()}]: {alert.alert_type}",
    MessageAttributes={...},
)
```

Add FIFO-required parameters:
```python
response = sns_client.publish(
    TopicArn=sns_topic_arn,
    Message=message_body,
    Subject=f"FraudAlert [{alert.severity.upper()}]: {alert.alert_type}",
    MessageGroupId=f"ttp-{alert.alert_type}",
    MessageDeduplicationId=alert.alert_id,  # Prevents duplicate on Lambda retry
    MessageAttributes={...},
)
```

**Why:** FIFO SNS topics REQUIRE `MessageGroupId`. `MessageDeduplicationId` prevents duplicate delivery when Lambda retries after a transient failure.

**Acceptance criteria:**
- All `sns_client.publish()` calls include `MessageGroupId` and `MessageDeduplicationId`
- No duplicate alerts for the same `alert_id` even if Lambda retries

---

## Task 5: DynamoDB ConditionExpression

**File:** `src/dark_web_fraud_agent/agents/alert_generator.py`

**What to change:**

Find `track_item()`:
```python
table.put_item(Item={
    "PK": f"CONV#{ttp_reference}",
    "SK": f"ITEM#{stix_id}",
    ...
})
```

Add a condition to prevent overwriting:
```python
from boto3.dynamodb.conditions import Attr

table.put_item(
    Item={
        "PK": f"CONV#{ttp_reference}",
        "SK": f"ITEM#{stix_id}",
        ...
    },
    ConditionExpression=Attr("SK").not_exists(),
)
```

Wrap in try/except to handle the expected ConditionalCheckFailedException (same item already tracked):
```python
try:
    table.put_item(
        Item={...},
        ConditionExpression=Attr("SK").not_exists(),
    )
except table.meta.client.exceptions.ConditionalCheckFailedException:
    pass  # Item already tracked — idempotent, skip silently
```

**Why:** Prevents concurrent Lambda invocations from overcounting convergence items.

**Acceptance criteria:**
- `put_item` uses ConditionExpression
- ConditionalCheckFailedException is caught and ignored

---

## Task 6: Handler Input Validation

**Files:** All 4 handler files:
- `src/dark_web_fraud_agent/agents/content_analyst.py`
- `src/dark_web_fraud_agent/agents/data_structurer.py`
- `src/dark_web_fraud_agent/agents/tagging_engine.py`
- `src/dark_web_fraud_agent/agents/alert_generator.py`

**What to change:**

At the top of each `handler(event, context)` function, add validation:
```python
def handler(event: dict, context) -> dict:
    # Input validation
    if not isinstance(event, dict):
        raise ValueError(f"Expected dict event, got {type(event).__name__}")
    if "Records" not in event:  # Skip validation for DynamoDB Streams path
        required_fields = ["s3_key"]  # Adjust per handler
        missing = [f for f in required_fields if f not in event]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")
    ...
```

Required fields per handler:
- content_analyst: `["s3_key"]`
- data_structurer: `["s3_key", "is_fraud_relevant"]`
- tagging_engine: `["s3_key"]`
- alert_generator: `["s3_key"]` (or `"Records"` for Streams path)

**Acceptance criteria:**
- Each handler raises `ValueError` with descriptive message on missing required fields
- DynamoDB Streams path (event with "Records") is exempt from s3_key validation

---

## Task 7: CloudWatch Alarms (Lambda Duration + Bedrock Throttle)

**File:** `src/dark_web_fraud_agent/infrastructure/cdk_pipeline_stack.py`

**What to add** (after existing alarms section):

```python
# Lambda duration alarm — detect Bedrock throttling early
# (4 min = 80% of the 5-min timeout)
content_analyst_duration_alarm = cloudwatch.Alarm(
    self,
    "ContentAnalystDurationAlarm",
    metric=cloudwatch.Metric(
        namespace="AWS/Lambda",
        metric_name="Duration",
        dimensions_map={"FunctionName": "dark-web-fraud-content-analyst"},
        statistic="p95",
        period=Duration.minutes(5),
    ),
    threshold=240_000,  # 4 minutes in ms
    evaluation_periods=2,
    alarm_description="Content Analyst P95 latency > 4 min — Bedrock may be throttling",
    comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
    treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
)

# Bedrock throttle alarm
bedrock_throttle_alarm = cloudwatch.Alarm(
    self,
    "BedrockThrottleAlarm",
    metric=cloudwatch.Metric(
        namespace="AWS/Bedrock",
        metric_name="InvocationThrottles",
        dimensions_map={"ModelId": "anthropic.claude-opus-4-5"},
        statistic="Sum",
        period=Duration.minutes(5),
    ),
    threshold=5,
    evaluation_periods=1,
    alarm_description="Bedrock throttling > 5 requests per 5-min — increase provisioned throughput",
    comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
    treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
)
```

**Acceptance criteria:**
- Both alarms appear in the CloudWatch Dashboard alarm status widget
- Both route to the alert SNS topic

---

## Task 8: Secrets Manager Rotation

**File:** `src/dark_web_fraud_agent/infrastructure/cdk_core_stack.py`

**What to add** after the MISP API key secret definition:

```python
# Rotation for MISP API key (30-day cycle)
# Requires a rotation Lambda that calls MISP's key regeneration API
# For now, set up the rotation schedule structure — implement rotation Lambda separately
self.misp_api_key.add_rotation_schedule(
    "MispKeyRotation",
    automatically_after=Duration.days(30),
    # rotation_lambda=misp_rotation_fn,  # TODO: implement MISP rotation Lambda
)
```

**Note:** Tor credentials are auto-generated and don't expire — rotation is less critical. MISP API keys typically expire or should be rotated per security policy.

**Acceptance criteria:**
- Rotation schedule configured (even if rotation Lambda is TODO)

---

## Task 9: GuardDuty + Security Hub

**File:** `src/dark_web_fraud_agent/infrastructure/cdk_core_stack.py`

**What to add** at the end of the stack (before outputs):

```python
# Security monitoring — enable at account level (idempotent)
from aws_cdk import aws_guardduty as guardduty, aws_securityhub as securityhub

guardduty.CfnDetector(
    self,
    "GuardDutyDetector",
    enable=True,
    finding_publishing_frequency="FIFTEEN_MINUTES",
)

securityhub.CfnHub(
    self,
    "SecurityHub",
    enable_default_standards=True,
)
```

**Acceptance criteria:**
- GuardDuty detector is enabled in the account/region
- Security Hub is enabled with default standards (CIS, AWS Foundational)

---

## Task 10: OpenSearch Serverless Standby

**File:** `src/dark_web_fraud_agent/infrastructure/cdk_intelligence_stack.py`

**What to change:**

Find the collection definition:
```python
self.opensearch_collection = aoss.CfnCollection(
    self,
    "ThreatIntelCollection",
    name="threat-intel",
    type="VECTORSEARCH",
    description="...",
)
```

Add standby replicas disabled:
```python
self.opensearch_collection = aoss.CfnCollection(
    self,
    "ThreatIntelCollection",
    name="threat-intel",
    type="VECTORSEARCH",
    description="...",
    standby_replicas="DISABLED",  # Halves baseline OCU cost for dev/test
)
```

**Note:** In production with SLA requirements, set to `"ENABLED"` for HA.

**Acceptance criteria:**
- `standbyReplicas: DISABLED` in synthesised CloudFormation template

---

## Task 11: EventBridge Scheduler (replace Rule)

**File:** `src/dark_web_fraud_agent/infrastructure/cdk_pipeline_stack.py`

**What to change:**

Replace the `events.Rule` block:
```python
from aws_cdk import aws_scheduler as scheduler, aws_scheduler_targets as scheduler_targets

# Replace the old Rule with EventBridge Scheduler
self.crawl_schedule = scheduler.CfnSchedule(
    self,
    "CrawlSchedule",
    name="dark-web-fraud-crawl-schedule",
    schedule_expression="rate(5 minutes)",
    flexible_time_window=scheduler.CfnSchedule.FlexibleTimeWindowProperty(
        mode="OFF"  # Exact timing for intelligence freshness
    ),
    target=scheduler.CfnSchedule.TargetProperty(
        arn=self.state_machine.state_machine_arn,
        role_arn=...,  # Create a scheduler execution role
        input='{"trigger":"scheduled","source":"eventbridge-scheduler"}',
        dead_letter_config=scheduler.CfnSchedule.DeadLetterConfigProperty(
            arn=self.dlq.queue_arn
        ),
    ),
)
```

**Why:** EventBridge Scheduler supports time zones, flexible windows, built-in DLQ per schedule, and is the recommended replacement for EventBridge Rules with schedule expressions.

**Acceptance criteria:**
- Old `events.Rule` removed
- `CfnSchedule` with rate(5 minutes) targeting state machine

---

## Task 12: CDK Cross-Stack Reference Flag

**File:** `cdk.json`

**What to change:**

Add to the `context` object:
```json
{
  "app": ".venv/bin/python3 app.py",
  "context": {
    "@aws-cdk/core:stackRelativeExports": true,
    "@aws-cdk/core:defaultCrossStackReferences": "strong"
  }
}
```

**Why:** Suppresses the synthesis warning and locks in producer-protecting behaviour.

**Acceptance criteria:**
- `cdk synth` no longer emits the cross-stack reference strength warning

---

## Task 13: .dockerignore

**File:** `.dockerignore` (NEW — create in project root)

**Content:**
```
.venv
.git
.github
__pycache__
*.egg-info
*.pyc
tests
cdk.out
.versions
.kiro
node_modules
.mypy_cache
.pytest_cache
.ruff_cache
```

**Why:** Prevents 100MB+ of unnecessary files from entering the Docker build context, speeding up builds from ~32s to ~10s.

**Acceptance criteria:**
- File exists at project root
- `docker build` context size < 5MB (instead of ~100MB+)

---

## Do-Not-Do List

- **Do NOT add Lambda VPC placement back** — it was removed to eliminate CDK dependency cycles. Lambda reaches AWS services via public HTTPS + IAM SigV4.
- **Do NOT change from CallAwsService back to EcsRunTask** — L2 construct cross-stack refs cause cycles.
- **Do NOT change from SSM parameter passing** — this is the anti-cycle pattern. Fn::ImportValue is the CDK alternative but creates tighter coupling.
- **Do NOT change DynamoDB from On-Demand to Provisioned** — access pattern is bursty (every 5 min) and variable.
- **Do NOT remove Object Lock from S3** — required for forensic chain of custody in banking fraud investigations.
- **Do NOT change from FIFO to Standard** on SNS/SQS — ordered delivery is required for campaign alert integrity.

---

## Verification

After all changes, run:
```bash
cd /Users/fahaddad/Documents/DarkWeb && source .venv/bin/activate
JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1 cdk synth --quiet
pytest tests/ -v --tb=short
```

Both must pass with zero errors before deploying.
