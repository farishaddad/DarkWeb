# AWS Conventions — Dark Web Fraud Agent

## CDK v2 imports
```python
from aws_cdk import (
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
)
from constructs import Construct
```

## Lambda sizing
| Agent | Memory | Timeout | Architecture |
|-------|--------|---------|-------------|
| ContentAnalyst | 1024 MB | 300s | ARM64 |
| DataStructurer | 512 MB | 120s | ARM64 |
| TaggingEngine | 512 MB | 60s | ARM64 |
| AlertGenerator | 256 MB | 60s | ARM64 |

## DynamoDB key schema
ConvergenceTable PK/SK:
- TTP items: `PK = "CONV#<ttp_reference>"`, `SK = "ITEM#<stix_id>"`
- Entity items: `PK = "ENTITY#<entity_type>#<value_lower>"`, `SK = "ITEM#<stix_id>"`
- All items carry `TTL` epoch attribute for auto-expiry.

## GSI — entity-cooccurrence-index
- Index name: `entity-cooccurrence-index`  (set by CDK, injected as `ENTITY_INDEX_NAME` env var)
- PK: `PK` (STRING) — queries `ENTITY#bank_name#<institution>` items
- SK: `SK` (STRING)
- Projection: ALL
- Billing: inherits PAY_PER_REQUEST from table

## IAM grants (CDK)
```python
# Full read/write including GSI Query:
core_stack.convergence_table.grant_read_write_data(lambda_role)
# S3 prefixed access:
core_stack.artifacts_bucket.grant_read(lambda_role)
core_stack.artifacts_bucket.grant_put(lambda_role)
```

## Step Functions payload contract
```json
{
  "s3_key": "crawl-artifacts/...",
  "execution_id": "<SFN execution ARN>",
  "entities": [{"entity_type": "bank_name", "value": "HSBC", ...}],
  "fraud_category": "money_mule",
  "severity_score": 9,
  "stix_bundle_key": "stix-bundles/...",
  "tags": ["mitre-attack:technique=\"T1531\"", ...],
  "tier": "observable"
}
```

## CloudWatch custom metrics
Namespace: `dark-web-fraud`
| Metric name | Unit | Dimensions |
|-------------|------|-----------|
| `EntityCooccurrenceAlerts` | Count | `AlertType=composite` |
| `TTPConvergenceAlerts` | Count | — |
| `ImmediateSeverityAlerts` | Count | — |

Publish in `AlertGenerator.publish_alert()` via `boto3.client("cloudwatch").put_metric_data()`.

## Bedrock model ID
`anthropic.claude-opus-4-8-20260601-v1:0` — do not hardcode; read from `BEDROCK_MODEL_ID` env var.

## Naming conventions
- Lambda functions: `dark-web-fraud-<agent-name>` (e.g. `dark-web-fraud-content-analyst`)
- DynamoDB tables: `dark-web-fraud-<purpose>` (e.g. `dark-web-fraud-convergence`)
- SSM parameters: `/dark-web-fraud/<resource>/<attribute>` (e.g. `/dark-web-fraud/lambda/alert-generator-arn`)
