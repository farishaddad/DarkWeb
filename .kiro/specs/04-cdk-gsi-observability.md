# Spec 04 — CDK Infrastructure: GSI + Observability

## Goal
Three CDK changes to support the entity co-occurrence feature and pipeline observability:

1. **`cdk_core_stack.py`** — add `entity-cooccurrence-index` GSI to `ConvergenceTable`
2. **`cdk_pipeline_stack.py`** — thread `entities` array through to `GenerateAlerts` Lambda payload; inject `ENTITY_INDEX_NAME` env var; add alert-type CloudWatch dashboard row
3. **`agents/alert_generator.py`** — use `ENTITY_INDEX_NAME` env var for GSI query (runtime wiring of infra name → code)

---

## Context
`check_entity_cooccurrence()` (Spec 03) needs to query DynamoDB by
`ENTITY#bank_name#<institution>` PK. Without a GSI, this requires a full table scan
(expensive, slow). The GSI enables a targeted `Query` call.

The Step Functions payload currently passes `tagging_output` to the Alert Generator
but not `entities`. Without it, `track_item(entity_values=entities_payload)` always
receives an empty list and co-occurrence never fires.

---

## Files to modify
| File | Change |
|------|--------|
| `src/dark_web_fraud_agent/infrastructure/cdk_core_stack.py` | Add GSI to `ConvergenceTable`; add `CfnOutput("EntityCooccurrenceIndexName")` |
| `src/dark_web_fraud_agent/infrastructure/cdk_pipeline_stack.py` | Add `entities` to alert state payload; add `ENTITY_INDEX_NAME` env var; add alert-type CloudWatch widgets |
| `src/dark_web_fraud_agent/agents/alert_generator.py` | Read `ENTITY_INDEX_NAME` from `os.environ` in `check_entity_cooccurrence()` |

---

## Acceptance criteria

### AC-01: GSI on ConvergenceTable (`cdk_core_stack.py`)
```python
self.convergence_table.add_global_secondary_index(
    index_name="entity-cooccurrence-index",
    partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
    sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
    projection_type=dynamodb.ProjectionType.ALL,
)
```
- [ ] Uses L2 `add_global_secondary_index()` — no `CfnTable` override
- [ ] `projection_type=dynamodb.ProjectionType.ALL` (stix_id + tier both needed)
- [ ] No `read_capacity` / `write_capacity` specified (inherits PAY_PER_REQUEST)
- [ ] `CfnOutput` named `"EntityCooccurrenceIndexName"` with value `"entity-cooccurrence-index"` and description

### AC-02: Alert state payload (`cdk_pipeline_stack.py`)
```python
"entities": sfn.JsonPath.object_at("$.analyst_result.analyst_output.entities"),
```
- [ ] `entities` key added to `GenerateAlerts` LambdaInvoke payload
- [ ] Path: `$.analyst_result.analyst_output.entities` (sourced from Content Analyst output)
- [ ] Does not change `tagging_output` or `execution_id` keys

### AC-03: Env var injection (`cdk_pipeline_stack.py`)
```python
alert_generator_fn.add_environment("ENTITY_INDEX_NAME", "entity-cooccurrence-index")
```
- [ ] Called immediately after `alert_generator_fn` is imported/resolved from SSM
- [ ] Value matches the index name in AC-01

### AC-04: CloudWatch dashboard (`cdk_pipeline_stack.py`)
A new `cloudwatch.Row` added to the existing dashboard with one `GraphWidget`:
- Title: `"Alert Generator — Alert Types (15-min windows)"`
- Left metrics:
  - `cloudwatch.Metric(namespace="dark-web-fraud", metric_name="EntityCooccurrenceAlerts", period=Duration.minutes(15), statistic="Sum", dimensions_map={"AlertType": "composite"})`
  - `cloudwatch.Metric(namespace="dark-web-fraud", metric_name="TTPConvergenceAlerts", period=Duration.minutes(15), statistic="Sum")`
  - `cloudwatch.Metric(namespace="dark-web-fraud", metric_name="ImmediateSeverityAlerts", period=Duration.minutes(15), statistic="Sum")`
- `width=24, height=6`
- [ ] Widget added **after** the existing pipeline executions + queue depth row

### AC-05: Runtime GSI name wiring (`alert_generator.py`)
```python
index_name = os.environ.get("ENTITY_INDEX_NAME", "entity-cooccurrence-index")
resp = table.query(IndexName=index_name, KeyConditionExpression=...)
```
- [ ] `os.environ.get()` with fallback (never fails if env var absent)
- [ ] `IndexName=index_name` added to the `table.query()` call in `check_entity_cooccurrence()`

### AC-06: CDK snapshot tests
Run `python -m pytest tests/unit/test_cdk_core_stack.py tests/unit/test_cdk_pipeline_stack.py -q`
- [ ] Existing CDK snapshot tests pass (update snapshots if needed with `--snapshot-update`)
- [ ] No new CDK snapshot failures introduced

### AC-07: AlertConfig extension (`config/settings.py`)
Add `entity_index_name` field to `AlertConfig`:
```python
entity_index_name: str = Field(
    default="entity-cooccurrence-index",
    min_length=1,
    description="DynamoDB GSI name for entity co-occurrence queries",
)
```
- [ ] Has a sensible default matching the CDK-provisioned index name
- [ ] Validated: non-empty string

---

## Deployment note
```bash
# GSI adds without downtime — DynamoDB backfills in the background
cdk deploy DarkWebFraudCoreStack

# Then pipeline stack for env var + dashboard
cdk deploy DarkWebFraudPipelineStack
```
New Lambda deployments pick up `ENTITY_INDEX_NAME` from the env var injection.

---

## Do NOT
- Use `CfnTable` or any `CfnResource` to add the GSI
- Set `read_capacity` or `write_capacity` on the GSI (incompatible with PAY_PER_REQUEST)
- Change existing CloudWatch widget sizes or metric periods
- Modify the `CrawlSources` ECS state in the Step Functions machine
