# Spec 03 — Entity Co-occurrence Composite Alerting

## Goal
Implement cross-signal composite alerting for pattern CHAPS-026 (reverse money mule).

When the same institution name appears in signals from **two or more distinct intelligence
tiers** (e.g. a Source 1 credential listing at `tier=observable` AND a Source 2
mule-recruitment post at `tier=ttp`) within the convergence window, fire a composite
alert labelled `+cross_signal_cooccurrence`.

---

## Context
The existing campaign convergence logic keys on `ttp_reference` only. CHAPS-026 involves
two signals that share an institution name but differ in fraud category:
- Credential listing → `fraud:account_takeover` (observable)
- Mule script → `fraud:money_mule` (ttp)

Neither crosses the 3× TTP threshold alone. Without co-occurrence, both go to
`requires-review`. The GSI `entity-cooccurrence-index` (provisioned in Spec 04/CDK)
enables a targeted Query rather than a table scan.

---

## Files to modify
| File | Change |
|------|--------|
| `src/dark_web_fraud_agent/agents/alert_generator.py` | Add `entity_values` param to `track_item()`; add `check_entity_cooccurrence()` method; update Step Functions handler path to call co-occurrence check; use `ENTITY_INDEX_NAME` env var in GSI query |

## Files to create
| File | Purpose |
|------|---------|
| `tests/unit/test_entity_cooccurrence.py` | track_item entity routing, check_entity_cooccurrence tier-diversity logic, Sigma map coverage |

---

## Acceptance criteria

### AC-01: `track_item()` signature extension
```python
def track_item(
    self,
    stix_id: str,
    ttp_reference: str,
    tier: str,
    entity_values: list[dict] | None = None,
) -> None:
```
- [ ] `entity_values=None` is backward compatible — existing callers without the param work unchanged
- [ ] When `entity_values` contains `{"entity_type": "bank_name", "value": "<name>"}` items:
  - For each, writes a DynamoDB item with `PK = f"ENTITY#bank_name#{name.lower()}"`, `SK = f"ITEM#{stix_id}"`
  - Item carries: `stix_id`, `ttp_reference`, `tier`, `entity_type`, `entity_value`, `timestamp`, `TTL`
- [ ] Only `entity_type == "bank_name"` items are indexed (all other types skipped silently)
- [ ] Multiple bank names in one signal produce separate DynamoDB items (one per name)
- [ ] Bank name is lowercased in the PK

### AC-02: `check_entity_cooccurrence()` method
```python
def check_entity_cooccurrence(
    self, entity_type: str, entity_value: str
) -> Optional[list[str]]:
```
- [ ] Queries DynamoDB using `IndexName = os.environ.get("ENTITY_INDEX_NAME", "entity-cooccurrence-index")`
- [ ] PK query key: `f"ENTITY#{entity_type}#{entity_value.lower()}"`
- [ ] Returns `None` if fewer than 2 items
- [ ] Returns `None` if all items have the same `tier`
- [ ] Returns list of `stix_id` strings when ≥2 items from ≥2 distinct tiers
- [ ] `entity_value` is lowercased before query (case-insensitive lookup)

### AC-03: Step Functions handler integration
In the `handler()` Step Functions path, after `check_campaign_convergence()`:
```python
# Pseudo-code — implement in agent
if not convergence_ids:
    for entity in entities_payload:
        if entity.get("entity_type") == "bank_name":
            convergence_ids = generator.check_entity_cooccurrence(
                entity_type="bank_name",
                entity_value=entity["value"],
            )
            if convergence_ids:
                fraud_category = f"{fraud_category}+cross_signal_cooccurrence"
                break
```
- [ ] `entities_payload = event.get("entities", [])` (defaults to empty list if key absent)
- [ ] `entity_values=entities_payload` is passed to `track_item()`
- [ ] `+cross_signal_cooccurrence` suffix appended to `fraud_category` in alert description when triggered

### AC-04: Tests
- [ ] `tests/unit/test_entity_cooccurrence.py` covers:
  - `track_item` writes exactly N+1 DynamoDB puts (1 TTP + N entity items)
  - Non-bank entities produce no extra puts
  - `check_entity_cooccurrence` returns `None` for <2 items
  - `check_entity_cooccurrence` returns `None` for 2 items same tier
  - `check_entity_cooccurrence` fires for 2 items from different tiers (CHAPS-026 scenario)
  - Query uses correct `ENTITY#bank_name#<lower>` PK
- [ ] All pre-existing tests remain green

---

## Do NOT
- Change the `PK/SK` schema of existing `CONV#` items
- Add a boto3 import to `models/` 
- Hardcode `"entity-cooccurrence-index"` in the Lambda body (use env var)
- Index entity types other than `bank_name` in this spec (future work)
