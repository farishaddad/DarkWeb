# Code Style — Dark Web Fraud Agent

## Python version
3.11+ — use `str | None` union syntax, `match` statements where natural,
`list[str]` lowercase generics (not `List[str]`).

## Imports
Standard library → third-party → internal. Alphabetical within each group.
No wildcard imports. `from __future__ import annotations` only if needed.

## Dataclasses vs Pydantic
- `models/` — Python `@dataclass` with `__post_init__` validation. No Pydantic.
- `config/` — Pydantic `BaseModel` with `field_validator` and `model_validator`.
- Agents — plain classes inheriting `AgentBase`. No dataclass decorator.

## Type annotations
All public methods and functions must be fully annotated.
Use `Optional[X]` only in `models/` for backward compat; prefer `X | None` elsewhere.

## Logging
```python
import logging
logger = logging.getLogger(__name__)
logger.info("AgentName: %s processed for category=%s", count, category)
```
Never `print()` in production code paths.

## Error handling
- Raise `ValueError` for invalid input (caught by callers and logged).
- Raise `RuntimeError` for infrastructure failures (Bedrock, DynamoDB, S3).
- Never swallow exceptions silently — always log then re-raise or return sentinel.

## Constants
UPPER_SNAKE_CASE at module level. Prefixed with `_` if module-private.
Tuples for immutable collections (`VALID_FRAUD_CATEGORIES`), sets for lookup.

## Test naming
```
tests/unit/test_<subject>_<feature>.py
class Test<Feature>:
    def test_<scenario>_<expected_outcome>(self):
```
One assert per test preferred; parametrize for exhaustive value coverage.
Use `setup_method` not fixtures for simple per-test state; use fixtures for
shared heavy objects (moto mocks, Pydantic configs).

## Regex patterns
Module-level, prefixed `_`, compiled at import time.
Name: `_<ENTITY_TYPE>_PATTERN` (for extraction patterns).

## CDK
- L2 constructs only — no `CfnResource`, `CfnTable`, `Cfn*`.
- All resources tagged with `{"Project": "dark-web-fraud", "Env": "prod"}`.
- `removal_policy=RemovalPolicy.RETAIN` on all stateful resources.
- `billing_mode=BillingMode.PAY_PER_REQUEST` on all DynamoDB tables.
