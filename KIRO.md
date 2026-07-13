# Dark Web Fraud Intelligence Agent — Kiro Project Context

## What this project is
An AWS-native autonomous multi-agent pipeline that crawls dark web sources,
classifies fraud-relevant content via Claude Opus through Amazon Bedrock,
structures findings as STIX 2.1 bundles, tags with MITRE ATT&CK and custom
banking-fraud taxonomies, and publishes campaign alerts via SNS — running on
a five-minute EventBridge schedule.

## Stack snapshot
| Layer | Technology |
|-------|-----------|
| Language | Python 3.11 |
| LLM | Claude Opus via Amazon Bedrock |
| Orchestration | AWS Step Functions Express Workflow |
| Agent runtime | Amazon Bedrock AgentCore |
| Storage | Amazon S3 (raw artifacts), DynamoDB (state + convergence), OpenSearch Serverless (vectors) |
| Infra-as-code | AWS CDK v2 (Python) |
| Test framework | pytest + moto + hypothesis |
| Linter/formatter | ruff (line-length 120) |
| Type checker | mypy strict |

## Repository layout
```
src/dark_web_fraud_agent/
  agents/            ← Lambda handlers (one file per agent)
    content_analyst.py
    tagging_engine.py
    alert_generator.py
    data_structurer.py
    crawling_engine.py
    misp_integration.py
  models/            ← Pure dataclasses/enums, no AWS dependencies
    content_analyst.py   ← EntityType, VALID_FRAUD_CATEGORIES, ClassifiedContent
    alerts.py            ← FraudAlert, AlertProvenance, DetectionRule
    shared.py            ← AgentBase, AgentConfig, AgentHealth
    crawl_result.py
  config/
    settings.py      ← Pydantic v2 configs per agent
  infrastructure/    ← CDK stacks
    cdk_core_stack.py        ← VPC, KMS, S3, DynamoDB (ConvergenceTable + GSI)
    cdk_compute_stack.py
    cdk_pipeline_stack.py    ← Step Functions, EventBridge, SNS, CloudWatch
    cdk_intelligence_stack.py
tests/
  unit/              ← 33 test files, ~300+ test functions
  integration/
  property/
```

## Current enhancement backlog (4 modules — see .kiro/specs/)
| Module | Spec file | Status |
|--------|-----------|--------|
| 1 | `specs/01-extended-fraud-taxonomy.md` | Ready to build |
| 2 | `specs/02-coached-secrecy-severity-boost.md` | Ready to build |
| 3 | `specs/03-entity-cooccurrence.md` | Ready to build |
| 4 | `specs/04-cdk-gsi-observability.md` | Ready to build |

## Hard rules — DO NOT violate
- **No AWS calls in `models/`** — models are pure Python dataclasses/enums, zero boto3.
- **No `Cfn*` L1 constructs in CDK stacks** — use L2 constructs only.
- **All new DynamoDB attributes use `AttributeType.STRING`** — no N or B types.
- **All test files live under `tests/unit/`** unless explicitly integration tests.
- **Test file naming**: `test_<module>_<feature>.py` — match existing convention.
- **`VALID_FRAUD_CATEGORIES` is a tuple, not a list** — preserve immutability.
- **`EntityType` is a `str, Enum`** — values must be valid Python identifiers when lowercased.
- **Ruff line-length 120** — never exceed.
- **mypy strict** — all new functions need full type annotations.
- **Never modify `tests/unit/test_content_analyst_models.py`** — it pins the original 7 entity types; the new test file handles the extended set.

## Key technical gotchas
- The Lambda entry point (`handler`) is appended **after** the class definition in each agent file (file structure is inverted — handler at top in truncated reads, class below). Do not rearrange.
- `classify_and_extract_combined()` makes a **single** Bedrock call (not 3×) — the `COMBINED_ANALYSIS_PROMPT` replaces the three individual prompts. Individual prompts are kept for unit tests only.
- `_convergence_tracker` (in-memory dict) is used by unit tests; production uses DynamoDB. Both paths must stay functional.
- The `entity_values` parameter in `track_item()` is optional and defaults to `None` for backward compatibility.
- `AlertConfig` in `config/settings.py` needs `entity_index_name` field to match the new `ENTITY_INDEX_NAME` env var.

## Opening message for each session
Read `KIRO.md` first, then `.kiro/specs/<module>.md` for the module you are assigned.
Run `pip install -e ".[dev]" -q` before starting. Run `python -m pytest tests/unit/ -q` to
establish a baseline — all existing tests must remain green after your changes.
