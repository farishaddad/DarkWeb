# Changelog

## [0.2.0] — 2026-07-14

### Added

#### Extended Fraud Taxonomy (Spec 01)
- 6 new `EntityType` enum members: `MERCHANT_ID`, `ACQUIRING_BIN`, `NATIONAL_ID`, `SORT_CODE`, `IBAN`, `MONERO_WALLET`
- 5 new `VALID_FRAUD_CATEGORIES` entries: `new_account_fraud`, `recurring_billing_fraud`, `money_mule`, `investment_fraud`, `social_engineering`
- ATT&CK mappings: T1136, T1565, T1537, T1583 (+ T1583.006), T1598 (+ T1598.003)
- MISP Galaxy clusters: `financial-fraud` and `social-engineering` galaxies with 5 new cluster entries
- Entity fraud tags: `crypto-laundering`, `merchant-account-fraud`, `acquiring-bin-abuse`, `cross-border-transfer`, `identity-document-fraud`
- Regex patterns: `_MONERO_PATTERN`, `_IBAN_PATTERN`, `_SORT_CODE_PATTERN`, `_MID_PATTERN`
- Updated BIN regex to support 8-digit IINs (ISO 7812:2022)
- Added `_BTC_BECH32_PATTERN` for bech32/taproot Bitcoin addresses

#### Coached-Secrecy Override and Severity Boost (Spec 02)
- `_COACHED_SECRECY_KEYWORDS` — 12 pig-butchering marker phrases
- Keyword override in `classify_and_extract_combined()` forces `social_engineering` when markers detected
- `adjust_severity_for_record_count()` method: +1 at 1k–4,999 records, +2 at ≥5,000
- Post-processing call in Lambda handler after `assign_severity()`

#### Entity Co-occurrence Composite Alerting (Spec 03)
- `track_item(entity_values=...)` parameter for DynamoDB entity routing
- `check_entity_cooccurrence()` method with cross-tier diversity check
- ENTITY# PK namespace in ConvergenceTable for bank_name indexing
- Composite alert labelling with `+cross_signal_cooccurrence` suffix
- Handler integration: entities threaded from Content Analyst through Step Functions payload

#### Infrastructure (Spec 04)
- Single-table DynamoDB design with CONV# and ENTITY# PK namespaces (no GSI needed)
- Standard Step Functions Workflow (replaced Express — correct cost at 288 executions/day)
- `ENTITY_INDEX_NAME` env var wiring (for future GSI migration if needed)
- CloudWatch custom metrics: `EntityCooccurrenceAlerts`, `TTPConvergenceAlerts`, `ImmediateSeverityAlerts`
- Dashboard row for alert-type breakdown

#### Sigma Rule Generation
- Technique-specific `detection_map` with per-logsource detection blocks
- 5 technique-aware detection patterns (T1111, T1078, T1566, T1136, T1537)
- `_SIGMA_LOGSOURCE_MAP` and `_SIGMA_TITLE_MAP` extended to 10 entries

#### Tests
- `tests/unit/test_extended_fraud_categories.py` — 18 test functions
- `tests/unit/test_coached_secrecy_override.py` — 12 test functions
- `tests/unit/test_severity_boost.py` — 17 test functions
- `tests/unit/test_entity_cooccurrence.py` — 17 test functions
- `tests/unit/test_extended_tagging.py` — 23 test functions
- Total: 87 new test functions

#### Kiro Project Artefacts
- `KIRO.md` — root context file
- `.kiro/steering/` — 3 steering files (project, code-style, aws-conventions)
- `.kiro/specs/` — 4 spec files with 76 acceptance criteria
- `.kiro/hooks/` — 3 on-save validation hooks
- `run_enhancement_harness.sh` — single-command validation script

#### Documentation
- 3-part AWS Builder Center article series (Part 1–3) in workspace artifacts
- `dark_web_patterns_analysis.md` — pattern-by-pattern pipeline review
- Updated `STIX_MISP_Explainer.md` coverage in article series

### Changed
- `agents/alert_generator.py` — `get_health()` stub fixed (was empty body)
- `agents/tagging_engine.py` — `apply_fraud_tags()` extended for new entity types
- `infrastructure/cdk_core_stack.py` — VPC endpoint documentation, single-table design
- `infrastructure/cdk_pipeline_stack.py` — entities in alert state payload, dashboard widgets
- Claude model references updated to Sonnet 4 / Opus 4

### Fixed
- Monero regex: `[0-9AB]` → full Base58 alphabet for 2nd character
- Sort code regex: removed `\d{6}` alternative (overlapped with BIN pattern)
- ATT&CK mapping: T1499 (DoS) → T1565 (Data Manipulation) for billing fraud
- ATT&CK mapping: T1531 (Access Removal) → T1537 (Transfer Data) for money mules
- Step Functions: Express → Standard Workflow (cost claim was factually incorrect)

## [0.1.0] — 2026-06-15

### Added
- Initial multi-agent pipeline implementation
- 5 agents: CrawlingEngine, ContentAnalyst, DataStructurer, TaggingEngine, AlertGenerator
- AWS CDK infrastructure (CoreStack, ComputeStack, IntelligenceStack, PipelineStack)
- STIX 2.1 + MISP integration
- Campaign convergence logic
- 28 unit test files
