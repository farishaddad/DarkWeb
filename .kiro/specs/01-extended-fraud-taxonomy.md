# Spec 01 — Extended Fraud Taxonomy

## Goal
Extend the content classification pipeline to cover five new fraud categories
and six new entity types identified from the annotated fraud pattern set
(DC-007, DC-008, CHAPS-026, PS-001, XC-007). All changes must be backward
compatible: no existing test may fail.

---

## Context
The current pipeline covers five fraud categories (`mfa_bypass`, `synthetic_identity`,
`phishing_kit`, `cnp_fraud`, `account_takeover`) and seven entity types
(`bank_name`, `bin_range`, `swift_code`, `btc_wallet`, `email`, `url`, `ip_address`).

Pattern analysis revealed that:
- **DC-007** (Fullz identity fraud) needs `new_account_fraud` + `national_id`, `sort_code`
- **DC-008** (card aggregation) needs `recurring_billing_fraud` + `acquiring_bin`, `merchant_id`
- **CHAPS-026** (reverse mule) needs `money_mule` + `iban`
- **XC-007** (pig butchering) needs `investment_fraud`, `social_engineering` + `monero_wallet`
- **PS-001** (purchase scam) needs `merchant_id`, `acquiring_bin`

---

## Files to modify
| File | Change |
|------|--------|
| `src/dark_web_fraud_agent/models/content_analyst.py` | Add 6 new `EntityType` members; add 5 new `VALID_FRAUD_CATEGORIES` entries |
| `src/dark_web_fraud_agent/agents/content_analyst.py` | Update all three prompts + `COMBINED_ANALYSIS_PROMPT`; add new regex patterns; extend `_extract_entities_via_regex()` |
| `src/dark_web_fraud_agent/agents/tagging_engine.py` | Extend `attack_map`, `sub_technique_map`, `galaxy_map`; extend `apply_fraud_tags()` |
| `src/dark_web_fraud_agent/agents/alert_generator.py` | Extend `_SIGMA_LOGSOURCE_MAP` and `_SIGMA_TITLE_MAP` |

## Files to create
| File | Purpose |
|------|---------|
| `tests/unit/test_extended_fraud_categories.py` | EntityType (13 members), VALID_FRAUD_CATEGORIES (10 entries), pattern-grounded entity creation |

---

## Acceptance criteria

### AC-01: EntityType enum
- [ ] `EntityType` has exactly **13 members** (7 original + 6 new)
- [ ] New members: `MERCHANT_ID`, `ACQUIRING_BIN`, `NATIONAL_ID`, `SORT_CODE`, `IBAN`, `MONERO_WALLET`
- [ ] Each new type is accepted by `ExtractedEntity.__post_init__` without raising
- [ ] `EntityType(value)` round-trip works for all 13 values

### AC-02: VALID_FRAUD_CATEGORIES
- [ ] Tuple has exactly **10 entries** (5 original + 5 new)
- [ ] New entries: `new_account_fraud`, `recurring_billing_fraud`, `money_mule`, `investment_fraud`, `social_engineering`
- [ ] `ClassifiedContent.__post_init__` accepts all 10 without raising
- [ ] Invalid category still raises `ValueError`

### AC-03: Prompts updated
- [ ] `ENTITY_EXTRACTION_PROMPT` lists all 13 entity types with descriptions
- [ ] `CATEGORIZATION_PROMPT` lists all 10 categories with descriptions
- [ ] `COMBINED_ANALYSIS_PROMPT` `fraud_category` pipe-list includes all 10

### AC-04: ATT&CK mappings
| Category | Primary technique | Sub-technique |
|----------|------------------|---------------|
| `new_account_fraud` | T1136 | — |
| `recurring_billing_fraud` | T1499 | — |
| `money_mule` | T1531 | — |
| `investment_fraud` | T1583 | T1583.006 |
| `social_engineering` | T1598 | T1598.003 |

- [ ] `apply_attack_tags("investment_fraud")` returns tags containing both `T1583` and `T1583.006`
- [ ] `apply_attack_tags("social_engineering")` returns tags containing both `T1598` and `T1598.003`

### AC-05: Galaxy clusters
- [ ] `match_galaxy_cluster("investment_fraud")` returns `{"galaxy": "financial-fraud", "cluster_value": "Investment Fraud / Pig Butchering", ...}`
- [ ] `match_galaxy_cluster("social_engineering")` returns `{"galaxy": "social-engineering", ...}`
- [ ] All 5 new categories have galaxy entries

### AC-06: Entity fraud tags
| Entity type | Expected `fraud:type` tag value |
|-------------|--------------------------------|
| `monero_wallet` | `crypto-laundering` |
| `merchant_id` | `merchant-account-fraud` |
| `acquiring_bin` | `acquiring-bin-abuse` |
| `iban` | `cross-border-transfer` |
| `national_id` | `identity-document-fraud` |

### AC-07: Regex patterns
- [ ] `_MONERO_PATTERN` matches a valid 95-char Monero address starting with `4`
- [ ] `_IBAN_PATTERN` matches `GB29NWBK60161331926819`
- [ ] `_SORT_CODE_PATTERN` matches `20-00-00`
- [ ] `_MID_PATTERN` matches `529910000000001` when adjacent to keyword `MID:`

### AC-08: Sigma maps
- [ ] `_SIGMA_LOGSOURCE_MAP` has entries for T1136, T1499, T1531, T1583, T1598
- [ ] `_SIGMA_TITLE_MAP` titles contain "New Account", "Recurring Billing", "Money Mule", "Investment Fraud", "Social Engineering" respectively

### AC-09: Tests
- [ ] `tests/unit/test_extended_fraud_categories.py` passes with zero failures
- [ ] All pre-existing unit tests remain green

---

## Do NOT
- Modify `tests/unit/test_content_analyst_models.py` (it pins the original 7 entity types)
- Change `VALID_FRAUD_CATEGORIES` from a tuple to a list
- Add boto3 imports to `models/content_analyst.py`
- Remove or rename any existing `EntityType` member
