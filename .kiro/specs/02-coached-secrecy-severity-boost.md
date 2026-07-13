# Spec 02 — Coached-Secrecy Override and Record-Count Severity Boost

## Goal
Add two post-processing rules to `ContentAnalyst.classify_and_extract_combined()`:

1. **Coached-secrecy keyword override** — forces `fraud_category = "social_engineering"`
   when pig-butchering marker phrases appear in the content, regardless of LLM output.
   Targets pattern XC-007 (romance/pig-butchering scripts).

2. **Record-count severity boost** — raises `severity_score` when a listing specifies
   a large-scale dump. Ensures DC-008 (10k card dump) reaches the immediate-alert
   threshold without waiting for campaign convergence.

---

## Context
Without these rules:
- A romance script containing "don't tell your bank" would be classified as `null`
  category (none of the five original categories match) and tagged `requires-review`.
  It would never auto-trigger a detection rule.
- A 10,000-card dump listing scores severity 6 (medium), missing the ≥7 threshold
  for immediate alerting. It waits 24 hours for three independent posts to converge.

---

## Files to modify
| File | Change |
|------|--------|
| `src/dark_web_fraud_agent/agents/content_analyst.py` | Add `_COACHED_SECRECY_KEYWORDS` constant; apply override at end of `classify_and_extract_combined()`; add `adjust_severity_for_record_count()` method; call it in handler |

## Files to create
| File | Purpose |
|------|---------|
| `tests/unit/test_coached_secrecy_override.py` | Keyword presence, case-insensitive match, override logic, confidence boost, non-matching content unchanged |
| `tests/unit/test_severity_boost.py` | No-op below 1k, +1 at 1k–4,999, +2 at ≥5k, clamping, threshold constants |

---

## Acceptance criteria

### AC-01: `_COACHED_SECRECY_KEYWORDS` constant
- [ ] Module-level tuple, named `_COACHED_SECRECY_KEYWORDS` (private)
- [ ] All entries are lowercase strings
- [ ] Contains at minimum: `"don't tell your bank"`, `"pig butcher"`, `"sha zhu pan"`, `"romance script"`, `"wrong number text"`, `"investment protection scheme"`
- [ ] At least 8 entries total

### AC-02: Coached-secrecy override in `classify_and_extract_combined()`
- [ ] Override runs **after** LLM response hydration, before return
- [ ] Text is lowercased before keyword check (`raw_snippet = text.lower()`)
- [ ] When any keyword matches: `result["fraud_category"] = "social_engineering"`
- [ ] When any keyword matches: `result["is_fraud_relevant"] = True`
- [ ] When any keyword matches and `confidence < 0.85`: set `confidence = 0.85`
- [ ] When `confidence >= 0.85`: leave confidence unchanged (no reduction)
- [ ] When no keyword matches: category and confidence unchanged

### AC-03: `adjust_severity_for_record_count()` method
Signature: `def adjust_severity_for_record_count(self, severity: int, estimated_record_count: int | None) -> int`

| Input `estimated_record_count` | Expected delta |
|-------------------------------|----------------|
| `None` | 0 (return severity unchanged) |
| `0–999` | 0 |
| `1,000–4,999` | +1 |
| `≥5,000` | +2 |
| Any value when result would exceed 10 | clamp to 10 |

- [ ] Class constants `_RECORD_COUNT_HIGH_THRESHOLD = 5_000` and `_RECORD_COUNT_MED_THRESHOLD = 1_000`
- [ ] Method is called in the Lambda `handler()` after `assign_severity()`:
  ```python
  classification.severity_score = analyst.adjust_severity_for_record_count(
      classification.severity_score,
      result.get("estimated_record_count"),
  )
  ```

### AC-04: Pattern verification
- [ ] DC-008 scenario: base severity 6 + record_count 10,000 → severity 8 ✓
- [ ] DC-007 scenario: base severity 7 + record_count 500 → severity 7 ✓ (no boost)
- [ ] XC-007 scenario: text containing "sha zhu pan" → `fraud_category = "social_engineering"` ✓

### AC-05: Tests
- [ ] `tests/unit/test_coached_secrecy_override.py` — 12+ test functions, all pass
- [ ] `tests/unit/test_severity_boost.py` — 17+ test functions, all pass
- [ ] `TestThresholdConstants` class verifies constant values are accessible
- [ ] All pre-existing tests remain green

---

## Do NOT
- Apply the keyword check before the Bedrock guardrail check (guardrail must run first)
- Modify the `assign_severity()` method itself — only add `adjust_severity_for_record_count()`
- Import `_COACHED_SECRECY_KEYWORDS` from outside the agents module
- Change the `confidence_threshold` field in `AnalystConfig`
