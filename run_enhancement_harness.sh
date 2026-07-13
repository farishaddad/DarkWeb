#!/bin/bash
# ============================================================================
# Dark Web Fraud Agent — Enhancement Harness
# Validates all four Kiro enhancement modules in one shot.
# Run from the project root: ./run_enhancement_harness.sh
# ============================================================================
set -e
cd "$(dirname "$0")"

echo ""
echo "============================================================"
echo "  Dark Web Fraud Agent — Enhancement Validation Harness"
echo "============================================================"
echo ""

# ─────────────────────────────────────────────────
# 0. Install dependencies
# ─────────────────────────────────────────────────
echo "[ 0/5 ] Installing in editable mode..."
pip install -e ".[dev]" -q
echo "        Done."
echo ""

# ─────────────────────────────────────────────────
# 1. Baseline — all pre-existing tests must pass
# ─────────────────────────────────────────────────
echo "[ 1/5 ] Baseline: running pre-existing unit tests..."
python -m pytest tests/unit/ -q --tb=short   --ignore=tests/unit/test_extended_fraud_categories.py   --ignore=tests/unit/test_coached_secrecy_override.py   --ignore=tests/unit/test_severity_boost.py   --ignore=tests/unit/test_entity_cooccurrence.py   --ignore=tests/unit/test_extended_tagging.py   2>&1 | tail -5
echo ""

# ─────────────────────────────────────────────────
# 2. Module 1 — Extended fraud taxonomy
# ─────────────────────────────────────────────────
echo "[ 2/5 ] Module 1: Extended fraud taxonomy..."
python -m pytest tests/unit/test_extended_fraud_categories.py -v --tb=short 2>&1 | tail -25
echo ""

# ─────────────────────────────────────────────────
# 3. Module 2 — Coached-secrecy + severity boost
# ─────────────────────────────────────────────────
echo "[ 3/5 ] Module 2: Coached-secrecy override + severity boost..."
python -m pytest   tests/unit/test_coached_secrecy_override.py   tests/unit/test_severity_boost.py   -v --tb=short 2>&1 | tail -35
echo ""

# ─────────────────────────────────────────────────
# 4. Module 3 — Entity co-occurrence
# ─────────────────────────────────────────────────
echo "[ 4/5 ] Module 3: Entity co-occurrence..."
python -m pytest tests/unit/test_entity_cooccurrence.py -v --tb=short 2>&1 | tail -25
echo ""

# ─────────────────────────────────────────────────
# 5. Full suite + extended tagging
# ─────────────────────────────────────────────────
echo "[ 5/5 ] Full suite (all tests including CDK and extended tagging)..."
python -m pytest tests/unit/ -q --tb=short 2>&1 | tail -10
echo ""

# ─────────────────────────────────────────────────
# 6. Quick import smoke test (all new symbols)
# ─────────────────────────────────────────────────
echo "[ 6/6 ] Smoke test: importing all new symbols..."
python -c "
# Module 1 — taxonomy
from dark_web_fraud_agent.models.content_analyst import EntityType, VALID_FRAUD_CATEGORIES
assert len(EntityType) == 13, f'Expected 13 EntityType members, got {len(EntityType)}'
assert len(VALID_FRAUD_CATEGORIES) == 10, f'Expected 10 categories, got {len(VALID_FRAUD_CATEGORIES)}'
print('  ✅ models/content_analyst.py — EntityType(13) + VALID_FRAUD_CATEGORIES(10)')

# Module 2 — coached-secrecy + severity boost
from dark_web_fraud_agent.agents.content_analyst import (
    ContentAnalyst, _COACHED_SECRECY_KEYWORDS, _MONERO_PATTERN, _MID_PATTERN
)
assert len(_COACHED_SECRECY_KEYWORDS) >= 8
assert _MONERO_PATTERN is not None and _MID_PATTERN is not None
print('  ✅ agents/content_analyst.py — keywords, regex patterns, severity boost')

# Module 3 — entity co-occurrence
from dark_web_fraud_agent.agents.alert_generator import AlertGenerator
gen = AlertGenerator()
assert hasattr(gen, 'check_entity_cooccurrence'), 'check_entity_cooccurrence missing'
assert hasattr(gen, 'get_health'), 'get_health missing'
import inspect
sig = inspect.signature(gen.track_item)
assert 'entity_values' in sig.parameters, 'track_item missing entity_values param'
print('  ✅ agents/alert_generator.py — check_entity_cooccurrence, track_item(entity_values=)')

# Module 1 tagging
from dark_web_fraud_agent.agents.tagging_engine import TaggingEngine
engine = TaggingEngine()
for cat, expected_tech in [
    ('investment_fraud', 'T1583'),
    ('social_engineering', 'T1598'),
    ('money_mule', 'T1531'),
    ('new_account_fraud', 'T1136'),
    ('recurring_billing_fraud', 'T1499'),
]:
    tags = [str(t) for t in engine.apply_attack_tags(cat)]
    assert any(expected_tech in t for t in tags), f'{cat} missing {expected_tech} in {tags}'
print('  ✅ agents/tagging_engine.py — all 5 new ATT&CK mappings present')

# Sigma maps
from dark_web_fraud_agent.agents.alert_generator import _SIGMA_LOGSOURCE_MAP, _SIGMA_TITLE_MAP
for tid in ('T1136', 'T1499', 'T1531', 'T1583', 'T1598'):
    assert tid in _SIGMA_LOGSOURCE_MAP, f'Missing Sigma logsource: {tid}'
    assert tid in _SIGMA_TITLE_MAP, f'Missing Sigma title: {tid}'
print('  ✅ agents/alert_generator.py — Sigma maps cover all 5 new techniques')

print('')
print('  ✅  All smoke tests passed.')
"

echo ""
echo "============================================================"
echo "  Harness complete."
echo "============================================================"
