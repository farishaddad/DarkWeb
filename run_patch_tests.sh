#!/bin/bash
# Run from the DarkWeb project root
set -e
cd "$(dirname "$0")"

echo "=== Installing in editable mode ==="
pip install -e ".[dev]" -q

echo ""
echo "=== Running full test suite ==="
python -m pytest tests/ -v --tb=short 2>&1 | tee test_output_after_patches.log

echo ""
echo "=== Quick smoke-test: import all patched modules ==="
python -c "
from dark_web_fraud_agent.models.content_analyst import EntityType, VALID_FRAUD_CATEGORIES
assert 'MERCHANT_ID' in [e.name for e in EntityType]
assert 'MONERO_WALLET' in [e.name for e in EntityType]
assert 'investment_fraud' in VALID_FRAUD_CATEGORIES
assert 'social_engineering' in VALID_FRAUD_CATEGORIES
print('  ✅ models/content_analyst.py — enums OK')

from dark_web_fraud_agent.agents.content_analyst import (
    ContentAnalyst, _COACHED_SECRECY_KEYWORDS, _MONERO_PATTERN, _MID_PATTERN
)
assert len(_COACHED_SECRECY_KEYWORDS) > 0
assert _MONERO_PATTERN is not None
print('  ✅ agents/content_analyst.py — symbols OK')

from dark_web_fraud_agent.agents.tagging_engine import TaggingEngine
engine = TaggingEngine()
# Verify new categories resolve to ATT&CK tags
for cat in ['investment_fraud', 'social_engineering', 'money_mule', 'new_account_fraud']:
    tags = engine.apply_attack_tags(cat)
    assert tags, f'No tags for {cat}'
    print(f'  ✅ tagging_engine — {cat} → {tags[0]}')

from dark_web_fraud_agent.agents.alert_generator import AlertGenerator
gen = AlertGenerator()
assert hasattr(gen, 'check_entity_cooccurrence')
assert hasattr(gen, 'get_health')
print('  ✅ agents/alert_generator.py — new methods present')

print('')
print('All smoke tests passed.')
"
