#!/bin/bash
# ============================================================================
# Git commit script for v0.2.0 enhancement release
# Run from project root: ./commit_v0.2.0.sh
# ============================================================================
set -e
cd "$(dirname "$0")"

echo "=== Dark Web Fraud Intelligence Agent — v0.2.0 Commit ==="
echo ""

# Stage all changes
git add -A

# Show what's being committed
echo "Files staged:"
git status --short
echo ""

# Commit with structured message
git commit -m "feat: Extended fraud taxonomy, co-occurrence alerting, and Sigma rule improvements (v0.2.0)

## Summary
- 5 new fraud categories + 6 new entity types (DC-007, DC-008, CHAPS-026, PS-001, XC-007)
- Coached-secrecy keyword override for pig-butchering detection (XC-007)
- Record-count severity boost for large-scale dumps (DC-008)
- Entity co-occurrence composite alerting (CHAPS-026 cross-signal pattern)
- Technique-specific Sigma rule generation
- Standard Step Functions Workflow (corrected from Express)
- Single-table DynamoDB design (no GSI needed)
- 87 new unit tests across 5 test files
- 3-part AWS Builder Center article series
- Kiro specs + steering for continued development

## Files changed
- src/dark_web_fraud_agent/models/content_analyst.py
- src/dark_web_fraud_agent/agents/content_analyst.py
- src/dark_web_fraud_agent/agents/tagging_engine.py
- src/dark_web_fraud_agent/agents/alert_generator.py
- src/dark_web_fraud_agent/infrastructure/cdk_core_stack.py
- src/dark_web_fraud_agent/infrastructure/cdk_pipeline_stack.py
- tests/unit/test_extended_fraud_categories.py (new)
- tests/unit/test_coached_secrecy_override.py (new)
- tests/unit/test_severity_boost.py (new)
- tests/unit/test_entity_cooccurrence.py (new)
- tests/unit/test_extended_tagging.py (new)
- KIRO.md, .kiro/specs/*, .kiro/steering/*, .kiro/hooks/* (new)
- docs/articles/* (new)
- CHANGELOG.md (new)
- pyproject.toml (version bump)
- README.md (updated)
- STIX_MISP_Explainer.md (extended)
"

echo ""
echo "✅ Committed. To push:"
echo "   git push origin main"
echo ""
