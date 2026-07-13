"""Verify tagging engine methods work correctly."""
import sys

def log(msg):
    sys.stderr.write(msg + "\n")

from dark_web_fraud_agent.agents.tagging_engine import TaggingEngine, MachineTag
from dark_web_fraud_agent.models.content_analyst import ExtractedEntity

engine = TaggingEngine()

# Test severity mapping
assert engine.map_severity_to_threat_level(1) == "low"
assert engine.map_severity_to_threat_level(3) == "low"
assert engine.map_severity_to_threat_level(4) == "medium"
assert engine.map_severity_to_threat_level(6) == "medium"
assert engine.map_severity_to_threat_level(7) == "high"
assert engine.map_severity_to_threat_level(9) == "high"
assert engine.map_severity_to_threat_level(10) == "critical"
log("severity mapping: OK")

# Test attack tags
tags = engine.apply_attack_tags("mfa_bypass")
assert MachineTag("mitre-attack", "technique", "T1111") in tags
tags = engine.apply_attack_tags("phishing_kit")
assert MachineTag("mitre-attack", "technique", "T1566") in tags
tags = engine.apply_attack_tags("account_takeover")
assert MachineTag("mitre-attack", "technique", "T1078") in tags
tags = engine.apply_attack_tags(None)
assert tags == []
tags = engine.apply_attack_tags("unknown")
assert tags == []
log("attack tags: OK")

# Test fraud tags
entities = [
    ExtractedEntity(entity_type="swift_code", value="SWIFT DEUTDEFF", context="", confidence=0.9),
    ExtractedEntity(entity_type="bin_range", value="411111", context="", confidence=0.9),
    ExtractedEntity(entity_type="btc_wallet", value="1A1zP1...", context="", confidence=0.9),
    ExtractedEntity(entity_type="bank_name", value="HSBC", context="", confidence=0.9),
]
tags = engine.apply_fraud_tags(entities)
assert MachineTag("fraud", "type", "swift-transfer") in tags
assert MachineTag("fraud", "type", "bin-attack") in tags
assert MachineTag("fraud", "type", "crypto-fraud") in tags
assert MachineTag("fraud", "target", "hsbc") in tags
log("fraud tags: OK")

# Test empty entities
tags = engine.apply_fraud_tags([])
assert tags == []
log("fraud tags empty: OK")

log("\nAll verifications passed!")
