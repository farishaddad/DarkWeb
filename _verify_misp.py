"""Direct verification of MISP integration without pytest."""
import sys
sys.path.insert(0, "src")

from dark_web_fraud_agent.agents.misp_integration import (
    MISPIntegration,
    STIX_TO_MISP_TYPE_MAP,
    STIX_TO_MISP_CATEGORY_MAP,
    MISP_TO_STIX_TYPE_MAP,
)
import stix2
from pymisp import MISPEvent

results = []

def check(name, condition):
    if condition:
        results.append(f"  PASS: {name}")
    else:
        results.append(f"  FAIL: {name}")

# 1. Type mapping
integration = MISPIntegration()
check("ipv4-addr -> ip-src", integration.map_sco_to_misp_type("ipv4-addr") == "ip-src")
check("ipv6-addr -> ip-src", integration.map_sco_to_misp_type("ipv6-addr") == "ip-src")
check("url -> url", integration.map_sco_to_misp_type("url") == "url")
check("email-addr -> email-src", integration.map_sco_to_misp_type("email-addr") == "email-src")
check("domain-name -> domain", integration.map_sco_to_misp_type("domain-name") == "domain")
check("artifact -> btc", integration.map_sco_to_misp_type("artifact") == "btc")
check("unknown -> text", integration.map_sco_to_misp_type("unknown") == "text")

# 2. stix_to_misp basic conversion
ipv4 = stix2.IPv4Address(value="192.168.1.1")
bundle = stix2.Bundle(objects=[ipv4])
event = integration.stix_to_misp(bundle)
check("returns MISPEvent", isinstance(event, MISPEvent))
check("has 1 attribute", len(event.attributes) == 1)
check("attr type is ip-src", event.attributes[0].type == "ip-src")
check("attr value is 192.168.1.1", event.attributes[0].value == "192.168.1.1")
check("attr category is Network activity", event.attributes[0].category == "Network activity")

# 3. Distribution levels
e_high = integration.stix_to_misp(bundle, sensitivity="high")
e_med = integration.stix_to_misp(bundle, sensitivity="medium")
e_low = integration.stix_to_misp(bundle, sensitivity="low")
e_explicit = integration.stix_to_misp(bundle, distribution=3)
e_default = integration.stix_to_misp(bundle)
check("high sensitivity -> dist 0", e_high.distribution == 0)
check("medium sensitivity -> dist 1", e_med.distribution == 1)
check("low sensitivity -> dist 2", e_low.distribution == 2)
check("explicit dist 3", e_explicit.distribution == 3)
check("default dist 0 (org only)", e_default.distribution == 0)

# 4. Organization context
check("org_name stored", integration._org_name == "DARK-WEB-FRAUD-AGENT")

# 5. Mixed bundle
url_obj = stix2.URL(value="http://dark.onion")
ta = stix2.ThreatActor(name="Actor1", threat_actor_types=["criminal"])
mixed = stix2.Bundle(objects=[ipv4, url_obj, ta])
mixed_event = integration.stix_to_misp(mixed)
check("mixed: 2 attributes", len(mixed_event.attributes) == 2)
check("mixed: 1 object", len(mixed_event.objects) == 1)

# 6. Error handling
try:
    integration.stix_to_misp("not a bundle")
    check("ValueError on invalid input", False)
except ValueError:
    check("ValueError on invalid input", True)

try:
    integration.stix_to_misp(bundle, distribution=5)
    check("ValueError on invalid distribution", False)
except ValueError:
    check("ValueError on invalid distribution", True)

# 7. All type map entries have categories
all_have_cats = all(t in STIX_TO_MISP_CATEGORY_MAP for t in STIX_TO_MISP_TYPE_MAP)
check("all type map entries have categories", all_have_cats)

# 8. Empty bundle
empty_bundle = stix2.Bundle(objects=[])
empty_event = integration.stix_to_misp(empty_bundle)
check("empty bundle: 0 STIX objects in info", "0 STIX objects" in empty_event.info)

# Print results
passed = sum(1 for r in results if "PASS" in r)
failed = sum(1 for r in results if "FAIL" in r)

sys.stderr.write(f"\n{'='*60}\n")
sys.stderr.write(f"MISP Integration Verification Results\n")
sys.stderr.write(f"{'='*60}\n")
for r in results:
    sys.stderr.write(r + "\n")
sys.stderr.write(f"\n{passed} passed, {failed} failed out of {len(results)} checks\n")
sys.stderr.write(f"{'='*60}\n")

if failed > 0:
    sys.exit(1)
sys.exit(0)
