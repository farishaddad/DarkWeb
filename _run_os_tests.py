"""Direct test execution - write results to file."""
import sys
sys.path.insert(0, "/Users/fahaddad/Documents/DarkWeb/src")

# First just try importing
try:
    from dark_web_fraud_agent.agents.data_structurer import DataStructurer, StructurerConfig
    msg = "Import OK"
except Exception as e:
    msg = f"Import FAILED: {e}"

with open("/Users/fahaddad/Documents/DarkWeb/_test_output.txt", "w") as f:
    f.write(msg + "\n")
