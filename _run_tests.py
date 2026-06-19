"""Temporary test runner script."""
import sys
import pytest

exit_code = pytest.main([
    "tests/unit/test_alert_generator.py",
    "-v",
    "--tb=short",
    "-p", "no:asyncio",
])
sys.stderr.write(f"\npytest exit code: {exit_code}\n")
sys.exit(int(exit_code))
