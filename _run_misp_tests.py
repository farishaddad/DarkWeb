"""Temporary test runner for MISP integration tests."""
import sys
import pytest

exit_code = pytest.main([
    "tests/unit/test_misp_integration.py",
    "-v",
    "--tb=short",
    "-p", "no:asyncio",
])
sys.stderr.write(f"\npytest exit code: {exit_code}\n")
sys.exit(int(exit_code))
