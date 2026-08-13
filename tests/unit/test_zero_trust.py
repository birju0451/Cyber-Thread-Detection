"""
tests/unit/test_zero_trust.py
===============================
Re-exported from tests/test_zero_trust.py for the unit/ subfolder.
Runs the same 30+ ZT pipeline tests.
"""
# Simply import and re-use all tests from the parent test file.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Import all test classes so pytest discovers them
from tests.test_zero_trust import (
    TestIdentityManager,
    TestDeviceAssessor,
    TestAppAssessor,
    TestProcessAssessor,
    TestRiskCalculator,
    TestTrustManager,
    TestPolicyEngine,
    TestResourceRegistry,
    TestAccessController,
)

# Fixtures must also be imported for pytest to resolve them
from tests.test_zero_trust import (
    identity_mgr,
    device_assessor,
    app_assessor,
    process_assessor,
    risk_calculator,
    trust_manager,
    policy_engine,
    resource_registry,
    access_controller,
)
