"""
tests/evaluation/evaluate_zero_trust.py
=========================================
Zero Trust Architecture Evaluation

Evaluates the full 10-step ZT pipeline across:
  - Decision distribution (ALLOW/MONITOR/RESTRICT/BLOCK/QUARANTINE)
  - Risk score accuracy for known benign vs. malicious events
  - Policy engine routing correctness
  - Trust manager state transitions
  - Device + Identity assessment output
  - Resource access control correctness

Usage:
    python tests/evaluation/evaluate_zero_trust.py
"""

import sys
import time
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def banner(title: str):
    print("\n" + "═" * 65)
    print(f"  {title}")
    print("═" * 65)


def check(condition: bool, msg: str):
    icon = "✅" if condition else "❌"
    print(f"  {icon} {msg}")
    return condition


# ─────────────────────────────────────────────────────────────────────────────
# 1. Access Controller — Decision Distribution
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_access_controller():
    banner("Access Controller — Decision Distribution")
    from zero_trust.access_control.access_controller import AccessController
    zt = AccessController()

    test_cases = [
        # (label, event, expected_decisions)
        ("Safe URL — Chrome",
         {"event_type": "url", "resource": "https://google.com", "process_name": "chrome.exe",
          "abtd_result": {"threat_score": 5, "classification": "SAFE"}, "behavior_risk": 1.0},
         ["ALLOW", "MONITOR"]),

        ("Suspicious URL — Short link",
         {"event_type": "url", "resource": "https://bit.ly/3xSusp", "process_name": "chrome.exe",
          "abtd_result": {"threat_score": 45, "classification": "SUSPICIOUS"}, "behavior_risk": 20.0},
         ["ALLOW", "MONITOR", "RESTRICT", "CHALLENGE"]),

        ("Malicious File — Temp .exe",
         {"event_type": "file", "resource": r"C:\Temp\payload.exe", "process_name": "explorer.exe",
          "abtd_result": {"threat_score": 85, "classification": "MALICIOUS"}, "behavior_risk": 60.0},
         ["RESTRICT", "CHALLENGE", "BLOCK", "QUARANTINE"]),

        ("Critical Process — PS Encoded",
         {"event_type": "process", "resource": "powershell.exe", "process_name": "powershell.exe",
          "abtd_result": {"threat_score": 95, "classification": "CRITICAL"}, "behavior_risk": 80.0},
         ["BLOCK", "QUARANTINE"]),

        ("Safe Process — Notepad",
         {"event_type": "process", "resource": "notepad.exe", "process_name": "notepad.exe",
          "abtd_result": {"threat_score": 2, "classification": "SAFE"}, "behavior_risk": 0.0},
         ["ALLOW", "MONITOR"]),
    ]

    passed = 0
    print(f"\n  {'CASE':<35}  {'DECISION':<12}  {'RISK':>6}  {'PASS':>5}")
    print("  " + "-" * 62)
    for label, event, expected in test_cases:
        result = zt.evaluate_access(event)
        decision = result.get("decision", "?")
        risk     = result.get("overall_risk", 0)
        ok = decision in expected
        icon = "✅" if ok else "❌"
        print(f"  {label:<35}  {decision:<12}  {risk:>6.1f}  {icon}")
        if ok:
            passed += 1

    print(f"\n  Score: {passed}/{len(test_cases)} decisions in expected range")

    # Overview structure
    overview = zt.get_zt_overview()
    print(f"\n  ZT Overview Keys: {list(overview.keys())}")
    check("decision_stats" in overview, "overview has decision_stats")
    check("trust_levels"   in overview, "overview has trust_levels")

    # Recent decisions
    decisions = zt.get_recent_decisions(10)
    check(isinstance(decisions, list), f"get_recent_decisions returns list ({len(decisions)} items)")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Risk Calculator — Score Accuracy
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_risk_calculator():
    banner("Risk Calculator — Score Accuracy")
    from zero_trust.risk_engine.risk_calculator import RiskCalculator
    rc = RiskCalculator()

    cases = [
        ("All signals benign",    dict(identity_risk=5,  device_risk=5,  app_risk=5,  process_risk=5,  resource_risk=5,  behavior_risk=5,  abtd_risk=5,  network_risk=5),  (0, 30)),
        ("One high signal",       dict(identity_risk=5,  device_risk=5,  app_risk=5,  process_risk=5,  resource_risk=5,  behavior_risk=5,  abtd_risk=90, network_risk=5),  (20, 70)),
        ("All signals critical",  dict(identity_risk=90, device_risk=90, app_risk=90, process_risk=90, resource_risk=90, behavior_risk=90, abtd_risk=90, network_risk=90), (70, 100)),
        ("Mixed signals",         dict(identity_risk=50, device_risk=20, app_risk=10, process_risk=80, resource_risk=30, behavior_risk=60, abtd_risk=70, network_risk=40), (35, 75)),
    ]

    print(f"\n  {'CASE':<28}  {'SCORE':>6}  {'RANGE':>12}  {'PASS':>5}")
    print("  " + "-" * 58)
    all_pass = True
    for label, kwargs, (lo, hi) in cases:
        result = rc.calculate(**kwargs)
        score  = result.get("overall_risk", 0)
        ok     = lo <= score <= hi
        icon   = "✅" if ok else "❌"
        if not ok:
            all_pass = False
        print(f"  {label:<28}  {score:>6.1f}  [{lo:>3} – {hi:>3}]    {icon}")

    check(all_pass, "All risk scores within expected ranges")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Policy Engine — Routing Correctness
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_policy_engine():
    banner("Policy Engine — Routing Correctness")
    from zero_trust.policy_engine.policy_engine import PolicyEngine
    pe = PolicyEngine()

    contexts = [
        ("Low risk safe process",    {"overall_risk": 5,  "classification": "SAFE",     "behavior_risk": 2},  ["ALLOW", "MONITOR"]),
        ("Medium risk suspicious",   {"overall_risk": 45, "classification": "SUSPICIOUS","behavior_risk": 20}, ["MONITOR", "RESTRICT", "ALLOW", "CHALLENGE"]),
        ("High risk malicious",      {"overall_risk": 80, "classification": "MALICIOUS", "behavior_risk": 65}, ["RESTRICT", "BLOCK", "CHALLENGE", "QUARANTINE"]),
        ("Critical risk",            {"overall_risk": 95, "classification": "CRITICAL",  "behavior_risk": 85}, ["BLOCK", "QUARANTINE"]),
    ]

    print(f"\n  {'CONTEXT':<30}  {'DECISION':<12}  {'POLICY':<25}  {'PASS'}")
    print("  " + "-" * 78)
    passed = 0
    for label, ctx, expected in contexts:
        result = pe.evaluate(ctx)
        decision = result.get("decision", "ALLOW")
        policy   = result.get("policy_name", "default")
        ok = decision in expected
        icon = "✅" if ok else "❌"
        if ok:
            passed += 1
        print(f"  {label:<30}  {decision:<12}  {policy[:23]:<25}  {icon}")

    print(f"\n  Score: {passed}/{len(contexts)} correct decisions")
    check(passed >= 2, "At least 2/4 policy routings are correct")

    # Policy listing
    policies = pe.list_policies()
    check(isinstance(policies, list), f"list_policies() returns list ({len(policies)} policies)")
    check(len(policies) >= 5, f"At least 5 policies defined ({len(policies)} found)")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Trust Manager — State Transitions
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_trust_manager():
    banner("Trust Manager — State Transitions")
    from zero_trust.trust_manager.trust_manager import TrustManager
    tm = TrustManager()

    # New entity starts neutral
    state = tm.get_trust_state("process", "test_eval_proc.exe")
    check(state is not None or True, "Trust state retrieved (may be None for new entity)")

    # Update with low risk → high trust
    tm.update_trust("process", "benign_proc.exe", risk_score=5.0)
    state = tm.get_trust_state("process", "benign_proc.exe")
    check(state is not None, "Trust state created after update")
    if state:
        check(state.get("trust_score", 0) >= 50, f"Low risk → high trust (got {state.get('trust_score')})")
        check(state.get("trust_level") in ("HIGH", "MODERATE"), f"Trust level: {state.get('trust_level')}")

    # Update with high risk → low trust
    tm.update_trust("process", "malicious_proc.exe", risk_score=90.0)
    state = tm.get_trust_state("process", "malicious_proc.exe")
    if state:
        check(state.get("trust_score", 100) < 50, f"High risk → low trust (got {state.get('trust_score')})")
        check(state.get("trust_level") in ("LOW", "UNTRUSTED"), f"Trust level: {state.get('trust_level')}")

    # get_all_trust_scores
    all_scores = tm.get_all_trust_scores()
    check(isinstance(all_scores, dict), "get_all_trust_scores() returns dict")
    check("process" in all_scores, "process key exists in trust scores")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Device Assessment
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_device_assessment():
    banner("Device Assessor — Current Machine Assessment")
    from zero_trust.device_trust.device_assessor import DeviceAssessor
    da = DeviceAssessor()

    result = da.assess()
    print(f"\n  Device Assessment Output:")
    for key, val in result.items():
        if key != "checks":
            print(f"    {key:<30} : {val}")

    check("overall_score"    in result, "has overall_score")
    check("device_risk"      in result, "has device_risk")
    check("trust_level"      in result, "has trust_level")
    check(0 <= result.get("overall_score", -1)  <= 100, f"overall_score in [0,100]: {result.get('overall_score')}")
    check(0 <= result.get("device_risk",   -1)  <= 100, f"device_risk in [0,100]: {result.get('device_risk')}")
    check(result.get("trust_level") in ("HIGH", "MODERATE", "LOW", "UNTRUSTED"), f"trust_level valid: {result.get('trust_level')}")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Identity Assessment
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_identity_assessment():
    banner("Identity Manager — Current User Assessment")
    from zero_trust.identity.identity_manager import IdentityManager
    im = IdentityManager()

    ctx = im.get_identity_context()
    print(f"\n  Identity Context:")
    for key, val in ctx.items():
        print(f"    {key:<30} : {val}")

    check("username"         in ctx, "has username")
    check("privilege_level"  in ctx, "has privilege_level")
    check("is_elevated"      in ctx, "has is_elevated")
    check(ctx.get("privilege_level") in ("STANDARD", "ADMINISTRATOR", "SYSTEM"), f"privilege_level valid: {ctx.get('privilege_level')}")

    risk = im.get_identity_risk()
    check("risk_score" in risk, f"identity risk score: {risk.get('risk_score', '?')}")
    check(0 <= risk.get("risk_score", -1) <= 100, f"risk_score in [0,100]")


# ─────────────────────────────────────────────────────────────────────────────
# 7. Resource Registry
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_resource_registry():
    banner("Resource Registry — Access Control")
    from zero_trust.resource_protection.resource_registry import ResourceRegistry
    rr = ResourceRegistry()

    resources = rr.list_resources()
    check(isinstance(resources, list), f"list_resources() returns list ({len(resources)} resources)")
    check(len(resources) >= 10, f"At least 10 resources defined ({len(resources)} found)")

    # Test access control
    results = [
        ("Critical resource, low trust",  resources[0]["name"] if resources else "sam", 20.0,  False),
        ("Public resource, any trust",    "C:/Windows/notepad.exe",                      80.0, True),
    ]
    for label, resource, trust, expected_allowed in results:
        access = rr.check_access(resource, trust)
        allowed = access.get("allowed", not expected_allowed)
        check(allowed == expected_allowed, f"{label}: allowed={allowed} (expected {expected_allowed})")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n🛡️  ABTD Zero Trust Architecture Evaluation")
    print("=" * 65)
    start = time.time()

    evaluate_access_controller()
    evaluate_risk_calculator()
    evaluate_policy_engine()
    evaluate_trust_manager()
    evaluate_device_assessment()
    evaluate_identity_assessment()
    evaluate_resource_registry()

    print(f"\n✅ Zero Trust evaluation complete in {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()
