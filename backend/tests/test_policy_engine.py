"""
AgentShield — Backend tests.
Tests the policy engine decisions and approval enforcement.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy_engine import evaluate_action, compute_risk_score, run_simulation
from models import ActionRequest, Decision, Operation, DataSensitivity


def test_public_document_read():
    """Public document read should be ALLOWED."""
    action = ActionRequest(
        action_name="Read Public Whitepaper",
        agent_id="agent-research-06",
        agent_name="Research Assistant",
        target_resource="/public/whitepapers/ai-safety.pdf",
        operation=Operation.READ,
        data_sensitivity=DataSensitivity.PUBLIC,
    )
    decision, risk, reason, policy = evaluate_action(action)
    assert decision == Decision.ALLOW, f"Expected ALLOW, got {decision}: {reason}"
    assert risk <= 30, f"Risk score too high for public read: {risk}"
    print(f"  [PASS] Public document read: {decision.value} (risk={risk})")


def test_authorized_internal_read():
    """Authorized agent reading internal report should be ALLOWED."""
    action = ActionRequest(
        action_name="Read Q3 Revenue Report",
        agent_id="agent-analytics-01",
        agent_name="Analytics Bot",
        target_resource="/reports/q3-revenue-2026.pdf",
        operation=Operation.READ,
        data_sensitivity=DataSensitivity.INTERNAL,
    )
    decision, risk, reason, policy = evaluate_action(action)
    assert decision == Decision.ALLOW, f"Expected ALLOW, got {decision}: {reason}"
    print(f"  [PASS] Authorized internal read: {decision.value} (risk={risk})")


def test_unauthorized_restricted_access():
    """HR bot accessing salary data should be BLOCKED."""
    action = ActionRequest(
        action_name="Access Salary Records",
        agent_id="agent-hr-02",
        agent_name="HR Assistant",
        target_resource="/hr/salaries/2026-all.xlsx",
        operation=Operation.READ,
        data_sensitivity=DataSensitivity.RESTRICTED,
    )
    decision, risk, reason, policy = evaluate_action(action)
    assert decision == Decision.BLOCK, f"Expected BLOCK, got {decision}: {reason}"
    assert risk >= 60, f"Risk score too low for restricted access: {risk}"
    print(f"  [PASS] Unauthorized restricted access: {decision.value} (risk={risk})")


def test_confidential_data_exfiltration():
    """Sending confidential data externally should be BLOCKED."""
    action = ActionRequest(
        action_name="Export Client List",
        agent_id="agent-sales-05",
        agent_name="Sales Copilot",
        target_resource="/sales/client-list-2026.csv",
        operation=Operation.SEND,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        destination="crm@competitor.com",
    )
    decision, risk, reason, policy = evaluate_action(action)
    assert decision == Decision.BLOCK, f"Expected BLOCK, got {decision}: {reason}"
    assert risk >= 80, f"Risk score too low for data exfiltration: {risk}"
    print(f"  [PASS] Confidential data exfiltration: {decision.value} (risk={risk})")


def test_delete_shared_folder():
    """Deleting shared folder should REQUIRE_APPROVAL."""
    action = ActionRequest(
        action_name="Delete Shared Archive",
        agent_id="agent-devops-04",
        agent_name="DevOps Agent",
        target_resource="/logs/shared-archive/2026/",
        operation=Operation.DELETE,
        data_sensitivity=DataSensitivity.INTERNAL,
    )
    decision, risk, reason, policy = evaluate_action(action)
    assert decision == Decision.REQUIRE_APPROVAL, f"Expected REQUIRE_APPROVAL, got {decision}: {reason}"
    print(f"  [PASS] Delete shared folder: {decision.value} (risk={risk})")


def test_modify_critical_record():
    """Modifying critical financial records should REQUIRE_APPROVAL."""
    action = ActionRequest(
        action_name="Modify Financial Projections",
        agent_id="agent-finance-07",
        agent_name="Finance Bot",
        target_resource="/finance/reports/projections-q2-2026.xlsx",
        operation=Operation.MODIFY,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
    )
    decision, risk, reason, policy = evaluate_action(action)
    # Finance Bot only has read access to /finance/reports/, so modify should be blocked
    assert decision == Decision.BLOCK, f"Expected BLOCK, got {decision}: {reason}"
    print(f"  [PASS] Modify critical record (unauthorized): {decision.value} (risk={risk})")


def test_unregistered_agent():
    """Unregistered agent should be BLOCKED."""
    action = ActionRequest(
        action_name="Scan Network",
        agent_id="agent-rogue-99",
        agent_name="Rogue Bot",
        target_resource="/infra/network/config",
        operation=Operation.EXECUTE,
        data_sensitivity=DataSensitivity.INTERNAL,
    )
    decision, risk, reason, policy = evaluate_action(action)
    assert decision == Decision.BLOCK, f"Expected BLOCK, got {decision}: {reason}"
    assert risk >= 70, f"Risk score too low for unregistered agent: {risk}"
    print(f"  [PASS] Unregistered agent: {decision.value} (risk={risk})")


def test_legitimate_internal_send():
    """Sending internal data within the org should be ALLOWED."""
    action = ActionRequest(
        action_name="Send Press Release",
        agent_id="agent-comms-03",
        agent_name="Communications Bot",
        target_resource="/comms/press-release-draft.docx",
        operation=Operation.SEND,
        data_sensitivity=DataSensitivity.INTERNAL,
    )
    decision, risk, reason, policy = evaluate_action(action)
    assert decision == Decision.ALLOW, f"Expected ALLOW, got {decision}: {reason}"
    print(f"  [PASS] Legitimate internal send: {decision.value} (risk={risk})")


def test_risk_score_computation():
    """Verify risk score components add up correctly."""
    # Base case: public read by authorized agent
    action = ActionRequest(
        action_name="Read Docs",
        agent_id="agent-research-06",
        agent_name="Research Assistant",
        target_resource="/public/docs/guide.pdf",
        operation=Operation.READ,
        data_sensitivity=DataSensitivity.PUBLIC,
    )
    score = compute_risk_score(action)
    assert score == 10, f"Expected base score 10, got {score}"

    # Restricted data + delete + external + unknown agent
    action2 = ActionRequest(
        action_name="Exfiltrate Secrets",
        agent_id="agent-unknown-99",
        agent_name="Unknown",
        target_resource="/secret/passwords.txt",
        operation=Operation.DELETE,
        data_sensitivity=DataSensitivity.RESTRICTED,
        destination="hacker@gmail.com",
    )
    score2 = compute_risk_score(action2)
    # 10 + 30 (restricted) + 25 (external) + 20 (delete) + 15 (restricted kw) + 15 (unknown) = 115 → capped at 100
    assert score2 == 100, f"Expected capped score 100, got {score2}"
    print(f"  [PASS] Risk score computation verified")


def test_simulation_suite():
    """Run the full simulation suite and verify metrics."""
    result = run_simulation()
    assert result["total_tests"] > 0
    assert result["total_tests"] == result["passed"] + result["failed"]
    assert "disclaimer" in result
    print(f"  [PASS] Simulation suite: {result['passed']}/{result['total_tests']} passed")
    if result["failed"] > 0:
        for r in result["results"]:
            if not r["passed"]:
                print(f"    [FAIL] FAILED: {r['scenario']} — expected {r['expected_decision']}, got {r['actual_decision']}")


def test_bypass_prevention():
    """
    Verify that changing display labels doesn't bypass policy.
    An agent trying to disguise a restricted read as something else
    must still be blocked based on the actual resource and permissions.
    """
    # Disguised action name but actual restricted resource
    action = ActionRequest(
        action_name="Totally Normal Report",  # Innocent name
        agent_id="agent-hr-02",
        agent_name="HR Assistant",
        target_resource="/hr/salaries/2026-all.xlsx",  # Restricted!
        operation=Operation.READ,
        data_sensitivity=DataSensitivity.RESTRICTED,
    )
    decision, risk, reason, policy = evaluate_action(action)
    assert decision == Decision.BLOCK, (
        f"SECURITY FAILURE: Disguised action was not blocked! Got {decision}: {reason}"
    )
    print(f"  [PASS] Bypass prevention: disguised action correctly blocked")


if __name__ == "__main__":
    print("\n[SHIELD] AgentShield - Policy Engine Tests\n")

    tests = [
        test_public_document_read,
        test_authorized_internal_read,
        test_unauthorized_restricted_access,
        test_confidential_data_exfiltration,
        test_delete_shared_folder,
        test_modify_critical_record,
        test_unregistered_agent,
        test_legitimate_internal_send,
        test_risk_score_computation,
        test_simulation_suite,
        test_bypass_prevention,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  [FAIL] {test.__name__}: UNEXPECTED ERROR: {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    if failed == 0:
        print("[OK] All tests passed!")
    else:
        print(f"[FAILED] {failed} test(s) failed")
    print()
