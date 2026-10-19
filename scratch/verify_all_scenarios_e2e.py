"""
SentinelML V2 — Execution of all 9 Security Test Lab Scenarios
"""
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.security_test_lab import SecurityTestLab

def run_all_scenarios():
    print("=" * 75)
    print("SENTINELML V2 SECURITY TEST LAB SCENARIO AUDIT (ALL 9 SCENARIOS)")
    print("=" * 75)

    test_sandbox = PROJECT_ROOT / "temp_lab_audit_sandbox"
    lab = SecurityTestLab(sandbox_dir=test_sandbox)
    scenarios = lab.get_available_scenarios()
    
    print(f"Total Available Scenarios: {len(scenarios)}\n")
    results = []

    for s in scenarios:
        sid = s["id"]
        sname = s["name"]
        stype = s["type"]
        t0 = time.time()
        outcome = lab.run_scenario(sid)
        elapsed = time.time() - t0

        print(f"[{outcome.scenario_id}] - {sname} ({stype})")
        print(f"    • Passed:            {outcome.passed_test}")
        print(f"    • Scan State:        {outcome.scan_state}")
        print(f"    • Classifier Output: {outcome.classifier_output} (p={outcome.probability})")
        print(f"    • Duration:          {elapsed:.3f}s")
        print(f"    • Evidence Items:    {len(outcome.evidence_collected)}")
        for e in outcome.evidence_collected[:2]:
            print(f"      - {e}")
        print()

        assert outcome.passed_test is True, f"Scenario {sid} failed invariant test!"
        results.append(outcome)

    # Clean sandbox
    lab.simulator.reset_sandbox()
    if test_sandbox.exists():
        import shutil
        shutil.rmtree(test_sandbox, ignore_errors=True)

    print("=" * 75)
    print(f"ALL {len(results)}/9 SECURITY TEST LAB SCENARIOS PASSED WITH VERIFIED INVARIANTS")
    print("=" * 75)

if __name__ == "__main__":
    run_all_scenarios()
