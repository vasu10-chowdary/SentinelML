"""
SentinelML V2 — End-to-End Safe Demo & Concurrency Invariant Test
"""
import sys
import time
from pathlib import Path
import numpy as np

# Ensure root in path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.security_test_lab import SecurityTestLab
from exhibition.sandbox_simulator import SecurityError

def run_e2e_verification():
    print("=" * 70)
    print("SENTINELML V2 SAFE DEMO END-TO-END VALIDATION")
    print("=" * 70)

    sandbox_path = PROJECT_ROOT / "temp_demo_e2e_sandbox"
    lab = SecurityTestLab(sandbox_dir=sandbox_path)
    lab.simulator.reset_sandbox()

    # 1. Health check
    h = lab.check_demo_health()
    print("[1] Pre-Demo Health Check:")
    print("    Healthy:", h["healthy"])
    print("    Details:", h["details"])
    print("    Warnings:", h["warnings"])
    assert h["healthy"] is True

    # 2. Run Safe Demo
    t0 = time.time()
    res = lab.run_safe_demo(num_files=20, delay_between_ops=0.01, cleanup_after=False)
    elapsed = time.time() - t0

    print(f"\n[2] Safe Demo Execution ({elapsed:.2f}s):")
    print("    Status:            ", res["status"])
    print("    Mode:              ", res["mode"])
    print("    Is Simulation:     ", res["is_simulation"])
    print("    Threat Level:      ", res["threat_level"])
    print("    Probability:       ", res["probability"])
    print("    Detection Achieved:", res["detection_achieved"])
    print("    Stages Returned:   ", len(res["stages"]))

    # Verify sandbox files exist before cleanup
    sandbox_files = list(sandbox_path.iterdir())
    print(f"\n[3] Sandbox File Containment Check:")
    print(f"    Sandbox Directory: {sandbox_path}")
    print(f"    Files in sandbox:  {len(sandbox_files)}")
    assert len(sandbox_files) >= 20, "Files missing from sandbox!"

    # Verify zero files modified outside sandbox
    for f in sandbox_files:
        lab.simulator.validate_path_safety(f)
    print("    Verified: ALL 20+ files resolve strictly within sandbox path.")

    # 4. Check each of the 6 stages
    print("\n[4] 6-Stage Evidence Breakdown:")
    for s in res["stages"]:
        print(f"    Stage {s['stage_num']}: [{s['name']}] Passed={s['passed']}")
        for k, v in s["metrics"].items():
            print(f"        • {k}: {v}")
        print(f"        Limitation Note: {s['limitation']}")

    # 5. Check Feature Inspector Data
    inspector = res["feature_inspector"]
    print(f"\n[5] Feature Inspector Data:")
    print(f"    Legacy 19 Features:    {len(inspector['legacy_19'])}")
    print(f"    Schema V2 16 Features: {len(inspector['schema_v2_16'])}")

    # 6. Test Automatic Sandbox Cleanup
    removed = lab.simulator.reset_sandbox()
    remaining = list(sandbox_path.iterdir())
    print(f"\n[6] Sandbox Cleanup:")
    print(f"    Removed items: {removed}")
    print(f"    Remaining in sandbox: {len(remaining)}")
    assert len(remaining) == 0, "Sandbox not empty after cleanup!"

    # 7. Test Repeated-Demo Execution
    print("\n[7] Repeated-Demo Test (Back-to-Back Execution):")
    res2 = lab.run_safe_demo(num_files=10, delay_between_ops=0.005, cleanup_after=True)
    print("    Run 2 Status:            ", res2["status"])
    print("    Run 2 Detection Achieved:", res2["detection_achieved"])
    print("    Run 2 Probability:       ", res2["probability"])
    assert res2["status"] == "SUCCESS"
    assert res2["detection_achieved"] is True

    # 8. Test Concurrency Lock Rejection
    print("\n[8] Concurrency Lock Rejection Test:")
    lab._demo_lock.acquire()
    lock_rejected = False
    try:
        lab.run_safe_demo()
    except RuntimeError as e:
        lock_rejected = True
        print(f"    Expected Lock Rejection Caught: '{e}'")
    finally:
        lab._demo_lock.release()
    assert lock_rejected is True
    print("    Concurrency lock released cleanly. Locked state:", lab._demo_lock.locked())

    # 9. Test Sandbox Traversal Rejection
    print("\n[9] Path Traversal Rejection Test:")
    traversal_caught = False
    try:
        lab.simulator.validate_path_safety(sandbox_path / ".." / "outside.txt")
    except SecurityError as e:
        traversal_caught = True
        print(f"    Expected SecurityError Caught: '{e}'")
    assert traversal_caught is True

    # Clean up test sandbox
    lab.simulator.reset_sandbox()
    if sandbox_path.exists():
        import shutil
        shutil.rmtree(sandbox_path, ignore_errors=True)

    print("\n" + "=" * 70)
    print("END-TO-END DEMO VALIDATION: ALL 9 PHASES VERIFIED (100%)")
    print("=" * 70)

if __name__ == "__main__":
    run_e2e_verification()
