"""
SentinelML V2 — Live Attack Replay Simulator (pure logic, no Tkinter)
=====================================================================
A scripted, step-by-step ransomware-incident replay that the UI plays back
with Play / Pause / Resume / Reset and speed controls.

Safety contract:
  * This is a SIMULATION ONLY. No ransomware is executed, no real file is
    encrypted, modified or deleted, and no real process is launched.
  * Every generated event is tagged ``SOURCE_SIMULATED`` so scripted data is
    never presented as a live observation or a real detection.
  * The replay never claims to prove real-world ransomware detection accuracy.

The module is pure data + a small state machine so it can be unit-tested
headless. The Tk page (gui/pages/attack_replay_page.py) drives it with
``safe_after`` timers (never ``time.sleep`` / tight loops on the UI thread).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from exhibition.investigation_timeline import (
    InvestigationTimeline,
    SOURCE_SIMULATED,
    CATEGORY_SCAN_INIT,
    CATEGORY_PROCESS_OBS,
    CATEGORY_FILE_OBS,
    CATEGORY_SIMULATION,
    CATEGORY_INDICATOR,
    CATEGORY_MODEL_INFERENCE,
    CATEGORY_CLASSIFICATION,
    CATEGORY_RESPONSE,
    CATEGORY_RECOVERY,
)

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"
VALID_SEVERITIES = (SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL)


@dataclass(frozen=True)
class ReplayStep:
    """One scripted incident event at a relative time (seconds from start)."""

    t: float
    category: str
    title: str
    detail: str
    severity: str = SEVERITY_INFO
    evidence: List[str] = field(default_factory=list)


def build_attack_replay_plan() -> List[ReplayStep]:
    """Return the scripted ransomware-incident replay (all events SIMULATED).

    The narrative is a representative kill-chain: initial access -> shadow-copy
    deletion -> payload -> bulk encryption -> mass rename -> tampering ->
    inference -> classification -> response -> recovery. Times are seconds
    from the start; the UI divides them by the playback speed.
    """
    return [
        ReplayStep(0.6, CATEGORY_SCAN_INIT,
                   "Initial access vector observed (simulated)",
                   "A scripted foothold event begins the incident replay. No real "
                   "process is launched on this host.",
                   SEVERITY_INFO,
                   ["Simulated incident replay", "No real process executed",
                    "All replay events are tagged SIMULATED"]),
        ReplayStep(2.2, CATEGORY_PROCESS_OBS,
                   "Suspicious process spawned: vssadmin delete shadows",
                   "A shadow-copy deletion command-line is observed in the simulated "
                   "telemetry stream — a classic ransomware pre-encryption step.",
                   SEVERITY_WARNING,
                   ["Heuristic: cmd_vssadmin_count elevated",
                    "Behavioural feature: cmd_vssadmin_count"]),
        ReplayStep(4.0, CATEGORY_PROCESS_OBS,
                   "PowerShell encoded-payload launcher observed",
                   "An obfuscated PowerShell launcher pattern appears in the "
                   "simulated process table.",
                   SEVERITY_WARNING,
                   ["powershell_process_count elevated",
                    "Obfuscated command-line pattern"]),
        ReplayStep(6.0, CATEGORY_FILE_OBS,
                   "Bulk file enumeration across user directories",
                   "Recursive directory traversal and a file-handle spike indicate "
                   "mass file discovery before encryption.",
                   SEVERITY_WARNING,
                   ["file_handle_count spike",
                    "recursive directory traversal pattern"]),
        ReplayStep(8.0, CATEGORY_SIMULATION,
                   "High-entropy rewrites begin on target files",
                   "Files are rewritten with ciphertext-like bytes, pushing average "
                   "entropy above 7.0 bits/byte (SIMULATED).",
                   SEVERITY_CRITICAL,
                   ["avg_entropy > 7.0 bits/byte",
                    "high_entropy_region_count elevated",
                    "Bulk rewrite with ciphertext-like bytes (SIMULATED)"]),
        ReplayStep(10.0, CATEGORY_FILE_OBS,
                   "Mass rename to .locked_sim extension",
                   "Target files are renamed in bulk to a simulated locked extension.",
                   SEVERITY_CRITICAL,
                   ["Bulk rename observed",
                    "Extension heuristic matched"]),
        ReplayStep(11.5, CATEGORY_INDICATOR,
                   "Endpoint-protection tampering attempt",
                   "An attempt to stop or disable the protection service is observed.",
                   SEVERITY_CRITICAL,
                   ["defender_tampering_count > 0",
                    "Attempt to stop/disable protection service"]),
        ReplayStep(12.5, CATEGORY_INDICATOR,
                   "Code-injection indicators (unbacked executable memory)",
                   "Injection-style indicators appear in the simulated telemetry.",
                   SEVERITY_WARNING,
                   ["malfind_injection_count elevated (heuristic proxy)",
                    "suspicious_thread_count elevated"]),
        ReplayStep(13.5, CATEGORY_MODEL_INFERENCE,
                   "Behavioural vector assembled and evaluated (SIMULATED)",
                   "The 19-feature vector is fed to the REAL Random Forest model. "
                   "The probability crosses the WARNING threshold.",
                   SEVERITY_WARNING,
                   ["19-feature vector fed to the real Random Forest",
                    "Threshold: >=0.50 WARNING, >=0.90 CRITICAL"]),
        ReplayStep(14.5, CATEGORY_CLASSIFICATION,
                   "Final classification: CRITICAL [SIMULATED VECTOR]",
                   "The scripted vector classifies CRITICAL. This is a controlled "
                   "simulation, NOT a real malware detection.",
                   SEVERITY_CRITICAL,
                   ["Threshold: >=0.90 CRITICAL",
                    "Outcome is a controlled simulation — NOT a real detection"]),
        ReplayStep(16.0, CATEGORY_RESPONSE,
                   "Recommended response: isolate host, restore from offline backup",
                   "Containment and recovery guidance for the simulated incident.",
                   SEVERITY_INFO,
                   ["Disconnect from network",
                    "Restore from known-good offline backup",
                    "Preserve evidence for forensics"]),
        ReplayStep(17.5, CATEGORY_RECOVERY,
                   "Incident contained (end of simulated replay)",
                   "Replay complete. No real files were encrypted or modified; every "
                   "event was labelled SIMULATED.",
                   SEVERITY_INFO,
                   ["No real files encrypted or modified",
                    "All events labelled SIMULATED"]),
    ]


def replay_steps_ordered(plan: List[ReplayStep]) -> bool:
    """True when step times are strictly non-decreasing."""
    for i in range(1, len(plan)):
        if plan[i].t < plan[i - 1].t:
            return False
    return True


def apply_replay_step_to_timeline(step: ReplayStep,
                                  timeline: InvestigationTimeline):
    """Append one replay step to an InvestigationTimeline as a SIMULATED event.

    Returns the created InvestigationEvent. Safe to call from the UI thread.
    """
    return timeline.add(step.category, step.title, step.detail,
                        source=SOURCE_SIMULATED, evidence=list(step.evidence))


def apply_full_replay_to_timeline(plan: List[ReplayStep],
                                 timeline: InvestigationTimeline) -> int:
    """Apply every step in order. Returns the number of events added. All SIMULATED."""
    count = 0
    for step in plan:
        apply_replay_step_to_timeline(step, timeline)
        count += 1
    return count


@dataclass
class ReplayController:
    """Pure state machine for playback (no timers; the UI wires ``safe_after``).

    state: idle | playing | paused | done
    """

    plan: List[ReplayStep]
    index: int = 0
    speed: float = 1.0
    state: str = "idle"
    _min_speed: float = 0.25
    _max_speed: float = 4.0

    def __post_init__(self) -> None:
        if not self.plan:
            raise ValueError("ReplayController requires a non-empty plan")
        if not replay_steps_ordered(self.plan):
            raise ValueError("Replay plan must be ordered by step time")

    # ── queries ─────────────────────────────────────────────────────────
    def total_steps(self) -> int:
        return len(self.plan)

    def remaining(self) -> int:
        return max(0, len(self.plan) - self.index)

    def is_done(self) -> bool:
        return self.index >= len(self.plan)

    def current_step(self) -> Optional[ReplayStep]:
        if 0 <= self.index < len(self.plan):
            return self.plan[self.index]
        return None

    # ── transitions ──────────────────────────────────────────────────────
    def start(self) -> None:
        self.index = 0
        self.state = "playing"

    def pause(self) -> None:
        if self.state == "playing":
            self.state = "paused"

    def resume(self) -> None:
        if self.state == "paused":
            self.state = "playing"

    def reset(self) -> None:
        self.index = 0
        self.state = "idle"

    def set_speed(self, speed: float) -> None:
        try:
            s = float(speed)
        except (TypeError, ValueError):
            return
        self.speed = max(self._min_speed, min(self._max_speed, s))

    # ── stepping ─────────────────────────────────────────────────────────
    def advance(self) -> Optional[ReplayStep]:
        """Return the current step and move forward. Marks done at the end."""
        if self.is_done():
            return None
        step = self.plan[self.index]
        self.index += 1
        if self.index >= len(self.plan):
            self.state = "done"
        return step

    def delay_before_next_ms(self) -> int:
        """Milliseconds to wait before applying the next step, scaled by speed.

        For the first step (index 0) this is ``plan[0].t``. For later steps it is
        the gap from the previous step's time. Always >= 1 ms.
        """
        if self.is_done():
            return 0
        i = self.index
        if i == 0:
            base = self.plan[0].t
        else:
            base = max(0.0, self.plan[i].t - self.plan[i - 1].t)
        speed = self.speed if self.speed > 0 else 1.0
        return max(1, int(round((base / speed) * 1000.0)))
