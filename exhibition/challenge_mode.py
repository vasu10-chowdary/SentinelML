"""
SentinelML V2 — Exhibition Challenge Mode (pure logic, no Tkinter)
==================================================================
A deterministic, file-safe investigation exercise. Players inspect evidence,
select timeline events, compare hashes, read a clearly-labelled SIMULATED model
result, and choose response actions.

Safety contract:
  * No malware is executed and no user files are read, written, or deleted —
    every case is a static, scripted data set.
  * The model result inside a case is always badged SIMULATED.
  * Scoring never rewards treating everything as ransomware: over-escalation on
    benign or inconclusive cases loses points, and "SAFE" is never the correct
    answer when coverage is insufficient.
  * Fully deterministic: no clock, randomness, or environment reads.

``ChallengeSession`` is a small state machine; the Tk page in
``gui/pages/challenge_mode_page.py`` only renders it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

PROV_MEASURED = "MEASURED"
PROV_SIMULATED = "SIMULATED"
PROV_HEURISTIC = "HEURISTIC"
PROV_UNAVAILABLE = "UNAVAILABLE"
PROV_APPLICATION = "APPLICATION"

VERDICT_INVESTIGATE = "INVESTIGATE"
VERDICT_BENIGN = "LIKELY_BENIGN"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICTS = (VERDICT_INVESTIGATE, VERDICT_INCONCLUSIVE, VERDICT_BENIGN)

MAX_EVIDENCE_POINTS = 30
MAX_HASH_POINTS = 10
MAX_VERDICT_POINTS = 20
MAX_ACTION_POINTS = 40
MAX_SCORE = 100


@dataclass(frozen=True)
class EvidenceCard:
    event_id: str
    timestamp: str
    provenance: str
    title: str
    detail: str
    relevant: bool = False
    old_hash: str = ""
    new_hash: str = ""
    rationale: str = ""

    @property
    def has_hash_pair(self) -> bool:
        return bool(self.old_hash and self.new_hash)


@dataclass(frozen=True)
class ActionCard:
    action_id: str
    label: str
    points: int
    rationale: str
    unsafe: bool = False


@dataclass(frozen=True)
class ChallengeCase:
    case_id: str
    title: str
    brief: str
    model_label: str
    model_probability: Optional[float]
    model_note: str
    expected_verdict: str
    evidence: Tuple[EvidenceCard, ...]
    actions: Tuple[ActionCard, ...]
    learning: str

    def evidence_by_id(self, event_id: str) -> Optional[EvidenceCard]:
        for card in self.evidence:
            if card.event_id == event_id:
                return card
        return None

    def action_by_id(self, action_id: str) -> Optional[ActionCard]:
        for card in self.actions:
            if card.action_id == action_id:
                return card
        return None


CASES: Tuple[ChallengeCase, ...] = (
    ChallengeCase(
        case_id="CASE-FINANCE-WRITES",
        title="Case 1 — Rapid spreadsheet changes",
        brief=(
            "A finance workstation finished a quick scan. Several spreadsheets changed "
            "within a few minutes while a temporary-file burst appeared. All evidence "
            "below is scripted for training; no real files were touched."
        ),
        model_label="WARNING",
        model_probability=0.64,
        model_note="Simulated model output for this exercise — not a detection of real files.",
        expected_verdict=VERDICT_INVESTIGATE,
        evidence=(
            EvidenceCard(
                "e1", "09:11:40", PROV_MEASURED, "Scan completed",
                "Quick scan finished: 1,204 files, 38 processes.",
                relevant=True,
                rationale="Establishes what was actually observed on the host."),
            EvidenceCard(
                "e2", "09:12:05", PROV_SIMULATED, "Simulated model: WARNING p=0.640",
                "Fraction of positive voting trees = 0.640 (WARNING >= 0.50).",
                relevant=True,
                rationale=("Worth considering, but a simulated prediction is not proof "
                           "and must be corroborated.")),
            EvidenceCard(
                "e3", "09:12:30", PROV_MEASURED, "4 spreadsheets modified",
                "Files under Finance/ changed inside a 3-minute window.",
                old_hash="9f2a" + "0" * 60,
                new_hash="c41b" + "0" * 60,
                relevant=True,
                rationale=("A real file-state change worth correlating — the change itself "
                           "does not prove ransomware.")),
            EvidenceCard(
                "e4", "09:12:44", PROV_MEASURED, "12 .tmp files added",
                "Temporary files appeared next to the modified spreadsheets.",
                relevant=True,
                rationale="New files are context, not proof; correlate with the writer."),
            EvidenceCard(
                "e5", "09:13:02", PROV_HEURISTIC, "Rapid writes by a document process",
                "Heuristic: the spreadsheet process wrote to 4 files quickly.",
                relevant=True,
                rationale=("A heuristic indicator can guide investigation but is not "
                           "confirmed malware.")),
            EvidenceCard(
                "e6", "09:10:11", PROV_MEASURED, "User opened a spreadsheet",
                "Normal user action recorded before the change window.",
                relevant=False,
                rationale="Benign context that does not itself support escalation."),
            EvidenceCard(
                "e7", "09:13:20", PROV_UNAVAILABLE, "Backup service state unavailable",
                "Could not read backup service status (permission denied).",
                relevant=True,
                rationale="A coverage gap must be acknowledged, not treated as evidence of safety."),
        ),
        actions=(
            ActionCard("a1", "Preserve the evidence and stop further writes", 12,
                       "Protects the observations before anything changes.", False),
            ActionCard("a2", "Investigate the process that wrote the files", 10,
                       "Corroborates or dismisses the heuristic guess.", False),
            ActionCard("a3", "Isolate the host using the normal incident process", 10,
                       "Limits spread if the activity is malicious.", False),
            ActionCard("a4", "Verify a trusted backup before any restore", 8,
                       "A restore is only safe from a validated copy.", False),
            ActionCard("a5", "Delete all .tmp files immediately", -10,
                       "Destroys potential evidence and may not stop the writer.", True),
            ActionCard("a6", "Restore from any available shadow copy now", -8,
                       "An unvalidated restore can overwrite evidence.", True),
            ActionCard("a7", "Declare ransomware and act on that label", -12,
                       "The evidence does not establish ransomware.", True),
        ),
        learning=(
            "A model warning plus file changes is a reason to investigate, not a verdict. "
            "Correlate the writer, preserve evidence, and validate backups before acting."
        ),
    ),
    ChallengeCase(
        case_id="CASE-BUILD-ACTIVITY",
        title="Case 2 — Build folder activity",
        brief=(
            "A developer workstation shows source-file changes and an object file with "
            "high entropy. The simulated model result is low. Decide whether this "
            "warrants escalation. All evidence is scripted."
        ),
        model_label="SAFE",
        model_probability=0.12,
        model_note="Simulated model output for this exercise — not a detection of real files.",
        expected_verdict=VERDICT_BENIGN,
        evidence=(
            EvidenceCard(
                "b1", "10:01:50", PROV_MEASURED, "Scan completed",
                "Quick scan finished: 2,410 files, 61 processes.",
                relevant=True,
                rationale="Establishes the observation window."),
            EvidenceCard(
                "b2", "10:02:10", PROV_SIMULATED, "Simulated model: SAFE p=0.120",
                "Fraction of positive voting trees = 0.120.",
                relevant=True,
                rationale="A simulated low score still does not certify the host as safe."),
            EvidenceCard(
                "b3", "10:02:22", PROV_MEASURED, "3 source files modified",
                "Files changed under src/ during the build window.",
                old_hash="11aa" + "0" * 60,
                new_hash="77cc" + "0" * 60,
                relevant=True,
                rationale="A hash change needs an explanation; here the build may explain it."),
            EvidenceCard(
                "b4", "10:02:25", PROV_APPLICATION, "Compiler ran",
                "Developer launched the project compiler just before the changes.",
                relevant=True,
                rationale="Timeline correlation offers a benign explanation — not proof by itself."),
            EvidenceCard(
                "b5", "10:02:31", PROV_HEURISTIC, "High entropy in an object file",
                "object.o has near-random content, typical of compiled output.",
                relevant=True,
                rationale="High entropy is expected for compiled files; context matters."),
            EvidenceCard(
                "b6", "09:58:00", PROV_APPLICATION, "Scheduled update ran",
                "Windows Update executed an hour earlier.",
                relevant=False,
                rationale="Unrelated to this change window."),
            EvidenceCard(
                "b7", "10:02:40", PROV_UNAVAILABLE, "Network telemetry unavailable",
                "Connection counters could not be read on this host.",
                relevant=True,
                rationale="A gap must be recorded even when the rest looks benign."),
        ),
        actions=(
            ActionCard("c1", "Correlate the changes with the build log", 12,
                       "Tests the benign explanation against the evidence.", False),
            ActionCard("c2", "Verify the object file matches the build output", 10,
                       "Confirms the expected artifact rather than guessing.", False),
            ActionCard("c3", "Preserve logs before cleanup", 8,
                       "Keeps the evidence that supports the conclusion.", False),
            ActionCard("c4", "Continue monitoring and record the coverage gap", 10,
                       "Honest follow-up when nothing malicious is established.", False),
            ActionCard("c5", "Isolate the host as a ransomware case", -12,
                       "Over-escalation without corroboration.", True),
            ActionCard("c6", "Delete object files immediately", -10,
                       "Destroys evidence and disrupts the build.", True),
            ActionCard("c7", "Report confirmed ransomware", -12,
                       "Nothing here proves malware.", True),
        ),
        learning=(
            "Low-risk evidence still needs an explanation and a recorded coverage gap. "
            "Labelling this ransomware is over-escalation and loses points."
        ),
    ),
    ChallengeCase(
        case_id="CASE-SILENT-GAPS",
        title="Case 3 — Silent coverage gaps",
        brief=(
            "A limited scan could not read several sensors and produced no model "
            "prediction. There is no integrity baseline yet. Choose the honest outcome."
        ),
        model_label="UNAVAILABLE",
        model_probability=None,
        model_note="No prediction was produced for this case — ML did not execute.",
        expected_verdict=VERDICT_INCONCLUSIVE,
        evidence=(
            EvidenceCard(
                "g1", "14:20:00", PROV_MEASURED, "Scan ended with limited coverage",
                "7 of 19 behavioral sensors returned no data.",
                relevant=True,
                rationale="Coverage limits the confidence of any conclusion."),
            EvidenceCard(
                "g2", "14:20:01", PROV_UNAVAILABLE, "No model prediction",
                "The ML stage did not execute; no probability exists.",
                relevant=True,
                rationale="Missing model output cannot be interpreted as SAFE."),
            EvidenceCard(
                "g3", "14:20:02", PROV_UNAVAILABLE, "No integrity baseline",
                "No SHA-256 baseline exists for the selected folder.",
                relevant=True,
                rationale="Without a baseline there is nothing to compare."),
            EvidenceCard(
                "g4", "14:15:00", PROV_APPLICATION, "Operator selected a folder",
                "The operator chose a test folder before the scan.",
                relevant=False,
                rationale="Routine setup, not evidence about threats."),
        ),
        actions=(
            ActionCard("h1", "State that the result is inconclusive, not SAFE", 12,
                       "Honest classification under insufficient coverage.", False),
            ActionCard("h2", "Collect the missing telemetry and re-run", 12,
                       "Closes the gap before drawing conclusions.", False),
            ActionCard("h3", "Create an integrity baseline before further work", 10,
                       "Enables meaningful comparison later.", False),
            ActionCard("h4", "Preserve the current logs", 6,
                       "Keeps what little evidence exists.", False),
            ActionCard("h5", "Declare the host safe because nothing appeared", -12,
                       "Absence of evidence is not evidence of absence.", True),
            ActionCard("h6", "Declare ransomware based on missing data", -12,
                       "Missing data cannot establish malware.", True),
            ActionCard("h7", "Ignore the coverage gap", -10,
                       "Hides the limitation that matters most.", True),
        ),
        learning=(
            "When sensors or the model are unavailable, the honest outcome is "
            "INCONCLUSIVE — never SAFE, never ransomware-by-default."
        ),
    ),
)

CASE_BY_ID: Dict[str, ChallengeCase] = {c.case_id: c for c in CASES}


def get_case(case_id: str) -> Optional[ChallengeCase]:
    return CASE_BY_ID.get(str(case_id))


def _verdict_points(expected: str, chosen: Optional[str]) -> int:
    if chosen is None:
        return 0
    chosen = str(chosen).upper()
    if chosen == expected:
        return MAX_VERDICT_POINTS
    # Caution is partially credited; over-escalation and premature SAFE are not.
    if expected == VERDICT_INVESTIGATE and chosen == VERDICT_INCONCLUSIVE:
        return 8
    if expected == VERDICT_INCONCLUSIVE and chosen == VERDICT_INVESTIGATE:
        return 10
    if expected == VERDICT_BENIGN and chosen == VERDICT_INCONCLUSIVE:
        return 6
    if expected == VERDICT_BENIGN and chosen == VERDICT_INVESTIGATE:
        return 4
    return 0


class ChallengeSession:
    """Deterministic state machine for one scripted case."""

    def __init__(self, case: ChallengeCase):
        self.case = case
        self.started = False
        self.finished = False
        self.result: Optional[Dict] = None
        self.inspected: List[str] = []
        self.selected_events: List[str] = []
        self.hashes_compared: List[str] = []
        self.chosen_actions: List[str] = []
        self.verdict: Optional[str] = None

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        self.started = True
        self.finished = False
        self.result = None

    def restart(self) -> None:
        self.started = False
        self.finished = False
        self.result = None
        self.inspected = []
        self.selected_events = []
        self.hashes_compared = []
        self.chosen_actions = []
        self.verdict = None

    def _active(self) -> bool:
        return self.started and not self.finished

    # -- interactions ----------------------------------------------------
    def inspect(self, event_id: str) -> Optional[Dict]:
        card = self.case.evidence_by_id(event_id)
        if card is None:
            return None
        if card.event_id not in self.inspected:
            self.inspected.append(card.event_id)
        return self._card_dict(card)

    def toggle_event(self, event_id: str) -> bool:
        if not self._active():
            return False
        if self.case.evidence_by_id(event_id) is None:
            return False
        if event_id in self.selected_events:
            self.selected_events.remove(event_id)
            return False
        self.selected_events.append(event_id)
        return True

    def compare_hashes(self, event_id: str) -> Optional[Dict]:
        card = self.case.evidence_by_id(event_id)
        if card is None or not card.has_hash_pair:
            return None
        if event_id not in self.hashes_compared:
            self.hashes_compared.append(event_id)
        return {
            "event_id": event_id,
            "old_hash": card.old_hash,
            "new_hash": card.new_hash,
            "changed": card.old_hash != card.new_hash,
            "interpretation": ("The hash changed, so the content changed. This does not "
                               "show why, when, or by what."),
        }

    def choose_action(self, action_id: str) -> bool:
        if not self._active():
            return False
        if self.case.action_by_id(action_id) is None:
            return False
        if action_id in self.chosen_actions:
            self.chosen_actions.remove(action_id)
            return False
        self.chosen_actions.append(action_id)
        return True

    def choose_verdict(self, verdict: str) -> bool:
        if not self._active():
            return False
        verdict = str(verdict or "").upper()
        if verdict not in VERDICTS:
            return False
        self.verdict = verdict
        return True

    # -- scoring ---------------------------------------------------------
    def _evidence_points(self) -> Tuple[int, List[str], List[str], List[str]]:
        relevant = [c.event_id for c in self.case.evidence if c.relevant]
        irrelevant = [c.event_id for c in self.case.evidence if not c.relevant]
        selected_relevant = [e for e in self.selected_events if e in relevant]
        selected_irrelevant = [e for e in self.selected_events if e in irrelevant]
        missed = [e for e in relevant if e not in self.selected_events]
        if relevant:
            base = MAX_EVIDENCE_POINTS * (len(selected_relevant) / len(relevant))
        else:
            base = MAX_EVIDENCE_POINTS
        penalty = (MAX_EVIDENCE_POINTS / 3.0) * (len(selected_irrelevant) / max(1, len(irrelevant)))
        points = max(0, min(MAX_EVIDENCE_POINTS, int(round(base - penalty))))
        return points, selected_relevant, missed, selected_irrelevant

    def _action_points(self) -> Tuple[int, List[Dict]]:
        rows: List[Dict] = []
        total = 0
        for action in self.case.actions:
            selected = action.action_id in self.chosen_actions
            if selected:
                total += action.points
            rows.append({
                "action_id": action.action_id,
                "label": action.label,
                "points": action.points,
                "selected": selected,
                "unsafe": action.unsafe,
                "rationale": action.rationale,
            })
        return max(0, min(MAX_ACTION_POINTS, total)), rows

    def finish(self) -> Dict:
        if not self.started:
            return {"error": "Call start() before finishing the challenge."}
        evidence_pts, sel_rel, missed, sel_irrel = self._evidence_points()
        hash_pts = MAX_HASH_POINTS if self.hashes_compared else 0
        verdict_pts = _verdict_points(self.case.expected_verdict, self.verdict)
        action_pts, action_rows = self._action_points()
        total = evidence_pts + hash_pts + verdict_pts + action_pts

        if total >= 80:
            grade = "STRONG"
        elif total >= 55:
            grade = "DEVELOPING"
        else:
            grade = "NEEDS REVIEW"

        learning = [self.case.learning]
        if missed:
            for eid in missed:
                card = self.case.evidence_by_id(eid)
                if card:
                    learning.append(f"Missed relevant evidence: {card.title} — {card.rationale}")
        if sel_irrel:
            for eid in sel_irrel:
                card = self.case.evidence_by_id(eid)
                if card:
                    learning.append(f"Less relevant evidence selected: {card.title} — {card.rationale}")
        if self.verdict and self.verdict != self.case.expected_verdict:
            learning.append(
                f"You chose {self.verdict}; this case supports {self.case.expected_verdict}.")
        unsafe_chosen = [r for r in action_rows if r["selected"] and r["points"] < 0]
        for row in unsafe_chosen:
            learning.append(f"Avoid: {row['label']} — {row['rationale']}")
        if not self.hashes_compared:
            learning.append("Compare at least one old/new hash pair before concluding.")
        if not self.verdict:
            learning.append("Record an explicit verdict (INVESTIGATE / INCONCLUSIVE / LIKELY_BENIGN).")

        self.finished = True
        self.result = {
            "case_id": self.case.case_id,
            "title": self.case.title,
            "score": int(total),
            "max_score": MAX_SCORE,
            "grade": grade,
            "breakdown": {
                "evidence": {"points": evidence_pts, "max": MAX_EVIDENCE_POINTS},
                "hash_comparison": {"points": hash_pts, "max": MAX_HASH_POINTS},
                "verdict": {"points": verdict_pts, "max": MAX_VERDICT_POINTS},
                "actions": {"points": action_pts, "max": MAX_ACTION_POINTS},
            },
            "verdict": self.verdict,
            "expected_verdict": self.case.expected_verdict,
            "verdict_correct": self.verdict == self.case.expected_verdict,
            "selected_relevant": sel_rel,
            "missed_relevant": missed,
            "selected_irrelevant": sel_irrel,
            "hashes_compared": list(self.hashes_compared),
            "actions": action_rows,
            "learning": learning,
            "is_inconclusive_outcome": self.case.expected_verdict == VERDICT_INCONCLUSIVE,
            "simulated_model": {
                "label": self.case.model_label,
                "probability": self.case.model_probability,
                "note": self.case.model_note,
                "is_simulation": True,
            },
        }
        return self.result

    # -- presentation helpers -------------------------------------------
    def _card_dict(self, card: EvidenceCard) -> Dict:
        return {
            "event_id": card.event_id,
            "timestamp": card.timestamp,
            "provenance": card.provenance,
            "title": card.title,
            "detail": card.detail,
            "old_hash": card.old_hash,
            "new_hash": card.new_hash,
            "has_hash_pair": card.has_hash_pair,
        }

    def evidence_rows(self) -> List[Dict]:
        rows = []
        for card in self.case.evidence:
            row = self._card_dict(card)
            row["selected"] = card.event_id in self.selected_events
            row["inspected"] = card.event_id in self.inspected
            rows.append(row)
        return rows

    def action_rows(self) -> List[Dict]:
        return [
            {"action_id": a.action_id, "label": a.label, "selected": a.action_id in self.chosen_actions}
            for a in self.case.actions
        ]
