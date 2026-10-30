"""Challenge Mode tests (Phase 6) — determinism, scoring, safe behaviour."""

import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.challenge_mode import (
    CASES,
    MAX_ACTION_POINTS,
    VERDICT_BENIGN,
    VERDICT_INCONCLUSIVE,
    VERDICT_INVESTIGATE,
    ChallengeSession,
    get_case,
)


def _perfect(case):
    s = ChallengeSession(case)
    s.start()
    for card in case.evidence:
        if card.relevant:
            s.toggle_event(card.event_id)
    for card in case.evidence:
        if card.has_hash_pair:
            s.compare_hashes(card.event_id)
            break
    s.choose_verdict(case.expected_verdict)
    for a in case.actions:
        if a.points > 0:
            s.choose_action(a.action_id)
    return s


class TestCaseData(unittest.TestCase):

    def test_cases_have_unique_ids_and_expected_verdicts(self):
        ids = [c.case_id for c in CASES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(CASES), 3)
        expected = {c.expected_verdict for c in CASES}
        self.assertEqual(expected, {VERDICT_INVESTIGATE, VERDICT_BENIGN, VERDICT_INCONCLUSIVE})

    def test_every_case_has_relevant_and_irrelevant_evidence(self):
        for case in CASES:
            self.assertTrue(any(c.relevant for c in case.evidence))
            self.assertTrue(any(not c.relevant for c in case.evidence))
            self.assertTrue(case.learning)

    def test_positive_actions_fit_point_budget(self):
        for case in CASES:
            positives = sum(a.points for a in case.actions if a.points > 0)
            self.assertLessEqual(positives, MAX_ACTION_POINTS)
            self.assertTrue(any(a.unsafe for a in case.actions))


class TestSessionLifecycle(unittest.TestCase):

    def test_finish_requires_start(self):
        session = ChallengeSession(CASES[0])
        self.assertIn("error", session.finish())

    def test_restart_clears_progress(self):
        case = CASES[0]
        session = ChallengeSession(case)
        session.start()
        session.toggle_event("e1")
        session.choose_verdict(VERDICT_INVESTIGATE)
        session.restart()
        self.assertEqual(session.selected_events, [])
        self.assertIsNone(session.verdict)
        self.assertFalse(session.started)
        self.assertFalse(session.finished)

    def test_interactions_blocked_after_finish(self):
        case = CASES[0]
        session = _perfect(case)
        session.finish()
        self.assertFalse(session.toggle_event("e4"))
        self.assertFalse(session.choose_action("a1"))
        self.assertFalse(session.choose_verdict(VERDICT_BENIGN))

    def test_invalid_ids_are_ignored(self):
        session = ChallengeSession(CASES[0])
        session.start()
        self.assertIsNone(session.inspect("nope"))
        self.assertFalse(session.toggle_event("nope"))
        self.assertIsNone(session.compare_hashes("e1"))  # no hash pair
        self.assertFalse(session.choose_verdict("SAFE"))


class TestScoring(unittest.TestCase):

    def test_perfect_play_scores_100(self):
        result = _perfect(CASES[0]).finish()
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "STRONG")
        self.assertTrue(result["verdict_correct"])
        self.assertEqual(result["breakdown"]["evidence"]["points"], 30)
        self.assertEqual(result["breakdown"]["hash_comparison"]["points"], 10)
        self.assertEqual(result["breakdown"]["verdict"]["points"], 20)
        self.assertEqual(result["breakdown"]["actions"]["points"], 40)

    def test_time_limited_case_without_hash_can_reach_90(self):
        result = _perfect(CASES[2]).finish()
        self.assertEqual(result["score"], 90)
        self.assertTrue(result["is_inconclusive_outcome"])
        self.assertEqual(result["verdict"], VERDICT_INCONCLUSIVE)

    def test_ransomware_panic_on_benign_case_is_not_rewarded(self):
        case = get_case("CASE-BUILD-ACTIVITY")
        session = ChallengeSession(case)
        session.start()
        for card in case.evidence:
            session.toggle_event(card.event_id)  # select everything
        for card in case.evidence:
            if card.has_hash_pair:
                session.compare_hashes(card.event_id)
        session.choose_verdict(VERDICT_INVESTIGATE)
        for aid in ("c5", "c6", "c7"):
            session.choose_action(aid)
        result = session.finish()
        self.assertLess(result["score"], 55)
        self.assertEqual(result["grade"], "NEEDS REVIEW")
        self.assertFalse(result["verdict_correct"])
        self.assertTrue(any("avoid" in item.lower() for item in result["learning"]))
        self.assertTrue(any("over-escalation" in item.lower() or "avoid" in item.lower()
                            for item in result["learning"]))

    def test_declaring_safe_on_inconclusive_case_scores_zero_verdict(self):
        case = get_case("CASE-SILENT-GAPS")
        session = ChallengeSession(case)
        session.start()
        session.choose_verdict(VERDICT_BENIGN)
        session.choose_action("h5")
        result = session.finish()
        self.assertEqual(result["breakdown"]["verdict"]["points"], 0)
        self.assertEqual(result["breakdown"]["actions"]["points"], 0)
        self.assertTrue(any("INCONCLUSIVE" in item for item in result["learning"]))

    def test_selecting_irrelevant_evidence_reduces_points(self):
        case = CASES[0]
        clean = ChallengeSession(case)
        clean.start()
        for c in case.evidence:
            if c.relevant:
                clean.toggle_event(c.event_id)
        clean_points = clean.finish()["breakdown"]["evidence"]["points"]

        noisy = ChallengeSession(case)
        noisy.start()
        for c in case.evidence:
            noisy.toggle_event(c.event_id)
        noisy_points = noisy.finish()["breakdown"]["evidence"]["points"]
        self.assertLess(noisy_points, clean_points)

    def test_results_are_deterministic(self):
        first = _perfect(CASES[1]).finish()
        second = _perfect(CASES[1]).finish()
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_missing_hash_comparison_is_explained(self):
        case = CASES[0]
        session = ChallengeSession(case)
        session.start()
        for c in case.evidence:
            if c.relevant:
                session.toggle_event(c.event_id)
        session.choose_verdict(VERDICT_INVESTIGATE)
        result = session.finish()
        self.assertTrue(any("hash pair" in item.lower() for item in result["learning"]))


class TestChallengePage(unittest.TestCase):
    _root = None

    @classmethod
    def setUpClass(cls):
        try:
            import customtkinter as ctk
            cls._root = ctk.CTk()
            cls._root.withdraw()
        except Exception as exc:
            cls._root = None
            cls._skip_reason = str(exc)

    @classmethod
    def tearDownClass(cls):
        if cls._root is not None:
            try:
                cls._root.destroy()
            except Exception:
                pass

    def _skip(self):
        if self._root is None:
            self.skipTest(getattr(self, "_skip_reason", "Tk unavailable"))

    def _make_page(self):
        from gui.pages.challenge_mode_page import ChallengeModePage
        return ChallengeModePage(self._root, config={})

    def test_start_loads_scripted_evidence(self):
        self._skip()
        page = self._make_page()
        try:
            page._on_start()
            self.assertIsNotNone(page._session)
            self.assertEqual(len(page._session.evidence_rows()), len(page._case.evidence))
            self.assertTrue(page._session.started)
            self.assertEqual(str(page._submit_btn.cget("state")), "normal")
        finally:
            page.destroy()

    def test_back_buttons_navigate(self):
        self._skip()
        page = self._make_page()
        calls = []

        class _Nav:
            def _show_page(self, uid):
                calls.append(uid)

        page.master = _Nav()
        try:
            page._back_to_lab()
            page._back_to_dashboard()
        finally:
            page.destroy()
        self.assertEqual(calls, ["exhibition_lab", "dashboard"])

    def test_full_flow_scores_and_restarts(self):
        self._skip()
        page = self._make_page()
        try:
            page._on_start()
            for card in page._case.evidence:
                if card.relevant:
                    page._on_event_toggle(card.event_id)
            page._on_compare("e3")
            page._on_verdict(VERDICT_INVESTIGATE)
            for action in page._case.actions:
                if action.points > 0:
                    page._on_action_toggle(action.action_id)
            page._on_submit()
            text = page._result_box.get("1.0", "end")
            self.assertIn("SCORE: 100", text)
            self.assertIn("LEARNING SUMMARY", text)
            self.assertTrue(page._session.finished)

            page._on_restart()
            self.assertFalse(page._session.finished)
            self.assertTrue(page._session.started)
            self.assertEqual(page._session.selected_events, [])
        finally:
            page.destroy()

    def test_switch_case_resets_session(self):
        self._skip()
        page = self._make_page()
        try:
            page._on_start()
            other = page._case_titles[1]
            page._on_case_change(other)
            self.assertIsNone(page._session)
            self.assertEqual(page._case.title, other)
            self.assertEqual(str(page._submit_btn.cget("state")), "disabled")
        finally:
            page.destroy()

    def test_simulated_model_is_labelled(self):
        self._skip()
        page = self._make_page()
        try:
            text = page._model_lbl.cget("text")
            self.assertIn("SIMULATED", page._case.model_note.upper())
            self.assertIn(page._case.model_label, text)
        finally:
            page.destroy()

    def test_destroy_sets_flag(self):
        self._skip()
        page = self._make_page()
        page.destroy()
        self.assertTrue(page._is_destroyed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
