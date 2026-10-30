"""
SentinelML V2 — Attack Replay Simulator tests (Phase 8 / Task 3)
=================================================================
Covers the pure-logic layer (exhibition/attack_replay.py) and, where Tk is
available, basic construction / playback of AttackReplayPage using a single
shared CTk root so repeated-root Tcl/Tk flakiness is avoided.
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.attack_replay import (
    ReplayController,
    ReplayStep,
    SEVERITY_CRITICAL,
    SEVERITY_INFO,
    SEVERITY_WARNING,
    apply_full_replay_to_timeline,
    apply_replay_step_to_timeline,
    build_attack_replay_plan,
    replay_steps_ordered,
)
from exhibition.investigation_timeline import (
    InvestigationTimeline,
    SOURCE_SIMULATED,
)


# ---------------------------------------------------------------------------
# Pure-logic tests (no Tkinter)
# ---------------------------------------------------------------------------

class TestReplayPlan(unittest.TestCase):
    def setUp(self):
        self.plan = build_attack_replay_plan()

    def test_plan_not_empty(self):
        self.assertGreater(len(self.plan), 0)

    def test_plan_is_ordered(self):
        self.assertTrue(replay_steps_ordered(self.plan))

    def test_all_steps_have_required_fields(self):
        for step in self.plan:
            self.assertIsInstance(step.t, float)
            self.assertGreaterEqual(step.t, 0.0)
            self.assertIsInstance(step.title, str)
            self.assertTrue(step.title)
            self.assertIsInstance(step.detail, str)
            self.assertIn(step.severity, (SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL))
            self.assertIsInstance(step.category, str)

    def test_plan_contains_critical_and_recovery(self):
        severities = {s.severity for s in self.plan}
        self.assertIn(SEVERITY_CRITICAL, severities)
        # At least one recovery/response event
        from exhibition.investigation_timeline import CATEGORY_RECOVERY, CATEGORY_RESPONSE
        cats = {s.category for s in self.plan}
        self.assertTrue(cats & {CATEGORY_RECOVERY, CATEGORY_RESPONSE})

    def test_unordered_plan_detected(self):
        bad = [
            ReplayStep(5.0, "SCAN_INIT", "A", "detail", SEVERITY_INFO),
            ReplayStep(1.0, "SCAN_INIT", "B", "detail", SEVERITY_INFO),
        ]
        self.assertFalse(replay_steps_ordered(bad))

    def test_empty_plan_is_ordered(self):
        self.assertTrue(replay_steps_ordered([]))


class TestReplayController(unittest.TestCase):
    def setUp(self):
        self.plan = build_attack_replay_plan()
        self.ctrl = ReplayController(self.plan)

    def test_initial_state_is_idle(self):
        self.assertEqual(self.ctrl.state, "idle")
        self.assertEqual(self.ctrl.index, 0)

    def test_start_sets_playing(self):
        self.ctrl.start()
        self.assertEqual(self.ctrl.state, "playing")

    def test_pause_and_resume(self):
        self.ctrl.start()
        self.ctrl.pause()
        self.assertEqual(self.ctrl.state, "paused")
        self.ctrl.resume()
        self.assertEqual(self.ctrl.state, "playing")

    def test_pause_only_from_playing(self):
        # pause from idle must not change state
        self.ctrl.pause()
        self.assertEqual(self.ctrl.state, "idle")

    def test_resume_only_from_paused(self):
        # resume from idle must not change state
        self.ctrl.resume()
        self.assertEqual(self.ctrl.state, "idle")

    def test_reset_returns_to_idle(self):
        self.ctrl.start()
        self.ctrl.advance()
        self.ctrl.reset()
        self.assertEqual(self.ctrl.state, "idle")
        self.assertEqual(self.ctrl.index, 0)

    def test_advance_returns_steps(self):
        self.ctrl.start()
        step = self.ctrl.advance()
        self.assertIsNotNone(step)
        self.assertIsInstance(step, ReplayStep)
        self.assertEqual(self.ctrl.index, 1)

    def test_advance_past_end_returns_none(self):
        self.ctrl.start()
        for _ in range(len(self.plan)):
            self.ctrl.advance()
        self.assertTrue(self.ctrl.is_done())
        self.assertEqual(self.ctrl.state, "done")
        self.assertIsNone(self.ctrl.advance())

    def test_remaining_count(self):
        self.ctrl.start()
        total = self.ctrl.total_steps()
        for i in range(3):
            self.ctrl.advance()
        self.assertEqual(self.ctrl.remaining(), total - 3)

    def test_speed_clamping(self):
        self.ctrl.set_speed(100.0)
        self.assertEqual(self.ctrl.speed, self.ctrl._max_speed)
        self.ctrl.set_speed(-5.0)
        self.assertEqual(self.ctrl.speed, self.ctrl._min_speed)

    def test_delay_scales_with_speed(self):
        self.ctrl.start()
        self.ctrl.set_speed(1.0)
        delay_1x = self.ctrl.delay_before_next_ms()
        self.ctrl.set_speed(2.0)
        delay_2x = self.ctrl.delay_before_next_ms()
        self.assertGreater(delay_1x, delay_2x)
        self.assertGreater(delay_1x, 0)

    def test_invalid_plan_raises(self):
        with self.assertRaises(ValueError):
            ReplayController([])

    def test_unordered_plan_raises(self):
        bad = [
            ReplayStep(5.0, "SCAN_INIT", "A", "d", SEVERITY_INFO),
            ReplayStep(1.0, "SCAN_INIT", "B", "d", SEVERITY_INFO),
        ]
        with self.assertRaises(ValueError):
            ReplayController(bad)


class TestReplayTimeline(unittest.TestCase):
    def test_apply_single_step_is_simulated(self):
        plan = build_attack_replay_plan()
        tl = InvestigationTimeline()
        evt = apply_replay_step_to_timeline(plan[0], tl)
        self.assertEqual(evt.source, SOURCE_SIMULATED)
        self.assertEqual(len(tl), 1)

    def test_apply_full_replay_all_simulated(self):
        plan = build_attack_replay_plan()
        tl = InvestigationTimeline()
        count = apply_full_replay_to_timeline(plan, tl)
        self.assertEqual(count, len(plan))
        self.assertEqual(len(tl), len(plan))
        self.assertTrue(tl.is_ordered())
        for evt in tl.events:
            self.assertEqual(evt.source, SOURCE_SIMULATED,
                             f"Event '{evt.title}' must be SIMULATED, got {evt.source}")

    def test_evidence_preserved(self):
        plan = build_attack_replay_plan()
        tl = InvestigationTimeline()
        step = next(s for s in plan if s.evidence)
        evt = apply_replay_step_to_timeline(step, tl)
        self.assertEqual(evt.evidence, step.evidence)

    def test_category_preserved(self):
        plan = build_attack_replay_plan()
        tl = InvestigationTimeline()
        for step in plan:
            evt = apply_replay_step_to_timeline(step, tl)
            self.assertEqual(evt.category, step.category)


# ---------------------------------------------------------------------------
# Tk UI tests (single shared root, skipped if Tk unavailable)
# ---------------------------------------------------------------------------

class TestAttackReplayPageUI(unittest.TestCase):
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

    def test_page_constructs(self):
        self._skip()
        from gui.pages.attack_replay_page import AttackReplayPage
        page = AttackReplayPage(self._root, config={})
        try:
            self.assertEqual(page._ctrl.state, "idle")
            self.assertEqual(page._play_btn.cget("state"), "normal")
            self.assertEqual(page._pause_btn.cget("state"), "disabled")
            self.assertEqual(page._resume_btn.cget("state"), "disabled")
        finally:
            page.destroy()

    def test_idle_state_initial(self):
        self._skip()
        from gui.pages.attack_replay_page import AttackReplayPage
        page = AttackReplayPage(self._root, config={})
        try:
            self.assertTrue(page._is_destroyed is False)
            self.assertEqual(page._ctrl.index, 0)
        finally:
            page.destroy()

    def test_reset_clears_events(self):
        self._skip()
        from gui.pages.attack_replay_page import AttackReplayPage
        page = AttackReplayPage(self._root, config={})
        try:
            # Add an event row directly, then reset
            plan = build_attack_replay_plan()
            step = plan[0]
            evt = apply_replay_step_to_timeline(step, page._timeline)
            page._add_event_row(evt, step)
            self.assertEqual(len(page._event_rows), 1)
            page._reset()
            self.assertEqual(len(page._event_rows), 0)
            self.assertEqual(page._ctrl.state, "idle")
        finally:
            page.destroy()

    def test_speed_changes_controller(self):
        self._skip()
        from gui.pages.attack_replay_page import AttackReplayPage
        page = AttackReplayPage(self._root, config={})
        try:
            page._on_speed("2x")
            self.assertAlmostEqual(page._ctrl.speed, 2.0)
            page._on_speed("0.5x")
            self.assertAlmostEqual(page._ctrl.speed, 0.5)
        finally:
            page.destroy()

    def test_destroy_sets_flag(self):
        self._skip()
        from gui.pages.attack_replay_page import AttackReplayPage
        page = AttackReplayPage(self._root, config={})
        page.destroy()
        self.assertTrue(page._is_destroyed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
