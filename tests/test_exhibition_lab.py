"""
SentinelML V2 — Interactive Exhibition Lab regression tests (Phase 8).
====================================================================
Headless logic tests (no Tk) for scenarios A–E, real-vs-simulated data
labeling, INCONCLUSIVE safety, cancellation safety, investigation-event
ordering, detection-result explanation fields, and reset behaviour.

Tk UI tests (single shared root to avoid repeated-root Tcl/Tk flakiness)
cover construction of ExhibitionLabPage / GuidedTourPage, guided-presentation
navigation, reset, evidence-panel rendering, and clean shutdown. If the
host Tk cannot initialise (a known environmental issue on some Python/Tcl
installs), the Tk tests skip rather than fail.
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.scenario_lab import (
    ScenarioRunner,
    SCENARIOS,
    run_scenario,
)
from exhibition.investigation_timeline import SOURCE_SIMULATED

VALID_CLASSIFICATIONS = {
    "SAFE", "WARNING", "CRITICAL", "THREAT", "THREAT_DETECTED",
    "INCONCLUSIVE", "LIMITED_COVERAGE", "CANCELLED", "SCAN_INCOMPLETE",
    "INCOMPLETE", "ERROR", "ANALYSIS_ERROR", "NOT_SCANNED",
}
REQUIRED_EXPLANATION_KEYS = {
    "classification", "data_origin", "probability", "probability_note",
    "indicators", "telemetry_gaps", "evidence", "next_steps", "limitations",
    "scan_state",
}


# ===========================================================================
# Headless scenario logic — exercises the REAL ScanEngine + Random Forest.
# ===========================================================================
class TestExhibitionScenarios(unittest.TestCase):
    """Each scenario A–E must genuinely execute and meet its contract."""

    def test_scenarios_catalogue(self):
        self.assertEqual([s.key for s in SCENARIOS], ["A", "B", "C", "D", "E"])
        self.assertEqual(len({s.scenario_id for s in SCENARIOS}), 5)
        for s in SCENARIOS:
            self.assertTrue(s.purpose and s.expected_outcome and s.safety_note)

    def test_scenario_a_benign_real_scan(self):
        r = run_scenario("A")
        self.assertIn(r.classification, VALID_CLASSIFICATIONS)
        self.assertNotEqual(r.classification, "ERROR")
        self.assertFalse(r.is_simulation, "Benign scan must be REAL, not simulated")
        self.assertIn("REAL", r.data_origin.upper())
        self.assertNotIn("SIMULAT", r.data_origin.upper())
        self.assertTrue(r.timeline.is_ordered())
        self.assertGreater(len(r.timeline), 0)
        self.assertTrue(set(REQUIRED_EXPLANATION_KEYS).issubset(r.explanation.keys()))

    def test_scenario_b_suspicious_simulated_vector(self):
        r = run_scenario("B")
        self.assertIn(r.classification, VALID_CLASSIFICATIONS)
        labelled_sim = (
            r.is_simulation
            or "SIMULAT" in r.data_origin.upper()
            or "SIMULATED" in r.outcome_label.upper()
        )
        self.assertTrue(labelled_sim, "Suspicious vector must be labelled SIMULATED")
        self.assertTrue(r.timeline.is_ordered())
        sim_events = [e for e in r.timeline.events if e.source == SOURCE_SIMULATED]
        self.assertGreater(len(sim_events), 0, "Suspicious vector must be emitted as SIMULATED")

    def test_scenario_c_simulation_labeled(self):
        r = run_scenario("C")
        self.assertTrue(r.is_simulation, "Ransomware sim must be labelled simulation")
        self.assertIn("SIMULAT", r.data_origin.upper())
        self.assertIn(r.classification, {"WARNING", "CRITICAL", "THREAT", "THREAT_DETECTED"})
        self.assertTrue(r.timeline.is_ordered())
        self.assertGreater(len(r.timeline), 0)

    def test_scenario_d_inconclusive_never_safe(self):
        r = run_scenario("D")
        self.assertEqual(r.classification, "INCONCLUSIVE")
        self.assertNotEqual(r.classification, "SAFE", "Limited telemetry must never be SAFE")
        self.assertIsNone(r.probability, "No probability invented under sensor outage")
        self.assertFalse(r.is_simulation)
        self.assertTrue(r.expectation_met, "Scenario D expectation should be met")

    def test_scenario_e_cancellation_failure_never_safe(self):
        r = run_scenario("E")
        self.assertNotEqual(r.classification, "SAFE", "Cancellation/failure must never be SAFE")
        self.assertIn(r.classification, {"CANCELLED", "SCAN_INCOMPLETE", "INCOMPLETE",
                                          "ERROR", "ANALYSIS_ERROR"})
        self.assertFalse(r.is_simulation)
        self.assertTrue(r.timeline.is_ordered())
        # ERROR is the runner's last-resort wrapper for an unhandled exception; reaching
        # it here means the cancellation/failure scenario itself broke.
        self.assertNotEqual(r.classification, "ERROR",
                            f"Scenario E fell back to ERROR: {r.outcome_detail}")
        self.assertNotIn("Scenario failed", r.outcome_detail)
        self.assertTrue(
            any(lim.startswith("Phase 2 failure path result:") for lim in r.limitations),
            "Phase 2 failure branch did not produce its limitation entry",
        )
        self.assertTrue(r.expectation_met, "Scenario E expectation should be met")

    def test_immediate_cancellation_never_safe(self):
        r = run_scenario("A", cancel_check=lambda: True)
        self.assertEqual(r.classification, "CANCELLED")
        self.assertNotEqual(r.classification, "SAFE")
        self.assertIn("cancel", r.data_origin.lower())

    def test_explanation_required_fields(self):
        r = run_scenario("C")
        for k in REQUIRED_EXPLANATION_KEYS:
            self.assertIn(k, r.explanation, f"missing explanation key: {k}")
        self.assertIsInstance(r.explanation["indicators"], list)
        self.assertIsInstance(r.explanation["telemetry_gaps"], dict)
        self.assertIsInstance(r.explanation["evidence"], list)
        self.assertIsInstance(r.explanation["next_steps"], list)
        self.assertIsInstance(r.explanation["limitations"], list)

    def test_reset_clears_timeline_and_sandbox(self):
        runner = ScenarioRunner()
        runner.run("C")
        self.assertGreater(len(runner.timeline), 0)
        removed = runner.reset()
        self.assertGreaterEqual(removed, 0)
        self.assertEqual(len(runner.timeline), 0, "Reset must clear the timeline")

    def test_real_vs_simulation_origin_labels(self):
        a = run_scenario("A")
        c = run_scenario("C")
        self.assertFalse(a.is_simulation)
        self.assertTrue(c.is_simulation)
        self.assertNotIn("SIMULAT", a.data_origin.upper())
        self.assertIn("SIMULAT", c.data_origin.upper())

    def test_results_carry_report_text(self):
        r = run_scenario("C")
        text = r.report_text()
        self.assertIn("SCENARIO C", text)
        self.assertIn("DATA ORIGIN", text)


# ===========================================================================
# Tk UI tests — single shared root to avoid repeated-root Tcl/Tk flakiness.
# ===========================================================================
class TestExhibitionLabUI(unittest.TestCase):
    """Construction, navigation, reset, evidence rendering, shutdown."""

    _root = None

    @classmethod
    def setUpClass(cls):
        try:
            import customtkinter as ctk
            cls._root = ctk.CTk()
            cls._root.withdraw()
        except Exception as exc:
            cls._root = None
            cls._tk_skip_reason = str(exc)

    @classmethod
    def tearDownClass(cls):
        if cls._root is not None:
            try:
                cls._root.destroy()
            except Exception:
                pass

    def _skip_if_no_tk(self):
        if self._root is None:
            self.skipTest("Tk unavailable in this environment: " + getattr(self, "_tk_skip_reason", ""))

    def test_exhibition_lab_page_constructs(self):
        self._skip_if_no_tk()
        from gui.pages.exhibition_lab import ExhibitionLabPage
        page = ExhibitionLabPage(self._root, config={})
        try:
            self.assertEqual(len(page._scenario_cards), 5, "All five scenarios must render as cards")
            self.assertEqual(page._run_btn.cget("state"), "disabled", "Run disabled until a scenario is selected")
            self.assertEqual(page._cancel_btn.cget("state"), "disabled")
            self.assertEqual(page._reset_btn.cget("state"), "normal")
            self.assertEqual(page._status_badge.cget("text"), "STATE: IDLE")
        finally:
            page.destroy()

    def test_exhibition_lab_scenario_selection_enables_run(self):
        self._skip_if_no_tk()
        from gui.pages.exhibition_lab import ExhibitionLabPage
        page = ExhibitionLabPage(self._root, config={})
        try:
            page._select_scenario("C")
            self.assertEqual(page._selected_scenario_key, "C")
            self.assertEqual(page._run_btn.cget("state"), "normal")
        finally:
            page.destroy()

    def test_exhibition_lab_evidence_panel_rendering(self):
        self._skip_if_no_tk()
        from gui.pages.exhibition_lab import ExhibitionLabPage
        page = ExhibitionLabPage(self._root, config={})
        try:
            # Drive the result + timeline rendering directly with a real scenario result.
            page._last_result = run_scenario("C")
            page._ensure_timeline_complete(page._last_result.timeline)
            self.assertGreater(len(page._timeline_rows), 0, "Timeline rows must render")
            page._render_result(page._last_result)
            cls_text = page._result_class_lbl.cget("text")
            self.assertIn(cls_text, {"WARNING", "CRITICAL", "THREAT", "THREAT_DETECTED"})
            self.assertIn("SIMULATION", page._result_origin_lbl.cget("text"))
            # Selecting an event must populate the detail panel without crashing.
            first_seq = page._last_result.timeline.events[0].seq
            page._on_select_event(first_seq)
            self.assertNotEqual(page._detail_title.cget("text"), "")
        finally:
            page.destroy()

    def test_exhibition_lab_reset_restores_idle(self):
        self._skip_if_no_tk()
        from gui.pages.exhibition_lab import ExhibitionLabPage
        page = ExhibitionLabPage(self._root, config={})
        try:
            page._select_scenario("C")
            page._on_reset()
            self.assertEqual(page._status_badge.cget("text"), "STATE: IDLE")
            self.assertEqual(len(page._timeline_rows), 0)
            self.assertIsNone(page._last_result)
        finally:
            page.destroy()

    def test_exhibition_lab_health_panel_populates(self):
        self._skip_if_no_tk()
        from gui.pages.exhibition_lab import ExhibitionLabPage
        page = ExhibitionLabPage(self._root, config={})
        try:
            page._refresh_system_health()
            self.assertNotEqual(page._health_labels["platform"].cget("text"), "Not measured.")
            self.assertIn("model", page._health_labels["model"].cget("text").lower())
            self.assertIn("sensor", page._health_labels["sensors_summary"].cget("text").lower())
            self.assertIn("user-space", page._health_labels["limitations"].cget("text").lower())
        finally:
            page.destroy()

    def test_guided_tour_navigation(self):
        self._skip_if_no_tk()
        from gui.pages.guided_tour import GuidedTourPage, STAGES
        page = GuidedTourPage(self._root, config={})
        try:
            self.assertEqual(page._stage_index, 0)
            page._go_next()
            self.assertEqual(page._stage_index, 1)
            page._go_next()
            self.assertEqual(page._stage_index, 2)
            page._go_back()
            self.assertEqual(page._stage_index, 1)
            page._restart()
            self.assertEqual(page._stage_index, 0)
            # Progress indicator text must track the stage.
            self.assertIn("Stage", page._progress_lbl.cget("text"))
        finally:
            page.destroy()

    def test_guided_tour_exit_is_safe_without_show_page(self):
        self._skip_if_no_tk()
        from gui.pages.guided_tour import GuidedTourPage
        page = GuidedTourPage(self._root, config={})
        try:
            # master (shared root) has no _show_page; exit must not raise.
            page._exit_tour()
            page._go_next()
            page._go_next()
        finally:
            page.destroy()

    def test_shutdown_sets_destroyed_flag(self):
        self._skip_if_no_tk()
        from gui.pages.exhibition_lab import ExhibitionLabPage
        page = ExhibitionLabPage(self._root, config={})
        page.destroy()
        self.assertTrue(page._is_destroyed)

    def test_guided_tour_shutdown_sets_destroyed_flag(self):
        self._skip_if_no_tk()
        from gui.pages.guided_tour import GuidedTourPage
        page = GuidedTourPage(self._root, config={})
        page.destroy()
        self.assertTrue(page._is_destroyed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
