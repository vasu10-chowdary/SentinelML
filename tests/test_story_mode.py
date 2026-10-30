"""Story Mode tests (Phase 1) — scene order, provenance, navigation, cleanup."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.story_mode_3d import (
    STORY_SCENES,
    SCENE_TITLES,
    SCENE_NORMAL,
    SCENE_SUSPICIOUS,
    SCENE_AI,
    SCENE_VERDICT,
    SCENE_INVESTIGATION,
    SCENE_RESPONSE,
    PROVENANCE_COLORS,
    StoryMode3D,
)
from scanner.scan_engine import ScanResult, ScanState, ScanType


def _scan(**overrides):
    values = dict(
        scan_type=ScanType.QUICK,
        state=ScanState.COMPLETE,
        files_inspected=120,
        directories_inspected=8,
        processes_analyzed=64,
        ml_executed=True,
        ml_probability=0.72,
        threat_level="WARNING",
        elapsed_seconds=3.5,
        scan_id="SCN-Story0001",
        scan_origin="LIVE_HOST_SCAN",
        model_source="EXPERIMENTAL_SYNTHETIC_BASELINE_V1",
    )
    values.update(overrides)
    return ScanResult(**values)


class TestStorySceneContract(unittest.TestCase):

    def test_scene_order_matches_required_narrative(self):
        self.assertEqual(STORY_SCENES, [
            SCENE_NORMAL, SCENE_SUSPICIOUS, SCENE_AI,
            SCENE_VERDICT, SCENE_INVESTIGATION, SCENE_RESPONSE,
        ])

    def test_every_scene_has_a_title(self):
        for scene in STORY_SCENES:
            self.assertIn(scene, SCENE_TITLES)
            self.assertTrue(SCENE_TITLES[scene])

    def test_provenance_palette_is_complete(self):
        for prov in ("MEASURED", "SIMULATED", "HEURISTIC",
                     "UNAVAILABLE", "ERROR", "APPLICATION"):
            self.assertIn(prov, PROVENANCE_COLORS)


class TestStoryRenderer(unittest.TestCase):
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

    def test_canvas_construction_and_scene_walk(self):
        self._skip()
        canvas = StoryMode3D(self._root)
        try:
            self.assertEqual(canvas.current_scene, SCENE_NORMAL)
            for expected in STORY_SCENES:
                canvas.set_scene(expected)
                self.assertEqual(canvas.current_scene, expected)
            self.assertFalse(canvas.next_scene())  # at the end
            self.assertTrue(canvas.prev_scene())
        finally:
            canvas.destroy()

    def test_ai_scene_exposes_trained_feature_order(self):
        self._skip()
        from ml.predictor import FEATURE_NAMES
        canvas = StoryMode3D(self._root, feature_names=FEATURE_NAMES)
        try:
            canvas.set_scene(SCENE_AI)
            canvas._render()
            labels = [obj["label"] for obj in canvas._hit_objects]
            feature_label = next(
                lbl for lbl in labels if lbl.startswith("19 model features"))
            positions = [feature_label.find(name) for name in FEATURE_NAMES]
            self.assertTrue(all(pos >= 0 for pos in positions),
                            "every trained feature name must appear")
            self.assertEqual(positions, sorted(positions),
                             "feature names must appear in trained order")
        finally:
            canvas.destroy()

    def test_verdict_placeholder_does_not_overlap_threshold_label(self):
        self._skip()
        canvas = StoryMode3D(self._root)
        try:
            canvas.set_scene(SCENE_VERDICT)
            canvas._render()
            boxes = {}
            for item in canvas.find_all():
                if canvas.type(item) != "text":
                    continue
                text = canvas.itemcget(item, "text")
                if text in ("NO VALID SCAN YET", "0.50 WARN"):
                    boxes[text] = canvas.bbox(item)
            placeholder = boxes.get("NO VALID SCAN YET")
            threshold = boxes.get("0.50 WARN")
            self.assertIsNotNone(placeholder, "placeholder caption missing")
            self.assertIsNotNone(threshold, "0.50 threshold label missing")
            self.assertLess(placeholder[2], threshold[0],
                            f"captions overlap: {placeholder} vs {threshold}")
        finally:
            canvas.destroy()

    def test_live_result_only_for_measured_valid_scan(self):
        self._skip()
        canvas = StoryMode3D(self._root)
        try:
            canvas.set_scan_context("WARNING", 0.8, "MEASURED", "SCN-1")
            self.assertTrue(canvas.has_live_result)

            canvas.set_scan_context("WARNING", 0.8, "SIMULATED", "SCN-2")
            self.assertFalse(canvas.has_live_result)

            canvas.set_scan_context("ERROR", 0.0, "MEASURED", "SCN-3")
            self.assertFalse(canvas.has_live_result)

            canvas.set_scan_context("SCAN_INCOMPLETE", 0.2, "MEASURED", "SCN-4")
            self.assertFalse(canvas.has_live_result)
        finally:
            canvas.destroy()

    def test_evidence_items_are_bounded_and_copied(self):
        self._skip()
        canvas = StoryMode3D(self._root)
        try:
            items = [{"title": f"e{i}", "provenance": "MEASURED"} for i in range(20)]
            canvas.set_evidence_items(items)
            self.assertEqual(len(canvas._evidence_items), 8)
            items[0]["title"] = "mutated"
            self.assertNotEqual(canvas._evidence_items[0]["title"], "mutated")
        finally:
            canvas.destroy()

    def test_destroy_stops_frame_loop(self):
        self._skip()
        canvas = StoryMode3D(self._root)
        canvas.destroy()
        self.assertFalse(canvas._running)


class TestStoryPage(unittest.TestCase):
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
        from gui.pages.story_mode_page import StoryModePage
        return StoryModePage(self._root, config={})

    def _set_dashboard(self, **attrs):
        stub = SimpleNamespace(
            _threat_level=attrs.get("status", "NOT_SCANNED"),
            _risk_score=attrs.get("prob", 0.0),
            _last_scan_result=attrs.get("scan"),
            _last_host_scan_result=None,
        )
        old = getattr(self._root, "_pages", None)
        self._root._pages = {"dashboard": stub}
        return old

    def _restore_pages(self, old):
        if old is None:
            try:
                del self._root._pages
            except Exception:
                pass
        else:
            self._root._pages = old

    def test_page_has_all_chapters(self):
        self._skip()
        page = self._make_page()
        try:
            self.assertEqual(len(page._chapter_btns), 6)
            self.assertEqual(len(page._evidence_buttons), 0)
        finally:
            page.destroy()

    def test_story_navigation_targets_are_registered(self):
        self._skip()
        page = self._make_page()
        calls = []

        class _Nav:
            def _show_page(self, uid):
                calls.append(uid)

        page.master = _Nav()
        try:
            page._open_challenge()
            page._open_investigation_suite()
        finally:
            page.destroy()
        self.assertEqual(calls, ["challenge_mode", "exhibition_lab"])

    def test_chapter_navigation_and_progress(self):
        self._skip()
        page = self._make_page()
        try:
            for i, scene in enumerate(STORY_SCENES):
                page._set_chapter(i)
                self.assertEqual(page._index, i)
                self.assertEqual(page._canvas.current_scene, scene)
                self.assertAlmostEqual(page._progress.get(), (i + 1) / 6)
            self.assertEqual(str(page._prev_btn.cget("state")), "normal")
            self.assertEqual(str(page._next_btn.cget("state")), "disabled")
        finally:
            page.destroy()

    def test_start_pause_resume_and_restart(self):
        self._skip()
        page = self._make_page()
        try:
            self.assertEqual(page._play_btn.cget("text"), "Start")
            page._on_play_clicked()
            self.assertTrue(page._playing)
            self.assertEqual(page._play_btn.cget("text"), "Pause")
            page._on_play_clicked()
            self.assertFalse(page._playing)
            self.assertEqual(page._play_btn.cget("text"), "Resume")
            page._on_play_clicked()  # resume
            page._set_chapter(4)
            page.restart_story()
            self.assertEqual(page._index, 0)
            self.assertTrue(page._playing)
            self.assertIsNotNone(page._auto_after_id)
        finally:
            page.destroy()

    def test_evidence_section_only_on_investigation(self):
        self._skip()
        page = self._make_page()
        try:
            page._set_chapter(0)
            self.assertFalse(bool(page._evidence_frame.grid_info()))
            page._set_chapter(4)
            self.assertTrue(bool(page._evidence_frame.grid_info()))
        finally:
            page.destroy()

    def test_no_scan_falls_back_to_labelled_simulated_sample(self):
        self._skip()
        page = self._make_page()
        try:
            old = self._set_dashboard(status="NOT_SCANNED")
            page._refresh_canvas_state()
            self.assertTrue(page._evidence_is_sample)
            self.assertGreater(len(page._evidence_rows), 0)
            for row in page._evidence_rows:
                self.assertIn(row["provenance"], ("SIMULATED", "HEURISTIC"))
            self.assertFalse(page._canvas.has_live_result)
        finally:
            self._restore_pages(old)
            page.destroy()

    def test_measured_scan_is_correlated_and_shown_as_live(self):
        self._skip()
        page = self._make_page()
        try:
            scan = _scan()
            old = self._set_dashboard(status="WARNING", prob=0.72, scan=scan)
            page._refresh_canvas_state()
            self.assertFalse(page._evidence_is_sample)
            titles = [r["title"] for r in page._evidence_rows]
            self.assertTrue(any("prediction" in t.lower() for t in titles))
            self.assertTrue(page._canvas.has_live_result)
            self.assertEqual(page._canvas._scan_provenance, "MEASURED")
        finally:
            self._restore_pages(old)
            page.destroy()

    def test_simulated_scan_is_never_shown_as_live(self):
        self._skip()
        page = self._make_page()
        try:
            scan = _scan(scan_origin="CONTROLLED_SIMULATION", is_simulation=True)
            old = self._set_dashboard(status="WARNING", prob=0.72, scan=scan)
            page._refresh_canvas_state()
            self.assertEqual(page._canvas._scan_provenance, "SIMULATED")
            self.assertFalse(page._canvas.has_live_result)
            self.assertFalse(page._evidence_is_sample)
        finally:
            self._restore_pages(old)
            page.destroy()

    def test_incomplete_scan_never_reports_safe(self):
        self._skip()
        page = self._make_page()
        try:
            scan = _scan(state=ScanState.SCAN_INCOMPLETE, cancelled=True,
                         threat_level="SCAN_INCOMPLETE")
            old = self._set_dashboard(status="SCAN_INCOMPLETE", prob=0.9, scan=scan)
            page._refresh_canvas_state()
            self.assertFalse(page._canvas.has_live_result)
            self.assertEqual(page._canvas._scan_prob, 0.0)
            self.assertEqual(page._canvas._scan_provenance, "UNAVAILABLE")
        finally:
            self._restore_pages(old)
            page.destroy()

    def test_evidence_detail_reveals_provenance_and_limits(self):
        self._skip()
        page = self._make_page()
        try:
            page._refresh_canvas_state()  # no dashboard -> labelled sample
            page._set_chapter(4)
            page._show_evidence_detail(0)
            text = page._detail_label.cget("text")
            self.assertIn("SIMULATED", text)
            self.assertIn("Limits:", text)
            self.assertEqual(page._selected_evidence, 0)
        finally:
            page.destroy()

    def test_destroy_cancels_timers(self):
        self._skip()
        page = self._make_page()
        page._on_play_clicked()
        self.assertIsNotNone(page._auto_after_id)
        page.destroy()
        self.assertTrue(page._is_destroyed)
        self.assertIsNone(page._auto_after_id)
        self.assertEqual(len(page._pending_after), 0)


if __name__ == "__main__":
    unittest.main()
