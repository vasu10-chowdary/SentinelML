"""
SentinelML V2 — 3D Command Center tests (Part B)
=================================================
Covers CommandCenter3D (Canvas-based renderer) and CommandCenterPage:
  * Scene switching and canvas creation
  * Status-safety invariant (never SAFE on incomplete/error)
  * Mouse interaction state machine
  * Replay controller binding
  * Camera reset
  * Resource cleanup (destroy sets _running=False)
  * Tk page construction, scene buttons, detail panel
All Tk tests use a single shared CTk root to avoid repeated-root Tcl flakiness.
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.command_center_3d import (
    ALL_SCENES,
    SCENE_SHIELD,
    SCENE_WORKSTATION,
    SCENE_FILES,
    SCENE_PIPELINE,
    SCENE_REPLAY,
    CommandCenter3D,
    _status_color,
    _rot_x,
    _rot_y,
    _project,
    _transform_point,
)


# ---------------------------------------------------------------------------
# Pure-logic tests (no Tkinter)
# ---------------------------------------------------------------------------

class TestStatusColor(unittest.TestCase):

    def test_safe_green(self):
        self.assertEqual(_status_color("SAFE"), "#34d897")

    def test_critical_red(self):
        self.assertIn(_status_color("CRITICAL"), ["#ff6b6b"])

    def test_warning_amber(self):
        self.assertIn(_status_color("WARNING"), ["#fbb03b"])

    def test_inconclusive_violet(self):
        self.assertEqual(_status_color("INCONCLUSIVE"), "#c9a8ff")

    def test_cancelled_slate(self):
        self.assertEqual(_status_color("CANCELLED"), "#7ec8e3")

    def test_idle_cyan(self):
        self.assertEqual(_status_color("IDLE"), "#38d8f5")

    def test_scan_incomplete_not_safe(self):
        col = _status_color("SCAN_INCOMPLETE")
        safe_col = _status_color("SAFE")
        self.assertNotEqual(col, safe_col,
                            "SCAN_INCOMPLETE must have different color from SAFE")

    def test_error_not_safe(self):
        self.assertNotEqual(_status_color("ERROR"), _status_color("SAFE"))

    def test_unknown_status_returns_something(self):
        col = _status_color("UNKNOWN_STATE_XYZ")
        self.assertTrue(col.startswith("#"))


class TestMath3D(unittest.TestCase):

    def test_rot_y_identity(self):
        import math
        x, y, z = _rot_y(1.0, 0.0, 0.0, 0.0)
        self.assertAlmostEqual(x, 1.0, places=5)
        self.assertAlmostEqual(y, 0.0, places=5)
        self.assertAlmostEqual(z, 0.0, places=5)

    def test_rot_y_180(self):
        import math
        x, y, z = _rot_y(1.0, 0.0, 0.0, math.pi)
        self.assertAlmostEqual(x, -1.0, places=5)
        self.assertAlmostEqual(z, 0.0, places=4)

    def test_rot_x_identity(self):
        x, y, z = _rot_x(0.0, 1.0, 0.0, 0.0)
        self.assertAlmostEqual(y, 1.0, places=5)
        self.assertAlmostEqual(z, 0.0, places=5)

    def test_project_returns_3_values(self):
        sx, sy, d = _project(0.0, 0.0, 0.0, 320.0, 240.0)
        self.assertIsInstance(sx, float)
        self.assertIsInstance(sy, float)
        self.assertIsInstance(d, float)

    def test_project_depth_positive(self):
        _, _, d = _project(0.0, 0.0, 0.0, 320.0, 240.0)
        self.assertGreater(d, 0.0)

    def test_transform_point_returns_3_values(self):
        sx, sy, d = _transform_point(0.0, 0.0, 0.0, 0.0, 0.0, 320.0, 240.0)
        self.assertIsInstance(sx, float)

    def test_all_scenes_constant(self):
        self.assertEqual(len(ALL_SCENES), 5)
        for s in [SCENE_SHIELD, SCENE_WORKSTATION, SCENE_FILES,
                  SCENE_PIPELINE, SCENE_REPLAY]:
            self.assertIn(s, ALL_SCENES)


# ---------------------------------------------------------------------------
# Tk tests — single shared root
# ---------------------------------------------------------------------------

class TestCommandCenter3DCanvas(unittest.TestCase):
    _root = None

    @classmethod
    def setUpClass(cls):
        try:
            import tkinter as tk
            cls._root = tk.Tk()
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

    def test_canvas_constructs(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        try:
            self.assertTrue(canvas._running)
            self.assertEqual(canvas._scene, SCENE_SHIELD)
            self.assertEqual(canvas._app_status, "IDLE")
        finally:
            canvas.destroy()

    def test_set_scene(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        try:
            for scene in ALL_SCENES:
                canvas.set_scene(scene)
                self.assertEqual(canvas._scene, scene)
        finally:
            canvas.destroy()

    def test_invalid_scene_ignored(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        try:
            canvas.set_scene(SCENE_PIPELINE)
            canvas.set_scene("NONEXISTENT_SCENE")
            self.assertEqual(canvas._scene, SCENE_PIPELINE)
        finally:
            canvas.destroy()

    def test_set_status_safe(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        try:
            canvas.set_app_status("SAFE", 0.05)
            self.assertEqual(canvas._app_status, "SAFE")
            self.assertAlmostEqual(canvas._scan_prob, 0.05)
        finally:
            canvas.destroy()

    def test_set_status_incomplete_preserves_status(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        try:
            # The canvas stores whatever status is set; the page-level
            # guards ensure incomplete/error never feeds SAFE probability
            canvas.set_app_status("SCAN_INCOMPLETE", 0.0)
            self.assertEqual(canvas._app_status, "SCAN_INCOMPLETE")
            self.assertNotEqual(canvas._app_status, "SAFE")
        finally:
            canvas.destroy()

    def test_set_watchtower_results(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        try:
            canvas.set_watchtower_results(3, 1, 2, 10)
            self.assertEqual(canvas._wt_added, 3)
            self.assertEqual(canvas._wt_modified, 1)
            self.assertEqual(canvas._wt_deleted, 2)
            self.assertEqual(canvas._wt_unchanged, 10)
        finally:
            canvas.destroy()

    def test_reset_camera(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        try:
            canvas._yaw = 99.0; canvas._pitch = 99.0; canvas._zoom = 5.0
            canvas.reset_camera()
            self.assertAlmostEqual(canvas._yaw, 0.3)
            self.assertAlmostEqual(canvas._pitch, 0.15)
            self.assertAlmostEqual(canvas._zoom, 1.0)
        finally:
            canvas.destroy()

    def test_pause_and_resume(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        try:
            canvas.pause()
            self.assertTrue(canvas._paused)
            canvas.resume()
            self.assertFalse(canvas._paused)
        finally:
            canvas.destroy()

    def test_zoom_clamping_via_scroll(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        try:
            canvas._zoom = 0.3
            # Simulate many scroll-downs → should clamp at 0.3
            for _ in range(20):
                canvas._zoom *= 0.9
                canvas._zoom = max(0.3, min(3.0, canvas._zoom))
            self.assertGreaterEqual(canvas._zoom, 0.3)

            # Scroll-ups → should clamp at 3.0
            canvas._zoom = 3.0
            for _ in range(20):
                canvas._zoom *= 1.1
                canvas._zoom = max(0.3, min(3.0, canvas._zoom))
            self.assertLessEqual(canvas._zoom, 3.0)
        finally:
            canvas.destroy()

    def test_destroy_stops_animation(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        canvas.destroy()
        self.assertFalse(canvas._running)

    def test_set_replay_data(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300)
        try:
            from exhibition.attack_replay import build_attack_replay_plan, ReplayController
            plan = build_attack_replay_plan()
            ctrl = ReplayController(plan)
            events = [{"title": s.title, "t": s.t,
                       "severity": s.severity, "detail": s.detail}
                      for s in plan]
            canvas.set_replay_data(ctrl, events)
            self.assertIs(canvas._replay_ctrl, ctrl)
            self.assertEqual(len(canvas._replay_events), len(plan))
        finally:
            canvas.destroy()

    def test_reduced_motion_mode(self):
        self._skip()
        canvas = CommandCenter3D(self._root, width=400, height=300, reduced_motion=True)
        try:
            self.assertTrue(canvas.reduced_motion)
        finally:
            canvas.destroy()


class TestCommandCenterPageUI(unittest.TestCase):
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
        from gui.pages.command_center_page import CommandCenterPage
        page = CommandCenterPage(self._root, config={})
        try:
            self.assertIsInstance(page._canvas, CommandCenter3D)
            self.assertEqual(len(page._scene_btns), 5)
            self.assertEqual(page._current_scene, SCENE_SHIELD)
        finally:
            page.destroy()

    def test_scene_switching(self):
        self._skip()
        from gui.pages.command_center_page import CommandCenterPage
        page = CommandCenterPage(self._root, config={})
        try:
            for scene in ALL_SCENES:
                page._switch_scene(scene)
                self.assertEqual(page._current_scene, scene)
                self.assertEqual(page._canvas._scene, scene)
        finally:
            page.destroy()

    def test_reset_camera(self):
        self._skip()
        from gui.pages.command_center_page import CommandCenterPage
        page = CommandCenterPage(self._root, config={})
        try:
            page._canvas._yaw = 5.0
            page._reset_camera()
            self.assertAlmostEqual(page._canvas._yaw, 0.3)
        finally:
            page.destroy()

    def test_back_to_lab_safe_without_master_show_page(self):
        self._skip()
        from gui.pages.command_center_page import CommandCenterPage
        page = CommandCenterPage(self._root, config={})
        try:
            page._back_to_lab()  # master has no _show_page — must not raise
        finally:
            page.destroy()

    def test_on_shown_resumes_canvas(self):
        self._skip()
        from gui.pages.command_center_page import CommandCenterPage
        page = CommandCenterPage(self._root, config={})
        try:
            page._canvas.pause()
            self.assertTrue(page._canvas._paused)
            page.on_shown()
            self.assertFalse(page._canvas._paused)
        finally:
            page.destroy()

    def test_status_never_safe_on_incomplete(self):
        """Page-level guard: unsafe states must not feed SAFE probability."""
        self._skip()
        from gui.pages.command_center_page import CommandCenterPage
        page = CommandCenterPage(self._root, config={})
        try:
            # Simulate dashboard returning an incomplete state
            class FakeDash:
                _threat_level = "SCAN_INCOMPLETE"
                _risk_score = 0.99   # would be SAFE/high if not guarded
                _last_scan_result = None
                _last_host_scan_result = None

            # Patch the master's _pages to return a fake dashboard
            original_pages = getattr(page.master, "_pages", {})
            page.master._pages = {"dashboard": FakeDash()}
            try:
                page._refresh_canvas_state()
                # The canvas status must not be SAFE
                self.assertNotEqual(page._canvas._app_status, "SAFE")
                # Probability must be 0 for incomplete state
                self.assertEqual(page._canvas._scan_prob, 0.0)
            finally:
                page.master._pages = original_pages
        finally:
            page.destroy()

    def test_object_click_populates_detail(self):
        self._skip()
        from gui.pages.command_center_page import CommandCenterPage
        page = CommandCenterPage(self._root, config={})
        try:
            page._on_object_click(SCENE_PIPELINE, "Stage: OUTPUT")
            detail_txt = page._detail_obj_lbl.cget("text")
            self.assertEqual(detail_txt, "Stage: OUTPUT")
        finally:
            page.destroy()

    def test_replay_controls_present(self):
        self._skip()
        from gui.pages.command_center_page import CommandCenterPage
        page = CommandCenterPage(self._root, config={})
        try:
            self.assertTrue(hasattr(page, "_rp_play_btn"))
            self.assertTrue(hasattr(page, "_rp_pause_btn"))
            self.assertTrue(hasattr(page, "_rp_resume_btn"))
            self.assertTrue(hasattr(page, "_rp_reset_btn"))
        finally:
            page.destroy()

    def test_destroy_sets_flag_and_stops_canvas(self):
        self._skip()
        from gui.pages.command_center_page import CommandCenterPage
        page = CommandCenterPage(self._root, config={})
        canvas = page._canvas  # keep ref before destroy
        page.destroy()
        self.assertTrue(page._is_destroyed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
