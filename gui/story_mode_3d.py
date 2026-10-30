"""
SentinelML V2 — Six-Scene 3D Story Mode Canvas
===============================================
A narrative renderer built on the same perspective-projection math as
gui/command_center_3d.py. This is a Canvas-based 3D-style renderer, not a
GPU 3D engine and not a model-visualisation of the classifier's internals.

Scenes: NORMAL, SUSPICIOUS, AI_PIPELINE, VERDICT, INVESTIGATION, RESPONSE.
Scene 2 is an explicitly labelled simulation; scene 4 shows a live result
only when a valid scan is supplied, otherwise a clearly separated simulation.
Interaction: mouse drag (rotate), scroll (zoom), click (inspect object).
"""

from __future__ import annotations

import math
import time
import tkinter as tk
from typing import Any, Callable, Dict, List, Optional, Tuple

from gui.command_center_3d import (
    _rot_x,
    _rot_y,
    _project,
    _status_color,
)

_BG        = "#0b1427"
_PANEL     = "#162040"
_PANEL_ALT = "#0f1d38"
_GOLD      = "#e8c84a"
_CYAN      = "#38d8f5"
_WHITE     = "#f0f4ff"
_MUTED     = "#b8c5d9"
_SAFE      = "#34d897"
_WARNING   = "#fbb03b"
_CRITICAL  = "#ff6b6b"
_INCON     = "#c9a8ff"

SCENE_NORMAL        = "NORMAL"
SCENE_SUSPICIOUS    = "SUSPICIOUS"
SCENE_AI            = "AI_PIPELINE"
SCENE_VERDICT       = "VERDICT"
SCENE_INVESTIGATION = "INVESTIGATION"
SCENE_RESPONSE      = "RESPONSE"

STORY_SCENES = [
    SCENE_NORMAL,
    SCENE_SUSPICIOUS,
    SCENE_AI,
    SCENE_VERDICT,
    SCENE_INVESTIGATION,
    SCENE_RESPONSE,
]

SCENE_TITLES = {
    SCENE_NORMAL:        "NORMAL SYSTEM",
    SCENE_SUSPICIOUS:    "SUSPICIOUS ACTIVITY",
    SCENE_AI:            "AI ANALYSIS",
    SCENE_VERDICT:       "THREAT ASSESSMENT",
    SCENE_INVESTIGATION: "INVESTIGATION",
    SCENE_RESPONSE:      "RESPONSE",
}

# Provenance palette shared with the evidence correlation layer.
PROVENANCE_COLORS = {
    "MEASURED":    _SAFE,
    "SIMULATED":   _GOLD,
    "HEURISTIC":   _WARNING,
    "UNAVAILABLE": _MUTED,
    "ERROR":       _CRITICAL,
    "APPLICATION": _CYAN,
}

_SAFE_STATUSES = {"SAFE", "CLEAN"}
_ELEVATED_STATUSES = {"WARNING", "CRITICAL", "THREAT DETECTED", "HIGH"}
_INVALID_STATUSES = {
    "CANCELLED", "SCAN_INCOMPLETE", "INCOMPLETE", "ERROR", "ANALYSIS_ERROR",
    "INCONCLUSIVE", "NOT_SCANNED", "IDLE",
}


class StoryMode3D(tk.Canvas):
    """Six-scene narrative canvas — pure Tk, no external 3D libraries."""

    def __init__(self, master, width: int = 760, height: int = 500,
                 reduced_motion: bool = False,
                 on_select: Optional[Callable[[str, str, Optional[dict]], None]] = None,
                 feature_names: Optional[List[str]] = None,
                 **kwargs) -> None:
        kwargs.setdefault("bg", _BG)
        kwargs.setdefault("highlightthickness", 1)
        kwargs.setdefault("highlightbackground", "#162338")
        super().__init__(master, width=width, height=height, **kwargs)

        self.reduced_motion = reduced_motion
        self.on_select = on_select
        self._feature_names: List[str] = list(feature_names or [])

        self._scene_index = 0
        self._app_status = "IDLE"
        self._scan_prob = 0.0
        self._scan_provenance = "UNAVAILABLE"
        self._scan_id = ""
        self._files_inspected = 0
        self._processes = 0
        self._evidence_items: List[Dict[str, Any]] = []

        self._yaw = 0.25
        self._pitch = 0.15
        self._zoom = 1.0
        self._drag_x: Optional[int] = None
        self._drag_y: Optional[int] = None

        self._start_time = time.time()
        self._running = True
        self._paused = False
        self._after_id: Optional[str] = None
        self._hit_objects: List[Dict[str, Any]] = []

        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<B1-Motion>", self._on_drag)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<MouseWheel>", self._on_scroll)
        self.bind("<Button-4>", self._on_scroll)
        self.bind("<Button-5>", self._on_scroll)
        self.bind("<Configure>", self._on_configure)
        self.bind("<Destroy>", lambda e: self._on_destroy(e), add=True)

        self._schedule(33 if not reduced_motion else 400)

    # --- Public API ----------------------------------------------------------

    @property
    def current_scene(self) -> str:
        return STORY_SCENES[self._scene_index]

    @property
    def scene_index(self) -> int:
        return self._scene_index

    def set_scene(self, scene) -> None:
        """Select a scene by id or zero-based index."""
        if isinstance(scene, int):
            if 0 <= scene < len(STORY_SCENES):
                self._scene_index = scene
            return
        if scene in STORY_SCENES:
            self._scene_index = STORY_SCENES.index(scene)

    def next_scene(self) -> bool:
        if self._scene_index < len(STORY_SCENES) - 1:
            self._scene_index += 1
            return True
        return False

    def prev_scene(self) -> bool:
        if self._scene_index > 0:
            self._scene_index -= 1
            return True
        return False

    def set_app_status(self, status: str, probability: float = 0.0) -> None:
        self._app_status = str(status or "IDLE").upper()
        try:
            self._scan_prob = max(0.0, min(1.0, float(probability)))
        except (TypeError, ValueError):
            self._scan_prob = 0.0

    def set_scan_context(self, status: str, probability: float = 0.0,
                         provenance: str = "UNAVAILABLE",
                         scan_id: str = "") -> None:
        """Set the live-scan state used by the threat-assessment scene.

        provenance is one of MEASURED, SIMULATED, UNAVAILABLE or ERROR.
        Only MEASURED results are drawn as a live verdict.
        """
        self.set_app_status(status, probability)
        prov = str(provenance or "UNAVAILABLE").upper()
        self._scan_provenance = prov if prov in PROVENANCE_COLORS else "UNAVAILABLE"
        self._scan_id = str(scan_id or "")

    @property
    def has_live_result(self) -> bool:
        return (self._scan_provenance == "MEASURED"
                and self._app_status not in _INVALID_STATUSES)

    def set_scan_stats(self, files: int, procs: int) -> None:
        self._files_inspected = int(files)
        self._processes = int(procs)

    def set_evidence_items(self, items: List[Dict[str, Any]]) -> None:
        """Evidence rows for the investigation scene (dicts from the
        evidence correlator, ordered oldest to newest)."""
        self._evidence_items = [dict(i) for i in (items or [])][:8]

    def set_reduced_motion(self, flag: bool) -> None:
        self.reduced_motion = bool(flag)
        self._cancel_frame()
        self._schedule(400 if self.reduced_motion else 33)

    def reset_camera(self) -> None:
        self._yaw = 0.25
        self._pitch = 0.15
        self._zoom = 1.0

    def pause(self) -> None:
        self._paused = True
        self._cancel_frame()

    def resume(self) -> None:
        if self._paused:
            self._paused = False
            self._start_time = time.time()
            self._schedule(33 if not self.reduced_motion else 400)

    def redraw(self) -> None:
        """Force a single repaint without restarting the animation loop."""
        if self._paused:
            return
        try:
            if self.winfo_exists() and self.winfo_ismapped():
                self._render()
        except Exception:
            pass

    # --- Mouse ---------------------------------------------------------------

    def _on_press(self, event: tk.Event) -> None:
        self._drag_x = event.x
        self._drag_y = event.y
        for obj in self._hit_objects:
            if math.hypot(event.x - obj["sx"], event.y - obj["sy"]) <= obj["radius"]:
                if self.on_select:
                    try:
                        self.on_select(obj["scene"], obj["label"], obj.get("meta"))
                    except TypeError:
                        try:
                            self.on_select(obj["scene"], obj["label"])
                        except Exception:
                            pass
                    except Exception:
                        pass
                break

    def _on_drag(self, event: tk.Event) -> None:
        if self._drag_x is not None:
            self._yaw += (event.x - self._drag_x) * 0.01
            self._pitch += (event.y - self._drag_y) * 0.01
            self._pitch = max(-1.2, min(1.2, self._pitch))
            self._drag_x = event.x
            self._drag_y = event.y

    def _on_release(self, _event: tk.Event) -> None:
        self._drag_x = None
        self._drag_y = None

    def _on_scroll(self, event: tk.Event) -> None:
        if hasattr(event, "delta") and event.delta:
            self._zoom *= 1.1 if event.delta > 0 else 0.9
        elif getattr(event, "num", None) == 4:
            self._zoom *= 1.1
        else:
            self._zoom *= 0.9
        self._zoom = max(0.3, min(3.0, self._zoom))

    def _on_configure(self, _event: tk.Event) -> None:
        # Redraw once the canvas has a real size (avoids one blank frame).
        self.redraw()

    # --- Animation loop ------------------------------------------------------

    def _schedule(self, ms: int) -> None:
        if not self._running:
            return
        try:
            if self.winfo_exists():
                self._after_id = self.after(ms, self._frame)
        except Exception:
            self._after_id = None

    def _cancel_frame(self) -> None:
        if self._after_id:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _frame(self) -> None:
        if not self._running:
            return
        try:
            if not self.winfo_exists():
                self._running = False
                return
        except Exception:
            self._running = False
            return
        if self._paused or not self.winfo_ismapped():
            self._schedule(250 if not self.reduced_motion else 500)
            return
        self._render()
        self._schedule(33 if not self.reduced_motion else 400)

    def _render(self) -> None:
        try:
            self.delete("all")
            w = max(self.winfo_width(), 100)
            h = max(self.winfo_height(), 80)
            # Shrink type on small canvases so captions never clip.
            self._scale = max(0.62, min(1.0, min(w / 720.0, h / 470.0)))
            cx, cy = w / 2.0, h / 2.0
            t = time.time() - self._start_time
            self._hit_objects = []

            scene = self.current_scene
            if scene == SCENE_NORMAL:
                self._draw_normal(cx, cy, t, w, h)
            elif scene == SCENE_SUSPICIOUS:
                self._draw_suspicious(cx, cy, t, w, h)
            elif scene == SCENE_AI:
                self._draw_ai(cx, cy, t, w, h)
            elif scene == SCENE_VERDICT:
                self._draw_verdict(cx, cy, t, w, h)
            elif scene == SCENE_INVESTIGATION:
                self._draw_investigation(cx, cy, t, w, h)
            elif scene == SCENE_RESPONSE:
                self._draw_response(cx, cy, t, w, h)
            self._draw_hud(w, h)
        except Exception:
            pass

    # --- HUD -----------------------------------------------------------------

    def _font(self, size: int, bold: bool = False):
        s = max(7, int(round(size * getattr(self, "_scale", 1.0))))
        return ("Consolas", s, "bold") if bold else ("Consolas", s)

    def _draw_hud(self, w: int, h: int) -> None:
        sc = _status_color(self._app_status)
        scene = self.current_scene
        title = SCENE_TITLES.get(scene, scene)

        pill_w = max(150, int(230 * getattr(self, "_scale", 1.0)))
        self.create_rectangle(4, 4, pill_w, 28, fill="#1a2e56", outline="#2a4a7f")
        self.create_text(pill_w / 2, 16, text=f"STATUS: {self._app_status}",
                         font=self._font(12, True), fill=sc, anchor="center")

        self.create_rectangle(w - pill_w - 4, 4, w - 4, 28,
                              fill="#1a2e56", outline="#2a4a7f")
        self.create_text(w - pill_w / 2 - 4, 16,
                         text=f"SCENE {self._scene_index + 1}/{len(STORY_SCENES)}  ·  {title}",
                         font=self._font(10, True), fill=_GOLD, anchor="center")

        hint_w = int(400 * getattr(self, "_scale", 1.0))
        self.create_rectangle(w // 2 - hint_w // 2, h - 24,
                              w // 2 + hint_w // 2, h - 4,
                              fill="#0f1d38", outline="#2a4a7f")
        self.create_text(w // 2, h - 14,
                         text="Drag = rotate   Scroll = zoom   Click = inspect",
                         font=self._font(9), fill=_MUTED, anchor="center")

    def _draw_captions(self, cx: float, h: int, title: str, subtitle: str,
                       color: str) -> None:
        self.create_text(cx, h - 54, text=title,
                         font=self._font(12, True), fill=color)
        self.create_text(cx, h - 35, text=subtitle,
                         font=self._font(10), fill=_MUTED)

    def _badge(self, x: int, y: int, text: str, color: str,
               fill: str = "#1a1020") -> None:
        pad = 8
        f = self._font(9, True)
        width = max(90, len(text) * 7 + pad * 2)
        self.create_rectangle(x, y, x + width, y + 20, fill=fill, outline=color)
        self.create_text(x + width / 2, y + 10, text=text, font=f, fill=color)

    # --- Helpers -------------------------------------------------------------

    def _pp(self, x: float, y: float, z: float,
            cx: float, cy: float) -> Tuple[float, float, float]:
        x2, y2, z2 = _rot_y(x, y, z, self._yaw)
        x3, y3, z3 = _rot_x(x2, y2, z2, self._pitch)
        return _project(x3 * self._zoom, y3 * self._zoom,
                        z3 * self._zoom, cx, cy)

    def _draw_grid(self, cx: float, cy: float, w: int, h: int) -> None:
        gy = cy + h * 0.30
        self.create_line(cx - w * 0.42, gy, cx + w * 0.42, gy,
                         fill="#1e3a6e", width=1)
        for gx in range(-int(w * 0.4), int(w * 0.4), 46):
            self.create_line(cx + gx, gy, cx + gx * 1.3, gy + 26,
                             fill="#162850", width=1)

    @staticmethod
    def _box_faces(px, py, pz, sx, sy, sz):
        hw, hh, hd = sx / 2, sy / 2, sz / 2
        c = [
            (px - hw, py - hh, pz - hd), (px + hw, py - hh, pz - hd),
            (px + hw, py + hh, pz - hd), (px - hw, py + hh, pz - hd),
            (px - hw, py - hh, pz + hd), (px + hw, py - hh, pz + hd),
            (px + hw, py + hh, pz + hd), (px - hw, py + hh, pz + hd),
        ]
        return [
            [c[0], c[1], c[2], c[3]], [c[4], c[5], c[6], c[7]],
            [c[0], c[4], c[7], c[3]], [c[1], c[5], c[6], c[2]],
            [c[0], c[1], c[5], c[4]], [c[3], c[2], c[6], c[7]],
        ]

    def _draw_box(self, px, py, pz, sx, sy, sz,
                  cx, cy, fill: str, outline: str, width: int = 1) -> Tuple[float, float, float]:
        for face in self._box_faces(px, py, pz, sx, sy, sz):
            pts = [self._pp(v[0], v[1], v[2], cx, cy) for v in face]
            self.create_polygon([c for p in pts for c in (p[0], p[1])],
                                fill=fill, outline=outline, width=width)
        return self._pp(px, py, pz, cx, cy)

    # --- Scene 1: NORMAL SYSTEM ---------------------------------------------

    def _draw_normal(self, cx, cy, t, w, h) -> None:
        self._draw_grid(cx, cy, w, h)
        bob = 0.0 if self.reduced_motion else math.sin(t * 0.8) * 3

        # Workstation — the "measured" element of this scene.
        self._draw_box(0, -30, 0, 180, 116, 14, cx, cy, _PANEL, _GOLD)
        screen = [(-72, -72, -10), (72, -72, -10), (72, -4, -10), (-72, -4, -10)]
        pts = [self._pp(*p, cx, cy) for p in screen]
        self.create_polygon([c for p in pts for c in (p[0], p[1])],
                            fill="#14345f", outline=_CYAN, width=2)
        if self._files_inspected or self._processes:
            stats = f"MEASURED: {self._processes} procs · {self._files_inspected} files"
            stats_col = _SAFE
        else:
            stats = "NO LIVE SCAN YET"
            stats_col = _MUTED
        self.create_text(cx, cy - 34 + bob,
                         text=stats, font=self._font(10, True),
                         fill=stats_col, anchor="center")
        self.create_text(cx, cy - 16 + bob, text="READ-ONLY TELEMETRY",
                         font=self._font(9), fill=_MUTED, anchor="center")
        self._hit_objects.append({
            "scene": SCENE_NORMAL,
            "label": ("Workstation status — measured counters from the most "
                      "recent scan (read-only)"),
            "sx": cx, "sy": cy - 30, "radius": 48,
        })

        # Illustrative files on the desktop.
        for i in range(6):
            ang = math.radians(60 * i + 20)
            fx = math.cos(ang) * 190
            fz = math.sin(ang) * 105
            fy = 42 + (0.0 if self.reduced_motion else
                       math.sin(t * 0.9 + i) * 4)
            sx, sy, _ = self._draw_box(fx, fy, fz, 22, 28, 5, cx, cy,
                                       _PANEL_ALT, "#3a6aa8")
            self.create_text(sx, sy, text="FILE", font=self._font(7, True),
                             fill=_MUTED)
            self._hit_objects.append({
                "scene": SCENE_NORMAL,
                "label": f"Illustrative file object {i + 1} — not a real file listing",
                "sx": sx, "sy": sy, "radius": 15,
            })
            if i < 5:
                self.create_line(sx, sy + 16, sx, sy + 26,
                                 fill="#2a4a7f", width=1)

        self._badge(8, 34, "ILLUSTRATIVE OBJECTS", _MUTED)
        self._draw_captions(
            cx, h, "NORMAL SYSTEM  ·  BASELINE ACTIVITY",
            "Counters are measured; the file icons are illustrative, not a directory listing",
            _SAFE)

    # --- Scene 2: SUSPICIOUS ACTIVITY (simulated) ----------------------------

    def _draw_suspicious(self, cx, cy, t, w, h) -> None:
        self._draw_grid(cx, cy, w, h)
        auto = 0.0 if self.reduced_motion else t * 0.35

        # Dimmed workstation, as the simulated event unfolds around it.
        self._draw_box(0, -28, 0, 150, 96, 12, cx, cy, "#101a30", "#2a4a7f")
        self.create_text(cx, cy - 28, text="WORKSTATION",
                         font=self._font(9, True), fill=_MUTED)

        for i in range(7):
            ang = math.radians(51.4 * i) + auto
            fx = math.cos(ang) * 180
            fz = math.sin(ang) * 100
            fy = 30 + (0.0 if self.reduced_motion else
                       math.sin(t * 1.1 + i) * 5)
            # Harmless animation: alternating highlight, never touches disk.
            active = self.reduced_motion or ((t * 0.8 + i * 0.5) % 2.4) < 1.2
            col = _WARNING if active else _MUTED
            fill = "#241a10" if active else _PANEL_ALT
            sx, sy, _ = self._draw_box(fx, fy, fz, 22, 28, 5, cx, cy,
                                       fill, col, width=2 if active else 1)
            self.create_text(sx, sy, text="WRITE" if active else "FILE",
                             font=self._font(7, True), fill=col)
            if active:
                self.create_text(sx, sy - 20, text="!",
                                 font=self._font(12, True), fill=_WARNING)
            self._hit_objects.append({
                "scene": SCENE_SUSPICIOUS,
                "label": ("Simulated high-entropy write on file object "
                          f"{i + 1} — no host file is touched"),
                "sx": sx, "sy": sy, "radius": 16,
            })

        # Simulated entropy meter (illustrative, never a live sensor read).
        meter_x, meter_y = 34, h // 2 + 10
        meter_h = 90
        self.create_rectangle(meter_x, meter_y - meter_h,
                              meter_x + 16, meter_y,
                              fill="#0f1d38", outline="#2a4a7f")
        frac = 0.72 if self.reduced_motion else min(
            0.95, 0.35 + 0.6 * (math.sin(t * 0.9) * 0.5 + 0.5))
        self.create_rectangle(meter_x, meter_y - meter_h * frac,
                              meter_x + 16, meter_y,
                              fill=_WARNING, outline="")
        self.create_text(meter_x + 8, meter_y + 10, text="ENTROPY",
                         font=self._font(7, True), fill=_WARNING)
        self.create_text(meter_x + 8, meter_y + 22, text="(SIM)",
                         font=self._font(7), fill=_MUTED)

        # Persistent simulation labels (never removed during animation).
        self._badge(8, 34, "SIMULATION", _GOLD)
        self._badge(8, 58, "NO FILES ENCRYPTED", _GOLD)
        self.create_text(w - 10, 42, text="EDUCATIONAL ONLY",
                         font=self._font(9, True), fill=_GOLD, anchor="e")

        self._draw_captions(
            cx, h, "SUSPICIOUS ACTIVITY  ·  CONTROLLED SIMULATION",
            "A harmless animation of the behaviour SentinelML looks for — nothing is executed",
            _WARNING)

    # --- Scene 3: AI ANALYSIS ------------------------------------------------

    _STAGES = [
        ("TELEMETRY", "19 sensors", -270, _CYAN),
        ("FEATURES",  "vector",     -135, _GOLD),
        ("SCALER",    "standardise",   0, _MUTED),
        ("FOREST",    "100 trees",   135, _WARNING),
        ("PREDICT",   "probability", 270, _SAFE),
    ]

    def _draw_ai(self, cx, cy, t, w, h) -> None:
        self.create_rectangle(0, 0, w, h, fill=_BG, outline="")
        for gy in range(0, h, 40):
            self.create_line(0, gy, w, gy, fill="#1a2e56", width=1)

        pulse = 0.0 if self.reduced_motion else math.sin(t * 1.6) * 0.5 + 0.5
        projected = []
        for label, sub, sx_w, col in self._STAGES:
            sx, sy, d = self._pp(sx_w, 0, 0, cx, cy)
            projected.append((sx, sy, d, label, sub, col))

        for i in range(len(projected) - 1):
            x1, y1 = projected[i][0], projected[i][1]
            x2, y2 = projected[i + 1][0], projected[i + 1][1]
            self.create_line(x1, y1, x2, y2, fill="#2a5aa0", width=2,
                             arrow=tk.LAST)
            if not self.reduced_motion:
                frac = (t * 0.5 + i * 0.25) % 1.0
                px = x1 + (x2 - x1) * frac
                py = y1 + (y2 - y1) * frac
                self.create_oval(px - 4, py - 4, px + 4, py + 4,
                                 fill=projected[i][5], outline="")

        for sx, sy, d, label, sub, col in projected:
            scale = max(0.55, min(1.35, 320 / max(d, 100)))
            bw, bh = 46 * scale, 34 * scale
            if label == "PREDICT" and self.has_live_result:
                gr = 46 + pulse * 12
                self.create_oval(sx - gr, sy - gr, sx + gr, sy + gr,
                                 fill="", outline=col, width=2)
            self.create_rectangle(sx - bw, sy - bh, sx + bw, sy + bh,
                                  fill=_PANEL, outline=col, width=2)
            self.create_text(sx, sy - 8, text=label,
                             font=self._font(10, True), fill=col)
            self.create_text(sx, sy + 9, text=sub,
                             font=self._font(8), fill=_MUTED)
            if label == "FEATURES" and self._feature_names:
                detail = (f"19 model features, in the trained order: "
                          + ", ".join(self._feature_names))
            else:
                detail = f"Pipeline stage: {label} ({sub}) — diagram only"
            self._hit_objects.append({
                "scene": SCENE_AI,
                "label": detail,
                "sx": sx, "sy": sy, "radius": 34,
            })

        out_x, out_y = projected[-1][0], projected[-1][1]
        if self.has_live_result:
            self.create_text(out_x, out_y + 50,
                             text=f"p={self._scan_prob:.3f}  →  {self._app_status}",
                             font=self._font(11, True),
                             fill=_status_color(self._app_status))

        self.create_text(cx, h - 70,
                         text="19 features → StandardScaler → Random Forest (100 trees)",
                         font=self._font(9), fill=_MUTED)
        self._draw_captions(
            cx, h, "AI ANALYSIS  ·  TRAINED PIPELINE",
            "Diagram of pipeline stages — not a view of the model's internal computation",
            _GOLD)

    # --- Scene 4: THREAT ASSESSMENT -----------------------------------------

    def _draw_verdict(self, cx, cy, t, w, h) -> None:
        self._draw_grid(cx, cy, w, h)
        live = self.has_live_result
        sc = _status_color(self._app_status) if live else _MUTED
        cy_s = cy - 28
        R = 88.0
        auto_yaw = self._yaw + (t * 0.35 if not self.reduced_motion else 0)

        def proj(x, y, z):
            x2, y2, z2 = _rot_y(x, y, z, auto_yaw)
            x3, y3, z3 = _rot_x(x2, y2, z2, self._pitch)
            return _project(x3 * self._zoom, y3 * self._zoom,
                            z3 * self._zoom, cx, cy_s)

        hexa = [(math.cos(math.radians(60 * i + 30)) * R,
                 math.sin(math.radians(60 * i + 30)) * R * 1.12, 0.0)
                for i in range(6)]
        front = [proj(*p) for p in hexa]
        back = [proj(p[0], p[1], p[2] - 14) for p in hexa]

        for i in range(6):
            j = (i + 1) % 6
            pts = [front[i], front[j], back[j], back[i]]
            self.create_polygon([c for p in pts for c in (p[0], p[1])],
                                fill=_PANEL, outline="#2a4a7f", width=1)
        self.create_polygon([c for p in front for c in (p[0], p[1])],
                            fill=_PANEL_ALT, outline=sc, width=3)
        inner = [(cx + (p[0] - cx) * 0.62, cy_s + (p[1] - cy_s) * 0.62)
                 for p in front]
        self.create_polygon([c for p in inner for c in (p[0], p[1])],
                            fill=_PANEL, outline=_GOLD, width=1, dash=(4, 3))

        glyphs = {
            "SAFE": "S", "CLEAN": "S", "SCANNING": "…", "WARNING": "!",
            "CRITICAL": "!", "THREAT DETECTED": "!", "ERROR": "×",
            "ANALYSIS_ERROR": "×", "CANCELLED": "–", "SCAN_INCOMPLETE": "–",
            "INCONCLUSIVE": "?", "IDLE": "S", "NOT_SCANNED": "?",
        }
        self.create_text(cx, cy_s, text=glyphs.get(self._app_status, "?") if live else "?",
                         font=("Arial", max(18, int(26 * getattr(self, "_scale", 1))), "bold"),
                         fill=sc)

        ring_r = 126
        self.create_oval(cx - ring_r, cy_s - ring_r,
                         cx + ring_r, cy_s + ring_r,
                         outline="#1e3a6e", width=7)
        prob = self._scan_prob if live else 0.0
        if prob > 0:
            extent = -359.9 * max(0.0, min(1.0, prob))
            self.create_arc(cx - ring_r, cy_s - ring_r,
                            cx + ring_r, cy_s + ring_r,
                            start=90, extent=extent, style=tk.ARC,
                            outline=sc, width=7)
        if live:
            self.create_text(cx, cy_s + ring_r + 18,
                             text=f"{prob * 100:.1f}%",
                             font=self._font(16, True), fill=sc)
        else:
            self.create_text(cx, cy_s + ring_r + 18,
                             text="NO VALID SCAN YET",
                             font=self._font(10, True), fill=_MUTED)

        for frac, label in ((0.5, "0.50 WARN"), (0.9, "0.90 CRIT")):
            ang = math.radians(90 - 360 * frac)
            if frac == 0.5:
                # Placed clear of the centred caption beneath the ring
                # ("NO VALID SCAN YET" / "xx.x%") so the two never overlap.
                tx, ty, anchor = cx + 74, cy_s + ring_r + 18, "w"
            else:
                tx = cx + math.cos(ang) * (ring_r + 18)
                ty = cy_s - math.sin(ang) * (ring_r + 18)
                anchor = "center"
            self.create_text(tx, ty, text=label, anchor=anchor,
                             font=self._font(8), fill=_MUTED)

        if live:
            prov = f"LIVE SCAN · {self._scan_id or 'SCAN'}"
            self._badge(8, 34, "MEASURED RESULT", _SAFE, fill="#0d241c")
            self.create_text(8, 68, text=prov, anchor="nw",
                             font=self._font(8), fill=_SAFE)
        else:
            # Separate, clearly labelled educational example (never presented
            # as a live verdict). Kept inset so it cannot be confused with
            # the main gauge.
            self._badge(8, 34, "NO LIVE RESULT", _MUTED)
            self.create_text(8, 68, text="Educational example (simulated):",
                             anchor="nw", font=self._font(8), fill=_GOLD)
            sim_x, sim_y, sim_r = 78, 108, 18
            self.create_oval(sim_x - sim_r, sim_y - sim_r,
                             sim_x + sim_r, sim_y + sim_r,
                             outline=_WARNING, width=2)
            self.create_arc(sim_x - sim_r, sim_y - sim_r,
                            sim_x + sim_r, sim_y + sim_r,
                            start=90, extent=-359.9 * 0.65, style=tk.ARC,
                            outline=_WARNING, width=2)
            self.create_text(sim_x + sim_r + 8, sim_y - 6,
                             text="p=0.650", anchor="w",
                             font=self._font(8, True), fill=_WARNING)
            self.create_text(sim_x + sim_r + 8, sim_y + 8,
                             text="WARNING (SIM)", anchor="w",
                             font=self._font(8), fill=_MUTED)
            self._hit_objects.append({
                "scene": SCENE_VERDICT,
                "label": ("Simulated example only — not a result from this "
                          "machine; run a scan to see a real verdict"),
                "sx": sim_x, "sy": sim_y, "radius": 24,
            })

        scanner_label = "MEASURED" if live else "SIMULATED EXAMPLE"
        self._draw_captions(
            cx, h,
            "THREAT ASSESSMENT  ·  " + scanner_label,
            "Prediction ≠ proof: thresholds 0.50 warn / 0.90 critical; failed scans are never SAFE",
            _status_color(self._app_status) if live else _GOLD)

    # --- Scene 5: INVESTIGATION ---------------------------------------------

    def _draw_investigation(self, cx, cy, t, w, h) -> None:
        self._draw_grid(cx, cy, w, h)
        items = self._evidence_items
        axis_y = cy - 12
        left = cx - min(300, w * 0.36)
        right = cx + min(300, w * 0.36)

        self.create_line(left, axis_y, right, axis_y,
                         fill="#2a4a7f", width=2, arrow=tk.LAST)
        self.create_text(left, axis_y + 16, text="EARLIER",
                         font=self._font(7), fill=_MUTED, anchor="w")
        self.create_text(right, axis_y + 16, text="LATER",
                         font=self._font(7), fill=_MUTED, anchor="e")

        if not items:
            self.create_text(cx, cy - 70, text="NO EVIDENCE COLLECTED YET",
                             font=self._font(11, True), fill=_MUTED)
            self.create_text(cx, cy - 48,
                             text="Run a scan, a scenario, or an integrity comparison",
                             font=self._font(9), fill=_MUTED)
        else:
            n = len(items)
            step = (right - left) / max(1, n) if n > 1 else 0
            for i, item in enumerate(items):
                px = left + step * i + (0 if n > 1 else (right - left) / 2)
                prov = str(item.get("provenance", "UNAVAILABLE")).upper()
                col = PROVENANCE_COLORS.get(prov, _MUTED)
                lit = self.reduced_motion or (
                    (t * 0.7 - i * 0.45) % max(1.0, n) < 1.2)
                r = 9 if lit else 7
                self.create_line(px, axis_y + r, px, axis_y + 34,
                                 fill="#2a4a7f", width=1)
                self.create_oval(px - r, axis_y - r, px + r, axis_y + r,
                                 fill=col if lit else _PANEL, outline=col,
                                 width=2)
                self.create_text(px, axis_y + 48, text=f"{i + 1:02d}",
                                 font=self._font(8, True), fill=col)
                max_chars = max(6, min(22, int(max(48, step - 10) / 4.8)))
                title = str(item.get("title", ""))
                if len(title) > max_chars:
                    title = title[:max_chars - 1] + "…"
                self.create_text(px, axis_y + 62, text=title,
                                 font=self._font(7), fill=_MUTED)
                self.create_text(px, axis_y + 76, text=prov[:11],
                                 font=self._font(7, True), fill=col)
                self._hit_objects.append({
                    "scene": SCENE_INVESTIGATION,
                    "label": str(item.get("title", "Evidence item")),
                    "sx": px, "sy": axis_y, "radius": 16,
                    "meta": {"index": i, "provenance": prov,
                             "timestamp": item.get("timestamp"),
                             "source": item.get("source", ""),
                             "detail": item.get("detail", ""),
                             "limitations": item.get("limitations", [])},
                })

        # Provenance legend
        legend = [("MEASURED", _SAFE), ("SIMULATED", _GOLD),
                  ("HEURISTIC", _WARNING), ("UNAVAILABLE", _MUTED),
                  ("ERROR", _CRITICAL)]
        lx = 14
        for i, (name, col) in enumerate(legend):
            self.create_oval(lx, h - 96, lx + 8, h - 88, fill=col, outline="")
            self.create_text(lx + 12, h - 92, text=name, anchor="w",
                             font=self._font(7), fill=col)
            lx += 74

        self._draw_captions(
            cx, h, "INVESTIGATION  ·  CORRELATED EVIDENCE",
            "Click a marker to read its timestamp, source, and limitations",
            _CYAN)

    # --- Scene 6: RESPONSE ---------------------------------------------------

    def _draw_response(self, cx, cy, t, w, h) -> None:
        self._draw_grid(cx, cy, w, h)
        threat_active = self._app_status in _ELEVATED_STATUSES
        barrier_col = _WARNING if threat_active else _SAFE

        dome_cy = cy + 12
        self.create_oval(cx - 185, dome_cy - 55, cx + 185, dome_cy + 75,
                         outline=barrier_col, width=3)
        self.create_oval(cx - 185, dome_cy - 120, cx + 185, dome_cy + 40,
                         outline=barrier_col, width=2)
        self.create_oval(cx - 150, dome_cy - 90, cx + 150, dome_cy + 30,
                         outline="#2a4a7f", width=1, dash=(4, 4))

        for i in range(4):
            fx = -48 + i * 32
            fz = 8 * math.sin(i * 1.7)
            fy = 4 + (0.0 if self.reduced_motion else math.sin(t + i) * 4)
            sx, sy, _ = self._draw_box(fx, fy, fz, 16, 20, 5, cx, cy,
                                       _PANEL_ALT, _SAFE)
            self._hit_objects.append({
                "scene": SCENE_RESPONSE,
                "label": "Evidence to preserve before remediation (read-only)",
                "sx": sx, "sy": sy, "radius": 14,
            })

        for i in range(6):
            ang = math.radians(60 * i) + (0 if self.reduced_motion else t * 0.1)
            tx = math.cos(ang) * 235
            tz = math.sin(ang) * 120
            self._draw_box(tx, -8, tz, 20, 26, 6, cx, cy, "#2a1218", _CRITICAL)
            ex = math.cos(ang) * 188
            ez = math.sin(ang) * 96
            x1, y1, _ = self._pp(tx, -8, tz, cx, cy)
            x2, y2, _ = self._pp(ex, -8, ez, cx, cy)
            self.create_line(x1, y1, x2, y2, fill=_CRITICAL, width=1,
                             dash=(3, 4))
            self._hit_objects.append({
                "scene": SCENE_RESPONSE,
                "label": "Detected threat indicator (advisory only)",
                "sx": x1, "sy": y1, "radius": 15,
            })

        self.create_text(cx, dome_cy + 96,
                         text="ADVISORY BARRIER", font=self._font(10, True),
                         fill=barrier_col)

        steps = "1 PRESERVE EVIDENCE  ·  2 ISOLATE HOST  ·  3 RESTORE TRUSTED BACKUP"
        self.create_text(cx, h - 76, text=steps,
                         font=self._font(8, True), fill=_CYAN)
        self._draw_captions(
            cx, h, "RESPONSE  ·  OPERATOR-DRIVEN",
            "SentinelML advises; it does not block, quarantine, or restore files",
            barrier_col)

    # --- Destroy -------------------------------------------------------------

    def _on_destroy(self, event: tk.Event) -> None:
        if event.widget == self:
            self._running = False
            self._cancel_frame()

    def destroy(self) -> None:
        self._running = False
        self._cancel_frame()
        try:
            super().destroy()
        except Exception:
            pass
