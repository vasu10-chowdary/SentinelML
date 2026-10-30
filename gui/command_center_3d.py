"""
SentinelML V2 — Interactive 3D Command Center Canvas
=====================================================
Five selectable 3D scenes rendered on a single tk.Canvas using
perspective-projection math — same renderer architecture as
gui/dashboard_3d.py (no external 3D libraries required).

Scenes: SHIELD, WORKSTATION, FILES, AI_PIPELINE, ATTACK_REPLAY.
Interaction: mouse drag (rotate), scroll (zoom), click (select object).
Safety: never shows SAFE for incomplete/error/cancelled states.
"""

from __future__ import annotations

import math
import random
import time
import tkinter as tk
from typing import Any, Callable, Dict, List, Optional, Tuple

_BG           = "#0b1427"   # matched to EX_COLORS bg
_GOLD         = "#e8c84a"   # matched to EX_COLORS gold
_CYAN         = "#38d8f5"   # matched to EX_COLORS cyan
_WHITE        = "#f0f4ff"   # matched to EX_COLORS white
_MUTED        = "#b8c5d9"   # raised contrast (was #94a3b8 → ~3.5:1, now ~7:1)
_SAFE         = "#34d897"   # matched to EX_COLORS safe
_WARNING      = "#fbb03b"   # matched to EX_COLORS warning
_CRITICAL     = "#ff6b6b"   # matched to EX_COLORS critical
_INCONCLUSIVE = "#c9a8ff"   # matched to EX_COLORS inconclusive
_CANCELLED    = "#7ec8e3"   # raised from #64748b (~2.5:1) to #7ec8e3 (~7.6:1)
_ERROR        = "#ff6b6b"
_SIMULATED    = "#fbb03b"   # matched to EX_COLORS simulated

SCENE_SHIELD      = "SHIELD"
SCENE_WORKSTATION = "WORKSTATION"
SCENE_FILES       = "FILES"
SCENE_PIPELINE    = "AI_PIPELINE"
SCENE_REPLAY      = "ATTACK_REPLAY"
ALL_SCENES = [SCENE_SHIELD, SCENE_WORKSTATION, SCENE_FILES, SCENE_PIPELINE, SCENE_REPLAY]

_STATUS_COLOR = {
    "SAFE": _SAFE, "CLEAN": _SAFE, "NO_THREATS": _SAFE,
    "WARNING": _WARNING, "ELEVATED": _WARNING,
    "CRITICAL": _CRITICAL, "THREAT": _CRITICAL, "THREAT DETECTED": _CRITICAL,
    "INCONCLUSIVE": _INCONCLUSIVE, "LIMITED_COVERAGE": _INCONCLUSIVE,
    "CANCELLED": _CANCELLED, "SCAN_INCOMPLETE": _CANCELLED, "INCOMPLETE": _CANCELLED,
    "ERROR": _ERROR, "ANALYSIS_ERROR": _ERROR,
    "IDLE": _CYAN, "SCANNING": _CYAN, "NOT_SCANNED": _MUTED,
}


def _status_color(status: str) -> str:
    return _STATUS_COLOR.get(str(status).upper(), _MUTED)


# --- 3-D math ----------------------------------------------------------------

def _rot_y(x: float, y: float, z: float, a: float) -> Tuple[float, float, float]:
    ca, sa = math.cos(a), math.sin(a)
    return x * ca - z * sa, y, x * sa + z * ca


def _rot_x(x: float, y: float, z: float, a: float) -> Tuple[float, float, float]:
    ca, sa = math.cos(a), math.sin(a)
    return x, y * ca - z * sa, y * sa + z * ca


def _project(x: float, y: float, z: float,
             cx: float, cy: float, fov: float = 320.0) -> Tuple[float, float, float]:
    d = max(fov + z, 1.0)
    return cx + x * fov / d, cy + y * fov / d, d


def _transform_point(x: float, y: float, z: float,
                     yaw: float, pitch: float,
                     cx: float, cy: float,
                     zoom: float = 1.0,
                     fov: float = 320.0) -> Tuple[float, float, float]:
    x2, y2, z2 = _rot_y(x, y, z, yaw)
    x3, y3, z3 = _rot_x(x2, y2, z2, pitch)
    return _project(x3 * zoom, y3 * zoom, z3 * zoom, cx, cy, fov)


# --- Canvas ------------------------------------------------------------------

class CommandCenter3D(tk.Canvas):
    """Interactive 3-D Command Center canvas — zero external dependencies."""

    def __init__(self, master, width: int = 680, height: int = 480,
                 reduced_motion: bool = False,
                 on_select: Optional[Callable[[str, str], None]] = None,
                 **kwargs) -> None:
        kwargs.setdefault("bg", _BG)
        kwargs.setdefault("highlightthickness", 1)
        kwargs.setdefault("highlightbackground", "#162338")
        super().__init__(master, width=width, height=height, **kwargs)

        self.reduced_motion = reduced_motion
        self.on_select = on_select

        self._yaw:   float = 0.3
        self._pitch: float = 0.15
        self._zoom:  float = 1.0
        self._drag_x: Optional[int] = None
        self._drag_y: Optional[int] = None

        self._app_status:      str   = "IDLE"
        self._scan_prob:       float = 0.0
        self._files_inspected: int   = 0
        self._processes:       int   = 0

        self._wt_added:     int = 0
        self._wt_modified:  int = 0
        self._wt_deleted:   int = 0
        self._wt_unchanged: int = 0

        self._replay_ctrl   = None
        self._replay_events: List[Dict[str, Any]] = []

        self._scene       = SCENE_SHIELD
        self._start_time  = time.time()
        self._running     = True
        self._paused      = False
        self._after_id: Optional[str] = None
        self._hit_objects: List[Dict[str, Any]] = []

        self.bind("<ButtonPress-1>",   self._on_press)
        self.bind("<B1-Motion>",       self._on_drag)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<MouseWheel>",      self._on_scroll)
        self.bind("<Button-4>",        self._on_scroll)
        self.bind("<Button-5>",        self._on_scroll)
        self.bind("<Destroy>", lambda e: self._on_destroy(e), add=True)

        self._schedule(33)

    # --- Public API ----------------------------------------------------------

    def set_scene(self, scene: str) -> None:
        if scene in ALL_SCENES:
            self._scene = scene

    def set_app_status(self, status: str, probability: float = 0.0) -> None:
        self._app_status = str(status).upper()
        try:
            self._scan_prob = max(0.0, min(1.0, float(probability)))
        except (TypeError, ValueError):
            self._scan_prob = 0.0

    def set_scan_stats(self, files: int, procs: int) -> None:
        self._files_inspected = int(files)
        self._processes = int(procs)

    def set_watchtower_results(self, added: int, modified: int,
                               deleted: int, unchanged: int) -> None:
        self._wt_added     = added
        self._wt_modified  = modified
        self._wt_deleted   = deleted
        self._wt_unchanged = unchanged

    def set_replay_data(self, ctrl, events: List[Dict[str, Any]]) -> None:
        self._replay_ctrl   = ctrl
        self._replay_events = events or []

    def reset_camera(self) -> None:
        self._yaw   = 0.3
        self._pitch = 0.15
        self._zoom  = 1.0

    def pause(self) -> None:
        self._paused = True
        if self._after_id:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def resume(self) -> None:
        if self._paused:
            self._paused = False
            self._start_time = time.time()
            self._schedule(33)

    # --- Mouse ---------------------------------------------------------------

    def _on_press(self, event: tk.Event) -> None:
        self._drag_x = event.x
        self._drag_y = event.y
        for obj in self._hit_objects:
            if math.hypot(event.x - obj["sx"], event.y - obj["sy"]) <= obj["radius"]:
                if self.on_select:
                    try:
                        self.on_select(self._scene, obj["label"])
                    except Exception:
                        pass
                break

    def _on_drag(self, event: tk.Event) -> None:
        if self._drag_x is not None:
            self._yaw   += (event.x - self._drag_x) * 0.01
            self._pitch += (event.y - self._drag_y) * 0.01
            self._pitch  = max(-1.2, min(1.2, self._pitch))
            self._drag_x = event.x
            self._drag_y = event.y

    def _on_release(self, _event: tk.Event) -> None:
        self._drag_x = None
        self._drag_y = None

    def _on_scroll(self, event: tk.Event) -> None:
        if hasattr(event, "delta") and event.delta:
            self._zoom *= 1.1 if event.delta > 0 else 0.9
        elif event.num == 4:
            self._zoom *= 1.1
        else:
            self._zoom *= 0.9
        self._zoom = max(0.3, min(3.0, self._zoom))

    # --- Animation loop ------------------------------------------------------

    def _schedule(self, ms: int) -> None:
        if self._running:
            try:
                if self.winfo_exists():
                    self._after_id = self.after(ms, self._frame)
            except Exception:
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
            self._schedule(250)
            return
        try:
            self.delete("all")
            w = max(self.winfo_width(), 100)
            h = max(self.winfo_height(), 80)
            cx, cy = w / 2.0, h / 2.0
            t = time.time() - self._start_time
            self._hit_objects = []
            if self._scene == SCENE_SHIELD:
                self._draw_shield(cx, cy, t, w, h)
            elif self._scene == SCENE_WORKSTATION:
                self._draw_workstation(cx, cy, t, w, h)
            elif self._scene == SCENE_FILES:
                self._draw_files(cx, cy, t, w, h)
            elif self._scene == SCENE_PIPELINE:
                self._draw_pipeline(cx, cy, t, w, h)
            elif self._scene == SCENE_REPLAY:
                self._draw_replay(cx, cy, t, w, h)
            self._draw_hud(w, h)
        except Exception:
            pass
        self._schedule(33)

    # --- HUD -----------------------------------------------------------------

    def _draw_hud(self, w: int, h: int) -> None:
        sc = _status_color(self._app_status)
        labels = {
            SCENE_SHIELD: "SENTINEL SHIELD", SCENE_WORKSTATION: "SYSTEM WORKSTATION",
            SCENE_FILES: "FILE INTEGRITY", SCENE_PIPELINE: "AI PIPELINE",
            SCENE_REPLAY: "ATTACK REPLAY",
        }
        scene_name = labels.get(self._scene, self._scene)
        # Top-right: scene label pill
        self.create_rectangle(w - 180, 4, w - 4, 28, fill="#1a2e56", outline="#2a4a7f")
        self.create_text(w - 92, 16, text=scene_name,
                         anchor="center", font=("Consolas", 11, "bold"), fill=_GOLD)
        # Top-left: status pill
        self.create_rectangle(4, 4, 220, 28, fill="#1a2e56", outline="#2a4a7f")
        self.create_text(112, 16, text=f"STATUS: {self._app_status}",
                         anchor="center", font=("Consolas", 14, "bold"), fill=sc)
        # Bottom hint
        self.create_rectangle(w//2 - 180, h - 24, w//2 + 180, h - 4,
                              fill="#0f1d38", outline="#2a4a7f")
        self.create_text(w // 2, h - 14,
                         text="Drag = rotate   Scroll = zoom   Click = detail",
                         font=("Consolas", 10), fill=_MUTED, anchor="center")

    # --- Helpers -------------------------------------------------------------

    def _pp(self, x: float, y: float, z: float,
            cx: float, cy: float) -> Tuple[float, float, float]:
        return _transform_point(x, y, z, self._yaw, self._pitch, cx, cy, self._zoom)

    def _draw_grid(self, cx: float, cy: float, w: int, h: int, sc: str) -> None:
        gy = cy + h * 0.28
        # Brighter grid so scene floors are visible
        self.create_line(cx - w * 0.4, gy, cx + w * 0.4, gy, fill="#1e3a6e", width=1)
        for gx in range(-int(w * 0.4), int(w * 0.4), 50):
            self.create_line(cx + gx, gy, cx + gx * 1.25, gy + 22, fill="#162850", width=1)

    def _box_faces(self, px, py, pz, sx, sy, sz):
        hw, hh, hd = sx / 2, sy / 2, sz / 2
        c = [
            (px-hw, py-hh, pz-hd), (px+hw, py-hh, pz-hd),
            (px+hw, py+hh, pz-hd), (px-hw, py+hh, pz-hd),
            (px-hw, py-hh, pz+hd), (px+hw, py-hh, pz+hd),
            (px+hw, py+hh, pz+hd), (px-hw, py+hh, pz+hd),
        ]
        return [
            [c[0],c[1],c[2],c[3]], [c[4],c[5],c[6],c[7]],
            [c[0],c[4],c[7],c[3]], [c[1],c[5],c[6],c[2]],
            [c[0],c[1],c[5],c[4]], [c[3],c[2],c[6],c[7]],
        ]

    # --- Scene 1: SHIELD -----------------------------------------------------

    def _draw_shield(self, cx, cy, t, w, h) -> None:
        sc = _status_color(self._app_status)
        self._draw_grid(cx, cy, w, h, sc)
        auto_yaw = self._yaw + (t * 0.4 if not self.reduced_motion else 0)

        if not self.reduced_motion:
            for i, (r_orb, spd, col) in enumerate([
                    (110, 0.3, "#1e4a7a"), (140, -0.2, "#2456a0"), (170, 0.12, "#163870")]):
                ang = t * spd + i * 1.2
                ox = cx + math.cos(ang) * r_orb
                oy = cy + math.sin(ang) * r_orb * 0.35
                self.create_oval(ox-4, oy-4, ox+4, oy+4, fill=sc, outline=_WHITE)

        R = 80.0
        pts_obj = [(math.cos(math.radians(60*i+30))*R, math.sin(math.radians(60*i+30))*R*1.15, 0.0)
                   for i in range(6)]

        def proj(x, y, z):
            x2, y2, z2 = _rot_y(x, y, z, auto_yaw)
            x3, y3, z3 = _rot_x(x2, y2, z2, self._pitch)
            return _project(x3*self._zoom, y3*self._zoom, z3*self._zoom, cx, cy-15)

        fp = [proj(*p) for p in pts_obj]
        bp = [proj(p[0], p[1], p[2]-14) for p in pts_obj]

        sides = []
        n = len(pts_obj)
        for i in range(n):
            j = (i+1) % n
            sides.append((fp[i][0],fp[i][1], fp[j][0],fp[j][1],
                          bp[j][0],bp[j][1], bp[i][0],bp[i][1],
                          (fp[i][2]+fp[j][2])/2))
        sides.sort(key=lambda x: x[8], reverse=True)
        for s in sides:
            self.create_polygon(s[:8], fill="#162040", outline="#2a4a7f", width=1)

        flat_f = [c for p in fp for c in (p[0], p[1])]
        self.create_polygon(flat_f, fill="#162040", outline=sc, width=3)
        flat_i2 = []
        for sx, sy, _ in fp:
            flat_i2.extend([cx+(sx-cx)*0.6, cy-15+(sy-cy+15)*0.6])
        self.create_polygon(flat_i2, fill="#0f1d38", outline=_GOLD, width=1, dash=(4,3))

        status_map = {
            "SAFE":("S",_SAFE), "SCANNING":("↻",_CYAN), "WARNING":("!",_WARNING),
            "THREAT DETECTED":("⚠",_CRITICAL), "CRITICAL":("⚠",_CRITICAL),
            "IDLE":("S",_CYAN), "ERROR":("✕",_ERROR), "ANALYSIS_ERROR":("✕",_ERROR),
            "CANCELLED":("—",_CANCELLED), "SCAN_INCOMPLETE":("—",_CANCELLED),
            "INCONCLUSIVE":("?",_INCONCLUSIVE),
        }
        em_txt, em_col = status_map.get(self._app_status, ("S", sc))
        self.create_text(cx, cy-15, text=em_txt, font=("Arial", 22, "bold"), fill=em_col)

        if self._app_status == "SCANNING" and not self.reduced_motion:
            for k in range(3):
                r_wave = ((t*60 + k*40) % 130)
                alpha = max(0, 1.0 - r_wave/130)
                self.create_oval(cx-r_wave, cy-15-r_wave*0.6,
                                 cx+r_wave, cy-15+r_wave*0.6,
                                 outline=sc, width=max(1, int(alpha*3)))

        if not self.reduced_motion and self._app_status != "IDLE":
            for k in range(8):
                a = t*0.7 + k*0.78
                r = 100 + math.sin(t+k)*20
                px = cx + math.cos(a)*r
                py = cy-15 + math.sin(a)*r*0.5
                self.create_oval(px-2, py-2, px+2, py+2, fill=sc, outline="")

        prob_txt = f"{self._scan_prob*100:.1f}%" if self._scan_prob > 0 else ""
        self.create_text(cx, h-48, text=f"SENTINEL SHIELD  ·  {self._app_status}",
                         font=("Consolas", 14, "bold"), fill=sc)
        if prob_txt:
            self.create_text(cx, h-30, text=f"Threat probability: {prob_txt}",
                             font=("Consolas", 12), fill=_MUTED)

    # --- Scene 2: WORKSTATION ------------------------------------------------

    _WS_NODES = [
        ("total_processes", -120, -40, -20, "MEASURED"),
        ("suspicious_process_count", -60, -70, 0, "MEASURED"),
        ("avg_entropy", 20, -70, 10, "MEASURED"),
        ("network_connection_count", 100, -40, -10, "MEASURED"),
        ("malfind_injection_count", -80, 20, 0, "HEURISTIC"),
        ("registry_handle_count", 60, 20, 20, "HEURISTIC"),
        ("cmd_vssadmin_count", 0, 60, -10, "MEASURED"),
        ("defender_tampering_count", 80, 50, 15, "MEASURED"),
    ]

    def _draw_workstation(self, cx, cy, t, w, h) -> None:
        sc = _status_color(self._app_status)
        self._draw_grid(cx, cy, w, h, sc)

        for face in self._box_faces(0, -20, 0, 130, 90, 10):
            proj = [self._pp(v[0],v[1],v[2],cx,cy) for v in face]
            self.create_polygon([c for p in proj for c in (p[0],p[1])],
                                fill="#162040", outline=_GOLD, width=1)
        sc_pts = [self._pp(v[0],v[1],v[2],cx,cy)
                  for v in [(-55,-55,-6),(55,-55,-6),(55,15,-6),(-55,15,-6)]]
        self.create_polygon([c for p in sc_pts for c in (p[0],p[1])],
                            fill="#1a3a6e", outline=sc, width=2)
        self.create_text(cx, cy-20, text=f"PROCS:{self._processes}  FILES:{self._files_inspected}",
                         font=("Consolas", 12, "bold"), fill=sc, anchor="center")
        for face in self._box_faces(0, 60, 0, 40, 14, 60):
            proj = [self._pp(v[0],v[1],v[2],cx,cy) for v in face]
            self.create_polygon([c for p in proj for c in (p[0],p[1])],
                                fill="#0f1d38", outline="#2a4a7f", width=1)

        nc_map = {"MEASURED":_SAFE, "HEURISTIC":_WARNING}
        for feat, nx, ny, nz, kind in self._WS_NODES:
            bob = 0.0 if self.reduced_motion else math.sin(t*0.6+nx*0.05)*8
            sx2, sy2, _ = self._pp(nx, ny+bob, nz, cx, cy)
            nc = nc_map.get(kind, _MUTED)
            r = 8
            self.create_oval(sx2-r, sy2-r, sx2+r, sy2+r, fill=nc, outline=_WHITE)
            self.create_text(sx2, sy2+r+8, text=feat[:10],
                             font=("Consolas", 11, "bold"), fill=nc, anchor="n")
            mon_sx, mon_sy, _ = self._pp(0, 0, -6, cx, cy)
            self.create_line(mon_sx, mon_sy, sx2, sy2, fill=nc, width=1, dash=(2,4))
            self._hit_objects.append({"label": f"{feat} [{kind}]",
                                      "sx": sx2, "sy": sy2, "radius": r+4})

        self.create_text(cx, h-48, text=f"SYSTEM WORKSTATION  ·  {self._app_status}",
                         font=("Consolas", 14, "bold"), fill=sc)
        self.create_text(cx, h-30,
                         text="MEASURED=direct telemetry  HEURISTIC=proxy approximation",
                         font=("Consolas", 11), fill=_MUTED)

    # --- Scene 3: FILES ------------------------------------------------------

    def _draw_files(self, cx, cy, t, w, h) -> None:
        sc = _status_color(self._app_status)
        self._draw_grid(cx, cy, w, h, sc)

        total = self._wt_added + self._wt_modified + self._wt_deleted + self._wt_unchanged
        have = total > 0
        file_data = []
        if have:
            for i in range(min(self._wt_added, 2)):
                file_data.append(("added", f"new_{i+1}.txt"))
            for i in range(min(self._wt_modified, 2)):
                file_data.append(("modified", f"changed_{i+1}.txt"))
            for i in range(min(self._wt_deleted, 2)):
                file_data.append(("deleted", f"removed_{i+1}.txt"))
            for i in range(min(self._wt_unchanged, 7-len(file_data))):
                file_data.append(("unchanged", f"stable_{i+1}.txt"))
        else:
            for name in ["document.docx","spreadsheet.xlsx","report.pdf",
                         "config.ini","database.db","backup.zip","notes.txt"]:
                file_data.append(("simulated", name))

        sc_map = {"added":_SAFE,"modified":_WARNING,"deleted":_CRITICAL,
                  "unchanged":_MUTED,"simulated":_CYAN}
        n = len(file_data)
        for i, (fstatus, fname) in enumerate(file_data):
            a = (i/max(n,1))*math.pi*1.5 - math.pi*0.75
            r_orb = 130.0
            bx = math.cos(a)*r_orb
            by = -20 + math.sin(a*0.4)*30
            bz = math.sin(a)*r_orb*0.5
            bob = 0.0 if self.reduced_motion else math.sin(t*0.8+i*1.1)*8
            fc = sc_map.get(fstatus, _MUTED)
            for face in self._box_faces(bx, by+bob, bz, 24, 30, 6):
                proj = [self._pp(v[0],v[1],v[2],cx,cy) for v in face]
                self.create_polygon([c for p in proj for c in (p[0],p[1])],
                                    fill="#162040", outline=fc, width=1)
            csx, csy, _ = self._pp(bx, by+bob, bz, cx, cy)
            self.create_text(csx, csy, text=fstatus.upper()[:3],
                             font=("Consolas", 12, "bold"), fill=fc)
            nsx, nsy, _ = self._pp(bx, by+bob+22, bz, cx, cy)
            self.create_text(nsx, nsy,
                             text=(fname[:10]+"…" if len(fname)>10 else fname),
                             font=("Consolas", 11), fill=_MUTED)
            self._hit_objects.append({"label": f"{fstatus}: {fname}",
                                      "sx": csx, "sy": csy, "radius": 18})

        summary = (f"+{self._wt_added} added  ~{self._wt_modified} modified  "
                   f"-{self._wt_deleted} deleted  {self._wt_unchanged} unchanged"
                   if have else
                   "No baseline — showing SIMULATION  ·  run File Integrity Watchtower")
        self.create_text(cx, h-48, text="FILE INTEGRITY SCENE",
                         font=("Consolas", 14, "bold"), fill=sc)
        self.create_text(cx, h-30, text=summary, font=("Consolas", 11), fill=_MUTED)
        if not have:
            self.create_text(cx, 20, text="SIMULATION MODE — no real files shown",
                             font=("Consolas", 13, "bold"), fill=_SIMULATED)

    # --- Scene 4: AI PIPELINE ------------------------------------------------

    _PIPE_STAGES = [
        ("TELEMETRY", "19 sensors\ncollected",       -240, _CYAN),
        ("FEATURES",  "Vector\nassembled",            -120, _GOLD),
        ("SCALER",    "Standard\nScaler",                0, _MUTED),
        ("FOREST",    "Random\nForest\n100 trees",     120, _WARNING),
        ("OUTPUT",    "Probability\n+ Class",          240, _SAFE),
    ]

    def _draw_pipeline(self, cx, cy, t, w, h) -> None:
        sc = _status_color(self._app_status)
        self.create_rectangle(0, 0, w, h, fill="#0b1427", outline="")
        for gy in range(0, h, 40):
            self.create_line(0, gy, w, gy, fill="#1a2e56", width=1)

        pulse = 0.0 if self.reduced_motion else math.sin(t*1.5)*0.5+0.5
        proj_stages = []
        for label, sublabel, stage_x, col in self._PIPE_STAGES:
            sx2, sy2, d = self._pp(stage_x, 0, 0, cx, cy)
            proj_stages.append((sx2, sy2, d, label, sublabel, col))
            self._hit_objects.append({"label": f"Stage: {label}", "sx": sx2, "sy": sy2, "radius": 32})

        for i in range(len(proj_stages)-1):
            x1,y1 = proj_stages[i][0], proj_stages[i][1]
            x2,y2 = proj_stages[i+1][0], proj_stages[i+1][1]
            self.create_line(x1,y1,x2,y2, fill="#2a5aa0", width=2, arrow=tk.LAST)
            if not self.reduced_motion:
                frac = (t*0.5 + i*0.25) % 1.0
                self.create_oval(x1+(x2-x1)*frac-4, y1+(y2-y1)*frac-4,
                                 x1+(x2-x1)*frac+4, y1+(y2-y1)*frac+4,
                                 fill=proj_stages[i][5], outline="")

        for sx2, sy2, d, label, sublabel, col in proj_stages:
            scale = max(0.5, min(1.4, 320/max(d,100)))
            bw2, bh2 = 40*scale, 30*scale
            if label == "OUTPUT" and self._app_status not in ("IDLE","SCANNING","NOT_SCANNED"):
                gr = 42 + pulse*12
                self.create_oval(sx2-gr, sy2-gr, sx2+gr, sy2+gr, fill="", outline=col, width=2)
            self.create_rectangle(sx2-bw2, sy2-bh2, sx2+bw2, sy2+bh2,
                                  fill="#162040", outline=col, width=2)
            self.create_text(sx2, sy2-8, text=label, font=("Consolas", 12, "bold"), fill=col)
            self.create_text(sx2, sy2+8, text=sublabel,
                             font=("Consolas", 11), fill=_MUTED, justify="center")

        if self._app_status not in ("IDLE","NOT_SCANNED"):
            lsx, lsy = proj_stages[-1][0], proj_stages[-1][1]
            self.create_text(lsx, lsy+42,
                             text=f"p={self._scan_prob:.3f}  →  {self._app_status}",
                             font=("Consolas", 12, "bold"), fill=_status_color(self._app_status))

        self.create_text(w//2, h-48, text="AI PIPELINE MODEL  ·  real trained forest",
                         font=("Consolas", 14, "bold"), fill=sc)
        self.create_text(w//2, h-30,
                         text="Global Gini importance in AI Observatory  ·  Not per-prediction",
                         font=("Consolas", 11), fill=_MUTED)

    # --- Scene 5: ATTACK REPLAY ----------------------------------------------

    def _draw_replay(self, cx, cy, t, w, h) -> None:
        sc = _status_color(self._app_status)
        self.create_rectangle(0, 0, w, h, fill="#0b1427", outline="")
        spine_y = cy
        spine_x0, spine_x1 = 60.0, w - 60.0
        self.create_line(spine_x0, spine_y, spine_x1, spine_y, fill="#2a4a7f", width=3)

        events = self._replay_events
        if not events:
            try:
                from exhibition.attack_replay import build_attack_replay_plan
                plan = build_attack_replay_plan()
                events = [{"title":s.title,"t":s.t,"severity":s.severity,"detail":s.detail}
                          for s in plan]
            except Exception:
                events = []
        if not events:
            return

        played_count = len(events)
        if self._replay_ctrl is not None:
            try:
                played_count = getattr(self._replay_ctrl, "index", len(events))
            except Exception:
                pass

        max_t = max(ev["t"] for ev in events) or 1.0
        try:
            from exhibition.attack_replay import SEVERITY_CRITICAL, SEVERITY_WARNING
        except Exception:
            SEVERITY_CRITICAL, SEVERITY_WARNING = "critical", "warning"

        for i, ev in enumerate(events):
            frac = ev["t"] / max_t
            ex = spine_x0 + frac * (spine_x1 - spine_x0)
            played = i < played_count
            sev = ev.get("severity", "info")
            col = (_CRITICAL if sev == SEVERITY_CRITICAL
                   else _WARNING if sev == SEVERITY_WARNING else _CYAN)
            col = col if played else _MUTED
            bob = 0.0 if self.reduced_motion else math.sin(t*1.2+i*0.7)*6
            ey = spine_y - 40 - bob
            self.create_line(ex, spine_y, ex, ey, fill=col, width=1, dash=(2,3))
            r_m = 9 if played else 5
            self.create_oval(ex-r_m, ey-r_m, ex+r_m, ey+r_m,
                             fill=col if played else "#0f1d38", outline=col, width=2)
            badge = {"critical":"!","warning":"~","info":"·"}.get(sev,"·")
            self.create_text(ex, ey, text=badge,
                             font=("Arial", 12, "bold"), fill=_WHITE if played else _MUTED)
            if i % 2 == 0:
                self.create_text(ex, spine_y+14, text=f"{ev['t']:.1f}s",
                                 font=("Consolas", 11), fill=_MUTED)
            ey2 = spine_y + 30 + (i%2)*14
            self.create_text(ex, ey2, text=ev.get("title","")[:22],
                             font=("Consolas", 11, "bold"), fill=col, anchor="center")
            self._hit_objects.append({"label": ev.get("title",""),
                                      "sx": ex, "sy": ey, "radius": r_m+4})

        state_txt = "IDLE"
        if self._replay_ctrl is not None:
            try:
                state_txt = str(getattr(self._replay_ctrl, "state", "idle")).upper()
            except Exception:
                pass
        self.create_text(cx, h-48,
                         text=f"ATTACK REPLAY  ·  {state_txt}  ·  SIMULATED",
                         font=("Consolas", 14, "bold"), fill=_SIMULATED)
        self.create_text(cx, h-30,
                         text="All events SIMULATED — not real malware executions",
                         font=("Consolas", 11), fill=_MUTED)

    # --- Destroy -------------------------------------------------------------

    def _on_destroy(self, event: tk.Event) -> None:
        if event.widget == self:
            self._running = False
            if self._after_id:
                try:
                    self.after_cancel(self._after_id)
                except Exception:
                    pass
                self._after_id = None

    def destroy(self) -> None:
        self._running = False
        if self._after_id:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
        try:
            super().destroy()
        except Exception:
            pass
