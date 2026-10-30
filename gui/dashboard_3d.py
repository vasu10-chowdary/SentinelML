"""
SentinelML V2 — 3D Animated Sentinel Security Core
==================================================
Non-blocking, frame-rate aware 3D perspective canvas for the main dashboard.
Features:
- Rotating 3D Sentinel Shield geometry with perspective depth projection
- Layered rotating orbital rings and orbiting telemetry nodes
- Continuous ambient / scanning radar sweep
- Dynamic telemetry particle flow
- Real application state responsiveness (IDLE, SCANNING, SAFE, WARNING, THREAT, ERROR)
- Automatic animation throttling when unmapped / minimized
- Guaranteed clean cancellation on window destruction
"""

import math
import random
import time
import tkinter as tk
from typing import Optional, Dict, Any, List

class Dashboard3DCore(tk.Canvas):
    """
    Animated 3D Sentinel Core centerpiece for the Main Dashboard.
    Visualizes real-time host protection status and telemetry with
    subtle, high-performance Canvas perspective rendering.
    """

    def __init__(self, master, width: int = 380, height: int = 240, reduced_motion: bool = False, **kwargs):
        kwargs.setdefault("bg", "#070e1c")
        kwargs.setdefault("highlightthickness", 1)
        kwargs.setdefault("highlightbackground", "#162338")
        super().__init__(master, width=width, height=height, **kwargs)

        self.reduced_motion = reduced_motion
        self.state = "IDLE"
        self.risk_score = 0.0
        self.files_inspected = 0
        self.processes_analyzed = 0
        self.current_stage = "IDLE"

        self.start_time = time.time()
        self.state_time = time.time()
        self.scan_data = None
        self._running = True
        self._paused = False
        self._after_id: Optional[str] = None

        # 3D Shield geometry: 6 hexagonal vertices in object space
        self.shield_points: List[Dict[str, float]] = []
        radius = 80.0
        for i in range(6):
            a = math.radians(60 * i + 30)
            self.shield_points.append({
                "x": math.cos(a) * radius,
                "y": math.sin(a) * radius * 1.15,
                "z": 0.0
            })

        # Dynamic visual entities
        self.particles: List[Dict[str, Any]] = []
        self.rings: List[Dict[str, Any]] = []
        self._last_frame_time = time.time()

        # Clean destroy listener
        def _on_destroy(event):
            if event.widget == self:
                self._running = False
                if self._after_id:
                    try:
                        self.after_cancel(self._after_id)
                    except Exception:
                        pass
                    self._after_id = None
        self.bind("<Destroy>", _on_destroy, add=True)

        # Start animation loop
        self._schedule_next_frame(33)

    def pause(self) -> None:
        """Pause rendering when covered by another view to eliminate canvas CPU churn."""
        self._paused = True
        if self._after_id:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def resume(self) -> None:
        """Resume rendering when visible again."""
        if getattr(self, "_paused", False):
            self._paused = False
            self._last_frame_time = time.time()
            self._schedule_next_frame(33)

    def _schedule_next_frame(self, delay_ms: int) -> None:
        if self._running:
            try:
                if self.winfo_exists():
                    self._after_id = self.after(delay_ms, self._animate)
            except Exception:
                self._after_id = None

    def set_state(self, state: str, risk_score: float = 0.0) -> None:
        """Update core state and trigger dynamic visual reactions."""
        # Normalize states
        s = state.upper()
        if s in ("READY TO SCAN", "NOT_SCANNED", "NOT YET SCANNED"):
            s = "IDLE"
        elif s in ("SCANNING", "INITIALIZING"):
            s = "SCANNING"
        elif s in ("SAFE", "NO THREATS DETECTED", "NO_THREATS", "CLEAN"):
            s = "SAFE"
        elif s in ("WARNING", "ELEVATED"):
            s = "WARNING"
        elif s in ("THREAT DETECTED", "CRITICAL", "THREAT"):
            s = "THREAT DETECTED"
        elif s in ("CANCELLED", "SCAN_INCOMPLETE", "INCOMPLETE"):
            s = "SCAN_INCOMPLETE"
        elif s in ("INCONCLUSIVE", "LIMITED_COVERAGE"):
            s = "INCONCLUSIVE"
        elif s in ("ERROR", "ANALYSIS_ERROR"):
            s = "ANALYSIS_ERROR"

        self.state = s
        from ml.predictor import normalize_risk_score
        fval, _, _ = normalize_risk_score(risk_score)
        self.risk_score = fval
        self.state_time = time.time()

        if self.state == "SCANNING":
            # Pulse ring on scan trigger
            self.rings.append({"radius": 25.0, "life": 1.0, "color": "#00ffcc", "speed": 4.0})
        elif self.state == "SAFE":
            self.rings.append({"radius": 30.0, "life": 1.0, "color": "#00ff88", "speed": 3.0})
        elif self.state == "WARNING":
            self.rings.append({"radius": 30.0, "life": 1.2, "color": "#ffab00", "speed": 4.5})
        elif self.state == "THREAT DETECTED":
            self.rings.append({"radius": 30.0, "life": 1.5, "color": "#ff2a2a", "speed": 6.0})
            # Scatter warning particles
            for _ in range(20):
                ang = random.uniform(0, math.pi * 2)
                spd = random.uniform(3, 8)
                self.particles.append({
                    "x": 0.0, "y": 0.0,
                    "vx": math.cos(ang) * spd, "vy": math.sin(ang) * spd,
                    "life": 1.2, "color": "#ff2a2a", "size": 3
                })

    def update_progress(self, files: int = 0, procs: int = 0, stage: str = "") -> None:
        """Feed real scan metrics to the 3D core display."""
        self.files_inspected = files
        self.processes_analyzed = procs
        if stage:
            self.current_stage = stage
        if self.state not in ("SAFE", "WARNING", "THREAT DETECTED", "SCAN_INCOMPLETE", "INCONCLUSIVE", "ANALYSIS_ERROR"):
            self.state = "SCANNING"

    def update_data(self, scan_result) -> None:
        """Inspect ScanResult safely."""
        self.scan_data = scan_result
        if scan_result:
            self.files_inspected = getattr(scan_result, "files_inspected", self.files_inspected)
            self.processes_analyzed = getattr(scan_result, "processes_analyzed", self.processes_analyzed)

    def _animate(self) -> None:
        if not self._running or getattr(self, "_paused", False):
            return
        try:
            if not self.winfo_exists():
                self._running = False
                return
        except Exception:
            self._running = False
            return

        # Performance rule: pause when unmapped (page hidden or minimized)
        if not self.winfo_ismapped():
            self._schedule_next_frame(250)
            return

        try:
            self.delete("all")
            w = self.winfo_width()
            h = self.winfo_height()
            if w < 50 or h < 50:
                w, h = 380, 240

            cx, cy = w / 2.0, h / 2.0 - 10.0
            now = time.time()
            elapsed = now - self.start_time

            # State-specific theme colors
            if self.state == "IDLE":
                theme_color = "#00d4ff"
                status_title = "SENTINEL CORE // IDLE"
                status_sub = "READY TO SCAN • TELEMETRY ACTIVE"
                rot_speed = 0.5
                sweep_speed = 1.8
            elif self.state == "SCANNING":
                theme_color = "#00ffcc"
                status_title = "SCAN IN PROGRESS"
                status_sub = f"EVALUATING: {self.files_inspected:,} files | {self.processes_analyzed} procs"
                rot_speed = 2.2
                sweep_speed = 5.0
            elif self.state == "SAFE":
                theme_color = "#00ff88"
                status_title = "NO THREATS DETECTED"
                status_sub = f"SYSTEM SAFE • {self.files_inspected:,} files inspected"
                rot_speed = 0.4
                sweep_speed = 1.0
            elif self.state == "WARNING":
                theme_color = "#ffab00"
                status_title = "ANOMALOUS RISK DETECTED"
                status_sub = f"ELEVATED RISK ({self.risk_score * 100:.1f}%)"
                rot_speed = 1.2
                sweep_speed = 3.0
            elif self.state == "THREAT DETECTED":
                theme_color = "#ff2a2a"
                status_title = "CRITICAL THREAT DETECTED"
                status_sub = f"MALICIOUS CONSENSUS ({self.risk_score * 100:.1f}%)"
                rot_speed = 3.0
                sweep_speed = 6.0
            elif self.state == "SCAN_INCOMPLETE":
                theme_color = "#8b949e"
                status_title = "SCAN CANCELLED"
                status_sub = "PARTIAL RESULTS DISCARDED"
                rot_speed = 0.2
                sweep_speed = 0.0
            elif self.state == "INCONCLUSIVE":
                theme_color = "#ffab00"
                status_title = "INCONCLUSIVE // LIMITED TELEMETRY"
                status_sub = "NOT CERTIFIED SAFE \u2022 SENSOR COVERAGE INCOMPLETE"
                rot_speed = 0.3
                sweep_speed = 0.0
            else:  # ANALYSIS_ERROR
                theme_color = "#d29922"
                status_title = "ANALYSIS ERROR"
                status_sub = "SCAN TERMINATED WITH ERROR"
                rot_speed = 0.2
                sweep_speed = 0.0

            # 1. Subtle Background Depth Grid Lines
            grid_y = cy + 90
            self.create_line(cx - 160, grid_y, cx + 160, grid_y, fill="#0f1f38", width=1)
            self.create_line(cx - 120, grid_y + 15, cx + 120, grid_y + 15, fill="#0a1526", width=1)
            for gx in range(-140, 150, 40):
                self.create_line(cx + gx, grid_y, cx + gx * 1.3, grid_y + 25, fill="#0a172a", width=1)

            # 2. Concentric Orbital Rings
            if not self.reduced_motion:
                rings_def = [
                    (95.0, 0.35, elapsed * 0.4, "#0e3352", (2, 6)),
                    (125.0, 0.30, -elapsed * 0.25, "#134269", (4, 8)),
                    (155.0, 0.25, elapsed * 0.15, "#0b253d", (2, 10)),
                ]
                for radius, aspect, ang, ring_col, dash in rings_def:
                    self.create_oval(
                        cx - radius, cy - radius * aspect,
                        cx + radius, cy + radius * aspect,
                        outline=ring_col, width=1, dash=dash
                    )
                    # Orbiting tracer node
                    dot_x = cx + math.cos(ang) * radius
                    dot_y = cy + math.sin(ang) * radius * aspect
                    self.create_oval(dot_x - 3, dot_y - 3, dot_x + 3, dot_y + 3, fill=theme_color, outline="")

            # 3. Radar Scanning Sweep (Active when sweeping)
            if sweep_speed > 0 and not self.reduced_motion:
                sweep_angle = (elapsed * sweep_speed) % (math.pi * 2)
                sweep_r = 110.0
                sw_x = cx + math.cos(sweep_angle) * sweep_r
                sw_y = cy + math.sin(sweep_angle) * (sweep_r * 0.75)
                self.create_line(cx, cy, sw_x, sw_y, fill=theme_color, width=1, dash=(2, 4))

            # 4. 3D Rotating Hexagonal Shield Projection
            rot_y = elapsed * rot_speed if not self.reduced_motion else 0.0
            rot_x = math.sin(elapsed * 0.6) * 0.12 if not self.reduced_motion else 0.0

            c_y, s_y = math.cos(rot_y), math.sin(rot_y)
            c_x, s_x = math.cos(rot_x), math.sin(rot_x)

            proj_points = []
            for p in self.shield_points:
                # Rotate Y
                rx = p["x"] * c_y - p["z"] * s_y
                rz = p["x"] * s_y + p["z"] * c_y
                ry = p["y"]
                # Rotate X
                ry2 = ry * c_x - rz * s_x
                rz2 = ry * s_x + rz * c_x
                # Perspective divide
                dist = 300.0 - rz2
                factor = 280.0 / dist if dist > 1.0 else 1.0
                proj_points.extend([cx + rx * factor, cy + ry2 * factor])

            if len(proj_points) == 12:
                # Outer Shield Polygon
                self.create_polygon(
                    proj_points,
                    fill="#081426",
                    outline=theme_color,
                    width=2
                )
                # Inner geometric shield (0.65 scale)
                inner_points = []
                for i in range(0, len(proj_points), 2):
                    inner_points.extend([
                        cx + (proj_points[i] - cx) * 0.65,
                        cy + (proj_points[i + 1] - cy) * 0.65
                    ])
                self.create_polygon(inner_points, fill="#040b17", outline="#1b4d73", width=1, dash=(3, 3))

                # Spokes connecting inner to outer vertices
                for i in range(0, len(proj_points), 2):
                    self.create_line(inner_points[i], inner_points[i + 1], proj_points[i], proj_points[i + 1], fill="#163e5c", width=1)

                # Core Emblem "S"
                self.create_text(
                    cx, cy,
                    text="S",
                    font=("Arial", 22, "bold"),
                    fill=theme_color
                )

            # 5. Expanding Wave Rings
            alive_rings = []
            for ring in self.rings:
                r = ring["radius"]
                ring["radius"] += ring["speed"]
                ring["life"] -= 0.035
                if ring["life"] > 0:
                    alpha_w = max(1, int(ring["life"] * 2.5))
                    self.create_oval(
                        cx - r, cy - r * 0.6,
                        cx + r, cy + r * 0.6,
                        outline=ring["color"], width=alpha_w
                    )
                    alive_rings.append(ring)
            self.rings = alive_rings

            # 6. Ambient Data Particles
            if not self.reduced_motion:
                if len(self.particles) < 18 and random.random() < 0.25:
                    a = random.uniform(0, math.pi * 2)
                    dist = random.uniform(120, 180)
                    self.particles.append({
                        "x": math.cos(a) * dist,
                        "y": math.sin(a) * (dist * 0.6),
                        "vx": -math.cos(a) * random.uniform(0.6, 2.0),
                        "vy": -math.sin(a) * random.uniform(0.4, 1.4),
                        "life": 1.0,
                        "color": theme_color,
                        "size": random.choice([1, 2])
                    })

                alive_particles = []
                for p in self.particles:
                    p["x"] += p["vx"]
                    p["y"] += p["vy"]
                    p["life"] -= 0.02
                    if p["life"] > 0:
                        px = cx + p["x"]
                        py = cy + p["y"]
                        sz = p.get("size", 2)
                        self.create_oval(px - sz, py - sz, px + sz, py + sz, fill=p["color"], outline="")
                        alive_particles.append(p)
                self.particles = alive_particles

            # 7. Status & Telemetry Typography (Bottom Overlay)
            self.create_text(
                cx, h - 34,
                text=status_title,
                font=("Consolas", 12, "bold"),
                fill=theme_color
            )
            self.create_text(
                cx, h - 16,
                text=status_sub,
                font=("Consolas", 9),
                fill="#8b949e"
            )

        except Exception:
            pass

        self._schedule_next_frame(33)

    def destroy(self) -> None:
        """Clean shutdown canceling scheduled after callbacks."""
        self._running = False
        if self._after_id:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
        super().destroy()
