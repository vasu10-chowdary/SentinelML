"""
SentinelML V2 — Cinematic 3D Startup Experience
================================================
Deliberate, cinematic 5-7 second 3D animated startup sequence.
Features:
- Pure Tkinter Canvas 3D perspective projection (no heavy 3D engine needed)
- 3D Hexagonal Sentinel Shield with multi-layered depth and inner concentric core
- Flowing 3D cyber perspective grid
- Layered rotating orbital rings and orbiting tracer nodes
- 19-Feature telemetry vector convergence representing the 19 behavioral ML features
- Anomaly particle deflection wave
- Integrity verification consensus flash
- Smooth camera zoom / iris expansion into the main dashboard
- User-skippable via Escape, Space, or clickable [SKIP] control
- Fail-safe fallback that immediately displays dashboard if rendering fails
"""

import logging
import tkinter as tk
import time
import math
import random
from typing import Optional, List, Dict, Any

log = logging.getLogger("sentinel.startup_animation")

class Vec3:
    __slots__ = ("x", "y", "z")
    def __init__(self, x: float, y: float, z: float):
        self.x = float(x)
        self.y = float(y)
        self.z = float(z)

class Particle:
    __slots__ = ("x", "y", "z", "vx", "vy", "vz", "life", "color", "type", "size")
    def __init__(self, x: float, y: float, z: float, vx: float, vy: float, vz: float,
                 life: float, color: str, ptype: str, size: float):
        self.x, self.y, self.z = float(x), float(y), float(z)
        self.vx, self.vy, self.vz = float(vx), float(vy), float(vz)
        self.life = float(life)
        self.color = color
        self.type = ptype
        self.size = float(size)

def rotate_y(p: Vec3, angle: float) -> Vec3:
    c, s = math.cos(angle), math.sin(angle)
    return Vec3(p.x * c - p.z * s, p.y, p.x * s + p.z * c)

def rotate_x(p: Vec3, angle: float) -> Vec3:
    c, s = math.cos(angle), math.sin(angle)
    return Vec3(p.x, p.y * c - p.z * s, p.y * s + p.z * c)

def project(p: Vec3, cx: float, cy: float, fov: float, viewer_z: float):
    z = p.z - viewer_z
    if z < 1.0:
        z = 1.0
    factor = fov / z
    return cx + p.x * factor, cy + p.y * factor, factor

def ease_out_cubic(x: float) -> float:
    return 1.0 - pow(1.0 - x, 3)

def ease_in_out_quad(x: float) -> float:
    return 2.0 * x * x if x < 0.5 else 1.0 - pow(-2.0 * x + 2.0, 2) / 2.0

def show_startup_animation_inline(main_window: tk.Tk, duration: int = 5000, on_complete=None) -> Optional[tk.Canvas]:
    """
    Launch the deliberate cinematic 3D startup sequence.
    Can be skipped at any moment with Escape, Space, or a mouse click.
    When finished or skipped, invokes on_complete callback (if provided) and reveals the dashboard.
    """
    canvas = None
    cleaned_up = [False]
    after_id = [None]
    timer_id = [None]

    def _cleanup(failed: bool = False):
        if cleaned_up[0]:
            return
        cleaned_up[0] = True

        # Cancel any pending frame callback
        if after_id[0] and canvas:
            try:
                canvas.after_cancel(after_id[0])
            except Exception:
                pass
            after_id[0] = None

        if timer_id[0]:
            try:
                main_window.after_cancel(timer_id[0])
            except Exception:
                pass
            timer_id[0] = None

        try:
            if canvas is not None and canvas.winfo_exists():
                canvas.destroy()
        except Exception as ex:
            log.debug("Error destroying animation canvas: %s", ex)

        if on_complete:
            try:
                on_complete()
            except Exception as ex:
                log.error("Error in startup animation on_complete: %s", ex)

        try:
            # Guarantee sidebar and active page (dashboard) are gridded and brought to front
            if hasattr(main_window, "_sidebar") and main_window._sidebar and main_window._sidebar.winfo_exists():
                main_window._sidebar.grid(row=0, column=0, sticky="nsew")
                tk.Misc.lift(main_window._sidebar)
            if hasattr(main_window, "_pages") and hasattr(main_window, "_current_page"):
                curr_key = getattr(main_window, "_current_page", "dashboard") or "dashboard"
                curr = main_window._pages.get(curr_key)
                if curr and curr.winfo_exists():
                    curr.grid(row=0, column=1, sticky="nsew")
                    tk.Misc.lift(curr)
            main_window.update_idletasks()
            main_window.focus_set()
            if not failed:
                log.info("Startup animation completed.")
            log.info("Dashboard visible after animation cleanup.")
        except Exception as ex:
            log.warning("Error during animation cleanup: %s", ex)

    try:
        log.info("Startup animation started (target duration: %d ms).", duration)
        canvas = tk.Canvas(main_window, bg="#050810", highlightthickness=0)
        canvas.place(x=0, y=0, relwidth=1.0, relheight=1.0)
        tk.Misc.lift(canvas)
        canvas._cleanup = _cleanup

        start_time = time.time()
        particles: List[Particle] = []

        # 3D Shield geometry: 6 hexagonal vertices
        shield_points: List[Vec3] = []
        radius = 115.0
        for i in range(6):
            a = math.radians(60 * i + 30)
            shield_points.append(Vec3(math.cos(a) * radius, math.sin(a) * radius * 1.15, 0.0))

        # 3D Perspective Ground/Ceiling Grid
        grid_lines: List[tuple] = []
        for i in range(-7, 8):
            grid_lines.append((Vec3(i * 140, 260, -400), Vec3(i * 140, 260, 2200)))
            grid_lines.append((Vec3(-1000, 260, i * 160 + 400), Vec3(1000, 260, i * 160 + 400)))

        # 19 Feature Telemetry Vectors (representing 19 behavioral ML features)
        feature_vectors: List[Dict[str, Any]] = []
        for i in range(19):
            ang = (i / 19.0) * math.pi * 2.0
            dist = random.uniform(350, 600)
            feature_vectors.append({
                "origin": Vec3(math.cos(ang) * dist, math.sin(ang) * (dist * 0.7), random.uniform(200, 800)),
                "progress": 0.0,
                "speed": random.uniform(0.7, 1.2),
                "color": random.choice(["#00d4ff", "#00ffcc", "#58a6ff"])
            })

        # Deflection particles helper
        def trigger_deflection_burst(cx: float, cy: float):
            for _ in range(60):
                ang = random.uniform(0, math.pi * 2)
                spd = random.uniform(8, 26)
                particles.append(Particle(
                    0.0, 0.0, 0.0,
                    math.cos(ang) * spd, math.sin(ang) * spd, random.uniform(-10, 20),
                    1.2, random.choice(["#00ff88", "#00d4ff", "#ffffff", "#2188ff"]), "dot", random.uniform(2, 5)
                ))

        impact_triggered = [False]

        def animate_frame():
            try:
                now = time.time()
                elapsed_ms = (now - start_time) * 1000.0
                progress = min(elapsed_ms / float(duration), 1.0)

                if progress >= 1.0:
                    _cleanup(failed=False)
                    return

                canvas.delete("all")
                width = canvas.winfo_width()
                height = canvas.winfo_height()
                if width < 200 or height < 200:
                    try:
                        width = main_window.winfo_width()
                        height = main_window.winfo_height()
                    except Exception:
                        pass
                if width < 200 or height < 200:
                    width, height = 1280, 800

                cx = width / 2.0
                cy = height / 2.0

                # Cinematic camera tracking
                # In scene 5 (zoom transition), camera glides forward through shield
                if progress > 0.88:
                    zoom_t = (progress - 0.88) / 0.12
                    cam_z = -400.0 + (progress * 100.0) + (ease_in_out_quad(zoom_t) * 350.0)
                    fade_alpha = max(0.0, 1.0 - zoom_t)
                else:
                    cam_z = -400.0 + (progress * 100.0)
                    fade_alpha = 1.0

                # ── 1. Cyber Grid In Perspective ───────────────────────────
                grid_speed = elapsed_ms * 0.25
                for p1, p2 in grid_lines:
                    shifted_p1 = Vec3(p1.x, p1.y, ((p1.z - grid_speed) % 2600) - 400)
                    shifted_p2 = Vec3(p2.x, p2.y, ((p2.z - grid_speed) % 2600) - 400)
                    px1, py1, f1 = project(shifted_p1, cx, cy, 400, cam_z)
                    px2, py2, f2 = project(shifted_p2, cx, cy, 400, cam_z)
                    if f1 > 0 and f2 > 0:
                        canvas.create_line(px1, py1, px2, py2, fill="#0b172a", width=1)

                # ── 2. Telemetry Particles Update ──────────────────────────
                if 0.15 < progress < 0.70 and random.random() < 0.35:
                    # Spawn ambient space particles
                    particles.append(Particle(
                        random.uniform(-500, 500), random.uniform(-300, 200), random.uniform(800, 1400),
                        0, 0, random.uniform(-25, -12),
                        1.2, random.choice(["#00d4ff", "#1f486b", "#ff4444" if random.random() < 0.15 else "#00ffcc"]),
                        "line", random.uniform(1.5, 3.5)
                    ))

                alive_particles = []
                for p in particles:
                    p.x += p.vx
                    p.y += p.vy
                    p.z += p.vz
                    p.life -= 0.010
                    if p.life > 0 and p.z > cam_z:
                        px, py, f = project(p, cx, cy, 400, cam_z)
                        if f > 0:
                            sz = max(1, int(p.size * f))
                            if p.type == "dot":
                                canvas.create_oval(px - sz, py - sz, px + sz, py + sz, fill=p.color, outline="")
                            else:
                                px_old, py_old, _ = project(Vec3(p.x - p.vx * 2, p.y - p.vy * 2, p.z - p.vz * 2), cx, cy, 400, cam_z)
                                canvas.create_line(px, py, px_old, py_old, fill=p.color, width=sz)
                        alive_particles.append(p)
                particles[:] = alive_particles

                # ── 3. 3D Rotating Shield & Orbital Rings ─────────────────
                if progress > 0.18:
                    shield_intro = min((progress - 0.18) / 0.15, 1.0)
                    shield_scale = ease_out_cubic(shield_intro)

                    # Rotation dynamics
                    if progress < 0.72:
                        rot_y = elapsed_ms * 0.0012
                        rot_x = math.sin(elapsed_ms * 0.0015) * 0.12
                    else:
                        # Lock facing forward with slight vibration
                        lock_t = min((progress - 0.72) / 0.10, 1.0)
                        rot_y = elapsed_ms * 0.0012 * (1.0 - lock_t)
                        rot_x = 0.0

                    # If zoom out in scene 5
                    if progress > 0.88:
                        shield_scale *= (1.0 + (progress - 0.88) * 8.0)

                    # Orbital rings around shield
                    ring_radii = [150.0, 190.0, 230.0]
                    for idx, r_base in enumerate(ring_radii):
                        r = r_base * shield_scale
                        ang = elapsed_ms * (0.0008 * (1 if idx % 2 == 0 else -1))
                        aspect = 0.32 + idx * 0.06
                        canvas.create_oval(
                            cx - r, cy - r * aspect,
                            cx + r, cy + r * aspect,
                            outline="#0f3454" if progress < 0.72 else "#0f4a36",
                            width=1, dash=(3, 7)
                        )
                        # Orbiting tracer node
                        nx = cx + math.cos(ang) * r
                        ny = cy + math.sin(ang) * (r * aspect)
                        canvas.create_oval(nx - 3, ny - 3, nx + 3, ny + 3, fill="#00d4ff" if progress < 0.72 else "#00ff88", outline="")

                    # Project 3D Shield Vertices
                    proj_points = []
                    for pt in shield_points:
                        rp = rotate_x(rotate_y(pt, rot_y), rot_x)
                        rp.x *= shield_scale
                        rp.y *= shield_scale
                        rp.z *= shield_scale
                        px, py, f = project(rp, cx, cy, 400, cam_z)
                        proj_points.extend([px, py])

                    if len(proj_points) == 12:
                        shield_color = "#00d4ff" if progress < 0.72 else "#00ff88"
                        # Outer shield
                        canvas.create_polygon(proj_points, fill="#061224", outline=shield_color, width=2)

                        # Inner concentric shield
                        inner_pts = []
                        for i in range(0, 12, 2):
                            inner_pts.extend([
                                cx + (proj_points[i] - cx) * 0.65,
                                cy + (proj_points[i + 1] - cy) * 0.65
                            ])
                        canvas.create_polygon(inner_pts, fill="#030814", outline="#17486e" if progress < 0.72 else "#175e3c", width=1, dash=(3, 3))

                        # Center Core Emblem "S"
                        font_sz = max(10, int(34 * shield_scale))
                        canvas.create_text(cx, cy, text="S", font=("Arial", font_sz, "bold"), fill=shield_color)

                # ── 4. 19-Feature Telemetry Convergence (Scene 2) ──────────
                if 0.22 <= progress < 0.50:
                    stream_prog = (progress - 0.22) / 0.28
                    for fv in feature_vectors:
                        t = (stream_prog * fv["speed"]) % 1.0
                        cur_x = fv["origin"].x * (1.0 - t)
                        cur_y = fv["origin"].y * (1.0 - t)
                        cur_z = fv["origin"].z * (1.0 - t)
                        px, py, f = project(Vec3(cur_x, cur_y, cur_z), cx, cy, 400, cam_z)
                        if f > 0:
                            canvas.create_oval(px - 2, py - 2, px + 2, py + 2, fill=fv["color"], outline="")
                            canvas.create_line(px, py, cx, cy, fill="#0d2c47", width=1, dash=(1, 5))

                # ── 5. Scanning Radar Sweep (Scene 3) ───────────────────────
                if 0.45 <= progress < 0.72:
                    sweep_a = (elapsed_ms * 0.005) % (math.pi * 2)
                    sw_r = 170.0
                    canvas.create_line(
                        cx, cy,
                        cx + math.cos(sweep_a) * sw_r,
                        cy + math.sin(sweep_a) * (sw_r * 0.7),
                        fill="#00ffcc", width=2, dash=(3, 3)
                    )

                # ── 6. Integrity Deflection Burst (Scene 4) ────────────────
                if 0.72 <= progress and not impact_triggered[0]:
                    impact_triggered[0] = True
                    trigger_deflection_burst(cx, cy)

                # Expanding integrity green ring wave
                if 0.72 <= progress < 0.88:
                    ring_t = (progress - 0.72) / 0.16
                    r_wave = ring_t * (width * 0.75)
                    alpha_w = max(1, int((1.0 - ring_t) * 8))
                    canvas.create_oval(
                        cx - r_wave, cy - r_wave * 0.6,
                        cx + r_wave, cy + r_wave * 0.6,
                        outline="#00ff88", width=alpha_w
                    )

                # ── 7. Cinematic HUD Typography ─────────────────────────────
                if progress < 0.20:
                    canvas.create_text(cx, cy - 80, text="SENTINELML V2", font=("Arial", 28, "bold"), fill="#ffffff")
                    canvas.create_text(cx, cy - 40, text="INITIALIZING BEHAVIORAL AI DEFENSE ARCHITECTURE...", font=("Consolas", 11, "bold"), fill="#00d4ff")
                    canvas.create_text(cx, cy + 90, text="● KERNEL & USER-SPACE HEURISTICS: ACTIVE", font=("Consolas", 10), fill="#8b949e")

                elif 0.20 <= progress < 0.46:
                    canvas.create_text(cx, cy - 145, text="SENTINEL ARCHITECTURE INITIALIZATION", font=("Arial", 20, "bold"), fill="#ffffff")
                    canvas.create_text(cx, cy - 118, text="CALIBRATING 19-POINT BEHAVIORAL MATRIX", font=("Consolas", 11, "bold"), fill="#00ffcc")
                    canvas.create_text(cx, cy + 140, text="[PROCESS]   [MEMORY]   [CRYPTO]   [FILESYSTEM]   [PRIVILEGE]   [NETWORK]", font=("Consolas", 10), fill="#58a6ff")

                elif 0.46 <= progress < 0.72:
                    canvas.create_text(cx, cy - 145, text="RANDOM FOREST ENSEMBLE ARMED", font=("Arial", 20, "bold"), fill="#ffffff")
                    canvas.create_text(cx, cy - 118, text="100 DECISION TREES CALIBRATED • INFERENCE READY", font=("Consolas", 11, "bold"), fill="#00d4ff")
                    canvas.create_text(cx, cy + 140, text="SYSTEM READY — WAITING FOR USER SCAN COMMAND", font=("Consolas", 10), fill="#8b949e")

                elif 0.72 <= progress < 0.88:
                    canvas.create_text(cx, cy - 145, text="CORE DEFENSE STANDBY", font=("Arial", 22, "bold"), fill="#00ff88")
                    canvas.create_text(cx, cy - 118, text="SYSTEM SAFE // READY TO SCAN", font=("Consolas", 12, "bold"), fill="#ffffff")
                    canvas.create_text(cx, cy + 140, text="ALL SUBSYSTEMS OPERATIONAL", font=("Consolas", 10, "bold"), fill="#00ff88")

                elif progress >= 0.88:
                    # Iris transition into dashboard
                    iris_t = (progress - 0.88) / 0.12
                    canvas.create_text(cx, cy, text="SENTINELML", font=("Arial", int(36 + iris_t * 20), "bold"), fill="#ffffff")

                # ── 8. Visible Skip Control Badge ──────────────────────────
                canvas.create_text(
                    width - 75, 26,
                    text="SKIP [ESC] »",
                    font=("Consolas", 11, "bold"),
                    fill="#00d4ff"
                )

                after_id[0] = canvas.after(16, animate_frame)
            except Exception as e:
                log.warning("Startup animation encountered error (%s) - transitioning to dashboard", e)
                _cleanup(failed=True)

        # Fail-safe timer to guarantee child frames are restored
        timer_id[0] = main_window.after(duration + 400, lambda: _cleanup(failed=False))

        # Skip bindings: click canvas, any key, Escape, or Space
        canvas.bind("<Button-1>", lambda e: _cleanup(failed=False))
        canvas.bind("<Key>", lambda e: _cleanup(failed=False))
        try:
            main_window.bind("<Escape>", lambda e: _cleanup(failed=False))
            main_window.bind("<space>", lambda e: _cleanup(failed=False))
        except Exception:
            pass

        animate_frame()
        return canvas

    except Exception as e:
        log.error("Startup animation failed to initialize: %s", e, exc_info=True)
        _cleanup(failed=True)
        return None
