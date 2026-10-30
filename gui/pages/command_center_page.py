"""
SentinelML V2 — Interactive 3D Cybersecurity Command Center (Tk page)
======================================================================
Five interactive 3D scenes via CommandCenter3D (Canvas, pure Python).
Live app-state polling every 2 s. Never feeds SAFE to canvas on incomplete
/error/cancelled states. No background threads — only safe_after timers.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import customtkinter as ctk

from gui.exhibition_theme import EX_COLORS
from gui.command_center_3d import (
    CommandCenter3D,
    ALL_SCENES,
    SCENE_SHIELD,
    SCENE_WORKSTATION,
    SCENE_FILES,
    SCENE_PIPELINE,
    SCENE_REPLAY,
    _status_color,
)

log = logging.getLogger("sentinel.gui.command_center_page")

_UNSAFE = {"CANCELLED", "SCAN_INCOMPLETE", "INCOMPLETE", "ERROR", "ANALYSIS_ERROR",
           "NOT_SCANNED"}

_SCENE_LABELS = {
    SCENE_SHIELD:      "🛡 Shield",
    SCENE_WORKSTATION: "🖥 Workstation",
    SCENE_FILES:       "📁 Files",
    SCENE_PIPELINE:    "🧠 AI Pipeline",
    SCENE_REPLAY:      "⏯ Replay",
}

_SCENE_DESCS = {
    SCENE_SHIELD:      "Rotating 3D shield bound to real scan status. Drag=rotate, scroll=zoom.",
    SCENE_WORKSTATION: "3D workstation with telemetry nodes. Click nodes for feature details.",
    SCENE_FILES:       "File cubes from File Integrity Watchtower (SIMULATION if no baseline).",
    SCENE_PIPELINE:    "5-stage AI pipeline: Telemetry → Features → Scaler → Forest → Output.",
    SCENE_REPLAY:      "Attack kill-chain replay. Use controls to Play/Pause/Reset.",
}


class CommandCenterPage(ctk.CTkFrame):
    """Interactive 3D Cybersecurity Command Center page."""

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=EX_COLORS["bg"], **kwargs)
        self._config       = config
        self._is_destroyed = False
        self._pending_after: set = set()
        self._current_scene   = SCENE_SHIELD
        self._last_scan_result: Optional[Any] = None

        self._build_ui()
        self._safe_after(300, self._poll_app_state)

    # --- Scheduling -----------------------------------------------------------

    def _safe_after(self, ms: int, fn, *args) -> None:
        if self._is_destroyed:
            return
        holder = [None]

        def wrapper():
            if self._is_destroyed:
                return
            try:
                if not self.winfo_exists():
                    return
                self._pending_after.discard(holder[0])
                fn(*args)
            except Exception:
                pass

        try:
            aid = self.after(ms, wrapper)
            holder[0] = aid
            self._pending_after.add(aid)
        except Exception:
            pass

    def destroy(self) -> None:
        self._is_destroyed = True
        for aid in list(self._pending_after):
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        self._pending_after.clear()
        try:
            self._canvas.pause()
            self._canvas.destroy()
        except Exception:
            pass
        try:
            super().destroy()
        except Exception:
            pass

    # --- UI ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._build_header()
        self._build_body()

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color=EX_COLORS["header"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            header, text="🎮  SENTINELML V2  —  3D CYBERSECURITY COMMAND CENTER",
            font=ctk.CTkFont("Segoe UI", 18, weight="bold"),
            text_color=EX_COLORS["white"],
        ).grid(row=0, column=0, padx=20, pady=12, sticky="w")

        self._status_badge = ctk.CTkLabel(
            header, text="STATUS: IDLE",
            font=ctk.CTkFont("Consolas", 12, weight="bold"),
            text_color=EX_COLORS["cyan"], fg_color="#1e3a6e", corner_radius=6, padx=12)
        self._status_badge.grid(row=0, column=1, padx=8, pady=12, sticky="w")

        btn_bar = ctk.CTkFrame(header, fg_color="transparent")
        btn_bar.grid(row=0, column=2, padx=16, pady=10, sticky="e")
        ctk.CTkButton(btn_bar, text="↺ Reset Camera",
                      font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                      fg_color="#243552", hover_color="#2a5a8a", text_color=EX_COLORS["white"], height=30,
                      command=self._reset_camera).pack(side="left", padx=4)
        ctk.CTkButton(btn_bar, text="← Back to Lab",
                      font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                      fg_color="#1a4a7a", hover_color="#2060a0", text_color=EX_COLORS["cyan"], height=30,
                      command=self._back_to_lab).pack(side="left", padx=4)

    def _build_body(self) -> None:
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        body.grid_columnconfigure(0, weight=4)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        # Left: canvas + scene bar
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left.grid_rowconfigure(2, weight=1)
        left.grid_columnconfigure(0, weight=1)

        sel_bar = ctk.CTkFrame(left, fg_color=EX_COLORS["card"], corner_radius=8,
                               border_width=1, border_color=EX_COLORS["card_border"])
        sel_bar.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        ctk.CTkLabel(sel_bar, text="SCENE:", font=ctk.CTkFont("Consolas", 10, weight="bold"),
                     text_color=EX_COLORS["muted"]).pack(side="left", padx=(12, 4), pady=6)
        self._scene_btns: dict = {}
        for key, label in _SCENE_LABELS.items():
            btn = ctk.CTkButton(
                sel_bar, text=label,
                font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                fg_color=EX_COLORS["gold"] if key == self._current_scene else "#243552",
                hover_color=EX_COLORS["gold_hover"] if key == self._current_scene else "#2a5a8a",
                text_color="#000000" if key == self._current_scene else EX_COLORS["white"],
                height=30, width=110,
                command=lambda k=key: self._switch_scene(k))
            btn.pack(side="left", padx=3, pady=4)
            self._scene_btns[key] = btn

        # Replay control bar (hidden until REPLAY scene)
        self._replay_bar = ctk.CTkFrame(left, fg_color=EX_COLORS["card"], corner_radius=8,
                                        border_width=1, border_color=EX_COLORS["card_border"])
        self._build_replay_bar()

        canvas_frame = ctk.CTkFrame(left, fg_color=EX_COLORS["panel_dark"], corner_radius=8,
                                    border_width=1, border_color=EX_COLORS["card_border"])
        canvas_frame.grid(row=2, column=0, sticky="nsew")
        canvas_frame.grid_rowconfigure(0, weight=1)
        canvas_frame.grid_columnconfigure(0, weight=1)

        self._canvas = CommandCenter3D(canvas_frame, width=640, height=460,
                                       reduced_motion=False, on_select=self._on_object_click)
        self._canvas.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

        # Right: detail panel
        right = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                             border_width=1, border_color=EX_COLORS["card_border"])
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right.grid_rowconfigure(2, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="OBJECT DETAIL",
                     font=ctk.CTkFont("Segoe UI", 13, weight="bold"), text_color=EX_COLORS["gold"]).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))

        self._detail_obj_lbl = ctk.CTkLabel(
            right, text="Click a 3D object to inspect it.",
            font=ctk.CTkFont("Segoe UI", 13, weight="bold"), text_color=EX_COLORS["white"], anchor="w", wraplength=320)
        self._detail_obj_lbl.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 4))

        detail_scroll = ctk.CTkScrollableFrame(right, fg_color=EX_COLORS["panel_dark"])
        detail_scroll.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 4))
        detail_scroll.grid_columnconfigure(0, weight=1)
        self._detail_body = ctk.CTkLabel(
            detail_scroll,
            text="Drag to rotate  ·  Scroll to zoom\nClick highlighted objects for details.\n\n"
                 "Live app status polled every 2s.\nRun a scan on the Dashboard, then\n"
                 "return here to see real telemetry.",
            font=ctk.CTkFont("Segoe UI", 12), text_color=EX_COLORS["muted"], anchor="w", justify="left", wraplength=300)
        self._detail_body.pack(fill="x", padx=8, pady=8, anchor="w")

        self._scene_desc = ctk.CTkLabel(
            right, text=_SCENE_DESCS.get(self._current_scene, ""),
            font=ctk.CTkFont("Segoe UI", 12, slant="italic"), text_color=EX_COLORS["muted"], anchor="w", justify="left", wraplength=320)
        self._scene_desc.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 8))

    def _build_replay_bar(self) -> None:
        self._rp_play_btn = ctk.CTkButton(
            self._replay_bar, text="▶ Play",
            font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
            fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"],
            text_color="#000000", height=28, width=70, command=self._replay_play)
        self._rp_play_btn.pack(side="left", padx=(10,4), pady=6)

        self._rp_pause_btn = ctk.CTkButton(
            self._replay_bar, text="⏸",
            fg_color="#3d5070", text_color=EX_COLORS["white"],
            height=28, width=44, state="disabled", command=self._replay_pause)
        self._rp_pause_btn.pack(side="left", padx=2, pady=6)

        self._rp_resume_btn = ctk.CTkButton(
            self._replay_bar, text="⏵",
            fg_color="#1a4a7a", text_color=EX_COLORS["cyan"],
            height=28, width=44, state="disabled", command=self._replay_resume)
        self._rp_resume_btn.pack(side="left", padx=2, pady=6)

        self._rp_reset_btn = ctk.CTkButton(
            self._replay_bar, text="↻",
            fg_color="#243552", text_color=EX_COLORS["white"],
            height=28, width=44, command=self._replay_reset)
        self._rp_reset_btn.pack(side="left", padx=2, pady=6)

        ctk.CTkLabel(self._replay_bar, text="Speed:",
                     font=ctk.CTkFont("Segoe UI", 10), text_color=EX_COLORS["muted"]
                     ).pack(side="left", padx=(8,2), pady=6)
        self._rp_speed = ctk.CTkSegmentedButton(
            self._replay_bar, values=["0.5x","1x","2x","4x"],
            selected_color=EX_COLORS["gold"], selected_hover_color=EX_COLORS["gold_hover"],
            text_color=EX_COLORS["white"], fg_color=EX_COLORS["panel_dark"],
            command=self._replay_speed)
        self._rp_speed.set("1x")
        self._rp_speed.pack(side="left", padx=6, pady=6)

    # --- Scene switch --------------------------------------------------------

    def _switch_scene(self, key: str) -> None:
        self._current_scene = key
        self._canvas.set_scene(key)
        for k, btn in self._scene_btns.items():
            active = k == key
            btn.configure(
                fg_color=EX_COLORS["gold"] if active else "#243552",
                hover_color=EX_COLORS["gold_hover"] if active else "#2a5a8a",
                text_color="#000000" if active else EX_COLORS["white"])
        if key == SCENE_REPLAY:
            self._replay_bar.grid(row=1, column=0, sticky="ew", pady=(0,4))
            self._bind_replay_ctrl()
        else:
            self._replay_bar.grid_remove()
        self._scene_desc.configure(text=_SCENE_DESCS.get(key, ""))

    # --- Object click detail -------------------------------------------------

    def _on_object_click(self, scene: str, label: str) -> None:
        self._detail_obj_lbl.configure(text=label)
        detail = self._build_detail(scene, label)
        for w in list(self._detail_body.master.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass
        ctk.CTkLabel(
            self._detail_body.master, text=detail,
            font=ctk.CTkFont("Segoe UI", 12), text_color=EX_COLORS["white"], anchor="w", justify="left", wraplength=300,
        ).pack(fill="x", padx=8, pady=8, anchor="w")

    def _build_detail(self, scene: str, label: str) -> str:
        if scene == SCENE_WORKSTATION and "[" in label:
            feat = label.split("[")[0].strip()
            kind = label.split("[")[1].rstrip("]").strip() if "[" in label else ""
            descs = {
                "total_processes": "Total running processes on this host.",
                "suspicious_process_count": "Processes matching ransomware name/path heuristics.",
                "avg_entropy": "Mean Shannon entropy across sampled files (bits/byte).",
                "network_connection_count": "Active TCP/UDP connections.",
                "malfind_injection_count": "Heuristic proxy for unbacked executable memory.",
                "registry_handle_count": "Open registry handle proxy (heuristic).",
                "cmd_vssadmin_count": "Shadow-copy deletion command-line heuristic.",
                "defender_tampering_count": "Attempts to disable endpoint protection.",
            }
            return (f"Feature: {feat}\nSensor type: {kind}\n\n"
                    f"{descs.get(feat, 'Behavioral feature: '+feat)}\n\n"
                    "MEASURED = direct OS query.\nHEURISTIC = approximate proxy.")
        if scene == SCENE_FILES:
            parts = label.split(": ", 1)
            status = parts[0] if parts else ""
            fname  = parts[1] if len(parts) > 1 else label
            descs = {
                "added":     "Not in baseline; appeared in current scan.",
                "modified":  "Hash changed since baseline.",
                "deleted":   "In baseline but absent now.",
                "unchanged": "Hash matches baseline.",
                "simulated": "SIMULATION placeholder — no real baseline yet.",
            }
            return (f"File: {fname}\nStatus: {status.upper()}\n\n"
                    f"{descs.get(status,'')}\n\n"
                    "⚠ A file change does NOT confirm ransomware.\n"
                    "Behavioral detection is in the Exhibition Lab.")
        if scene == SCENE_PIPELINE and "Stage:" in label:
            stage = label.replace("Stage: ", "")
            descs = {
                "TELEMETRY": "19 behavioral sensors from the host OS.",
                "FEATURES":  "19-element vector in FEATURE_NAMES order.",
                "SCALER":    "StandardScaler (models/scaler.pkl) — read-only.",
                "FOREST":    "100-tree Random Forest — EXPERIMENTAL_SYNTHETIC_BASELINE_V1.",
                "OUTPUT":    "p≥0.90→CRITICAL  p≥0.50→WARNING  p<0.50→SAFE\n"
                             "Missing telemetry→INCONCLUSIVE\nIncomplete→never SAFE.",
            }
            return descs.get(stage, f"Pipeline stage: {stage}")
        if scene == SCENE_REPLAY:
            return (f"Event: {label}\n\nSource: SIMULATED\n"
                    "No real malware executes; no real files modified.\n"
                    "See Attack Replay page for full detail.")
        return f"Object: {label}\nScene: {scene}"

    # --- App state polling ---------------------------------------------------

    def _poll_app_state(self) -> None:
        if self._is_destroyed:
            return
        try:
            self._refresh_canvas_state()
        except Exception as exc:
            log.debug("Command center poll: %s", exc)
        self._safe_after(2000, self._poll_app_state)

    def _refresh_canvas_state(self) -> None:
        win = self.master
        pages = getattr(win, "_pages", {})

        status = "IDLE"; prob = 0.0; files = 0; procs = 0
        dashboard = pages.get("dashboard")
        if dashboard is not None:
            try:
                tl = getattr(dashboard, "_threat_level", "NOT_SCANNED")
                status = str(tl).upper()
                prob = float(getattr(dashboard, "_risk_score", 0.0))
                sr = getattr(dashboard, "_last_scan_result", None) or \
                     getattr(dashboard, "_last_host_scan_result", None)
                if sr:
                    files = int(getattr(sr, "files_inspected", 0))
                    procs = int(getattr(sr, "processes_analyzed", 0))
            except Exception:
                pass

        # Safety: never feed SAFE-looking probability for unsafe states
        if status in _UNSAFE:
            prob = 0.0

        self._canvas.set_app_status(status, prob)
        self._canvas.set_scan_stats(files, procs)
        color = _status_color(status)
        self._status_badge.configure(
            text=f"STATUS: {status}" + (f"  ({prob*100:.0f}%)" if prob > 0 else ""),
            text_color=color)

        # Watchtower diff
        wt = pages.get("integrity_watchtower")
        if wt is not None:
            diff = getattr(wt, "_wt_last_diff", None)
            if diff is not None:
                try:
                    self._canvas.set_watchtower_results(
                        len(diff.added), len(diff.modified),
                        len(diff.deleted), diff.unchanged_count)
                except Exception:
                    pass

        if self._current_scene == SCENE_REPLAY:
            self._bind_replay_ctrl()

    def _bind_replay_ctrl(self) -> None:
        try:
            rp = getattr(self.master, "_pages", {}).get("attack_replay")
            if rp:
                ctrl = getattr(rp, "_ctrl", None)
                plan = getattr(rp, "_plan", [])
                events = [{"title": s.title, "t": s.t,
                           "severity": s.severity, "detail": s.detail}
                          for s in plan]
                self._canvas.set_replay_data(ctrl, events)
                if ctrl:
                    state = getattr(ctrl, "state", "idle")
                    self._rp_play_btn.configure(
                        state="normal" if state in ("idle","done") else "disabled")
                    self._rp_pause_btn.configure(state="normal" if state=="playing" else "disabled")
                    self._rp_resume_btn.configure(state="normal" if state=="paused" else "disabled")
        except Exception:
            pass

    # --- Replay controls -----------------------------------------------------

    def _get_ctrl(self):
        try:
            rp = getattr(self.master, "_pages", {}).get("attack_replay")
            if rp:
                return getattr(rp, "_ctrl", None)
        except Exception:
            pass
        return None

    def _replay_play(self) -> None:
        ctrl = self._get_ctrl()
        if ctrl is None:
            return
        try:
            if ctrl.state in ("idle","done"):
                ctrl.start()
            elif ctrl.state == "paused":
                ctrl.resume()
            self._rp_play_btn.configure(state="disabled")
            self._rp_pause_btn.configure(state="normal")
            self._rp_resume_btn.configure(state="disabled")
            rp = getattr(self.master, "_pages", {}).get("attack_replay")
            if rp and hasattr(rp, "_schedule_next"):
                rp._schedule_next()
        except Exception:
            pass

    def _replay_pause(self) -> None:
        ctrl = self._get_ctrl()
        if ctrl:
            try:
                ctrl.pause()
                self._rp_play_btn.configure(state="normal")
                self._rp_pause_btn.configure(state="disabled")
                self._rp_resume_btn.configure(state="normal")
            except Exception:
                pass

    def _replay_resume(self) -> None:
        ctrl = self._get_ctrl()
        if ctrl:
            try:
                ctrl.resume()
                rp = getattr(self.master, "_pages", {}).get("attack_replay")
                if rp and hasattr(rp, "_schedule_next"):
                    rp._schedule_next()
                self._rp_play_btn.configure(state="disabled")
                self._rp_pause_btn.configure(state="normal")
                self._rp_resume_btn.configure(state="disabled")
            except Exception:
                pass

    def _replay_reset(self) -> None:
        ctrl = self._get_ctrl()
        if ctrl:
            try:
                ctrl.reset()
                self._rp_play_btn.configure(state="normal")
                self._rp_pause_btn.configure(state="disabled")
                self._rp_resume_btn.configure(state="disabled")
            except Exception:
                pass

    def _replay_speed(self, val: str) -> None:
        ctrl = self._get_ctrl()
        if ctrl:
            try:
                ctrl.set_speed(float(val.rstrip("x")))
            except Exception:
                pass

    # --- Camera / nav --------------------------------------------------------

    def _reset_camera(self) -> None:
        self._canvas.reset_camera()

    def _back_to_lab(self) -> None:
        try:
            self._canvas.pause()
        except Exception:
            pass
        show = getattr(self.master, "_show_page", None)
        if callable(show):
            show("exhibition_lab")

    def on_shown(self) -> None:
        try:
            self._canvas.resume()
        except Exception:
            pass
        self._safe_after(100, self._refresh_canvas_state)
