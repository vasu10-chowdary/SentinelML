from scanner.scan_engine import ScanType, ScanState
from ml.predictor import normalize_risk_score
"""
SentinelML V2 — Cinematic Interactive 3D Scan Visualizer & Command Center
========================================================================
High-performance, non-blocking 3D perspective security command center.
Features:
  • Persistent Canvas objects with in-place coords() updates (0 canvas item churn, <0.5ms/frame)
  • Layered 3D Sentinel Shield geometry with perspective depth and interactive pointer parallax
  • Rotating orbital rings, continuous radar scan beam, and telemetry particle flow
  • 19 behavioral feature nodes orbiting during ML inference phases
  • Interactive 7-stage Analysis Pipeline with hover explanations and click inspection
  • Persistent, non-blank results and telemetry layout initialized from millisecond 0
  • Authoritative atomic state transitions: 3D shield, top status, results panel, and Cancel button
  • Impossible for Cancel button to coexist with SAFE or terminal classifications
  • Clean deferred destruction avoiding double-destroy and screen blanking on return to dashboard
  • Persistent Top Bar Close button (← Back to Dashboard) visible in all states
  • Manual scan start: Opening visualizer starts in IDLE; user must explicitly click Start Live Scan
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import math
import time
import webbrowser
import logging
from typing import Optional, Dict, Any, List, Tuple
from constants import COLOURS as C

log = logging.getLogger("sentinel.gui.visualizer")

# ── Feature catalogue (19 real ML features, 6 groups) ─────────────────────
_FEATURE_GROUPS = [
    ("PROCESS",    "#3fb950", ["total_processes", "suspicious_process_count",
                               "orphan_process_count", "powershell_process_count",
                               "suspicious_thread_count"]),
    ("MEMORY",     "#0ea5e9", ["malfind_injection_count", "unsigned_module_count",
                               "suspicious_mutex_count"]),
    ("CRYPTO",     "#d29922", ["avg_entropy", "max_entropy",
                               "high_entropy_region_count", "crypto_dll_count"]),
    ("NETWORK",    "#00d4aa", ["network_connection_count", "unique_external_ips"]),
    ("FILESYSTEM", "#8b949e", ["file_handle_count", "registry_handle_count",
                               "cmd_vssadmin_count"]),
    ("PRIVILEGE",  "#f85149", ["abnormal_privilege_count",
                               "defender_tampering_count"]),
]

# ── Pipeline stages ────────────────────────────────────────────────────────
_STAGES = [
    ("RAW_TELEMETRY",       "Raw Telemetry"),
    ("PROCESS_ANALYSIS",    "Process Analysis"),
    ("FILESYSTEM_ANALYSIS", "Filesystem Analysis"),
    ("FEATURE_EXTRACTION",  "19 Behavioral Features"),
    ("STANDARD_SCALER",     "Standard Scaler"),
    ("RANDOM_FOREST",       "Random Forest"),
    ("SECURITY_DECISION",   "Security Decision"),
]

_STAGE_EDU = {
    "RAW_TELEMETRY":
        "Collecting raw system telemetry from the operating system, "
        "running processes, and accessible filesystem directories.",
    "PROCESS_ANALYSIS":
        "Examining running processes for behavioral indicators — "
        "injection patterns, unsigned modules, orphan processes, and "
        "suspicious PowerShell activity.",
    "FILESYSTEM_ANALYSIS":
        "Inspecting accessible files, measuring Shannon entropy distributions, "
        "and identifying filesystem access patterns associated with "
        "anomalous or ransomware-like bulk modification.",
    "FEATURE_EXTRACTION":
        "Aggregating observed behavioral signals into a 19-dimensional "
        "feature vector representing the host's runtime threat profile.",
    "STANDARD_SCALER":
        "Applying the fitted StandardScaler to normalize the 19 "
        "feature values to zero mean and unit variance for model inference.",
    "RANDOM_FOREST":
        "The trained 100-tree Random Forest evaluates the normalized "
        "behavioral feature vector and estimates malicious probability.",
    "SECURITY_DECISION":
        "Applying verified classification thresholds (0.50 Warning, 0.90 Threat) "
        "to produce the final authoritative security classification.",
}

_LEARN_CARDS = [
    ("WHY PROCESS ANALYSIS?",
     "Malware commonly leaves behavioral indicators in running processes — "
     "injection patterns, unsigned modules, and abnormal thread activity."),
    ("WHY ENTROPY MEASUREMENT?",
     "High file entropy can be associated with encrypted or compressed "
     "content. Entropy alone does not prove ransomware, but it is one "
     "useful behavioral signal."),
    ("WHY 19 FEATURES?",
     "SentinelML combines multiple behavioral indicators rather than "
     "relying on any single signal. A combination is harder to evade."),
    ("WHY RANDOM FOREST?",
     "The Random Forest classifier aggregates 100 decision trees to "
     "produce a calibrated probability estimate from the behavioral profile."),
    ("WHY STANDARDSCALER?",
     "Feature values have different units and ranges. Normalizing them "
     "ensures no single feature dominates the model's decision."),
]


class ScanVisualizer(ctk.CTkFrame):
    """
    Cinematic Interactive 3D Security Command Center & Scan Overlay.
    Shown during live host analysis, behavioral simulation, and result evaluation.
    """

    def __init__(
        self,
        master,
        on_close=None,
        on_cancel=None,
        on_start_scan=None,
        mode: str = "LIVE ANALYSIS",
        initial_state: str = "IDLE",
        **kwargs
    ):
        super().__init__(master, fg_color=C["bg"], **kwargs)
        self.on_close = on_close
        self.on_cancel = on_cancel
        self.on_start_scan = on_start_scan
        self.mode = mode

        # Row 0 = top bar (fixed), Row 1 = body (expands)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ── State tracking ─────────────────────────────────────────────────
        self.running = True
        self._is_closing = False
        self._scan_in_flight = False
        self.angle = 0.0
        self.t0 = time.time()
        self.stage = "RAW_TELEMETRY"
        self.scan_state_str = initial_state
        self._hovered_stage: Optional[str] = None
        self._selected_stage: Optional[str] = None
        self._stage_timings: Dict[str, float] = {}
        self._stage_completed: set = set()
        self._learn_idx = 0
        self._last_learn_t = time.time()
        self._last_stage_t = time.time()
        self._last_frame_t = time.time()
        self._anim_job = None
        self._wrap_labels: List[ctk.CTkLabel] = []
        self._last_scan_result = None
        self._pacing_after_ids: List[str] = []

        # Clean lifecycle binding: guarantee animation cancellation on destruction
        def _on_destroy(event):
            if event.widget == self:
                self.running = False
                self._is_closing = True
                self._scan_in_flight = False
                if getattr(self, "_anim_job", None):
                    try:
                        self.after_cancel(self._anim_job)
                    except Exception:
                        pass
                    self._anim_job = None
        self.bind("<Destroy>", _on_destroy, add=True)

        # Interactive parallax offsets
        self._mouse_target_x = 0.0
        self._mouse_target_y = 0.0
        self._cur_ox = 0.0
        self._cur_oy = 0.0

        # Cached canvas objects for in-place coords() update
        self._canvas_initialized = False
        self._last_w = 0
        self._last_h = 0
        self._particles = self._make_particles()

        self._build_topbar()
        self._build_body()

        # Initialize to authoritative initial state (IDLE by default)
        self.set_scan_state(initial_state)
        self.set_stage("RAW_TELEMETRY")
        self._anim_job = self.after(33, self._animate)

    def _cancel_pacing_callbacks(self):
        """Cancel any pending layout pacing after-callbacks to prevent stale execution."""
        for aid in getattr(self, "_pacing_after_ids", []):
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        if hasattr(self, "_pacing_after_ids"):
            self._pacing_after_ids.clear()

    # ── Top Bar ───────────────────────────────────────────────────────────
    def _build_topbar(self):
        bar = ctk.CTkFrame(self, fg_color=C["panel"], height=42, corner_radius=0)
        bar.grid(row=0, column=0, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(1, weight=1)

        title_box = ctk.CTkFrame(bar, fg_color="transparent")
        title_box.grid(row=0, column=0, padx=18, pady=8, sticky="w")

        ctk.CTkLabel(
            title_box,
            text=f"SENTINELML  —  {self.mode.upper()}",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=C["accent"],
        ).pack(side="left")

        self._badge_3d = ctk.CTkLabel(
            title_box,
            text=" 3D CORE ACTIVE ",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color="#00ff88",
            fg_color="#0a2e1d",
            corner_radius=4,
            height=18
        )
        self._badge_3d.pack(side="left", padx=(10, 0))

        right_box = ctk.CTkFrame(bar, fg_color="transparent")
        right_box.grid(row=0, column=1, padx=18, sticky="e")

        # Top Bar Persistent Close / Return button (visible in all states)
        self._top_close_btn = ctk.CTkButton(
            right_box,
            text="← Back to Dashboard",
            width=145,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=C["card"],
            hover_color=C["border"],
            text_color=C["white"],
            border_width=1,
            border_color=C["border"],
            command=self._handle_top_close,
        )
        self._top_close_btn.pack(side="left", padx=(0, 10))

        # Cancel button (enabled and visible strictly during scanning/analyzing)
        self._cancel_btn = ctk.CTkButton(
            right_box,
            text="✕ Cancel Scan",
            width=100,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#2b1a1a",
            hover_color="#3d2424",
            text_color="#ff7b72",
            border_width=1,
            border_color="#f85149",
            command=self._handle_cancel,
        )
        # Packed conditionally in set_scan_state

        self._bar_stage = ctk.CTkLabel(
            right_box,
            text="IDLE",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["accent"],
        )
        self._bar_stage.pack(side="left")

    def _handle_top_close(self):
        """Handle top bar close click with confirmation if a scan is actively running."""
        is_active = self.scan_state_str in ("SCANNING", "ANALYZING") or getattr(self, "_scan_in_flight", False)
        if is_active:
            try:
                confirmed = messagebox.askyesno(
                    "Cancel Active Scan?",
                    "A live host scan is currently in progress.\n\n"
                    "Do you want to cancel the scan and return to the dashboard?",
                    parent=self
                )
            except Exception:
                confirmed = True

            if not confirmed:
                return  # Stay on visualization

            # User confirmed cancellation: request cancel safely
            if self.on_cancel:
                try:
                    self.on_cancel()
                except Exception as e:
                    log.error("Error invoking on_cancel during close: %s", e)

        # Return immediately to dashboard cleanly
        self.close()

    def _handle_cancel(self):
        if hasattr(self, "_cancel_btn") and self._cancel_btn:
            self._cancel_btn.configure(text="Cancelling…", state="disabled")
        if self.on_cancel:
            self.on_cancel()

    # ── Main Body Layout ──────────────────────────────────────────────────
    def _build_body(self):
        """Two-column body: 3D interactive canvas on left (hero), persistent info panel + fixed action bar on right."""
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=18, pady=(8, 14))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=3, minsize=420)   # Canvas hero
        body.grid_columnconfigure(1, weight=2, minsize=320)   # Info panel & Action bar

        # ── Left: Canvas Panel ────────────────────────────────────────────
        cp = ctk.CTkFrame(body, fg_color=C["panel"], corner_radius=12, border_width=1, border_color=C["border"])
        cp.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        cp.grid_rowconfigure(0, weight=1)
        cp.grid_columnconfigure(0, weight=1)

        self.canvas = tk.Canvas(cp, bg="#080c14", highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

        # Mouse interactivity bindings
        self.canvas.bind("<Motion>", self._on_canvas_mouse_motion)
        self.canvas.bind("<Leave>", self._on_canvas_mouse_leave)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        # Draw initial background and dynamic items immediately
        self._last_w = 600
        self._last_h = 400
        self._draw_static_background(600, 400)
        self._init_dynamic_canvas_objects()

        # ── Right Column: Container for Scrollable Cards + Permanent Fixed Action Bar ──
        right_container = ctk.CTkFrame(body, fg_color="transparent")
        right_container.grid(row=0, column=1, sticky="nsew")
        right_container.grid_rowconfigure(0, weight=1)  # Scrollable cards area
        right_container.grid_rowconfigure(1, weight=0)  # Permanent fixed action bar (docked at bottom)
        right_container.grid_columnconfigure(0, weight=1)

        # Scrollable Cards (Pipeline, Security Status, Live Telemetry, Highlights, Guidance)
        info = ctk.CTkScrollableFrame(right_container, fg_color="transparent")
        info.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        info.grid_columnconfigure(0, weight=1)

        info.bind("<Configure>", self._on_info_configure)

        self._build_pipeline(info)
        self._build_status_card(info)
        self._build_stats(info)
        self._build_highlights_card(info)
        self._build_action_card(info)

        # Permanent Fixed Action Bar (outside scrollable frame: NEVER scrolls, always visible!)
        self._build_fixed_action_bar(right_container)

        self._info_panel = info
        self._right_container = right_container

    def _on_info_configure(self, event):
        """Ensure all text labels wrap responsively to available panel width without horizontal clipping."""
        new_wrap = max(180, event.width - 56)
        if getattr(self, "_last_wraplength", None) == new_wrap:
            return
        self._last_wraplength = new_wrap
        for lbl in self._wrap_labels:
            try:
                lbl.configure(wraplength=new_wrap)
            except Exception:
                pass

    # ── 1. Pipeline Stage Card ────────────────────────────────────────────
    def _build_pipeline(self, parent):
        f = ctk.CTkFrame(parent, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"])
        f.pack(fill="x", pady=(0, 8))
        self._pipe_frame = f

        hdr_row = ctk.CTkFrame(f, fg_color="transparent")
        hdr_row.pack(fill="x", padx=14, pady=(8, 3))

        ctk.CTkLabel(
            hdr_row, text="ANALYSIS PIPELINE",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C["muted"],
        ).pack(side="left")

        ctk.CTkLabel(
            hdr_row, text="Hover stage to inspect",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color="#00a8cc",
        ).pack(side="right")

        self._font_stage_bold = ctk.CTkFont(size=11, weight="bold")
        self._font_stage_normal = ctk.CTkFont(size=11)
        # Shared Segoe UI Symbol font for dot labels avoids 500ms+ Windows GDI
        # fallback search when switching between · (middle dot), ● (circle), and ✓ (check mark)
        self._font_dot = ctk.CTkFont(family="Segoe UI Symbol", size=13, weight="bold")
        self._stage_widgets = {}
        for key, text in _STAGES:
            row_f = ctk.CTkFrame(f, fg_color="transparent", corner_radius=4)
            row_f.pack(fill="x", padx=10, pady=1)

            dot = ctk.CTkLabel(
                row_f, text="·",
                font=self._font_dot,
                text_color=C["muted"], width=18,
            )
            dot.pack(side="left")

            lbl = ctk.CTkLabel(
                row_f, text=text,
                font=ctk.CTkFont(size=11),
                text_color=C["muted"], anchor="w",
            )
            lbl.pack(side="left", fill="x", expand=True, pady=1)

            timing_lbl = ctk.CTkLabel(
                row_f, text="",
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=C["muted"], anchor="e", width=55
            )
            timing_lbl.pack(side="right", padx=(0, 6))

            # Bind hover & click events
            for w in (row_f, dot, lbl, timing_lbl):
                w.bind("<Enter>", lambda e, k=key: self._on_stage_hover(k))
                w.bind("<Leave>", lambda e, k=key: self._on_stage_unhover(k))
                w.bind("<Button-1>", lambda e, k=key: self._on_stage_click(k))

            self._stage_widgets[key] = (row_f, dot, lbl, timing_lbl)

        # Python-side state cache: tracks last configured value for each widget
        # to avoid expensive cget() round-trips. Initialized to match the IDLE defaults.
        self._stage_widget_state = {
            k: {"dot_text": "·", "dot_color": C["muted"], "lbl_color": C["muted"],
                "row_fg": "transparent", "timing_text": ""}
            for k in self._stage_widgets
        }

        ctk.CTkFrame(f, fg_color="transparent", height=2).pack()

    def _on_stage_hover(self, stage_key: str):
        self._hovered_stage = stage_key
        if stage_key in _STAGE_EDU:
            title = dict(_STAGES).get(stage_key, stage_key)
            self._action_title.configure(text=f"STAGE: {title.upper()}", text_color=C["accent"])
            self._action_desc.configure(text=_STAGE_EDU[stage_key])

    def _on_stage_unhover(self, stage_key: str):
        self._hovered_stage = None
        curr = self._selected_stage or self.stage
        if self.scan_state_str in ("SCANNING", "ANALYZING") and curr in _STAGE_EDU:
            title = dict(_STAGES).get(curr, curr)
            self._action_title.configure(text=f"STAGE: {title.upper()}", text_color=C["accent"])
            self._action_desc.configure(text=_STAGE_EDU[curr])
        else:
            self._restore_action_guidance()

    def _on_stage_click(self, stage_key: str):
        self._selected_stage = stage_key
        self._on_stage_hover(stage_key)

    # ── 2. Authoritative Security Status Card ─────────────────────────────
    def _build_status_card(self, parent):
        f = ctk.CTkFrame(parent, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"])
        f.pack(fill="x", pady=(0, 8))
        self._status_card_frame = f

        hdr_row = ctk.CTkFrame(f, fg_color="transparent")
        hdr_row.pack(fill="x", padx=14, pady=(10, 2))

        self._status_card_title = ctk.CTkLabel(
            hdr_row, text="SECURITY STATUS",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C["muted"],
        )
        self._status_card_title.pack(side="left")

        self._status_card_badge = ctk.CTkLabel(
            hdr_row, text="  READY  ",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=C["accent"],
            fg_color="#0a2540",
            corner_radius=4,
            height=18,
        )
        self._status_card_badge.pack(side="right")

        self._status_card_verdict = ctk.CTkLabel(
            f, text="READY TO SCAN",
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color=C["accent"],
            anchor="w",
        )
        self._status_card_verdict.pack(anchor="w", padx=14, pady=(2, 4))

        self._status_card_desc = ctk.CTkLabel(
            f, text="Ready when you are. Click 'Start Live Scan' below to inspect running processes, filesystem entropy, and evaluate the 19 behavioral feature Random Forest model.",
            font=ctk.CTkFont(size=11),
            text_color=C["white"],
            wraplength=260, justify="left",
            anchor="w",
        )
        self._status_card_desc.pack(anchor="w", padx=14, pady=(0, 10), fill="x")
        self._wrap_labels.append(self._status_card_desc)

    # ── 3. Responsive Live Telemetry & Verdict Metrics Card ───────────────
    def _build_stats(self, parent):
        f = ctk.CTkFrame(parent, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"])
        f.pack(fill="x", pady=(0, 8))
        self._stats_frame = f

        ctk.CTkLabel(
            f, text="LIVE TELEMETRY & VERDICT METRICS",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C["muted"],
        ).pack(anchor="w", padx=14, pady=(10, 4))

        # Structured two-column grid prevents any value/label overlapping
        grid_f = ctk.CTkFrame(f, fg_color="transparent")
        grid_f.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        grid_f.grid_columnconfigure(0, weight=1)  # Label (left)
        grid_f.grid_columnconfigure(1, weight=1)  # Value (right)

        self._stat_vars = {}
        rows = [
            ("ML Risk Probability",  "Pending"),
            ("Processes inspected",   "Ready"),
            ("Files inspected",       "Ready"),
            ("Active target",         "Idle — Ready to scan"),
            ("Suspicious indicators", "0"),
            ("Features extracted",    "Pending"),
            ("Scan Duration",         "0.0 s"),
        ]

        for i, (label, default) in enumerate(rows):
            lbl_w = ctk.CTkLabel(
                grid_f, text=label,
                font=ctk.CTkFont(size=11),
                text_color=C["muted"],
                anchor="w"
            )
            lbl_w.grid(row=i, column=0, sticky="w", pady=2)

            var = ctk.StringVar(value=default)
            val_w = ctk.CTkLabel(
                grid_f, textvariable=var,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                text_color=C["white"],
                anchor="e"
            )
            val_w.grid(row=i, column=1, sticky="e", pady=2)
            self._stat_vars[label] = var

    # ── 4. Behavioral Feature Highlights Card (Shown on detection) ───────
    def _build_highlights_card(self, parent):
        f = ctk.CTkFrame(parent, fg_color="#141c2b", corner_radius=10, border_width=1, border_color=C["border"])
        self._highlights_frame = f
        # Initially not packed until warning or threat detected

        ctk.CTkLabel(
            f, text="KEY BEHAVIORAL INDICATORS",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C["muted"],
        ).pack(anchor="w", padx=14, pady=(8, 4))

        self._highlights_box = ctk.CTkFrame(f, fg_color="transparent")
        self._highlights_box.pack(fill="x", padx=14, pady=(0, 8))
        self._highlights_box.grid_columnconfigure(0, weight=1)
        self._highlights_box.grid_columnconfigure(1, weight=1)
        # Pre-allocate indicator row labels once to eliminate widget creation/destruction stalls
        self._highlight_labels = []
        _hl_font_name = ctk.CTkFont(size=11)
        _hl_font_val = ctk.CTkFont(family="Consolas", size=11, weight="bold")
        for idx_row in range(4):
            _nl = ctk.CTkLabel(self._highlights_box, text="", font=_hl_font_name, text_color=C["white"], anchor="w")
            _nl.grid(row=idx_row, column=0, sticky="w", pady=1)
            _vl = ctk.CTkLabel(self._highlights_box, text="", font=_hl_font_val, text_color=C["accent"], anchor="e")
            _vl.grid(row=idx_row, column=1, sticky="e", pady=1)
            self._highlight_labels.append((_nl, _vl))

    # ── 5. Action Guidance Card (Scrollable) ──────────────────────────────
    def _build_action_card(self, parent):
        """Guidance and diagnostic recommendations card inside scrollable area."""
        f = ctk.CTkFrame(parent, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"])
        f.pack(fill="x", pady=(0, 6))
        self._action_frame = f

        self._action_title = ctk.CTkLabel(
            f, text="HOST SCAN CONTROL & GUIDANCE",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C["accent"],
        )
        self._action_title.pack(anchor="w", padx=14, pady=(10, 3))

        self._action_desc = ctk.CTkLabel(
            f, text="Ready when you are. System telemetry collection, Shannon entropy evaluation, and Random Forest inference will begin once started.",
            font=ctk.CTkFont(size=11),
            text_color=C["white"],
            wraplength=260, justify="left",
            anchor="w",
        )
        self._action_desc.pack(anchor="w", padx=14, pady=(0, 8), fill="x")
        self._wrap_labels.append(self._action_desc)

        # Cybercrime Helpline Frame (packed dynamically inside guidance card on suspicious/threat verdict)
        self._cybercrime_box = ctk.CTkFrame(f, fg_color="#180e0e", corner_radius=6, border_width=1, border_color="#3d1414")
        ctk.CTkLabel(
            self._cybercrime_box,
            text="CYBERCRIME SUPPORT HELPLINE: 1930",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color="#f85149"
        ).pack(pady=(6, 2))
        ctk.CTkButton(
            self._cybercrime_box,
            text="Open National Cybercrime Portal",
            command=lambda: webbrowser.open("https://www.cybercrime.gov.in/"),
            fg_color=C["card"],
            hover_color=C["border"],
            text_color=C["white"],
            height=24,
            font=ctk.CTkFont(size=10)
        ).pack(fill="x", padx=10, pady=(2, 6))

    # ── 6. Permanent Fixed Action Bar (Never scrolls, always visible) ─────
    def _build_fixed_action_bar(self, parent):
        """Permanently visible action bar pinned to the bottom of the right column."""
        bar = ctk.CTkFrame(parent, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"], height=95)
        bar.grid(row=1, column=0, sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        bar.grid_propagate(False)
        bar.pack_propagate(False)
        self._fixed_action_bar = bar

        # Action Buttons Box with fixed geometry
        box = ctk.CTkFrame(bar, fg_color="transparent", height=85)
        box.pack(fill="x", padx=12, pady=5)
        box.pack_propagate(False)
        self._action_btn_box = box

        # Prominent Start Live Scan button (always visible in IDLE & completed states)
        # NOTE: "Segoe UI Symbol" prevents Tkinter multi-second fallback font search
        #       for the ⚡ (U+26A1 LIGHTNING BOLT) glyph.
        self._start_scan_btn = ctk.CTkButton(
            box,
            text="⚡ Start Live Scan",
            font=ctk.CTkFont(family="Segoe UI Symbol", size=12, weight="bold"),
            fg_color=C["accent"],
            hover_color="#00b896",
            text_color="#080c14",
            height=36,
            corner_radius=8,
            command=self._handle_start_scan,
        )

        # In-progress scanning banner
        # NOTE: "Segoe UI Symbol" avoids Tkinter fallback font search for ⚡ (U+26A1).
        self._scanning_badge = ctk.CTkLabel(
            box,
            text="⚡ SCANNING IN PROGRESS — ML RADAR ACTIVE",
            font=ctk.CTkFont(family="Segoe UI Symbol", size=10, weight="bold"),
            text_color=C["accent"],
            fg_color="#0a2540",
            corner_radius=6,
            height=32
        )

        # Inspect Evidence button (ASCII marker avoids emoji font-fallback delay)
        self._evidence_inspect_btn = ctk.CTkButton(
            box,
            text="[+] Inspect Scan Evidence",
            fg_color=C["card"],
            hover_color=C["border"],
            text_color=C["white"],
            height=30,
            corner_radius=6,
            command=self._handle_inspect_evidence
        )

        # Return to Dashboard button
        self._return_btn = ctk.CTkButton(
            box,
            text="Close — Return to Dashboard",
            command=self.close,
            fg_color=C["card"],
            hover_color=C["border"],
            text_color=C["white"],
            border_width=1,
            border_color=C["border"],
            height=30,
            corner_radius=6,
        )

    def _pace_pack_start_btn(self, btn_text: str = "⚡ Start Live Scan"):
        """Paced Step 1 (+40ms): pack primary action button without reflow collision."""
        if getattr(self, "_is_closing", False) or not self.winfo_exists():
            return
        if hasattr(self, "_scanning_badge") and self._scanning_badge.winfo_manager() == "pack":
            self._scanning_badge.pack_forget()
        self._start_scan_btn.configure(text=btn_text, state="normal")
        if self._start_scan_btn.winfo_manager() != "pack":
            self._start_scan_btn.pack(fill="x", pady=(4, 6))

    def _pace_pack_return_btn(self):
        """Paced Step 2 (+80ms): pack return button."""
        if getattr(self, "_is_closing", False) or not self.winfo_exists():
            return
        self._return_btn.configure(state="normal")
        if self._return_btn.winfo_manager() != "pack":
            self._return_btn.pack(fill="x", pady=(2, 0))

    def _pace_restore_details(self, desc_text: str, act_title: str, act_color: str, act_desc: str, prob_str: str = None):
        """Paced Step 2 (+80ms): configure descriptions and guidance without geometry reflow."""
        if getattr(self, "_is_closing", False) or not self.winfo_exists():
            return
        if desc_text:
            self._status_card_desc.configure(text=desc_text)
        if act_title:
            self._action_title.configure(text=act_title, text_color=act_color)
        if act_desc:
            self._action_desc.configure(text=act_desc)
        if prob_str:
            self._stat_vars["ML Risk Probability"].set(prob_str)

    def _show_action_buttons(self, btn_text: str = "⚡ Start Live Scan"):
        """Backward-compatible entry point that triggers the paced restoration."""
        self._pace_pack_start_btn(btn_text)
        aid = self.after(40, self._pace_pack_return_btn)
        self._pacing_after_ids.append(aid)

    def _handle_start_scan(self):
        """Trigger scan start exactly once, preventing duplicate background threads."""
        self._cancel_pacing_callbacks()
        if self.scan_state_str in ("SCANNING", "ANALYZING") or self._scan_in_flight:
            log.warning("Scan already running, ignoring duplicate start click.")
            return

        self._scan_in_flight = True
        self.t0 = time.time()
        self._start_scan_btn.configure(state="disabled", text="Starting Scan…")

        if self.on_start_scan:
            try:
                self.on_start_scan()
            except Exception as e:
                log.error("Failed to start scan from visualizer: %s", e)
                self.set_scan_state("ANALYSIS ERROR", error=str(e))
                return
        else:
            self.set_scan_state("SCANNING")

    def _handle_inspect_evidence(self):
        db = self.master
        if hasattr(db, "_open_evidence_dialog"):
            db._open_evidence_dialog(getattr(self, "_last_scan_result", None))

    def _restore_action_guidance(self):
        """Restore appropriate action title and description for current state."""
        st = self.scan_state_str
        if st == "IDLE":
            self._action_title.configure(text="HOST SCAN CONTROL & GUIDANCE", text_color=C["accent"])
            self._action_desc.configure(
                text="Ready when you are. System telemetry collection, Shannon entropy evaluation, and Random Forest inference will begin once started."
            )
        elif st == "SAFE":
            self._action_title.configure(text="SECURITY RECOMMENDATIONS", text_color=C["green"])
            self._action_desc.configure(
                text="• Maintain routine backups of essential documents.\n• Keep Sentinel Guard background protection active."
            )
        elif st == "WARNING":
            self._action_title.configure(text="RECOMMENDED INVESTIGATION", text_color=C["yellow"])
            self._action_desc.configure(
                text="• Inspect suspicious processes in the Threat Log.\n• Preserve system event logs for investigation."
            )
        elif st in ("THREAT DETECTED", "CRITICAL"):
            self._action_title.configure(text="IMMEDIATE DEFENSIVE ACTIONS", text_color=C["red"])
            self._action_desc.configure(
                text="• Isolate system from the local area network immediately.\n• Do not execute unverified executable files.\n• Export and archive the SentinelML Incident Report."
            )
        elif st == "CANCELLED":
            self._action_title.configure(text="SCAN STATUS", text_color=C["orange"])
            self._action_desc.configure(
                text="Host scan aborted by user prior to completion. Partial results discarded to prevent false safety claims."
            )
        elif st in ("ERROR", "ANALYSIS ERROR"):
            self._action_title.configure(text="SYSTEM DIAGNOSTIC", text_color=C["red"])
            self._action_desc.configure(
                text="System inspection encountered an unrecoverable error. Inspect logs/app.log for details."
            )

    # ── High-Performance Canvas Management ────────────────────────────────
    @staticmethod
    def _make_particles():
        import random
        rng = random.Random(42)
        return [
            (rng.uniform(0, 2 * math.pi),
             rng.uniform(0.6, 1.6),
             rng.uniform(0.5, 2.0))
            for _ in range(20)
        ]

    def _on_canvas_mouse_motion(self, event):
        """Interactive parallax response: pointer motion tilts the 3D core perspective gently."""
        cx = self.canvas.winfo_width() / 2.0
        cy = self.canvas.winfo_height() / 2.0
        self._mouse_target_x = (event.x - cx) * 0.04
        self._mouse_target_y = (event.y - cy) * 0.04

    def _on_canvas_mouse_leave(self, event):
        """Smoothly reset 3D parallax tilt back to center when pointer exits."""
        self._mouse_target_x = 0.0
        self._mouse_target_y = 0.0

    def _on_canvas_configure(self, event):
        """Handle canvas resize: redraw static background grid once without churn."""
        if event.width <= 20 or event.height <= 20:
            return
        if event.width == self._last_w and event.height == self._last_h:
            return
        self._last_w = event.width
        self._last_h = event.height
        self._draw_static_background(event.width, event.height)
        self._init_dynamic_canvas_objects()

    def _draw_static_background(self, w: int, h: int):
        """Draw persistent static perspective grid and guidelines once."""
        self.canvas.delete("static_bg")
        cx, cy = w / 2.0, h / 2.0
        gc = "#101622"

        # Background grid
        step = max(int(min(w, h) * 0.08), 28)
        for x in range(0, w, step):
            self.canvas.create_line(x, 0, x, h, fill=gc, tags="static_bg")
        for y in range(0, h, step):
            self.canvas.create_line(0, y, w, y, fill=gc, tags="static_bg")

        # Subtle crosshairs
        self.canvas.create_line(cx, 0, cx, h, fill="#162234", width=1, tags="static_bg")
        self.canvas.create_line(0, cy, w, cy, fill="#162234", width=1, tags="static_bg")

    def _init_dynamic_canvas_objects(self):
        """Instantiate dynamic objects once for in-place coords() update without delete/recreate churn."""
        self.canvas.delete("dynamic")

        # 3 Orbital ring polygons
        self._ring_items = [
            self.canvas.create_polygon([0, 0], outline=C["muted"], fill="", width=1, dash=(3, 9), smooth=True, tags="dynamic"),
            self.canvas.create_polygon([0, 0], outline=C["accent2"], fill="", width=1, dash=(4, 5), smooth=True, tags="dynamic"),
            self.canvas.create_polygon([0, 0], outline=C["accent"], fill="", width=2, smooth=True, tags="dynamic"),
        ]

        # Scan radar beam and head
        self._beam_line = self.canvas.create_line(0, 0, 0, 0, fill=C["accent2"], width=2, tags="dynamic")
        self._beam_dot = self.canvas.create_oval(0, 0, 0, 0, fill=C["accent2"], outline="", tags="dynamic")

        # 3D Layered Shield: back bevel, outer face, inner boundary, center accent
        self._shield_bevel = self.canvas.create_polygon([0, 0], outline="#0a2538", fill="#07131e", width=1, tags="dynamic")
        self._shield_outer = self.canvas.create_polygon([0, 0], outline=C["accent"], fill="#091826", width=2, tags="dynamic")
        self._shield_inner = self.canvas.create_polygon([0, 0], outline=C["accent2"], fill="", width=1, dash=(5, 4), tags="dynamic")
        self._shield_emblem = self.canvas.create_polygon([0, 0], outline=C["accent"], fill="", width=1, tags="dynamic")

        # Center Status Text
        center_text = "READY TO SCAN" if self.scan_state_str == "IDLE" else self.scan_state_str
        self._state_text = self.canvas.create_text(0, 0, text=center_text, fill=C["white"], font=("Consolas", 14, "bold"), tags="dynamic")

        # Telemetry particles pool
        self._particle_items = [
            self.canvas.create_oval(0, 0, 0, 0, fill=C["accent2"], outline="", tags="dynamic")
            for _ in range(20)
        ]

        # Feature nodes pool (19 features)
        self._node_items = []
        self._node_label_items = []
        for group_name, group_color, features in _FEATURE_GROUPS:
            for feat in features:
                item = self.canvas.create_oval(0, 0, 0, 0, fill=group_color, outline="", tags="dynamic")
                lbl_item = None
                if feat == features[0]:
                    lbl_item = self.canvas.create_text(0, 0, text=group_name, fill=group_color, font=("Consolas", 8, "bold"), tags="dynamic")
                self._node_items.append((item, group_color))
                self._node_label_items.append(lbl_item)

        self._canvas_initialized = True

    # ── Animation Loop ────────────────────────────────────────────────────
    def _animate(self):
        if not getattr(self, "running", False) or getattr(self, "_is_closing", False) or not self.winfo_exists():
            return

        # Throttle when minimized or hidden
        if not self.winfo_ismapped():
            self._anim_job = self.after(250, self._animate)
            return

        now = time.time()
        self.angle += 0.038

        # Smooth parallax interpolation
        self._cur_ox += (self._mouse_target_x - self._cur_ox) * 0.15
        self._cur_oy += (self._mouse_target_y - self._cur_oy) * 0.15

        # ML sub-stage automatic progression while ANALYZING
        if self.scan_state_str == "ANALYZING":
            dt = now - self._last_stage_t
            if self.stage == "FEATURE_EXTRACTION" and dt > 0.8:
                self._stat_vars["Features extracted"].set("19 features (normalizing)")
                self.set_stage("STANDARD_SCALER")
                self._last_stage_t = now
            elif self.stage == "STANDARD_SCALER" and dt > 0.8:
                self.set_stage("RANDOM_FOREST")
                self._last_stage_t = now

        # In-place 3D Canvas Update
        try:
            w = self.canvas.winfo_width()
            h = self.canvas.winfo_height()
            if w > 40 and h > 40 and self._canvas_initialized:
                cx = (w / 2.0) + self._cur_ox
                cy = (h / 2.0) + self._cur_oy
                max_r = min(w / 2.0, h / 2.0) - 90
                r = max(55.0, min(max_r, min(w, h) / 2.7))
                self._update_canvas_frame(cx, cy, r, self.angle, w, h)
        except Exception:
            pass

        # Target smooth ~30 FPS
        if getattr(self, "running", False) and not getattr(self, "_is_closing", False) and self.winfo_exists():
            self._anim_job = self.after(33, self._animate)

    def _update_canvas_frame(self, cx: float, cy: float, r: float, angle: float, gw: int, gh: int):
        """Update existing canvas items in-place using cv.coords() for 15x faster rendering."""
        cv = self.canvas
        sr = r * 0.72
        tilt = 0.40

        # 1. Update 3 Orbital Rings
        ring_specs = [
            (r + 80,  0.25),
            (r + 48, -0.55),
            (r + 18,  1.00),
        ]
        for ring_idx, (rad, speed) in enumerate(ring_specs):
            a = angle * speed
            pts = []
            for i in range(48):
                th = i * (2 * math.pi / 48) + a
                pts.extend([cx + rad * math.cos(th), cy + rad * math.sin(th) * tilt])
            cv.coords(self._ring_items[ring_idx], *pts)

        # 2. Update Scan Beam
        ba = angle * 1.7
        bx = cx + (r + 80) * math.cos(ba)
        by = cy + (r + 80) * math.sin(ba) * tilt
        cv.coords(self._beam_line, cx, cy, bx, by)
        cv.coords(self._beam_dot, bx - 4, by - 4, bx + 4, by + 4)

        # 3. Update 3D Layered Shield
        bevel_pts = [
            cx + 6,           cy - sr + 5,
            cx + sr*0.75 + 6, cy - sr*0.30 + 5,
            cx + sr*0.65 + 6, cy + sr*0.55 + 5,
            cx + 6,           cy + sr + 5,
            cx - sr*0.65 + 6, cy + sr*0.55 + 5,
            cx - sr*0.75 + 6, cy - sr*0.30 + 5,
        ]
        cv.coords(self._shield_bevel, *bevel_pts)

        outer_pts = [
            cx,           cy - sr,
            cx + sr*0.75, cy - sr*0.30,
            cx + sr*0.65, cy + sr*0.55,
            cx,           cy + sr,
            cx - sr*0.65, cy + sr*0.55,
            cx - sr*0.75, cy - sr*0.30,
        ]
        cv.coords(self._shield_outer, *outer_pts)

        s_in = sr * 0.78
        inner_pts = [
            cx,              cy - s_in,
            cx + s_in*0.75,  cy - s_in*0.30,
            cx + s_in*0.65,  cy + s_in*0.55,
            cx,              cy + s_in,
            cx - s_in*0.65,  cy + s_in*0.55,
            cx - s_in*0.75,  cy - s_in*0.30,
        ]
        cv.coords(self._shield_inner, *inner_pts)

        tri_pts = [cx, cy - sr*0.42, cx + sr*0.32, cy + sr*0.22, cx - sr*0.32, cy + sr*0.22]
        cv.coords(self._shield_emblem, *tri_pts)

        # 4. Color Palette and Center Status Text
        state_colors = {
            "IDLE":            C["accent"],
            "SCANNING":        C["accent"],
            "ANALYZING":       C["yellow"],
            "SAFE":            C["green"],
            "WARNING":         C["yellow"],
            "THREAT DETECTED": C["red"],
            "CRITICAL":        C["red"],
            "CANCELLED":       C["orange"],
            "ERROR":           C["red"],
            "ANALYSIS ERROR":  C["red"],
        }
        st_color = state_colors.get(self.scan_state_str, C["accent"])
        cv.itemconfig(self._shield_outer, outline=st_color)
        cv.itemconfig(self._shield_emblem, outline=st_color)

        fs = max(10, int(sr * 0.17))
        cv.coords(self._state_text, cx, cy)
        center_text = "READY TO SCAN" if self.scan_state_str == "IDLE" else self.scan_state_str
        cv.itemconfig(self._state_text, text=center_text, fill=st_color, font=("Consolas", fs, "bold"))

        # 5. Telemetry Particles
        is_telemetry_stage = (self.scan_state_str == "IDLE") or (self.stage in ("RAW_TELEMETRY", "PROCESS_ANALYSIS", "FILESYSTEM_ANALYSIS"))
        for i, (ao, dist, speed) in enumerate(self._particles):
            p_item = self._particle_items[i]
            if is_telemetry_stage:
                pa = angle * speed + ao
                pr = (r + 20) + dist * (r * 0.50)
                px = cx + pr * math.cos(pa)
                py = cy + pr * math.sin(pa) * tilt
                sz = 2 if i % 2 == 0 else 3
                cv.coords(p_item, px - sz, py - sz, px + sz, py + sz)
            else:
                cv.coords(p_item, -10, -10, -10, -10)

        # 6. 19 Feature Nodes
        is_ml_stage = self.stage in ("FEATURE_EXTRACTION", "STANDARD_SCALER", "RANDOM_FOREST")
        total_nodes = len(self._node_items)
        target_r = r * 0.62 if self.stage == "FEATURE_EXTRACTION" else (r * 0.48 if self.stage == "STANDARD_SCALER" else r * 0.35)

        for idx, (n_item, n_color) in enumerate(self._node_items):
            if is_ml_stage:
                pa = idx * (2 * math.pi / total_nodes) + angle * 0.40
                px = cx + target_r * math.cos(pa)
                py = cy + target_r * math.sin(pa) * tilt
                cv.coords(n_item, px - 4, py - 4, px + 4, py + 4)

                lbl_item = self._node_label_items[idx]
                if lbl_item:
                    lx = cx + (target_r + 16) * math.cos(pa)
                    ly = cy + (target_r + 16) * math.sin(pa) * tilt
                    cv.coords(lbl_item, lx, ly)
            else:
                cv.coords(n_item, -10, -10, -10, -10)
                lbl_item = self._node_label_items[idx]
                if lbl_item:
                    cv.coords(lbl_item, -20, -20)

    # ── Authoritative Atomic State Machine ────────────────────────────────
    def set_scan_state(
        self,
        state: str,
        threat_level: Optional[str] = None,
        probability: Optional[float] = None,
        error: Optional[str] = None,
        scan_result=None
    ) -> None:
        """
        Single authoritative state transition engine.
        Atomically synchronizes:
          1. 3D Shield (center text & outline)
          2. Top Bar stage badge
          3. Security Status Card (badge, verdict, description)
          4. Cancel Button (strictly enabled ONLY during scanning; never visible with SAFE or IDLE)
          5. Start Live Scan button (enabled in IDLE and completed states; disabled in-flight)
          6. Action and Recommendations Card
        """
        # Idempotency guard: do not re-pack buttons and recalculate geometry on every progress tick
        if getattr(self, "_state_initialized", False) and state == getattr(self, "scan_state_str", None) and state in ("SCANNING", "ANALYZING", "IDLE"):
            return
        self._state_initialized = True
        self.scan_state_str = state
        if scan_result is not None:
            self._last_scan_result = scan_result

        # 0. State: IDLE
        if state == "IDLE":
            self.scan_state_str = "IDLE"
            self._scan_in_flight = False
            self._bar_stage.configure(text="IDLE", text_color=C["accent"])
            self._status_card_badge.configure(text="  READY  ", text_color=C["accent"], fg_color="#0a2540")
            self._status_card_verdict.configure(text="READY TO SCAN", text_color=C["accent"])
            self._status_card_desc.configure(
                text="Ready when you are. Click 'Start Live Scan' below to inspect running processes, filesystem entropy, and evaluate the 19 behavioral feature Random Forest model."
            )
            # Cancel button is hidden in IDLE
            self._cancel_btn.configure(state="disabled")
            if self._cancel_btn.winfo_manager() == "pack": self._cancel_btn.pack_forget()
            if hasattr(self, "_scanning_badge"):
                self._scanning_badge.pack_forget()
            if hasattr(self, "_scanning_badge"):
                self._scanning_badge.pack_forget()

            # Ensure start scan button is enabled and prominent
            self._start_scan_btn.configure(text="⚡ Start Live Scan", state="normal")
            self._start_scan_btn.pack(fill="x", pady=(4, 6))

            # Initialize stat variables to clean Idle state
            self._stat_vars["ML Risk Probability"].set("Pending")
            self._stat_vars["Processes inspected"].set("Ready")
            self._stat_vars["Files inspected"].set("Ready")
            self._stat_vars["Active target"].set("Idle — Ready to scan")
            self._stat_vars["Suspicious indicators"].set("0")
            self._stat_vars["Features extracted"].set("Pending")
            self._stat_vars["Scan Duration"].set("0.0 s")

            if self._highlights_frame.winfo_manager() == "pack": self._highlights_frame.pack_forget()
            if self._cybercrime_box.winfo_manager() == "pack": self._cybercrime_box.pack_forget()
            if self._evidence_inspect_btn.winfo_manager() == "pack": self._evidence_inspect_btn.pack_forget()

            self._action_title.configure(text="HOST SCAN CONTROL & GUIDANCE", text_color=C["accent"])
            self._action_desc.configure(
                text="Ready when you are. System telemetry collection, Shannon entropy evaluation, and Random Forest inference will begin once started."
            )
            self._return_btn.pack(fill="x", pady=(2, 0))

        # 1. State: SCANNING
        elif state == "SCANNING":
            self.scan_state_str = "SCANNING"
            self._bar_stage.configure(text=f"SCANNING ({self.stage.replace('_', ' ')})", text_color=C["accent"])
            self._status_card_badge.configure(text="  IN PROGRESS  ", text_color=C["accent"], fg_color="#0a2540")
            self._status_card_verdict.configure(text="[SCANNING]", text_color=C["accent"])
            self._status_card_desc.configure(
                text="SentinelML is actively inspecting runtime telemetry and filesystem behavior across monitored roots..."
            )
            # Cancel button enabled
            self._cancel_btn.configure(text="✕ Cancel Scan", state="normal")
            self._cancel_btn.pack(side="left", padx=(0, 14))

            # Start scan button and action card return button are hidden during active scan
            if self._start_scan_btn.winfo_manager() == "pack":
                self._start_scan_btn.pack_forget()
            if self._return_btn.winfo_manager() == "pack":
                self._return_btn.pack_forget()
            if hasattr(self, "_scanning_badge") and self._scanning_badge.winfo_manager() != "pack":
                self._scanning_badge.configure(text=f"⚡ SCANNING ({self.stage.replace('_', ' ')})")
                self._scanning_badge.pack(fill="x", pady=(2, 2))

            if self._highlights_frame.winfo_manager() == "pack": self._highlights_frame.pack_forget()
            if self._cybercrime_box.winfo_manager() == "pack": self._cybercrime_box.pack_forget()
            if self._evidence_inspect_btn.winfo_manager() == "pack": self._evidence_inspect_btn.pack_forget()

            if self.stage in _STAGE_EDU:
                title = dict(_STAGES).get(self.stage, self.stage)
                self._action_title.configure(text=f"STAGE: {title.upper()}", text_color=C["accent"])
                self._action_desc.configure(text=_STAGE_EDU[self.stage])

        # 2. State: ANALYZING
        elif state == "ANALYZING":
            self.scan_state_str = "ANALYZING"
            self._bar_stage.configure(text="ANALYZING (ML)", text_color=C["yellow"])
            self._status_card_badge.configure(text="  INFERENCE  ", text_color=C["yellow"], fg_color="#2b2010")
            self._status_card_verdict.configure(text="[ANALYZING]", text_color=C["yellow"])
            self._status_card_desc.configure(
                text="Aggregating 19 behavioral features into StandardScaler and Random Forest decision trees..."
            )
            # In analysis phase, cancel is disabled as inference concludes in <1s
            self._cancel_btn.configure(text="✕ Cancel Scan", state="disabled")
            self._cancel_btn.pack(side="left", padx=(0, 14))
            self._start_scan_btn.pack_forget()
            self._return_btn.pack_forget()
            if hasattr(self, "_scanning_badge"):
                self._scanning_badge.configure(text="⚡ ANALYZING — RANDOM FOREST INFERENCE")
                self._scanning_badge.pack(fill="x", pady=(2, 2))
            self._stat_vars["ML Risk Probability"].set("Analyzing…")

        # 2.5 State: INCONCLUSIVE
        elif state == "INCONCLUSIVE":
            self._scan_in_flight = False
            self._bar_stage.configure(text="INCONCLUSIVE", text_color=C["yellow"])
            self._status_card_badge.configure(text="  LIMITED COVERAGE  ", text_color=C["yellow"], fg_color="#2b2010")
            self._status_card_verdict.configure(text="INCONCLUSIVE — LIMITED COVERAGE", text_color=C["yellow"])

            self._cancel_btn.configure(state="disabled")
            if self._cancel_btn.winfo_manager() == "pack": self._cancel_btn.pack_forget()
            if hasattr(self, "_scanning_badge") and self._scanning_badge.winfo_manager() == "pack":
                self._scanning_badge.pack_forget()

            if self._highlights_frame.winfo_manager() == "pack": self._highlights_frame.pack_forget()
            if self._cybercrime_box.winfo_manager() == "pack": self._cybercrime_box.pack_forget()
            if self._evidence_inspect_btn.winfo_manager() == "pack": self._evidence_inspect_btn.pack_forget()

            p_str = None
            if probability is not None:
                try:
                    _, p_pct, _ = normalize_risk_score(probability)
                    p_str = f"{p_pct}%"
                except Exception:
                    p_str = f"{probability*100:.1f}%"

            inc_reason = getattr(scan_result, "inconclusive_reason", "Safety cannot be validated due to limited OS sensor availability.")

            aid1 = self.after(40, lambda: self._pace_pack_start_btn("⚡ Start New Scan"))
            self._pacing_after_ids.append(aid1)

            aid2 = self.after(80, lambda: (
                self._pace_pack_return_btn(),
                self._pace_restore_details(
                    f"{inc_reason} Telemetry is incomplete, so this host cannot be certified as SAFE.",
                    "PLATFORM COVERAGE NOTICE",
                    C["yellow"],
                    "• Run SentinelML on Windows for full 19-sensor behavioral coverage.\n• Exercise caution with untrusted binaries.",
                    p_str
                )
            ))
            self._pacing_after_ids.append(aid2)

        # 3. State: SAFE
        elif state == "SAFE":
            self._scan_in_flight = False
            is_limited = getattr(scan_result, "scan_type", None) == ScanType.QUICK or getattr(scan_result, "access_denied", 0) > 0
            badge_text = "  VERIFIED SAFE (LIMITED)  " if is_limited else "  VERIFIED SAFE  "
            verdict_text = "SAFE — NO THREATS DETECTED (LIMITED)" if is_limited else "SAFE — NO THREATS DETECTED"

            self._bar_stage.configure(text="SAFE", text_color=C["green"])
            self._status_card_badge.configure(text=badge_text, text_color=C["green"], fg_color="#0a2e1d")
            self._status_card_verdict.configure(text=verdict_text, text_color=C["green"])

            self._cancel_btn.configure(state="disabled")
            if self._cancel_btn.winfo_manager() == "pack": self._cancel_btn.pack_forget()
            if hasattr(self, "_scanning_badge") and self._scanning_badge.winfo_manager() == "pack":
                self._scanning_badge.pack_forget()

            if self._highlights_frame.winfo_manager() == "pack": self._highlights_frame.pack_forget()
            if self._cybercrime_box.winfo_manager() == "pack": self._cybercrime_box.pack_forget()
            if self._evidence_inspect_btn.winfo_manager() == "pack": self._evidence_inspect_btn.pack_forget()

            p_str = None
            if probability is not None:
                try:
                    _, p_pct, _ = normalize_risk_score(probability)
                    p_str = f"{p_pct}%"
                except Exception:
                    p_str = f"{probability*100:.1f}%"

            aid1 = self.after(40, lambda: self._pace_pack_start_btn("⚡ Start New Scan"))
            self._pacing_after_ids.append(aid1)

            aid2 = self.after(80, lambda: (
                self._pace_pack_return_btn(),
                self._pace_restore_details(
                    "No anomalous or malicious behavior detected across running processes and monitored directories.",
                    "SECURITY RECOMMENDATIONS",
                    C["green"],
                    "• Maintain routine backups of essential documents.\n• Keep Sentinel Guard background protection active.",
                    p_str
                )
            ))
            self._pacing_after_ids.append(aid2)

        # 4. State: WARNING
        elif state == "WARNING":
            self._scan_in_flight = False
            self._bar_stage.configure(text="WARNING", text_color=C["yellow"])
            self._status_card_badge.configure(text="  SUSPICIOUS ACTIVITY  ", text_color=C["yellow"], fg_color="#2b2010")
            self._status_card_verdict.configure(text="WARNING — SUSPICIOUS ACTIVITY", text_color=C["yellow"])

            self._cancel_btn.configure(state="disabled")
            if self._cancel_btn.winfo_manager() == "pack": self._cancel_btn.pack_forget()
            if hasattr(self, "_scanning_badge") and self._scanning_badge.winfo_manager() == "pack":
                self._scanning_badge.pack_forget()

            if self._highlights_frame.winfo_manager() == "pack": self._highlights_frame.pack_forget()
            if self._cybercrime_box.winfo_manager() == "pack": self._cybercrime_box.pack_forget()
            if self._evidence_inspect_btn.winfo_manager() == "pack": self._evidence_inspect_btn.pack_forget()

            p_str = None
            if probability is not None:
                try:
                    _, p_pct, _ = normalize_risk_score(probability)
                    p_str = f"{p_pct}%"
                except Exception:
                    p_str = f"{probability*100:.1f}%"

            aid1 = self.after(40, lambda: self._pace_pack_start_btn("⚡ Start New Scan"))
            self._pacing_after_ids.append(aid1)

            aid2 = self.after(80, lambda: (
                self._pace_pack_return_btn(),
                self._pace_restore_details(
                    "Elevated behavioral indicators detected. Manual inspection of suspicious processes recommended.",
                    "RECOMMENDED INVESTIGATION",
                    C["yellow"],
                    "• Inspect suspicious processes in the Threat Log.\n• Preserve system event logs for investigation.",
                    p_str
                )
            ))
            self._pacing_after_ids.append(aid2)

        # 5. State: THREAT DETECTED / CRITICAL
        elif state in ("THREAT DETECTED", "CRITICAL"):
            self._scan_in_flight = False
            self._bar_stage.configure(text="THREAT DETECTED", text_color=C["red"])
            self._status_card_badge.configure(text="  CRITICAL ALERT  ", text_color=C["red"], fg_color="#2e0a0a")
            self._status_card_verdict.configure(text="THREAT DETECTED — RANSOMWARE", text_color=C["red"])

            self._cancel_btn.configure(state="disabled")
            if self._cancel_btn.winfo_manager() == "pack": self._cancel_btn.pack_forget()
            if hasattr(self, "_scanning_badge") and self._scanning_badge.winfo_manager() == "pack":
                self._scanning_badge.pack_forget()

            if self._highlights_frame.winfo_manager() == "pack": self._highlights_frame.pack_forget()
            if self._cybercrime_box.winfo_manager() == "pack": self._cybercrime_box.pack_forget()
            if self._evidence_inspect_btn.winfo_manager() == "pack": self._evidence_inspect_btn.pack_forget()

            p_str = None
            if probability is not None:
                try:
                    _, p_pct, _ = normalize_risk_score(probability)
                    p_str = f"{p_pct}%"
                except Exception:
                    p_str = f"{probability*100:.1f}%"

            aid1 = self.after(40, lambda: self._pace_pack_start_btn("⚡ Start New Scan"))
            self._pacing_after_ids.append(aid1)

            aid2 = self.after(80, lambda: (
                self._pace_pack_return_btn(),
                self._pace_restore_details(
                    "High-confidence behavioral indicators of active ransomware detected by the Random Forest classifier.",
                    "IMMEDIATE DEFENSIVE ACTIONS",
                    C["red"],
                    "• Isolate system from the local area network immediately.\n• Do not execute unverified executable files.\n• Export and archive the SentinelML Incident Report.",
                    p_str
                )
            ))
            self._pacing_after_ids.append(aid2)

        # 6. State: CANCELLED
        elif state == "CANCELLED":
            self._scan_in_flight = False
            self._bar_stage.configure(text="CANCELLED", text_color=C["orange"])
            self._status_card_badge.configure(text="  ABORTED  ", text_color=C["orange"], fg_color="#36200c")
            self._status_card_verdict.configure(text="SCAN CANCELLED", text_color=C["orange"])

            self._cancel_btn.configure(state="disabled")
            if self._cancel_btn.winfo_manager() == "pack": self._cancel_btn.pack_forget()
            if hasattr(self, "_scanning_badge") and self._scanning_badge.winfo_manager() == "pack":
                self._scanning_badge.pack_forget()

            if self._highlights_frame.winfo_manager() == "pack": self._highlights_frame.pack_forget()
            if self._cybercrime_box.winfo_manager() == "pack": self._cybercrime_box.pack_forget()
            if self._evidence_inspect_btn.winfo_manager() == "pack": self._evidence_inspect_btn.pack_forget()

            aid1 = self.after(40, lambda: self._pace_pack_start_btn("⚡ Start Live Scan"))
            self._pacing_after_ids.append(aid1)

            aid2 = self.after(80, lambda: (
                self._pace_pack_return_btn(),
                self._pace_restore_details(
                    "Scan was stopped before completion. Partial results discarded to prevent false safety claims.",
                    "SCAN STATUS",
                    C["orange"],
                    "Host scan was safely stopped prior to analysis. Partial results discarded.",
                    "--%"
                )
            ))
            self._pacing_after_ids.append(aid2)

        # 7. State: ERROR / ANALYSIS ERROR
        else:
            self._scan_in_flight = False
            err_msg = error or getattr(scan_result, "error_message", "Analysis could not be safely completed.")
            self._bar_stage.configure(text="ERROR", text_color=C["red"])
            self._status_card_badge.configure(text="  INCOMPLETE  ", text_color=C["orange"], fg_color="#36200c")
            self._status_card_verdict.configure(text="ANALYSIS ERROR", text_color=C["red"])

            self._cancel_btn.configure(state="disabled")
            if self._cancel_btn.winfo_manager() == "pack": self._cancel_btn.pack_forget()
            if hasattr(self, "_scanning_badge") and self._scanning_badge.winfo_manager() == "pack":
                self._scanning_badge.pack_forget()

            if self._highlights_frame.winfo_manager() == "pack": self._highlights_frame.pack_forget()
            if self._cybercrime_box.winfo_manager() == "pack": self._cybercrime_box.pack_forget()
            if self._evidence_inspect_btn.winfo_manager() == "pack": self._evidence_inspect_btn.pack_forget()

            aid1 = self.after(40, lambda: self._pace_pack_start_btn("⚡ Start Live Scan"))
            self._pacing_after_ids.append(aid1)

            aid2 = self.after(80, lambda: (
                self._pace_pack_return_btn(),
                self._pace_restore_details(
                    f"⚠️ Analysis failed: {err_msg}. No security classification can be determined.",
                    "SYSTEM DIAGNOSTIC",
                    C["red"],
                    "System inspection encountered an unrecoverable error. Inspect logs/app.log for details.",
                    "ERR"
                )
            ))
            self._pacing_after_ids.append(aid2)

    def _populate_highlights(self, scan_result, accent_color: str):
        """Populate key behavioral indicators card if features array is present."""
        features_array = getattr(scan_result, "_features", None)
        if features_array is None or not hasattr(features_array, "shape") or features_array.shape != (1, 19):
            if self._highlights_frame.winfo_manager() == "pack": self._highlights_frame.pack_forget()
            return

        f_list = features_array[0].tolist()
        names = [
            "total_processes", "suspicious_process_count", "avg_entropy",
            "max_entropy", "high_entropy_region_count", "malfind_injection_count",
            "crypto_dll_count", "cmd_vssadmin_count", "network_connection_count",
            "unique_external_ips", "file_handle_count", "registry_handle_count",
            "orphan_process_count", "powershell_process_count",
            "unsigned_module_count", "suspicious_mutex_count",
            "abnormal_privilege_count", "suspicious_thread_count",
            "defender_tampering_count"
        ]
        human_names = {
            "malfind_injection_count": "Memory Injections",
            "crypto_dll_count": "Crypto DLLs Loaded",
            "cmd_vssadmin_count": "VSSAdmin Activity",
            "powershell_process_count": "PowerShell Activity",
            "suspicious_process_count": "Suspicious Processes",
            "unsigned_module_count": "Unsigned Modules",
            "suspicious_mutex_count": "Suspicious Mutexes",
            "abnormal_privilege_count": "Abnormal Privileges",
            "suspicious_thread_count": "Suspicious Threads",
            "defender_tampering_count": "Defender Tampering"
        }
        indicators = [(human_names[n], int(v) if v.is_integer() else v) for n, v in zip(names, f_list) if v > 0 and n in human_names]

        if indicators and hasattr(self, "_highlight_labels"):
            for idx_row, (_nl, _vl) in enumerate(self._highlight_labels):
                if idx_row < len(indicators[:4]):
                    iname, ival = indicators[idx_row]
                    _nl.configure(text=f"• {iname}:")
                    _vl.configure(text=str(ival), text_color=accent_color)
                    _nl.grid()
                    _vl.grid()
                else:
                    _nl.grid_remove()
                    _vl.grid_remove()
            if self._highlights_frame.winfo_manager() != "pack":
                self._highlights_frame.pack(fill="x", pady=(0, 8))
        else:
            if self._highlights_frame.winfo_manager() == "pack":
                if self._highlights_frame.winfo_manager() == "pack": self._highlights_frame.pack_forget()

    # ── Public Progress & Stage API ───────────────────────────────────────
    def set_stage(self, stage: str):
        if stage == getattr(self, "stage", None):
            return

        now = time.time()
        if hasattr(self, "_stage_start_t"):
            self._stage_timings[self.stage] = now - self._stage_start_t
            self._stage_completed.add(self.stage)
        self._stage_start_t = now

        self.stage = stage
        if self.scan_state_str == "SCANNING":
            self._bar_stage.configure(text=f"SCANNING ({stage.replace('_', ' ')})")
            if hasattr(self, "_scanning_badge") and self._scanning_badge.winfo_manager() == "pack":
                self._scanning_badge.configure(text=f"⚡ SCANNING ({stage.replace('_', ' ')})")

        # Update pipeline widgets: update only transitioned stages to prevent UI stall
        old_stage = getattr(self, "_active_stage_key", None)
        self._active_stage_key = stage

        target_keys = {k for k in (old_stage, stage) if k}
        if stage == "SECURITY_DECISION":
            target_keys = set(self._stage_widgets.keys())

        _ws_cache = getattr(self, "_stage_widget_state", {})
        for key in target_keys:
            if not key or key not in self._stage_widgets:
                continue
            row_f, dot, lbl, timing_lbl = self._stage_widgets[key]
            cached = _ws_cache.setdefault(key, {"dot_text": None, "dot_color": None,
                                                 "lbl_color": None, "row_fg": None, "timing_text": None})
            if key == stage:
                # Cache-based change-detection: zero cget() calls needed
                if cached["dot_text"] != "●":
                    dot.configure(text="●")
                    cached["dot_text"] = "●"
                if cached["dot_color"] != C["accent"]:
                    dot.configure(text_color=C["accent"])
                    cached["dot_color"] = C["accent"]
                if cached["lbl_color"] != C["white"]:
                    lbl.configure(text_color=C["white"], font=self._font_stage_bold)
                    cached["lbl_color"] = C["white"]
                if cached["row_fg"] != "#0e1e30":
                    row_f.configure(fg_color="#0e1e30")
                    cached["row_fg"] = "#0e1e30"
                if cached["timing_text"] != "RUNNING":
                    timing_lbl.configure(text="RUNNING", text_color=C["accent"])
                    cached["timing_text"] = "RUNNING"
            elif key in self._stage_completed or stage == "SECURITY_DECISION":
                t_val = self._stage_timings.get(key, 0.0)
                new_t_text = f"{t_val:.2f}s" if t_val > 0 else "OK"
                if cached["dot_text"] != "✓":
                    dot.configure(text="✓")
                    cached["dot_text"] = "✓"
                if cached["dot_color"] != C["green"]:
                    dot.configure(text_color=C["green"])
                    cached["dot_color"] = C["green"]
                if cached["lbl_color"] != C["green"]:
                    lbl.configure(text_color=C["green"], font=self._font_stage_normal)
                    cached["lbl_color"] = C["green"]
                if cached["row_fg"] != "transparent":
                    row_f.configure(fg_color="transparent")
                    cached["row_fg"] = "transparent"
                if cached["timing_text"] != new_t_text:
                    timing_lbl.configure(text=new_t_text, text_color=C["green"])
                    cached["timing_text"] = new_t_text
            else:
                if cached["dot_text"] != "·":
                    dot.configure(text="·")
                    cached["dot_text"] = "·"
                if cached["dot_color"] != C["muted"]:
                    dot.configure(text_color=C["muted"])
                    cached["dot_color"] = C["muted"]
                if cached["lbl_color"] != C["muted"]:
                    lbl.configure(text_color=C["muted"], font=self._font_stage_normal)
                    cached["lbl_color"] = C["muted"]
                if cached["row_fg"] != "transparent":
                    row_f.configure(fg_color="transparent")
                    cached["row_fg"] = "transparent"
                if cached["timing_text"] != "":
                    timing_lbl.configure(text="", text_color=C["muted"])
                    cached["timing_text"] = ""

        if self.scan_state_str in ("SCANNING", "ANALYZING") and stage in _STAGE_EDU and not self._hovered_stage:
            title = dict(_STAGES).get(stage, stage)
            new_title = f"STAGE: {title.upper()}"
            if getattr(self, "_last_action_title_str", None) != new_title:
                self._last_action_title_str = new_title
                self._action_title.configure(text=new_title, text_color=C["accent"])
            new_desc = _STAGE_EDU[stage]
            if getattr(self, "_last_action_desc_str", None) != new_desc:
                self._last_action_desc_str = new_desc
                self._action_desc.configure(text=new_desc)

    def update_progress(self, scan_result):
        """Update live telemetry metrics in-place without widget reconstruction."""
        if not getattr(self, "running", False) or getattr(self, "_is_closing", False):
            return

        elapsed = time.time() - self.t0
        new_dur = f"{elapsed:.1f} s"
        if self._stat_vars["Scan Duration"].get() != new_dur:
            self._stat_vars["Scan Duration"].set(new_dur)

        procs = getattr(scan_result, "processes_analyzed", 0)
        files = getattr(scan_result, "files_inspected", 0)
        if procs > 0:
            self._stat_vars["Processes inspected"].set(f"{procs:,}")
        if files > 0:
            self._stat_vars["Files inspected"].set(f"{files:,}")

        susp = len(getattr(scan_result, "suspicious_files", None) or [])
        self._stat_vars["Suspicious indicators"].set(str(susp))

        curr = getattr(scan_result, "current_path", "")
        if curr:
            short_path = curr if len(curr) <= 32 else "…" + curr[-31:]
            self._stat_vars["Active target"].set(short_path)

        state_enum = getattr(scan_result, "state", None)
        state_name = state_enum.name if state_enum else "SCANNING"

        # Only update in-flight progress states here. Terminal states are handled by on_complete()
        if state_name == "ANALYZING":
            if self.scan_state_str != "ANALYZING":
                self.set_scan_state("ANALYZING")
            if self.stage in ("FILESYSTEM_ANALYSIS", "PROCESS_ANALYSIS", "RAW_TELEMETRY"):
                self.set_stage("FEATURE_EXTRACTION")
                if self._stat_vars["Features extracted"].get() != "19 features (ready)":
                    self._stat_vars["Features extracted"].set("19 features (ready)")
                self._last_stage_t = time.time()
        elif state_name == "SCANNING":
            if self.scan_state_str != "SCANNING":
                self.set_scan_state("SCANNING")
            if files > 0:
                self.set_stage("FILESYSTEM_ANALYSIS")
            elif procs > 0:
                self.set_stage("PROCESS_ANALYSIS")

    def on_complete(self, threat_level: str, probability: float, scan_result=None, error: str = None):
        """Authoritative completion handler transitioning visualizer atomically to terminal state."""
        if getattr(self, "_is_closing", False):
            return

        self._scan_in_flight = False

        # 1. Determine canonical terminal state
        if error or (scan_result and getattr(scan_result, "state", None) in (ScanState.ERROR, ScanState.ANALYSIS_ERROR)):
            canonical_state = "ANALYSIS ERROR"
        elif threat_level == "CANCELLED" or (scan_result and getattr(scan_result, "cancelled", False)):
            canonical_state = "CANCELLED"
        elif threat_level in ("THREAT DETECTED", "CRITICAL"):
            canonical_state = "THREAT DETECTED"
        elif threat_level == "WARNING":
            canonical_state = "WARNING"
        elif threat_level in ("INCONCLUSIVE", "LIMITED_COVERAGE") or (scan_result and getattr(scan_result, "is_inconclusive", False)):
            canonical_state = "INCONCLUSIVE"
        elif threat_level in ("SAFE", "LOW"):
            canonical_state = "SAFE"
        else:
            canonical_state = threat_level.upper() if threat_level else "SAFE"

        # 2. Slice 0 (immediate): Transition canonical state + Cancel button removal
        self.set_scan_state(
            canonical_state,
            threat_level=threat_level,
            probability=probability,
            error=error,
            scan_result=scan_result
        )

        # 3. Slice 1 (deferred 25 ms): Finalize pipeline to SECURITY_DECISION
        # Spreading this across a second tick prevents a 200+ ms stall from
        # reconfiguring all 7 pipeline stage rows simultaneously.
        _sr = scan_result
        _cs = canonical_state

        # Finalize pipeline in micro-slices: update each stage widget individually
        # across separate after() ticks spaced 8ms apart. This avoids the
        # ~70-270ms stall caused by reconfiguring all 7 stage rows in one tick.
        _stage_keys = list(self._stage_widgets.keys())
        _timings = self._stage_timings
        _completed = self._stage_completed
        _completed.add("SECURITY_DECISION")

        def _update_stage_slice(idx):
            if getattr(self, "_is_closing", False):
                return
            if idx < len(_stage_keys):
                key = _stage_keys[idx]
                if key not in self._stage_widgets:
                    self.after(5, lambda: _update_stage_slice(idx + 1))
                    return
                row_f, dot, lbl, timing_lbl = self._stage_widgets[key]
                t_val = _timings.get(key, 0.0)
                new_t_text = f"{t_val:.2f}s" if t_val > 0 else "OK"
                # Cache-based change-detection: zero cget() calls
                _ws_cache = getattr(self, "_stage_widget_state", {})
                cached = _ws_cache.setdefault(key, {"dot_text": None, "dot_color": None,
                                                     "lbl_color": None, "row_fg": None, "timing_text": None})
                if cached["dot_text"] != "✓":
                    dot.configure(text="✓")
                    cached["dot_text"] = "✓"
                if cached["dot_color"] != C["green"]:
                    dot.configure(text_color=C["green"])
                    cached["dot_color"] = C["green"]
                if cached["lbl_color"] != C["green"]:
                    lbl.configure(text_color=C["green"], font=self._font_stage_normal)
                    cached["lbl_color"] = C["green"]
                if cached["row_fg"] != "transparent":
                    row_f.configure(fg_color="transparent")
                    cached["row_fg"] = "transparent"
                if cached["timing_text"] != new_t_text:
                    timing_lbl.configure(text=new_t_text, text_color=C["green"])
                    cached["timing_text"] = new_t_text
                # Schedule next stage in 8ms (avoids stacking in one event tick)
                aid = self.after(16, lambda: _update_stage_slice(idx + 1))
                self._pacing_after_ids.append(aid)
            else:
                # All stages updated — do final stat var + highlights
                self._stat_vars["Features extracted"].set("19 features (analyzed)")
                self._stat_vars["Active target"].set("Scan Complete")
                if _sr is not None:
                    procs = getattr(_sr, "processes_analyzed", 0)
                    files = getattr(_sr, "files_inspected", 0)
                    if procs > 0:
                        self._stat_vars["Processes inspected"].set(f"{procs:,}")
                    if files > 0:
                        self._stat_vars["Files inspected"].set(f"{files:,}")
                    dur = getattr(_sr, "elapsed_seconds", 0.0)
                    if dur > 0:
                        self._stat_vars["Scan Duration"].set(f"{dur:.1f} s")
                # Populate highlights (widget creation) in a dedicated deferred slice (15ms later)
                # to keep this slice strictly under 30ms
                def _deferred_highlights():
                    if getattr(self, "_is_closing", False) or not self.winfo_exists():
                        return
                    color = C["yellow"] if _cs == "WARNING" else C["red"]
                    if _cs in ("WARNING", "THREAT DETECTED", "CRITICAL"):
                        self._populate_highlights(_sr, color)
                        aid = self.after(35, _deferred_cybercrime)
                        self._pacing_after_ids.append(aid)

                def _deferred_cybercrime():
                    if getattr(self, "_is_closing", False) or not self.winfo_exists():
                        return
                    if self._cybercrime_box.winfo_manager() != "pack":
                        self._cybercrime_box.pack(fill="x", pady=(4, 6))
                    if hasattr(self.master, "_open_evidence_dialog"):
                        if self._evidence_inspect_btn.winfo_manager() != "pack":
                            self._evidence_inspect_btn.pack(fill="x", pady=(2, 6))

                aid = self.after(30, _deferred_highlights)
                self._pacing_after_ids.append(aid)

        # Also update the stage attribute and bar text immediately
        self.stage = "SECURITY_DECISION"
        self._active_stage_key = "SECURITY_DECISION"
        # Start micro-slice pipeline update 25ms after completion
        aid = self.after(120, lambda: _update_stage_slice(0))
        self._pacing_after_ids.append(aid)

    # ── Clean Lifecycle & Destruction ─────────────────────────────────────
    def close(self):
        """Cleanly dismiss visualizer without double destruction or screen blanking."""
        if getattr(self, "_is_closing", False):
            return
        self._is_closing = True
        self.running = False
        self._scan_in_flight = False
        self._cancel_pacing_callbacks()

        if getattr(self, "_anim_job", None):
            try:
                self.after_cancel(self._anim_job)
            except Exception:
                pass
            self._anim_job = None

        def _do_close():
            if self.on_close:
                try:
                    self.on_close()
                except Exception as e:
                    log.debug("Visualizer on_close handled: %s", e)
            elif self.winfo_exists():
                try:
                    self.place_forget()
                    super(ScanVisualizer, self).destroy()
                except Exception:
                    pass

        # Schedule after current event handler finishes to avoid Tcl re-entrancy
        self.after(5, _do_close)

    def destroy(self):
        """Ensure animation timer cancellation on widget destruction."""
        self.running = False
        self._is_closing = True
        self._scan_in_flight = False
        self._cancel_pacing_callbacks()
        if getattr(self, "_anim_job", None):
            try:
                self.after_cancel(self._anim_job)
            except Exception:
                pass
            self._anim_job = None
        super().destroy()
