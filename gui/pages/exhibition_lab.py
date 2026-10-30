"""
SentinelML V2 — Interactive Exhibition Lab
========================================
A dedicated, examiner-facing cybersecurity investigation workstation that
surfaces the project's real detection pipeline as explorable scenarios.

Four sections (tabs):
  1. Exhibition Lab     — scenarios A..E (benign, suspicious, simulated
                          ransomware, limited telemetry, cancellation/failure),
                          run through the REAL ScanEngine + Random Forest model
                          via ``exhibition.scenario_lab.ScenarioRunner``.
  2. Investigation      — chronological, selectable event timeline built from
                          ``InvestigationTimeline``; each event is provenance-
                          tagged (MEASURED / SIMULATED / FAILURE INJECTION /
                          APPLICATION) so scripted data is never presented as a
                          live detection.
  3. Detection Result   — honest post-scan explanation from
                          ``result_explainer.explain_scan_result``:
                          classification, genuine model probability (or an
                          explicit "Not available" reason), observed
                          indicators, missing telemetry, evidence, next steps
                          and limitations.
  4. System Health      — genuine platform/model/sensor status. Missing
                          measurements are shown as Unavailable, never silently
                          treated as zeros, and user-space monitoring scope is
                          disclosed.

Threading contract (hard rule, mirrors gui/pages/dashboard.py):
  * All ScanEngine/ScenarioRunner work runs on a daemon worker thread.
  * Worker threads NEVER touch Tkinter widgets. They hand results back through
    a thread-safe queue drained on the main thread via ``safe_after``.
  * A per-run token guards against stale callbacks; a destroyed-page flag
    stops every deferred update on close. A cancelled/failed/incomplete scan
    never silently becomes SAFE.
"""

from __future__ import annotations

import logging
import platform
import queue
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import customtkinter as ctk
import tkinter as tk

from constants import APP_VERSION
from gui.exhibition_theme import (
    EX_COLORS,
    severity_color,
    source_color,
    source_label,
    category_color,
    classify_origin_badge,
)
from exhibition.scenario_lab import ScenarioRunner, ScenarioResult, SCENARIOS, SCENARIOS_BY_KEY
from exhibition.investigation_timeline import InvestigationTimeline, InvestigationEvent
from exhibition.result_explainer import format_explanation_text
from scanner.live_scanner import get_platform_feature_availability
from ml.predictor import MLPredictor

log = logging.getLogger("sentinel.gui.exhibition_lab")


class ExhibitionLabPage(ctk.CTkFrame):
    """Interactive Exhibition Lab page (Phases 2, 3, 4, 6)."""

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=EX_COLORS["bg"], **kwargs)
        self._config = config
        self._is_destroyed = False

        # ── Threading primitives (Dashboard-style) ────────────────────────
        self._ui_queue: queue.Queue = queue.Queue()
        self._pending_after_ids: set = set()
        self._active_token: Optional[str] = None
        self._cancel_requested = False
        self._is_running = False

        # ── State ─────────────────────────────────────────────────────────
        self._runner = ScenarioRunner()
        self._runner.bind_sink(self._on_scenario_event)
        self._last_result: Optional[ScenarioResult] = None
        self._recent_outcomes: List[Dict[str, Any]] = []
        self._selected_scenario_key: Optional[str] = None
        self._timeline_rows: Dict[int, ctk.CTkFrame] = {}
        self._selected_event_seq: Optional[int] = None

        self._build_ui()
        self.safe_after(30, self._drain_ui_queue)
        self.safe_after(150, self._refresh_system_health)

    # ======================================================================
    # Threading / UI-safety (mirrors DashboardPage)
    # ======================================================================
    def safe_after(self, ms: int, fn, *args, **kwargs):
        if getattr(self, "_is_destroyed", False):
            return None
        aid_holder = [None]

        def wrapper():
            if getattr(self, "_is_destroyed", False):
                p = getattr(self, "_pending_after_ids", None)
                if p is not None and aid_holder[0] is not None:
                    p.discard(aid_holder[0])
                return
            try:
                if not self.winfo_exists():
                    return
                p = getattr(self, "_pending_after_ids", None)
                if p is not None and aid_holder[0] is not None:
                    p.discard(aid_holder[0])
                fn(*args, **kwargs)
            except Exception:
                pass

        try:
            aid = self.after(ms, wrapper)
            aid_holder[0] = aid
            p = getattr(self, "_pending_after_ids", None)
            if p is not None:
                p.add(aid)
            return aid
        except Exception:
            return None

    def _dispatch_to_main(self, fn, *args, **kwargs) -> None:
        """Marshal a call to the Tk main thread. Safe to call from worker threads."""
        self._ui_queue.put((fn, args, kwargs))
        if threading.current_thread() is threading.main_thread():
            self._drain_ui_queue()
        else:
            self.safe_after(0, self._drain_ui_queue)

    def _drain_ui_queue(self) -> None:
        if getattr(self, "_is_destroyed", False):
            return
        try:
            count = 0
            while True:
                try:
                    fn, args, kwargs = self._ui_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    fn(*args, **kwargs)
                except Exception as exc:
                    log.warning("UI queue callback failed: %s", exc)
                count += 1
                if count > 200:  # safety bound
                    break
        finally:
            if not getattr(self, "_is_destroyed", False):
                self.safe_after(80, self._drain_ui_queue)

    def destroy(self) -> None:
        # Cancel any in-flight scenario so the worker exits promptly.
        self._is_destroyed = True
        self._cancel_requested = True
        try:
            self._runner.reset()
        except Exception:
            pass
        for aid in list(getattr(self, "_pending_after_ids", set())):
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        self._pending_after_ids.clear()
        try:
            super().destroy()
        except Exception:
            pass

    # ======================================================================
    # UI construction
    # ======================================================================
    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_tabview()

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color=EX_COLORS["header"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(2, weight=1)

        title = ctk.CTkLabel(
            header,
            text="🛡  SENTINELML V2  —  INTERACTIVE EXHIBITION LAB",
            font=ctk.CTkFont("Segoe UI", 18, weight="bold"),
            text_color=EX_COLORS["white"],
        )
        title.grid(row=0, column=0, padx=20, pady=12, sticky="w")

        self._status_badge = ctk.CTkLabel(
            header,
            text="STATE: IDLE",
            font=ctk.CTkFont("Consolas", 12, weight="bold"),
            text_color=EX_COLORS["cyan"],
            fg_color="#1e3a6e",
            corner_radius=6,
            padx=12,
        )
        self._status_badge.grid(row=0, column=1, padx=8, pady=12)

        btn_box = ctk.CTkFrame(header, fg_color="transparent")
        btn_box.grid(row=1, column=0, columnspan=4, padx=12, pady=(0, 8), sticky="ew")
        for _col in range(7):
            btn_box.grid_columnconfigure(_col, weight=1)

        self._replay_btn = ctk.CTkButton(
            btn_box,
            text="Attack Replay",
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a",
            text_color=EX_COLORS["white"],
            height=30,
            command=lambda: self._open_tool("attack_replay"),
        )
        self._replay_btn.grid(row=0, column=0, padx=3, sticky="ew")

        self._obs_btn = ctk.CTkButton(
            btn_box,
            text="AI Observatory",
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a",
            text_color=EX_COLORS["white"],
            height=30,
            command=lambda: self._open_tool("ai_observatory"),
        )
        self._obs_btn.grid(row=0, column=1, padx=3, sticky="ew")

        self._watchtower_btn = ctk.CTkButton(
            btn_box,
            text="File Integrity",
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a",
            text_color=EX_COLORS["white"],
            height=30,
            command=lambda: self._open_tool("integrity_watchtower"),
        )
        self._watchtower_btn.grid(row=0, column=2, padx=3, sticky="ew")

        self._apps_btn = ctk.CTkButton(
            btn_box,
            text="Apps Center",
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a",
            text_color=EX_COLORS["white"],
            height=30,
            command=lambda: self._open_tool("applications_center"),
        )
        self._apps_btn.grid(row=0, column=3, padx=3, sticky="ew")

        self._cmd_btn = ctk.CTkButton(
            btn_box,
            text="3D Command Center",
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a",
            text_color=EX_COLORS["white"],
            height=30,
            command=lambda: self._open_tool("command_center"),
        )
        self._cmd_btn.grid(row=0, column=4, padx=3, sticky="ew")

        self._tour_btn = ctk.CTkButton(
            btn_box,
            text="Guided Tour",
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
            fg_color=EX_COLORS["gold"],
            hover_color=EX_COLORS["gold_hover"],
            text_color="#000000",
            height=30,
            command=self._open_guided_tour,
        )
        self._tour_btn.grid(row=0, column=5, padx=3, sticky="ew")

        self._back_btn = ctk.CTkButton(
            btn_box,
            text="Back to Dashboard",
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
            fg_color="#103a60",
            hover_color="#185285",
            text_color=EX_COLORS["cyan"],
            height=30,
            command=self._back_to_dashboard,
        )
        self._back_btn.grid(row=0, column=6, padx=3, sticky="ew")

    def _build_tabview(self) -> None:
        self._tabview = ctk.CTkTabview(
            self,
            fg_color=EX_COLORS["panel_dark"],
            segmented_button_selected_color=EX_COLORS["gold"],
            segmented_button_unselected_color=EX_COLORS["card"],
            segmented_button_selected_hover_color=EX_COLORS["gold_hover"],
            segmented_button_unselected_hover_color=EX_COLORS["card_border"],
            text_color=EX_COLORS["white"],
        )
        self._tabview.grid(row=1, column=0, sticky="nsew", padx=14, pady=12)

        self._tab_lab = self._tabview.add("Exhibition Lab")
        self._tab_timeline = self._tabview.add("Investigation Timeline")
        self._tab_result = self._tabview.add("Detection Result")
        self._tab_health = self._tabview.add("System Health")

        for tab in (self._tab_lab, self._tab_timeline, self._tab_result, self._tab_health):
            tab.grid_columnconfigure(0, weight=1)

        self._build_lab_tab(self._tab_lab)
        self._build_timeline_tab(self._tab_timeline)
        self._build_result_tab(self._tab_result)
        self._build_health_tab(self._tab_health)

    # ── Tab 1: Exhibition Lab (scenario selector + controls + live stream) ─
    def _build_lab_tab(self, parent) -> None:

        parent.grid_columnconfigure(0, weight=3)
        parent.grid_columnconfigure(1, weight=2)

        # Control bar
        ctrl = ctk.CTkFrame(parent, fg_color=EX_COLORS["card"], corner_radius=8,
                            border_width=1, border_color=EX_COLORS["card_border"])
        ctrl.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 6))
        ctrl.grid_columnconfigure(4, weight=1)

        self._run_btn = ctk.CTkButton(
            ctrl, text="▶ Run Scenario", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"],
            text_color="#000000", height=32, state="disabled", command=self._on_run)
        self._run_btn.grid(row=0, column=0, padx=10, pady=8)

        self._cancel_btn = ctk.CTkButton(
            ctrl, text="✖ Cancel", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#3d5070", hover_color="#4a6090", text_color=EX_COLORS["white"],
            width=90, height=32, state="disabled", command=self._on_cancel)
        self._cancel_btn.grid(row=0, column=1, padx=6, pady=8)

        self._reset_btn = ctk.CTkButton(
            ctrl, text="↻ Reset", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a", text_color=EX_COLORS["white"],
            width=90, height=32, command=self._on_reset)
        self._reset_btn.grid(row=0, column=2, padx=6, pady=8)

        self._export_btn = ctk.CTkButton(
            ctrl, text="⬇ Export Report", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#1a4a7a", hover_color="#2060a0", text_color=EX_COLORS["cyan"],
            height=32, state="disabled", command=self._on_export_report)
        self._export_btn.grid(row=0, column=3, padx=6, pady=8)

        self._activity_lbl = ctk.CTkLabel(
            ctrl, text="Select a scenario below, then press Run Scenario.",
            font=ctk.CTkFont("Segoe UI", 11), text_color=EX_COLORS["muted"],
            anchor="w")
        self._activity_lbl.grid(row=0, column=4, padx=12, pady=8, sticky="ew")

        # Left: scenario cards
        left = ctk.CTkFrame(parent, fg_color="transparent")
        left.grid(row=2, column=0, sticky="nsew", padx=(10, 5), pady=(0, 10))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="SCENARIO CATALOGUE  (A–E)",
                     font=ctk.CTkFont("Segoe UI", 14, weight="bold"), text_color=EX_COLORS["gold"]).grid(row=0, column=0, sticky="w", pady=(4, 6))

        self._scenario_scroll = ctk.CTkScrollableFrame(left, fg_color=EX_COLORS["panel_dark"])
        self._scenario_scroll.grid(row=1, column=0, sticky="nsew")
        self._scenario_scroll.grid_columnconfigure(0, weight=1)
        self._scenario_cards: Dict[str, ctk.CTkFrame] = {}
        self._render_scenario_cards()

        # Right: live event stream
        right = ctk.CTkFrame(parent, fg_color="transparent")
        right.grid(row=2, column=1, sticky="nsew", padx=(5, 10), pady=(0, 10))
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="LIVE EVENT STREAM",
                     font=ctk.CTkFont("Segoe UI", 14, weight="bold"), text_color=EX_COLORS["white"]).grid(row=0, column=0, sticky="w", pady=(4, 6))

        self._stream_scroll = ctk.CTkScrollableFrame(right, fg_color=EX_COLORS["panel_dark"])
        self._stream_scroll.grid(row=1, column=0, sticky="nsew")
        self._stream_scroll.grid_columnconfigure(0, weight=1)
        self._stream_placeholder = ctk.CTkLabel(
            self._stream_scroll,
            text="No events yet. Run a scenario to watch the investigation unfold live.\n"
                 "Events stream into this panel and the Investigation Timeline tab.",
            font=ctk.CTkFont("Segoe UI", 11, slant="italic"),
            text_color=EX_COLORS["muted"], justify="left")
        self._stream_placeholder.pack(padx=12, pady=16, anchor="w")

    def _render_scenario_cards(self) -> None:
        for spec in SCENARIOS:
            card = ctk.CTkFrame(self._scenario_scroll, fg_color=EX_COLORS["card"],
                                corner_radius=8, border_width=2,
                                border_color=EX_COLORS["card_border"])
            card.pack(fill="x", padx=6, pady=5)
            card.grid_columnconfigure(1, weight=1)

            pill = ctk.CTkLabel(card, text=spec.key, font=ctk.CTkFont("Segoe UI", 18, weight="bold"), text_color=EX_COLORS["gold"], fg_color="#1e3a6e",
                                corner_radius=6, width=44, height=44)
            pill.grid(row=0, column=0, padx=8, pady=8, rowspan=2)

            body = ctk.CTkFrame(card, fg_color="transparent")
            body.grid(row=0, column=1, sticky="ew", padx=4, pady=(8, 2))
            body.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(body, text=spec.name, font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                        text_color=EX_COLORS["white"], anchor="w").pack(fill="x")

            meta = ctk.CTkFrame(body, fg_color="transparent")
            meta.pack(fill="x", pady=(2, 0))
            mode_color = {
                "REAL_SCAN": EX_COLORS["real"], "SIMULATION": EX_COLORS["simulated"],
                "FAILURE_INJECTION": EX_COLORS["injected"], "MIXED": EX_COLORS["cyan"],
            }.get(spec.mode, EX_COLORS["muted"])
            ctk.CTkLabel(meta, text=f"[{spec.mode}]", font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=mode_color).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(meta, text=f"Expected: {spec.expected_outcome}",
                         font=ctk.CTkFont("Segoe UI", 11), text_color=EX_COLORS["muted"],
                         anchor="w", wraplength=300, justify="left").pack(side="left", fill="x")

            ctk.CTkLabel(card, text=f"Purpose: {spec.purpose}", font=ctk.CTkFont("Segoe UI", 11), text_color=EX_COLORS["muted"], anchor="w", wraplength=430,
                         justify="left").grid(row=1, column=1, sticky="ew", padx=4, pady=(0, 4))
            ctk.CTkLabel(card, text=f"🔒 {spec.safety_note}", font=ctk.CTkFont("Segoe UI", 10, slant="italic"), text_color=EX_COLORS["safe"], anchor="w", wraplength=430,
                         justify="left").grid(row=2, column=1, sticky="ew", padx=4, pady=(0, 8))

            key = spec.key
            card.bind("<Button-1>", lambda e, k=key: self._select_scenario(k))
            for child in card.winfo_children():
                child.bind("<Button-1>", lambda e, k=key: self._select_scenario(k))
                for grand in child.winfo_children():
                    grand.bind("<Button-1>", lambda e, k=key: self._select_scenario(k))
            self._scenario_cards[key] = card

    def _select_scenario(self, key: str) -> None:
        if self._is_running:
            return
        self._selected_scenario_key = key
        for k, card in self._scenario_cards.items():
            card.configure(border_color=EX_COLORS["gold"] if k == key else EX_COLORS["card_border"])
        spec = SCENARIOS_BY_KEY.get(key)
        self._run_btn.configure(state="normal")
        self._activity_lbl.configure(
            text=f"Selected: Scenario {key} — {spec.name}. Press ▶ Run Scenario to execute it.",
            text_color=EX_COLORS["white"])

    # ── Tab 2: Investigation Timeline ─────────────────────────────────────
    def _build_timeline_tab(self, parent) -> None:
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=2)
        parent.grid_columnconfigure(1, weight=3)

        left = ctk.CTkFrame(parent, fg_color=EX_COLORS["card"], corner_radius=8,
                           border_width=1, border_color=EX_COLORS["card_border"])
        left.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="CHRONOLOGICAL EVENTS",
                     font=ctk.CTkFont("Segoe UI", 14, weight="bold"), text_color=EX_COLORS["gold"]).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))

        self._timeline_summary_lbl = ctk.CTkLabel(
            left, text="No investigation yet. Run a scenario to populate the timeline.",
            font=ctk.CTkFont("Segoe UI", 10, slant="italic"),
            text_color=EX_COLORS["muted"], anchor="w")
        self._timeline_summary_lbl.grid(row=0, column=0, sticky="w", padx=10, pady=(0, 4))

        self._timeline_scroll = ctk.CTkScrollableFrame(left, fg_color=EX_COLORS["panel_dark"])
        self._timeline_scroll.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self._timeline_scroll.grid_columnconfigure(0, weight=1)
        self._timeline_empty = ctk.CTkLabel(
            self._timeline_scroll, text="Timeline is empty.",
            font=ctk.CTkFont("Segoe UI", 11, slant="italic"), text_color=EX_COLORS["muted"])
        self._timeline_empty.pack(padx=12, pady=16, anchor="w")

        right = ctk.CTkFrame(parent, fg_color=EX_COLORS["card"], corner_radius=8,
                             border_width=1, border_color=EX_COLORS["card_border"])
        right.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)
        right.grid_rowconfigure(3, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="EVENT DETAIL & EVIDENCE",
                     font=ctk.CTkFont("Segoe UI", 14, weight="bold"), text_color=EX_COLORS["cyan"]).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        self._detail_title = ctk.CTkLabel(right, text="Select an event to inspect its evidence.",
                                          font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                                          text_color=EX_COLORS["white"], anchor="w", wraplength=420)
        self._detail_title.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 2))

        self._detail_meta = ctk.CTkLabel(right, text="", font=ctk.CTkFont("Consolas", 10),
                                        text_color=EX_COLORS["muted"], anchor="w")
        self._detail_meta.grid(row=2, column=0, sticky="ew", padx=12)

        self._detail_scroll = ctk.CTkScrollableFrame(right, fg_color=EX_COLORS["panel_dark"])
        self._detail_scroll.grid(row=3, column=0, sticky="nsew", padx=8, pady=(4, 8))
        self._detail_scroll.grid_columnconfigure(0, weight=1)
        self._detail_body = ctk.CTkLabel(self._detail_scroll, text="", font=ctk.CTkFont("Segoe UI", 11),
                                         text_color=EX_COLORS["white"], anchor="w", justify="left", wraplength=420)
        self._detail_body.pack(fill="x", padx=6, pady=6, anchor="w")

    # ── Tab 3: Detection Result ──────────────────────────────────────────
    def _build_result_tab(self, parent) -> None:
        parent.grid_rowconfigure(1, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(parent, fg_color=EX_COLORS["card"], corner_radius=8,
                           border_width=1, border_color=EX_COLORS["card_border"])
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        top.grid_columnconfigure(0, weight=1)

        self._result_scenario_lbl = ctk.CTkLabel(
            top, text="No scan result yet.", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            text_color=EX_COLORS["muted"], anchor="w")
        self._result_scenario_lbl.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 2))

        row2 = ctk.CTkFrame(top, fg_color="transparent")
        row2.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 6))
        row2.grid_columnconfigure(2, weight=1)

        self._result_class_lbl = ctk.CTkLabel(
            row2, text="—", font=ctk.CTkFont("Segoe UI", 22, weight="bold"),
            text_color=EX_COLORS["muted"])
        self._result_class_lbl.grid(row=0, column=0, padx=(0, 12))

        self._result_origin_lbl = ctk.CTkLabel(
            row2, text="", font=ctk.CTkFont("Consolas", 11, weight="bold"),
            text_color=EX_COLORS["muted"], fg_color="#1e3a6e", corner_radius=6, padx=10)
        self._result_origin_lbl.grid(row=0, column=1, padx=6)

        self._result_prob_lbl = ctk.CTkLabel(
            row2, text="Model probability: —", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            text_color=EX_COLORS["white"], anchor="e")
        self._result_prob_lbl.grid(row=0, column=2, sticky="e")

        self._result_prob_note = ctk.CTkLabel(
            top, text="", font=ctk.CTkFont("Segoe UI", 10, slant="italic"),
            text_color=EX_COLORS["muted"], anchor="w", wraplength=760, justify="left")
        self._result_prob_note.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 4))

        self._result_desc = ctk.CTkLabel(
            top, text="", font=ctk.CTkFont("Segoe UI", 11), text_color=EX_COLORS["white"],
            anchor="w", justify="left", wraplength=760)
        self._result_desc.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 6))

        self._result_meta_lbl = ctk.CTkLabel(
            top, text="", font=ctk.CTkFont("Consolas", 10), text_color=EX_COLORS["muted"], anchor="w")
        self._result_meta_lbl.grid(row=4, column=0, sticky="ew", padx=14, pady=(0, 8))

        self._result_expect_lbl = ctk.CTkLabel(
            top, text="", font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
            text_color=EX_COLORS["muted"], anchor="w")
        self._result_expect_lbl.grid(row=5, column=0, sticky="ew", padx=14, pady=(0, 10))

        # Scrollable detail sections
        body = ctk.CTkScrollableFrame(parent, fg_color=EX_COLORS["panel_dark"])
        body.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        body.grid_columnconfigure(0, weight=1)

        self._result_sections: Dict[str, ctk.CTkLabel] = {}
        for key, title, color in [
            ("indicators", "OBSERVED INDICATORS", EX_COLORS["cyan"]),
            ("telemetry_gaps", "TELEMETRY — AVAILABLE & MISSING", EX_COLORS["inconclusive"]),
            ("evidence", "SUPPORTING EVIDENCE (timestamps)", EX_COLORS["white"]),
            ("next_steps", "RECOMMENDED NEXT STEPS", EX_COLORS["gold"]),
            ("limitations", "LIMITATIONS & DISCLOSURES", EX_COLORS["warning"]),
        ]:
            ctk.CTkLabel(body, text=title, font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                         text_color=color, anchor="w").pack(fill="x", padx=12, pady=(10, 2))
            lbl = ctk.CTkLabel(body, text="—", font=ctk.CTkFont("Segoe UI", 10),
                               text_color=EX_COLORS["muted"], anchor="w", justify="left", wraplength=760)
            lbl.pack(fill="x", padx=12, pady=(0, 2))
            self._result_sections[key] = lbl

    # ── Tab 4: System Health ──────────────────────────────────────────────
    def _build_health_tab(self, parent) -> None:
        parent.grid_rowconfigure(1, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        bar = ctk.CTkFrame(parent, fg_color=EX_COLORS["card"], corner_radius=8,
                           border_width=1, border_color=EX_COLORS["card_border"])
        bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        bar.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(bar, text="SECURITY HEALTH  —  GENUINE SYSTEM STATUS",
                     font=ctk.CTkFont("Segoe UI", 14, weight="bold"), text_color=EX_COLORS["gold"]).grid(row=0, column=0, padx=12, pady=8, sticky="w")
        self._health_refresh_btn = ctk.CTkButton(
            bar, text="↻ Refresh", font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a", text_color=EX_COLORS["white"],
            height=30, command=self._refresh_system_health)
        self._health_refresh_btn.grid(row=0, column=1, padx=6, pady=8)
        self._health_status_lbl = ctk.CTkLabel(
            bar, text="", font=ctk.CTkFont("Segoe UI", 10, slant="italic"),
            text_color=EX_COLORS["muted"], anchor="w")
        self._health_status_lbl.grid(row=0, column=2, padx=12, pady=8, sticky="ew")

        body = ctk.CTkScrollableFrame(parent, fg_color=EX_COLORS["panel_dark"])
        body.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        body.grid_columnconfigure(0, weight=1)

        self._health_labels: Dict[str, ctk.CTkLabel] = {}
        sections = [
            ("platform", "PLATFORM & VERSION", EX_COLORS["cyan"]),
            ("model", "MODEL & SCALER STATUS", EX_COLORS["gold"]),
            ("sensors_summary", "TELEMETRY SENSOR COVERAGE", EX_COLORS["cyan"]),
            ("sensors_table", "SENSOR AVAILABILITY (19-FEATURE SCHEMA)", EX_COLORS["white"]),
            ("last_scan", "LATEST SCAN", EX_COLORS["cyan"]),
            ("recent", "RECENT OUTCOMES", EX_COLORS["white"]),
            ("monitoring", "CURRENT MONITORING CAPABILITIES", EX_COLORS["cyan"]),
            ("limitations", "KNOWN PLATFORM LIMITATIONS", EX_COLORS["warning"]),
        ]
        for key, title, color in sections:
            ctk.CTkLabel(body, text=title, font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                         text_color=color, anchor="w").pack(fill="x", padx=12, pady=(10, 2))
            lbl = ctk.CTkLabel(body, text="Not measured.", font=ctk.CTkFont("Segoe UI", 10),
                               text_color=EX_COLORS["muted"], anchor="w", justify="left", wraplength=820)
            lbl.pack(fill="x", padx=12, pady=(0, 2))
            self._health_labels[key] = lbl

    # ======================================================================
    # Scenario execution (worker thread + main-thread marshalling)
    # ======================================================================
    def _on_run(self) -> None:
        if self._is_running or self._selected_scenario_key is None:
            return
        key = self._selected_scenario_key
        token = str(uuid.uuid4())
        self._active_token = token
        self._cancel_requested = False
        self._is_running = True
        self._set_controls_state("running")
        self._status_badge.configure(text="STATE: RUNNING", text_color=EX_COLORS["cyan"])
        self._activity_lbl.configure(text=f"Running Scenario {key} …", text_color=EX_COLORS["white"])
        self._clear_timeline_view()
        self._clear_result_view()
        threading.Thread(target=self._run_scenario_thread, args=(key, token),
                         daemon=True, name="ExhLabScenario").start()

    def _on_cancel(self) -> None:
        if not self._is_running:
            return
        self._cancel_requested = True
        self._cancel_btn.configure(state="disabled", text="Cancelling…")
        self._activity_lbl.configure(text="Cancellation requested — stopping at the next safe phase boundary…",
                                      text_color=EX_COLORS["warning"])

    def _on_reset(self) -> None:
        if self._is_running:
            return
        self._cancel_requested = False
        self._active_token = None
        self._last_result = None
        self._selected_event_seq = None
        try:
            self._runner.reset()
        except Exception as exc:
            log.warning("Runner reset failed: %s", exc)
        self._clear_timeline_view()
        self._clear_result_view()
        self._clear_stream_view()
        self._status_badge.configure(text="STATE: IDLE", text_color=EX_COLORS["cyan"])
        self._activity_lbl.configure(text="Reset complete. Select a scenario and run it again.",
                                     text_color=EX_COLORS["muted"])
        self._set_controls_state("idle")
        self.safe_after(100, self._refresh_system_health)

    def _set_controls_state(self, state: str) -> None:
        if state == "running":
            self._run_btn.configure(state="disabled")
            self._cancel_btn.configure(state="normal", text="✖ Cancel")
            self._reset_btn.configure(state="disabled")
            self._export_btn.configure(state="disabled")
        elif state == "done":
            self._run_btn.configure(state="normal")
            self._cancel_btn.configure(state="disabled", text="✖ Cancel")
            self._reset_btn.configure(state="normal")
            self._export_btn.configure(state="normal" if self._last_result is not None else "disabled")
        else:  # idle
            self._run_btn.configure(state="normal" if self._selected_scenario_key else "disabled")
            self._cancel_btn.configure(state="disabled", text="✖ Cancel")
            self._reset_btn.configure(state="normal")
            self._export_btn.configure(state="disabled")

    def _run_scenario_thread(self, key: str, token: str) -> None:
        """Worker: execute one scenario via the real pipeline. Never touches widgets."""
        try:
            self._runner.reset()  # fresh timeline + clean sandbox per run
            result = self._runner.run(
                key, cancel_check=lambda: self._cancel_requested or token != self._active_token)
            if token != self._active_token:
                log.info("Discarding stale scenario result for token %s", token)
                return
            self._dispatch_to_main(self._on_scenario_complete, result, token)
        except Exception as exc:
            log.error("Scenario %s failed: %s", key, exc, exc_info=True)
            if token == self._active_token:
                self._dispatch_to_main(self._on_scenario_error, str(exc), token)

    def _on_scenario_event(self, evt: InvestigationEvent) -> None:
        """ScenarioRunner emit sink — called from the worker thread. Marshals to main."""
        self._dispatch_to_main(self._append_timeline_event, evt)

    # ── Main-thread callbacks ────────────────────────────────────────────
    def _append_timeline_event(self, evt: InvestigationEvent) -> None:
        if getattr(self, "_is_destroyed", False) or not self.winfo_exists():
            return
        self._add_timeline_row(evt)
        self._add_stream_row(evt)
        self._activity_lbl.configure(text=f"[{evt.timestamp}] {evt.title}", text_color=EX_COLORS["white"])

    def _on_scenario_complete(self, result: ScenarioResult, token: str) -> None:
        if getattr(self, "_is_destroyed", False) or token != self._active_token:
            return
        self._is_running = False
        self._cancel_requested = False
        self._last_result = result
        self._recent_outcomes.append({
            "scenario": f"{result.scenario_key}: {result.name}",
            "outcome": result.outcome_label,
            "classification": result.classification,
            "simulation": result.is_simulation,
            "duration": round(result.duration_seconds, 3),
            "at": result.started_at,
        })
        if len(self._recent_outcomes) > 10:
            self._recent_outcomes = self._recent_outcomes[-10:]
        self._set_controls_state("done")
        self._status_badge.configure(text=f"STATE: {result.outcome_label}",
                                     text_color=severity_color(result.classification))
        self._activity_lbl.configure(
            text=f"Scenario {result.scenario_key} complete — {result.outcome_label} "
                 f"(origin: {result.data_origin}). See Detection Result.",
            text_color=severity_color(result.classification))
        # Ensure the authoritative timeline (incl. final classification/response) is fully shown.
        self._ensure_timeline_complete(result.timeline)
        self._render_result(result)
        try:
            self._tabview.set("Detection Result")
        except Exception:
            pass
        self._refresh_system_health()

    def _on_scenario_error(self, message: str, token: str) -> None:
        if getattr(self, "_is_destroyed", False) or token != self._active_token:
            return
        self._is_running = False
        self._cancel_requested = False
        self._set_controls_state("idle")
        self._status_badge.configure(text="STATE: ERROR", text_color=EX_COLORS["error"])
        self._activity_lbl.configure(text=f"Scenario error: {message}", text_color=EX_COLORS["error"])
        # An error must never silently become SAFE — render an explicit ERROR result.
        self._render_error_result(message)

    # ======================================================================
    # Timeline rendering
    # ======================================================================
    def _add_timeline_row(self, evt: InvestigationEvent) -> None:
        if evt.seq in self._timeline_rows:
            return
        if self._timeline_empty is not None:
            try:
                self._timeline_empty.destroy()
            except Exception:
                pass
            self._timeline_empty = None
        row = ctk.CTkFrame(self._timeline_scroll, fg_color=EX_COLORS["card"],
                           corner_radius=6, border_width=1, border_color=EX_COLORS["card_border"])
        row.pack(fill="x", padx=4, pady=2)
        row.grid_columnconfigure(2, weight=1)

        seq_lbl = ctk.CTkLabel(row, text=f"#{evt.seq}", font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=category_color(evt.category), width=42)
        seq_lbl.grid(row=0, column=0, padx=6, pady=4)

        src_lbl = ctk.CTkLabel(row, text=source_label(evt.source),
                               font=ctk.CTkFont("Consolas", 10, weight="bold"), text_color=source_color(evt.source), fg_color="#1e3a6e",
                               corner_radius=4, width=110)
        src_lbl.grid(row=0, column=1, padx=4, pady=4)

        txt = ctk.CTkLabel(row, text=f"{evt.timestamp}  {evt.title}",
                           font=ctk.CTkFont("Segoe UI", 12), text_color=EX_COLORS["white"], anchor="w")
        txt.grid(row=0, column=2, sticky="ew", padx=4, pady=4)

        seq_num = evt.seq
        row.bind("<Button-1>", lambda e, s=seq_num: self._on_select_event(s))
        for child in row.winfo_children():
            child.bind("<Button-1>", lambda e, s=seq_num: self._on_select_event(s))
        self._timeline_rows[seq_num] = row
        self._update_timeline_summary()

    def _add_stream_row(self, evt: InvestigationEvent) -> None:
        if self._stream_placeholder is not None:
            try:
                self._stream_placeholder.destroy()
            except Exception:
                pass
            self._stream_placeholder = None
        row = ctk.CTkFrame(self._stream_scroll, fg_color=EX_COLORS["card"],
                           corner_radius=6, border_width=1, border_color=EX_COLORS["card_border"])
        row.pack(fill="x", padx=4, pady=2)
        row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(row, text=f"[{evt.timestamp}] {source_label(evt.source)} — {evt.title}",
                     font=ctk.CTkFont("Consolas", 12, "bold"), text_color=source_color(evt.source),
                     anchor="w").grid(row=0, column=0, sticky="ew", padx=8, pady=3)
        ctk.CTkLabel(row, text=evt.detail, font=ctk.CTkFont("Segoe UI", 11), text_color=EX_COLORS["muted"], anchor="w", justify="left", wraplength=360).grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 3))
        self._stream_scroll._parent_canvas.yview_moveto(1.0)

    def _ensure_timeline_complete(self, timeline: InvestigationTimeline) -> None:
        for evt in timeline.events:
            self._add_timeline_row(evt)
        self._update_timeline_summary()

    def _on_select_event(self, seq: int) -> None:
        self._selected_event_seq = seq
        for s, row in self._timeline_rows.items():
            row.configure(border_color=EX_COLORS["gold"] if s == seq else EX_COLORS["card_border"])
        evt = None
        if self._last_result is not None:
            evt = self._last_result.timeline.get(seq)
        if evt is None and self._runner is not None:
            evt = self._runner.timeline.get(seq)
        self._show_event_detail(evt)

    def _show_event_detail(self, evt: Optional[InvestigationEvent]) -> None:
        if evt is None:
            self._detail_title.configure(text="Event not found.", text_color=EX_COLORS["warning"])
            self._detail_meta.configure(text="")
            self._detail_body.configure(text="")
            return
        self._detail_title.configure(text=evt.title, text_color=EX_COLORS["white"])
        self._detail_meta.configure(
            text=f"#{evt.seq}  •  {evt.timestamp}  •  {evt.category.replace('_', ' ')}  •  "
                 f"Source: {source_label(evt.source)}",
            text_color=source_color(evt.source))
        body_lines = [evt.detail, ""]
        if evt.evidence:
            body_lines.append("EVIDENCE:")
            body_lines += [f"  • {e}" for e in evt.evidence]
        self._detail_body.configure(text="\n".join(body_lines), text_color=EX_COLORS["white"])

    def _update_timeline_summary(self) -> None:
        tl = self._last_result.timeline if self._last_result else self._runner.timeline
        snap = tl.snapshot_summary()
        self._timeline_summary_lbl.configure(
            text=f"{snap['event_count']} events  •  ordered={snap['ordered']}  •  "
                 f"real={snap['real_events']}  simulated={snap['simulated_events']}  "
                 f"injected={snap['injected_events']}  •  {snap['first_timestamp']} → {snap['last_timestamp']}",
            text_color=EX_COLORS["muted"])

    def _clear_timeline_view(self) -> None:
        for row in list(self._timeline_rows.values()):
            try:
                row.destroy()
            except Exception:
                pass
        self._timeline_rows.clear()
        self._selected_event_seq = None
        if self._timeline_empty is None:
            self._timeline_empty = ctk.CTkLabel(
                self._timeline_scroll, text="Timeline cleared. Run a scenario to populate it.",
                font=ctk.CTkFont("Segoe UI", 11, slant="italic"), text_color=EX_COLORS["muted"])
            self._timeline_empty.pack(padx=12, pady=16, anchor="w")
        self._detail_title.configure(text="Select an event to inspect its evidence.",
                                      text_color=EX_COLORS["white"])
        self._detail_meta.configure(text="")
        self._detail_body.configure(text="")
        self._timeline_summary_lbl.configure(text="No investigation yet. Run a scenario to populate the timeline.",
                                            text_color=EX_COLORS["muted"])

    def _clear_stream_view(self) -> None:
        for w in list(self._stream_scroll.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass
        self._stream_placeholder = ctk.CTkLabel(
            self._stream_scroll,
            text="No events yet. Run a scenario to watch the investigation unfold live.",
            font=ctk.CTkFont("Segoe UI", 11, slant="italic"), text_color=EX_COLORS["muted"], justify="left")
        self._stream_placeholder.pack(padx=12, pady=16, anchor="w")

    # ======================================================================
    # Detection Result rendering
    # ======================================================================
    def _render_result(self, result: ScenarioResult) -> None:
        ex = result.explanation or {}
        classification = ex.get("classification") or result.classification or result.outcome_label
        color = severity_color(classification)
        self._result_class_lbl.configure(text=str(classification), text_color=color)

        badge_text, badge_color = classify_origin_badge(result.data_origin, result.is_simulation)
        self._result_origin_lbl.configure(text=badge_text, text_color=badge_color)

        prob = ex.get("probability")
        if prob is None:
            self._result_prob_lbl.configure(text="Model probability: Not available",
                                             text_color=EX_COLORS["muted"])
        else:
            try:
                p = float(prob)
                self._result_prob_lbl.configure(
                    text=f"Model probability: {p:.4f}  ({p*100:.1f}%)",
                    text_color=EX_COLORS["cyan"])
            except Exception:
                self._result_prob_lbl.configure(text="Model probability: Not available",
                                                 text_color=EX_COLORS["muted"])
        self._result_prob_note.configure(text=str(ex.get("probability_note", "")))

        detail = ex.get("classification_detail") or {}
        self._result_desc.configure(text=str(detail.get("description", "") or result.outcome_detail or ""))

        self._result_scenario_lbl.configure(
            text=f"Scenario {result.scenario_key}: {result.name}  •  Mode: {result.mode}")
        self._result_meta_lbl.configure(
            text=f"Scan ID: {ex.get('scan_id', '—')}    State: {ex.get('scan_state', '—')}    "
                 f"Duration: {float(ex.get('duration_seconds', result.duration_seconds) or 0):.2f}s    "
                 f"Generated: {ex.get('generated_at', '—')}")
        self._result_expect_lbl.configure(
            text=f"Expected: {result.expected_outcome}   |   Expectation met: "
                 f"{'YES' if result.expectation_met else 'NO'}",
            text_color=EX_COLORS["safe"] if result.expectation_met else EX_COLORS["warning"])

        # Indicators
        inds = ex.get("indicators", []) or []
        if inds:
            lines = []
            for i in inds:
                status = i.get("status", "NOMINAL")
                mark = "▲" if status == "ELEVATED" else "•"
                lines.append(f"{mark} {i.get('display_name', i.get('feature','?'))} = "
                             f"{i.get('value','?')} (baseline {i.get('baseline','?')}) — "
                             f"{status}  [{i.get('origin','')}]")
            self._result_sections["indicators"].configure(
                text="\n".join(lines), text_color=EX_COLORS["white"])
        else:
            self._result_sections["indicators"].configure(
                text="No elevated indicators. All heuristic indicators at nominal baseline.",
                text_color=EX_COLORS["muted"])

        # Telemetry gaps
        gaps = ex.get("telemetry_gaps", {}) or {}
        cov = gaps.get("coverage_ratio")
        avail = gaps.get("available_feature_count")
        unavail = gaps.get("unavailable", []) or []
        sub = gaps.get("substituted_or_proxy", []) or []
        gap_lines = []
        gap_lines.append(f"Coverage: {len(unavail)+len(sub)+ (avail or 0) } sensors reported; "
                         f"coverage ratio = {cov if cov is not None else 'n/a'}.")
        if unavail:
            gap_lines.append("Unavailable / restricted sensors:")
            gap_lines += [f"  • {g.get('feature','?')}: {g.get('status','?')}" for g in unavail]
        if sub:
            gap_lines.append("Heuristic-proxy / substituted sensors (not directly measured):")
            gap_lines += [f"  • {g.get('feature','?')}: {g.get('status','?')}" for g in sub]
        if not unavail and not sub:
            gap_lines.append("All 19 sensors available on this platform (no missing measurements).")
        self._result_sections["telemetry_gaps"].configure(text="\n".join(gap_lines),
                                                            text_color=EX_COLORS["white"])

        # Evidence
        ev = ex.get("evidence", []) or []
        if ev:
            ev_lines = [f"[{e.get('timestamp','')}] {e.get('text','')}  ({source_label(e.get('source','REAL'))})"
                        for e in ev[:20]]
            self._result_sections["evidence"].configure(text="\n".join(ev_lines),
                                                         text_color=EX_COLORS["white"])
        else:
            self._result_sections["evidence"].configure(text="No timestamped evidence recorded.",
                                                          text_color=EX_COLORS["muted"])

        # Next steps
        steps = ex.get("next_steps", []) or []
        self._result_sections["next_steps"].configure(
            text="\n".join(f"{i+1}. {s}" for i, s in enumerate(steps)) if steps
            else "Review the evidence and re-run the scan.",
            text_color=EX_COLORS["white"])

        # Limitations
        lims = ex.get("limitations", []) or list(result.limitations or [])
        self._result_sections["limitations"].configure(
            text="\n".join(f"• {l}" for l in lims) if lims else "None reported.",
            text_color=EX_COLORS["muted"])

    def _render_error_result(self, message: str) -> None:
        self._result_class_lbl.configure(text="ERROR", text_color=EX_COLORS["error"])
        self._result_origin_lbl.configure(text="REAL SCAN (FAILED)", text_color=EX_COLORS["error"])
        self._result_prob_lbl.configure(text="Model probability: Not available", text_color=EX_COLORS["muted"])
        self._result_prob_note.configure(text="No probability is produced for a failed scan.")
        self._result_desc.configure(text=f"The scenario failed before producing a classification: {message}")
        self._result_scenario_lbl.configure(text="Scenario execution failed — no security classification can be claimed.")
        self._result_meta_lbl.configure(text="")
        self._result_expect_lbl.configure(text="Expectation met: NO", text_color=EX_COLORS["warning"])
        self._result_sections["indicators"].configure(text="—", text_color=EX_COLORS["muted"])
        self._result_sections["telemetry_gaps"].configure(text="—", text_color=EX_COLORS["muted"])
        self._result_sections["evidence"].configure(text="—", text_color=EX_COLORS["muted"])
        self._result_sections["next_steps"].configure(
            text="1. Inspect the error message above.\n2. Verify model/scanner availability in System Health.\n"
                 "3. Re-run the scenario or reset.",
            text_color=EX_COLORS["white"])
        self._result_sections["limitations"].configure(
            text="• A failed, cancelled or incomplete scan is never treated as SAFE.\n"
                 "• SentinelAI advisory cannot override this authoritative outcome.",
            text_color=EX_COLORS["muted"])
        try:
            self._tabview.set("Detection Result")
        except Exception:
            pass

    def _clear_result_view(self) -> None:
        self._result_class_lbl.configure(text="—", text_color=EX_COLORS["muted"])
        self._result_origin_lbl.configure(text="", text_color=EX_COLORS["muted"])
        self._result_prob_lbl.configure(text="Model probability: —", text_color=EX_COLORS["white"])
        self._result_prob_note.configure(text="")
        self._result_desc.configure(text="")
        self._result_scenario_lbl.configure(text="No scan result yet.")
        self._result_meta_lbl.configure(text="")
        self._result_expect_lbl.configure(text="")
        for lbl in self._result_sections.values():
            lbl.configure(text="—", text_color=EX_COLORS["muted"])

    # ======================================================================
    # Report export
    # ======================================================================
    def _on_export_report(self) -> None:
        if self._last_result is None:
            return
        try:
            from tkinter import filedialog, messagebox
        except Exception:
            return
        result = self._last_result
        path = filedialog.asksaveasfilename(
            title="Export Exhibition Incident Report",
            defaultextension=".txt",
            initialfile=f"sentinelml_scenario_{result.scenario_key}_report.txt",
            filetypes=[("Text Report", "*.txt"), ("All Files", "*.*")])
        if not path:
            return
        try:
            text_parts = [result.report_text(), "", "=" * 78, "DETECTION RESULT EXPLANATION", "=" * 78]
            try:
                text_parts.append(format_explanation_text(result.explanation or {}))
            except Exception as exc:
                text_parts.append(f"(explanation text unavailable: {exc})")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(text_parts))
            try:
                messagebox.showinfo("Report Exported", f"Incident report saved to:\n{path}")
            except Exception:
                pass
        except Exception as exc:
            log.error("Report export failed: %s", exc, exc_info=True)
            try:
                messagebox.showerror("Export Failed", str(exc))
            except Exception:
                pass

    # ======================================================================
    # System Health (Phase 6) — genuine measurements, honest "Unavailable"
    # ======================================================================
    def _refresh_system_health(self) -> None:
        if getattr(self, "_is_destroyed", False) or not self.winfo_exists():
            return
        try:
            info = self._collect_health_info()
        except Exception as exc:
            log.warning("System health collection failed: %s", exc)
            self._health_status_lbl.configure(text=f"Health refresh failed: {exc}",
                                               text_color=EX_COLORS["error"])
            return
        self._render_health(info)

    def _collect_health_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        info["platform"] = (
            f"Operating System: {platform.system()} {platform.release()} ({platform.machine()})\n"
            f"Platform ID: {sys.platform}\n"
            f"Python: {platform.python_version()}\n"
            f"SentinelML Application Version: {APP_VERSION}\n"
            f"Build: {platform.version()}"
        )

        # Model & scaler
        model_lines: List[str] = []
        try:
            predictor = MLPredictor()
            loaded = predictor.is_loaded()
            if not loaded:
                loaded = predictor.load_model()
            mi = predictor.get_model_info()
            model_lines.append(f"Random Forest model: {'LOADED' if loaded else 'NOT LOADED'}")
            model_lines.append(f"  Type: {mi.get('type','?')}  |  Expected features: {mi.get('expected_features','?')}")
            model_lines.append(f"  Thresholds: WARNING >= {mi.get('threshold_warning',0.5)}  "
                               f"CRITICAL >= {mi.get('threshold_critical',0.9)}")
            model_lines.append(f"  Status note: thresholds, model and scaler are read-only — never retrained or "
                               f"replaced by this application.")
        except Exception as exc:
            model_lines.append(f"Model load failed: {exc}")
        for label, fname in [("Model", "models/saved_model.pkl"),
                             ("Scaler", "models/scaler.pkl"),
                             ("Metrics", "models/metrics.json")]:
            model_lines.append(self._file_status(Path(fname), label))
        info["model"] = "\n".join(model_lines)

        # Sensors
        try:
            avail = get_platform_feature_availability() or {}
        except Exception as exc:
            avail = {}
            info["_sensor_error"] = str(exc)
        genuine = sum(1 for s in avail.values() if s == "GENUINE_MEASURED")
        proxy = sum(1 for s in avail.values()
                    if s.startswith("HEURISTIC_PROXY") or s.startswith("SUBSTITUTED"))
        unavail = [f for f, s in avail.items()
                   if s.startswith("UNAVAILABLE") or s.startswith("RESTRICTED")]
        info["sensors_summary"] = (
            f"{len(avail)}/19 schema sensors reported on {sys.platform}.\n"
            f"  Directly measured (GENUINE_MEASURED): {genuine}\n"
            f"  Heuristic proxy / substituted: {proxy}\n"
            f"  Unavailable or permission-restricted: {len(unavail)}"
            + (f"  -> {', '.join(unavail)}" if unavail else "")
            + ("\n  WARNING: sensor enumeration failed — shown as Unavailable, not zeros."
               if not avail else "")
        )
        # Sensor table grouped by status
        order = ["GENUINE_MEASURED", "HEURISTIC_PROXY", "SUBSTITUTED",
                 "UNAVAILABLE_PLATFORM", "RESTRICTED_PERMISSION"]
        table_lines = []
        for status in order:
            feats = [f for f, s in avail.items() if s == status]
            if feats:
                table_lines.append(f"[{status}] ({len(feats)}): {', '.join(feats)}")
        other = [(f, s) for f, s in avail.items() if s not in order]
        for f, s in other:
            table_lines.append(f"[{s}] (1): {f}")
        if not table_lines:
            table_lines.append("Sensor enumeration unavailable on this platform.")
        info["sensors_table"] = "\n".join(table_lines)
        info["unavail_sensors"] = unavail

        # Last scan
        if self._last_result is not None:
            r = self._last_result
            info["last_scan"] = (
                f"Outcome: {r.outcome_label} ({r.classification})\n"
                f"Scenario: {r.scenario_key}: {r.name}\n"
                f"Data origin: {r.data_origin}  (simulation={r.is_simulation})\n"
                f"Duration: {r.duration_seconds:.2f}s   Started: {r.started_at}\n"
                f"Timeline events: {len(r.timeline)} (ordered={r.timeline.is_ordered()})"
            )
        else:
            info["last_scan"] = "Not measured — no scenario has been run in this session yet."

        # Recent outcomes
        if self._recent_outcomes:
            recent_lines = []
            for o in self._recent_outcomes[-5:]:
                tag = "SIM" if o["simulation"] else "REAL"
                recent_lines.append(f"  • [{tag}] {o['scenario']} -> {o['outcome']} ({o['duration']:.2f}s)")
            info["recent"] = "\n".join(recent_lines)
        else:
            info["recent"] = "No scenarios run yet in this session."

        # Monitoring capabilities
        guard_running = False
        try:
            from guard.sentinel_guard import get_guard_instance
            guard_running = bool(get_guard_instance().is_running())
        except Exception:
            pass
        info["monitoring"] = (
            f"SentinelGuard background monitor: {'RUNNING' if guard_running else 'IDLE / not started'}\n"
            f"Behavioral telemetry: user-space process + filesystem + entropy observation\n"
            f"ML inference: on-demand via ScanEngine (19-feature Random Forest)\n"
            f"Interactive Exhibition Lab: ACTIVE (this view)"
        )

        # Limitations + scope disclosure
        info["limitations"] = (
            "• SCOPE: SentinelML performs user-space behavioral monitoring only. It does NOT provide "
            "kernel-level protection, real-time blocking, or full-disk interception.\n"
            "• MODEL: trained model is an EXPERIMENTAL_SYNTHETIC_BASELINE_V1 classifier; predictions are "
            "behavioural risk scores, not definitive malware identifications.\n"
            "• TELEMETRY: several of the 19 features are heuristic proxies (not direct kernel measurements) "
            "on this platform and are reported as such — never silently treated as zeros.\n"
            "• COVERAGE: Quick scans use depth=1 over monitored roots; Full scans use depth=6. Neither "
            "guarantees absence of unknown malware.\n"
            "• INCONCLUSIVE: when sensor coverage drops below a validated level, the engine returns "
            "INCONCLUSIVE rather than a false SAFE.\n"
            "• ADVISORY: SentinelAI is advisory only and can never override the authoritative scan outcome."
        )
        return info

    def _render_health(self, info: Dict[str, Any]) -> None:
        for key, lbl in self._health_labels.items():
            val = info.get(key, "Not measured.")
            lbl.configure(text=str(val))
        unavail = info.get("unavail_sensors", [])
        self._health_status_lbl.configure(
            text=f"Refreshed {__import__('datetime').datetime.now().strftime('%H:%M:%S')}.  "
                 f"Missing measurements are shown as Unavailable, never as zeros.  "
                 f"User-space monitoring scope disclosed.",
            text_color=EX_COLORS["muted"])

    @staticmethod
    def _file_status(path: Path, label: str) -> str:
        try:
            if path.exists():
                size = path.stat().st_size
                return f"{label}: present ({size:,} bytes)  -> {path}"
            return f"{label}: NOT FOUND  -> {path}"
        except Exception as exc:
            return f"{label}: error checking ({exc})  -> {path}"

    # ======================================================================
    # Navigation helpers
    # ======================================================================
    def _back_to_dashboard(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("dashboard")

    def _open_guided_tour(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("guided_tour")

    def _open_tool(self, page_id: str) -> None:
        # Navigate to Attack Replay / AI Observatory / File Integrity page.
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show(page_id)

    def on_shown(self) -> None:
        # Called by MainWindow when this page becomes visible (refreshes live data).
        self.safe_after(150, self._refresh_system_health)
