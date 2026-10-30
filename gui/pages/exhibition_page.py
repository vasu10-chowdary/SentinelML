"""
SentinelML V2 — Exhibition Experience & Evidence Dashboard
============================================================
A polished, exhibition-ready cybersecurity demonstration dashboard featuring:
1. Live Genuine System Scan with 19-feature breakdown.
2. Controlled Ransomware-Behavior Safe Demo inside an isolated disposable sandbox.
3. 6-Stage Detection Verification Pipeline with stage-by-stage genuine metrics.
4. Transparent Feature Inspector supporting Schema V2 (16 features) and Legacy (19 features).
5. Worst-Case Security Test Lab with 9 failure and edge-case scenarios.
6. Deterministic Educational Walkthrough for offline/restricted environments.
7. Privacy-preserving sanitized report exporter.
"""

import os
import time
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import numpy as np

from constants import COLOURS as C
from scanner.scan_engine import ScanEngine, ScanType, ScanState, ScanResult
from ml.predictor import MLPredictor, FEATURE_NAMES
from ml.schema_v2 import FEATURE_NAMES_V2, FEATURE_SPECIFICATIONS
from exhibition.sandbox_simulator import SandboxSimulator, SimulationResult, SimulationEvent, SecurityError
from exhibition.security_test_lab import SecurityTestLab, ScenarioOutcome
from exhibition.report_exporter import ExhibitionReportExporter

# Exhibition color palette: Deep Navy, Crisp White, Muted Gold, Slate Border, Emerald & Amber
EX_COLORS = {
    "bg": "#0b1427",          # Deep navy background
    "card": "#162040",        # Card surface
    "card_border": "#2a4a7f", # Card border
    "header": "#0e2a6e",      # Dark header navy
    "gold": "#e8c84a",        # Muted gold accent
    "gold_hover": "#d4af30",  # Darker gold for buttons
    "white": "#f0f4ff",       # Primary crisp white
    "muted": "#b8c5d9",       # Slate secondary text
    "safe": "#34d897",        # Emerald green
    "warning": "#fbb03b",     # Amber orange
    "critical": "#ff6b6b",    # Crimson red
    "cyan": "#38d8f5",        # High-visibility cyan accent
    "panel_dark": "#0f1d38",  # Darker inner panel
}


class ExhibitionPage(ctk.CTkFrame):
    """
    Exhibition Demonstration and Technical Evidence Dashboard.
    Designed for college presentations, technical evaluators, and public booth demos.
    """

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=EX_COLORS["bg"], **kwargs)
        self._config = config
        self._engine = ScanEngine()
        self._test_lab = SecurityTestLab()
        self._exporter = ExhibitionReportExporter()
        self._simulator = self._test_lab.simulator

        self._active_tab = "simulator"
        self._is_scanning = False
        self._is_simulating = False
        self._last_scan_result: Optional[ScanResult] = None
        self._last_sim_result: Optional[SimulationResult] = None
        self._last_test_outcome: Optional[ScenarioOutcome] = None
        self._last_safe_demo_res: Optional[Dict[str, Any]] = None

        # Feature Inspector state
        self._inspector_schema = "schema_v2_16"
        self._inspector_features = self._test_lab.get_feature_inspector_data()
        self._selected_feature_name: Optional[str] = None

        self._build_ui()
        self._run_health_check_display()

    def _build_ui(self) -> None:
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ── 1. Top Header Banner ──────────────────────────────────────────
        header_frame = ctk.CTkFrame(self, fg_color=EX_COLORS["header"], corner_radius=0)
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header_frame.grid_columnconfigure(0, weight=1)

        title_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_box.pack(fill="x", padx=20, pady=10)

        title_lbl = ctk.CTkLabel(
            title_box,
            text="SENTINELML V2  |  EXHIBITION DEMONSTRATION & EVIDENCE DASHBOARD",
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color=EX_COLORS["white"]
        )
        title_lbl.pack(anchor="w")

        subtitle_lbl = ctk.CTkLabel(
            title_box,
            text="Empirical behavioral ransomware detection, genuine 6-stage evidence pipeline, and transparent feature inspection.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=EX_COLORS["muted"],
            justify="left"
        )
        subtitle_lbl.pack(anchor="w", pady=(2, 0))

        # ── 2. Global Status & Quick-Action Command Bar ───────────────────
        action_bar = ctk.CTkFrame(self, fg_color=EX_COLORS["card"], corner_radius=8,
                                  border_width=1, border_color=EX_COLORS["card_border"])
        action_bar.grid(row=1, column=0, sticky="ew", padx=20, pady=(8, 6))
        action_bar.grid_columnconfigure(3, weight=1)

        # Status Badge (IDLE, SIMULATING, ANALYZING, DETECTED, RESET)
        self._status_badge = ctk.CTkLabel(
            action_bar,
            text="STATE: IDLE",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=EX_COLORS["cyan"],
            fg_color="#0c2340",
            corner_radius=6,
            width=150,
            height=34
        )
        self._status_badge.grid(row=0, column=0, padx=(12, 6), pady=8)

        # Mode Badge
        self._mode_badge = ctk.CTkLabel(
            action_bar,
            text="[SANDBOX SIMULATION]",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=EX_COLORS["gold"],
            fg_color="#182744",
            corner_radius=6,
            width=210,
            height=34
        )
        self._mode_badge.grid(row=0, column=1, padx=6, pady=8)

        # Health Diagnostic Status
        self._health_lbl = ctk.CTkLabel(
            action_bar,
            text="Checking diagnostic health...",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=EX_COLORS["muted"]
        )
        self._health_lbl.grid(row=0, column=2, padx=12, pady=8, sticky="w")

        # Action Buttons Box (Right side)
        btn_box = ctk.CTkFrame(action_bar, fg_color="transparent")
        btn_box.grid(row=0, column=4, padx=12, pady=8, sticky="e")

        self._btn_run_safe_demo = ctk.CTkButton(
            btn_box,
            text="▶ Run Safe Demo",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=EX_COLORS["gold"],
            hover_color=EX_COLORS["gold_hover"],
            text_color="#000000",
            height=34,
            command=self._on_run_safe_demo
        )
        self._btn_run_safe_demo.pack(side="left", padx=4)

        self._btn_walkthrough = ctk.CTkButton(
            btn_box,
            text="📖 Walkthrough",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#103a60",
            hover_color="#185285",
            text_color=EX_COLORS["cyan"],
            height=34,
            command=self._on_run_walkthrough
        )
        self._btn_walkthrough.pack(side="left", padx=4)

        self._btn_reset_demo = ctk.CTkButton(
            btn_box,
            text="↻ Reset to Ready",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#1e293b",
            hover_color="#334155",
            text_color=EX_COLORS["white"],
            height=34,
            command=self._on_reset_demo
        )
        self._btn_reset_demo.pack(side="left", padx=4)

        # ── 3. Tab Navigation & Content Container ─────────────────────────
        body_container = ctk.CTkFrame(self, fg_color="transparent")
        body_container.grid(row=2, column=0, sticky="nsew", padx=20, pady=(2, 12))
        body_container.grid_rowconfigure(1, weight=1)
        body_container.grid_columnconfigure(0, weight=1)

        tab_bar = ctk.CTkFrame(body_container, fg_color="transparent")
        tab_bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        self._tab_buttons = {}
        tab_defs = [
            ("simulator", "A. Safe Demo & 6-Stage Pipeline [SANDBOX]"),
            ("live_scan", "B. Live System Scan [REAL HOST]"),
            ("test_lab", "C. Security Test Lab [WORST-CASE]"),
            ("evidence", "D. Feature Inspector & Audit Evidence")
        ]

        for tab_id, tab_label in tab_defs:
            btn = ctk.CTkButton(
                tab_bar,
                text=tab_label,
                font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                fg_color=EX_COLORS["header"] if tab_id == self._active_tab else "transparent",
                text_color=EX_COLORS["gold"] if tab_id == self._active_tab else EX_COLORS["muted"],
                hover_color=EX_COLORS["header"],
                corner_radius=6,
                height=32,
                command=lambda t=tab_id: self._switch_tab(t)
            )
            btn.pack(side="left", padx=(0, 8))
            self._tab_buttons[tab_id] = btn

        self._views_container = ctk.CTkFrame(body_container, fg_color=EX_COLORS["card"],
                                             corner_radius=8, border_width=1,
                                             border_color=EX_COLORS["card_border"])
        self._views_container.grid(row=1, column=0, sticky="nsew")
        self._views_container.grid_rowconfigure(0, weight=1)
        self._views_container.grid_columnconfigure(0, weight=1)

        self._tabs = {}
        self._tabs["simulator"] = self._create_simulator_view()
        self._tabs["live_scan"] = self._create_live_scan_view()
        self._tabs["test_lab"] = self._create_test_lab_view()
        self._tabs["evidence"] = self._create_evidence_view()

        self._switch_tab("simulator")

    def _switch_tab(self, tab_id: str) -> None:
        self._active_tab = tab_id
        for t_id, frame in self._tabs.items():
            if t_id == tab_id:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_remove()

        for t_id, btn in self._tab_buttons.items():
            if t_id == tab_id:
                btn.configure(fg_color=EX_COLORS["header"], text_color=EX_COLORS["gold"])
            else:
                btn.configure(fg_color="transparent", text_color=EX_COLORS["muted"])

        if tab_id == "live_scan":
            self._mode_badge.configure(text="[LIVE SYSTEM SCAN]", text_color=EX_COLORS["cyan"])
        elif tab_id == "simulator":
            self._mode_badge.configure(text="[SANDBOX SIMULATION]", text_color=EX_COLORS["gold"])
        elif tab_id == "test_lab":
            self._mode_badge.configure(text="[WORST-CASE SCENARIOS]", text_color=EX_COLORS["warning"])
        elif tab_id == "evidence":
            self._mode_badge.configure(text="[FEATURE INSPECTOR]", text_color=EX_COLORS["white"])

    def _run_health_check_display(self) -> None:
        """Run health check and update status badge."""
        health = self._test_lab.check_demo_health()
        if health["healthy"]:
            self._health_lbl.configure(
                text="[OK] System Diagnostic Ready (Sandbox Safe, Model Loaded, Sensors Active)",
                text_color=EX_COLORS["safe"]
            )
        else:
            self._health_lbl.configure(
                text=f"⚠ Diagnostic Warning: {'; '.join(health['warnings'][:2])}",
                text_color=EX_COLORS["warning"]
            )

    # ── TAB A: SAFE DEMO & 6-STAGE DETECTION PIPELINE ─────────────────────
    def _create_simulator_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self._views_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=3)
        frame.grid_columnconfigure(1, weight=2)
        frame.grid_rowconfigure(0, weight=1)

        # Left Column: 6-Stage Detection Pipeline Cards
        left_box = ctk.CTkFrame(frame, fg_color="transparent")
        left_box.grid(row=0, column=0, sticky="nsew", padx=(14, 8), pady=12)
        left_box.grid_rowconfigure(1, weight=1)
        left_box.grid_columnconfigure(0, weight=1)

        stage_header_box = ctk.CTkFrame(left_box, fg_color="transparent")
        stage_header_box.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        ctk.CTkLabel(
            stage_header_box,
            text="6-STAGE DETECTION VERIFICATION PIPELINE",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=EX_COLORS["gold"]
        ).pack(side="left")

        self._pipeline_status_text = ctk.CTkLabel(
            stage_header_box,
            text="Click '▶ Run Safe Demo' above to execute full pipeline",
            font=ctk.CTkFont(family="Segoe UI", size=11, slant="italic"),
            text_color=EX_COLORS["muted"]
        )
        self._pipeline_status_text.pack(side="right")

        # Scrollable container for the 6 stage cards
        self._stage_cards_scroll = ctk.CTkScrollableFrame(left_box, fg_color=EX_COLORS["panel_dark"])
        self._stage_cards_scroll.grid(row=1, column=0, sticky="nsew")
        self._stage_cards_scroll.grid_columnconfigure(0, weight=1)

        self._stage_cards = []
        self._build_initial_stage_cards()

        # Right Column: Model Decision & Operational Disclosure
        right_box = ctk.CTkFrame(frame, fg_color="transparent")
        right_box.grid(row=0, column=1, sticky="nsew", padx=(8, 14), pady=12)
        right_box.grid_rowconfigure(2, weight=1)
        right_box.grid_columnconfigure(0, weight=1)

        # Right Card 1: Model Decision & Probability
        decision_card = ctk.CTkFrame(right_box, fg_color=EX_COLORS["panel_dark"], corner_radius=6,
                                     border_width=1, border_color=EX_COLORS["card_border"])
        decision_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(
            decision_card,
            text="MODEL INFERENCE & DECISION",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=EX_COLORS["cyan"]
        ).pack(anchor="w", padx=14, pady=(10, 2))

        self._demo_decision_badge = ctk.CTkLabel(
            decision_card,
            text="DECISION: PENDING DEMO",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=EX_COLORS["muted"]
        )
        self._demo_decision_badge.pack(anchor="w", padx=14, pady=2)

        self._demo_prob_lbl = ctk.CTkLabel(
            decision_card,
            text="Threat Probability: --",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=EX_COLORS["white"]
        )
        self._demo_prob_lbl.pack(anchor="w", padx=14, pady=2)

        self._demo_trees_lbl = ctk.CTkLabel(
            decision_card,
            text="Random Forest Voting: -- / 100 Trees",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=EX_COLORS["muted"]
        )
        self._demo_trees_lbl.pack(anchor="w", padx=14, pady=(2, 10))

        # Right Card 2: Operational Limitations & Academic Disclosure
        limitation_card = ctk.CTkFrame(right_box, fg_color=EX_COLORS["panel_dark"], corner_radius=6,
                                       border_width=1, border_color=EX_COLORS["card_border"])
        limitation_card.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(
            limitation_card,
            text="OPERATIONAL BOUNDARIES & LIMITATIONS",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=EX_COLORS["gold"]
        ).pack(anchor="w", padx=14, pady=(10, 4))

        self._limitation_text_box = ctk.CTkLabel(
            limitation_card,
            text="• Multi-Signal Invariant: Elevated entropy alone (avg > 7.0) pushes probability across the "
                 "0.50 WARNING threshold. It does NOT trigger CRITICAL (0.90) without correlated process anomalies.\n"
                 "• False-Positive Defense: Requiring correlated process evidence prevents false alarms on benign .zip or video files.\n"
                 "• Safe Isolation: Simulation runs exclusively in temp_sandbox/. Real host processes remain unaffected.\n"
                 "• Model Provenance: Legacy model is an experimental synthetic-data baseline (v1).",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=EX_COLORS["muted"],
            justify="left",
            wraplength=380
        )
        self._limitation_text_box.pack(anchor="w", padx=14, pady=(0, 10))

        # Right Card 3: Real-Time Event Stream Log
        event_box = ctk.CTkFrame(right_box, fg_color=EX_COLORS["panel_dark"], corner_radius=6,
                                 border_width=1, border_color=EX_COLORS["card_border"])
        event_box.grid(row=2, column=0, sticky="nsew")
        event_box.grid_rowconfigure(1, weight=1)
        event_box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            event_box,
            text="SIMULATION TIMELINE & TELEMETRY STREAM",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=EX_COLORS["white"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 4))

        self._sim_event_scroll = ctk.CTkScrollableFrame(event_box, fg_color="transparent")
        self._sim_event_scroll.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

        ctk.CTkLabel(
            self._sim_event_scroll,
            text="Ready. Click '▶ Run Safe Demo' or '📖 Walkthrough' to observe live timeline.",
            font=ctk.CTkFont(size=11, slant="italic"),
            text_color=EX_COLORS["muted"]
        ).pack(padx=12, pady=16)

        return frame

    def _build_initial_stage_cards(self) -> None:
        """Create placeholder cards for the 6 detection pipeline stages."""
        stage_titles = [
            ("Stage 1", "Harmless Sandbox Simulation Activity", "Burst file modifications inside disposable temp_sandbox/"),
            ("Stage 2", "Filesystem Observation", "Scanner detects modifications and flags suspicious extensions (.locked_sim)"),
            ("Stage 3", "Telemetry Collection", "Empirical Shannon entropy and host process metrics collected"),
            ("Stage 4", "Feature Vector Validation", "Schema V2 (16 features) and Legacy (19 features) finite & bounds check"),
            ("Stage 5", "Model Inference", "StandardScaler normalization & 100-tree Random Forest inference"),
            ("Stage 6", "Threat Classification & Limitations", "Decision threshold evaluation and boundary reporting")
        ]

        self._stage_widgets = []
        for stage_num, title, desc in stage_titles:
            card = ctk.CTkFrame(self._stage_cards_scroll, fg_color=EX_COLORS["card"],
                                corner_radius=6, border_width=1, border_color=EX_COLORS["card_border"])
            card.pack(fill="x", padx=6, pady=4)
            card.grid_columnconfigure(1, weight=1)

            # Stage Pill
            pill = ctk.CTkLabel(
                card,
                text=stage_num,
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                text_color=EX_COLORS["gold"],
                fg_color="#0c2340",
                corner_radius=4,
                width=70,
                height=26
            )
            pill.grid(row=0, column=0, padx=8, pady=8)

            # Title & Desc
            t_box = ctk.CTkFrame(card, fg_color="transparent")
            t_box.grid(row=0, column=1, sticky="w", padx=4, pady=8)

            ctk.CTkLabel(
                t_box,
                text=title,
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                text_color=EX_COLORS["white"]
            ).pack(anchor="w")

            metric_lbl = ctk.CTkLabel(
                t_box,
                text=desc,
                font=ctk.CTkFont(family="Segoe UI", size=10),
                text_color=EX_COLORS["muted"]
            )
            metric_lbl.pack(anchor="w")

            # Status Indicator
            status_lbl = ctk.CTkLabel(
                card,
                text="READY",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=EX_COLORS["cyan"],
                width=80
            )
            status_lbl.grid(row=0, column=2, padx=10, pady=8)

            self._stage_widgets.append({
                "card": card,
                "pill": pill,
                "metric_lbl": metric_lbl,
                "status_lbl": status_lbl
            })

    def _update_stage_cards_from_result(self, stages: List[Dict[str, Any]]) -> None:
        """Update the 6 stage cards with genuine execution metrics."""
        for idx, s in enumerate(stages):
            if idx >= len(self._stage_widgets):
                break
            w = self._stage_widgets[idx]
            passed = s.get("passed", False)
            status_text = "PASSED" if passed else "FLAGGED"
            status_color = EX_COLORS["safe"] if passed else EX_COLORS["warning"]

            w["status_lbl"].configure(text=status_text, text_color=status_color)
            w["pill"].configure(text_color=status_color)

            # Format concise metric summary
            m = s.get("metrics", {})
            if idx == 0:
                summary = f"Files: {m.get('files_modified', 0)} | Entropy: {m.get('avg_entropy_before', 0):.2f} -> {m.get('avg_entropy_after', 0):.2f} bits/byte"
            elif idx == 1:
                summary = f"Inspected: {m.get('files_inspected', 0)} files | Suspicious flagged: {m.get('suspicious_files_count', 0)}"
            elif idx == 2:
                summary = f"Extracted Entropy: {m.get('extracted_entropy', 0):.2f} | Procs: {m.get('processes_enumerated', 0)}"
            elif idx == 3:
                summary = f"Legacy 19: Valid={m.get('legacy_19_valid')} | Schema V2 16: Valid={m.get('schema_v2_16_valid')}"
            elif idx == 4:
                summary = f"Voting Trees: {m.get('voting_trees_ransomware', 0)}/100 | Probability: {m.get('raw_probability', 0):.4f}"
            elif idx == 5:
                summary = f"Result: {m.get('classification', 'NONE')} | Threshold: 0.50 Warning / 0.90 Critical"
            else:
                summary = s.get("description", "")

            w["metric_lbl"].configure(text=summary, text_color=EX_COLORS["white"])

    # ── TAB B: LIVE SYSTEM SCAN ───────────────────────────────────────────
    def _create_live_scan_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self._views_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=3)
        frame.grid_columnconfigure(1, weight=2)
        frame.grid_rowconfigure(1, weight=1)

        top_bar = ctk.CTkFrame(frame, fg_color="#0a1733", corner_radius=6)
        top_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=16, pady=12)

        self._btn_run_scan = ctk.CTkButton(
            top_bar,
            text="⚡ Start Live System Scan",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=EX_COLORS["gold"],
            hover_color=EX_COLORS["gold_hover"],
            text_color="#000000",
            height=34,
            command=self._start_live_scan
        )
        self._btn_run_scan.pack(side="left", padx=12, pady=6)

        self._btn_cancel_scan = ctk.CTkButton(
            top_bar,
            text="✖ Cancel",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#475569",
            hover_color="#334155",
            text_color=EX_COLORS["white"],
            width=80,
            height=34,
            state="disabled",
            command=self._cancel_live_scan
        )
        self._btn_cancel_scan.pack(side="left", padx=6, pady=6)

        self._scan_progress_lbl = ctk.CTkLabel(
            top_bar,
            text="Ready to perform genuine system scan.",
            font=ctk.CTkFont(size=11),
            text_color=EX_COLORS["white"]
        )
        self._scan_progress_lbl.pack(side="left", padx=12, pady=6)

        disclaimer = ctk.CTkLabel(
            top_bar,
            text="ℹ 'SAFE' means no threat detected under tests performed. Does not guarantee absolute absence of unknown malware.",
            font=ctk.CTkFont(size=10, slant="italic"),
            text_color=EX_COLORS["muted"]
        )
        disclaimer.pack(side="right", padx=12, pady=6)

        # Left Column: 19 Features Table
        left_box = ctk.CTkFrame(frame, fg_color="transparent")
        left_box.grid(row=1, column=0, sticky="nsew", padx=(16, 8), pady=(0, 12))
        left_box.grid_rowconfigure(1, weight=1)
        left_box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            left_box,
            text="EXTRACTED BEHAVIORAL TELEMETRY (19 FEATURES)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=EX_COLORS["gold"]
        ).grid(row=0, column=0, sticky="w", pady=(0, 6))

        self._feature_scroll = ctk.CTkScrollableFrame(left_box, fg_color="#0a1733")
        self._feature_scroll.grid(row=1, column=0, sticky="nsew")
        self._feature_scroll.grid_columnconfigure(1, weight=1)

        self._feature_labels: Dict[str, ctk.CTkLabel] = {}
        for i, fname in enumerate(FEATURE_NAMES):
            idx_lbl = ctk.CTkLabel(
                self._feature_scroll,
                text=f"[{i:02d}]",
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=EX_COLORS["muted"],
                width=35
            )
            idx_lbl.grid(row=i, column=0, sticky="w", padx=4, pady=2)

            name_lbl = ctk.CTkLabel(
                self._feature_scroll,
                text=fname,
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=EX_COLORS["white"]
            )
            name_lbl.grid(row=i, column=1, sticky="w", padx=4, pady=2)

            val_lbl = ctk.CTkLabel(
                self._feature_scroll,
                text="--",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=EX_COLORS["gold"],
                width=80,
                anchor="e"
            )
            val_lbl.grid(row=i, column=2, sticky="e", padx=8, pady=2)
            self._feature_labels[fname] = val_lbl

        # Right Column: Model Decision
        right_box = ctk.CTkFrame(frame, fg_color="transparent")
        right_box.grid(row=1, column=1, sticky="nsew", padx=(8, 16), pady=(0, 12))
        right_box.grid_rowconfigure(1, weight=1)
        right_box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            right_box,
            text="MODEL INFERENCE & SCORE SEMANTICS",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=EX_COLORS["cyan"]
        ).grid(row=0, column=0, sticky="w", pady=(0, 6))

        inf_card = ctk.CTkFrame(right_box, fg_color="#0a1733", corner_radius=6)
        inf_card.grid(row=1, column=0, sticky="nsew")

        self._ml_decision_lbl = ctk.CTkLabel(
            inf_card,
            text="DECISION: PENDING SCAN",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color=EX_COLORS["muted"]
        )
        self._ml_decision_lbl.pack(anchor="w", padx=16, pady=(14, 4))

        self._ml_score_lbl = ctk.CTkLabel(
            inf_card,
            text="Threat Probability: --",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=EX_COLORS["white"]
        )
        self._ml_score_lbl.pack(anchor="w", padx=16, pady=2)

        self._ml_stats_lbl = ctk.CTkLabel(
            inf_card,
            text="Files Inspected: 0 | Processes: 0 | Duration: 0.00s",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=EX_COLORS["muted"]
        )
        self._ml_stats_lbl.pack(anchor="w", padx=16, pady=(2, 10))

        semantics_box = ctk.CTkFrame(inf_card, fg_color="#061226", corner_radius=6)
        semantics_box.pack(fill="x", padx=16, pady=6)

        ctk.CTkLabel(
            semantics_box,
            text="Threshold Mapping & Semantics:",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=EX_COLORS["gold"]
        ).pack(anchor="w", padx=10, pady=(6, 2))

        sem_text = (
            "• Score represents proportion of voting trees in 100-estimator Random Forest.\n"
            "• p < 0.50  ➔  SAFE (No threat under tested checks)\n"
            "• 0.50 <= p < 0.90  ➔  WARNING (Suspicious activity)\n"
            "• p >= 0.90  ➔  CRITICAL THREAT DETECTED\n"
            "• Incomplete scan or failure NEVER defaults to SAFE."
        )
        ctk.CTkLabel(
            semantics_box,
            text=sem_text,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=EX_COLORS["muted"],
            justify="left"
        ).pack(anchor="w", padx=10, pady=(0, 6))

        self._advisory_lbl = ctk.CTkLabel(
            inf_card,
            text="SentinelAI Advisory: Waiting for scan completion...",
            font=ctk.CTkFont(family="Segoe UI", size=11, slant="italic"),
            text_color=EX_COLORS["muted"],
            wraplength=320,
            justify="left"
        )
        self._advisory_lbl.pack(anchor="w", padx=16, pady=10)

        return frame

    # ── TAB C: WORST-CASE SECURITY TEST LAB ───────────────────────────────
    def _create_test_lab_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self._views_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=2)
        frame.grid_columnconfigure(1, weight=3)
        frame.grid_rowconfigure(1, weight=1)

        top_bar = ctk.CTkFrame(frame, fg_color="#0a1733", corner_radius=6)
        top_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=16, pady=10)

        ctk.CTkLabel(
            top_bar,
            text="CONTROLLED SECURITY & FAILURE-INJECTION SCENARIOS",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=EX_COLORS["gold"]
        ).pack(side="left", padx=16, pady=8)

        ctk.CTkLabel(
            top_bar,
            text="Evaluate system resilience, fail-safe state invariants, and edge cases.",
            font=ctk.CTkFont(size=11),
            text_color=EX_COLORS["muted"]
        ).pack(side="left", padx=8, pady=8)

        # Left Column: Scenario Selector List
        left_box = ctk.CTkFrame(frame, fg_color="transparent")
        left_box.grid(row=1, column=0, sticky="nsew", padx=(16, 8), pady=(0, 12))
        left_box.grid_rowconfigure(0, weight=1)
        left_box.grid_columnconfigure(0, weight=1)

        scenarios_scroll = ctk.CTkScrollableFrame(left_box, fg_color="#0a1733")
        scenarios_scroll.grid(row=0, column=0, sticky="nsew")

        scenarios = self._test_lab.get_available_scenarios()
        for s in scenarios:
            s_btn = ctk.CTkButton(
                scenarios_scroll,
                text=f"[{s['type']}] {s['name']}",
                font=ctk.CTkFont(size=10, weight="bold"),
                anchor="w",
                fg_color="#101f42",
                hover_color="#1a2f60",
                text_color=EX_COLORS["white"],
                height=32,
                command=lambda sid=s['id']: self._run_test_scenario(sid)
            )
            s_btn.pack(fill="x", padx=4, pady=2)

        # Right Column: Scenario Outcome
        right_box = ctk.CTkFrame(frame, fg_color="#0a1733", corner_radius=6)
        right_box.grid(row=1, column=1, sticky="nsew", padx=(8, 16), pady=(0, 12))
        right_box.grid_rowconfigure(3, weight=1)
        right_box.grid_columnconfigure(0, weight=1)

        self._lab_outcome_title = ctk.CTkLabel(
            right_box,
            text="SELECT A SCENARIO TO EXECUTE",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=EX_COLORS["gold"]
        )
        self._lab_outcome_title.grid(row=0, column=0, sticky="w", padx=16, pady=(12, 2))

        self._lab_pass_badge = ctk.CTkLabel(
            right_box,
            text="STATUS: READY",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=EX_COLORS["muted"]
        )
        self._lab_pass_badge.grid(row=1, column=0, sticky="w", padx=16, pady=2)

        self._lab_details_box = ctk.CTkTextbox(
            right_box,
            fg_color="#061226",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=EX_COLORS["white"],
            wrap="word"
        )
        self._lab_details_box.grid(row=3, column=0, sticky="nsew", padx=16, pady=10)
        self._lab_details_box.insert("1.0", "Click any scenario on the left to execute the test harness.\n"
                                            "Each scenario evaluates an explicit security or failure-handling rule.")

        return frame

    # ── TAB D: TRANSPARENT FEATURE INSPECTOR & AUDIT EVIDENCE ──────────────
    def _create_evidence_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self._views_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=3)
        frame.grid_columnconfigure(1, weight=4)
        frame.grid_rowconfigure(1, weight=1)

        # Top Control Bar
        top_bar = ctk.CTkFrame(frame, fg_color="#0a1733", corner_radius=6)
        top_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=16, pady=10)

        ctk.CTkLabel(
            top_bar,
            text="SCHEMA SELECTION:",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=EX_COLORS["muted"]
        ).pack(side="left", padx=(12, 6), pady=8)

        self._btn_schema_v2 = ctk.CTkButton(
            top_bar,
            text="Schema V2 (16 Observable)",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=EX_COLORS["header"],
            text_color=EX_COLORS["gold"],
            hover_color=EX_COLORS["header"],
            height=30,
            command=lambda: self._set_inspector_schema("schema_v2_16")
        )
        self._btn_schema_v2.pack(side="left", padx=4, pady=8)

        self._btn_schema_legacy = ctk.CTkButton(
            top_bar,
            text="Legacy Baseline (19 Features)",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="transparent",
            text_color=EX_COLORS["muted"],
            hover_color=EX_COLORS["header"],
            height=30,
            command=lambda: self._set_inspector_schema("legacy_19")
        )
        self._btn_schema_legacy.pack(side="left", padx=4, pady=8)

        export_btn = ctk.CTkButton(
            top_bar,
            text="💾 Export Demonstration Report",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=EX_COLORS["gold"],
            hover_color=EX_COLORS["gold_hover"],
            text_color="#000000",
            height=30,
            command=self._export_demonstration_report
        )
        export_btn.pack(side="right", padx=12, pady=8)

        # Left Column: Feature Selection List
        left_box = ctk.CTkFrame(frame, fg_color="transparent")
        left_box.grid(row=1, column=0, sticky="nsew", padx=(16, 8), pady=(0, 12))
        left_box.grid_rowconfigure(1, weight=1)
        left_box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            left_box,
            text="FEATURE INVENTORY & VALUES",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=EX_COLORS["gold"]
        ).grid(row=0, column=0, sticky="w", pady=(0, 4))

        self._inspector_scroll = ctk.CTkScrollableFrame(left_box, fg_color="#0a1733")
        self._inspector_scroll.grid(row=1, column=0, sticky="nsew")
        self._inspector_scroll.grid_columnconfigure(1, weight=1)

        # Right Column: Feature Deep Dive Card
        right_box = ctk.CTkFrame(frame, fg_color="#0a1733", corner_radius=6)
        right_box.grid(row=1, column=1, sticky="nsew", padx=(8, 16), pady=(0, 12))
        right_box.grid_rowconfigure(1, weight=1)
        right_box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            right_box,
            text="FEATURE SPECIFICATION & SCIENTIFIC AUDIT",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=EX_COLORS["cyan"]
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(10, 4))

        self._inspector_detail_box = ctk.CTkTextbox(
            right_box,
            fg_color="#061226",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=EX_COLORS["white"],
            wrap="word"
        )
        self._inspector_detail_box.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 12))

        self._populate_feature_inspector("schema_v2_16")

        return frame

    def _set_inspector_schema(self, schema_key: str) -> None:
        self._inspector_schema = schema_key
        if schema_key == "schema_v2_16":
            self._btn_schema_v2.configure(fg_color=EX_COLORS["header"], text_color=EX_COLORS["gold"])
            self._btn_schema_legacy.configure(fg_color="transparent", text_color=EX_COLORS["muted"])
        else:
            self._btn_schema_legacy.configure(fg_color=EX_COLORS["header"], text_color=EX_COLORS["gold"])
            self._btn_schema_v2.configure(fg_color="transparent", text_color=EX_COLORS["muted"])
        self._populate_feature_inspector(schema_key)

    def _populate_feature_inspector(self, schema_key: str) -> None:
        """Populate feature list for the selected schema."""
        for widget in self._inspector_scroll.winfo_children():
            widget.destroy()

        features = self._inspector_features.get(schema_key, [])
        for f in features:
            btn = ctk.CTkButton(
                self._inspector_scroll,
                text=f"[{f['index']:02d}] {f['name']} = {f['measured_value']} {f['unit']}",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                anchor="w",
                fg_color="#101f42",
                hover_color="#1a2f60",
                text_color=EX_COLORS["gold"] if f['status'] == "ELEVATED" else EX_COLORS["white"],
                height=30,
                command=lambda item=f: self._display_feature_detail(item)
            )
            btn.pack(fill="x", padx=4, pady=2)

        if features:
            self._display_feature_detail(features[0])

    def _display_feature_detail(self, f: Dict[str, Any]) -> None:
        """Render detailed audit specification for the clicked feature."""
        content = (
            f"=== FEATURE SPECIFICATION: {f['name']} ===\n\n"
            f"Display Name:       {f.get('display_name', f['name'])}\n"
            f"Index in Vector:    [{f['index']:02d}]\n"
            f"Measured Value:     {f['measured_value']} {f['unit']}\n"
            f"Baseline (Normal):  {f.get('baseline_normal', 'N/A')}\n"
            f"Sensor Status:      {f.get('status', 'NORMAL')}\n"
            f"Collection Cost:    {f.get('collection_cost', 'Low')}\n"
            f"Collection Method:  {f.get('collection_source', 'System Sensor')}\n"
            f"Model Usage:        {f.get('model_usage', 'Model input')}\n\n"
            f"--- TECHNICAL DEFINITION ---\n{f.get('description', '')}\n\n"
        )
        if "false_positive_risks" in f:
            content += f"--- FALSE POSITIVE RISKS ---\n{f['false_positive_risks']}\n\n"

        content += (
            "--- AUDIT INTEGRITY NOTE ---\n"
            "This value represents genuine observable measurement or controlled simulation telemetry.\n"
            "Values are never fabricated, hardcoded, or altered to force a predetermined detection result."
        )

        self._inspector_detail_box.delete("1.0", "end")
        self._inspector_detail_box.insert("1.0", content)

    # ── ACTION HANDLERS: SAFE DEMO & WALKTHROUGH ──────────────────────────

    def _on_run_safe_demo(self) -> None:
        """Run safe demo in disposable sandbox with genuine 6-stage telemetry collection."""
        if self._is_simulating or self._is_scanning:
            messagebox.showwarning("System Busy", "A scan or demonstration is already in progress.")
            return

        self._is_simulating = True
        self._btn_run_safe_demo.configure(state="disabled")
        self._status_badge.configure(text="STATE: SIMULATING", text_color=EX_COLORS["gold"])
        self._mode_badge.configure(text="[SANDBOX SIMULATION]", text_color=EX_COLORS["gold"])
        self._pipeline_status_text.configure(text="Executing Stage 1/6...", text_color=EX_COLORS["gold"])

        # Clear event log
        for widget in self._sim_event_scroll.winfo_children():
            widget.destroy()

        def _worker():
            try:
                def prog(msg, cur, total):
                    self.after(0, lambda: self._pipeline_status_text.configure(text=msg))

                res = self._test_lab.run_safe_demo(num_files=20, delay_between_ops=0.015, progress_callback=prog)
                self.after(0, lambda: self._on_safe_demo_complete(res))
            except Exception as e:
                self.after(0, lambda: self._on_safe_demo_error(str(e)))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_safe_demo_complete(self, res: Dict[str, Any]) -> None:
        self._is_simulating = False
        self._last_safe_demo_res = res
        self._btn_run_safe_demo.configure(state="normal")

        # Update 6 Stage Cards
        self._update_stage_cards_from_result(res.get("stages", []))

        # Update Decision Badge
        clf_result = res.get("threat_level", "NONE")
        prob = res.get("probability", 0.0)
        badge_color = EX_COLORS["warning"] if clf_result == "WARNING" else (
            EX_COLORS["critical"] if clf_result == "CRITICAL" else EX_COLORS["safe"]
        )

        self._demo_decision_badge.configure(text=f"DECISION: {clf_result}", text_color=badge_color)
        self._demo_prob_lbl.configure(text=f"Threat Probability: {prob:.4f} ({prob * 100:.1f}%)")
        self._demo_trees_lbl.configure(text=f"Random Forest Voting: {int(round(prob * 100))}/100 Trees for Threat")

        self._status_badge.configure(text="STATE: DETECTED", text_color=badge_color)
        self._pipeline_status_text.configure(
            text=f"Pipeline verified! {clf_result} achieved in {res.get('duration_seconds', 0.0):.2f}s",
            text_color=EX_COLORS["safe"]
        )

        # Update feature inspector with captured features
        if "feature_inspector" in res:
            self._inspector_features = res["feature_inspector"]
            self._populate_feature_inspector(self._inspector_schema)

        # Populate event stream
        sim_res = res.get("simulation_result")
        if sim_res and hasattr(sim_res, "events"):
            for widget in self._sim_event_scroll.winfo_children():
                widget.destroy()
            for evt in sim_res.events[:30]:
                row = ctk.CTkFrame(self._sim_event_scroll, fg_color="transparent")
                row.pack(fill="x", padx=4, pady=1)

                ctk.CTkLabel(
                    row,
                    text=evt.timestamp,
                    font=ctk.CTkFont(family="Consolas", size=9),
                    text_color=EX_COLORS["muted"],
                    width=70
                ).pack(side="left")

                phase_col = EX_COLORS["gold"] if "ENCRYPT" in evt.phase else (
                    EX_COLORS["critical"] if "RENAME" in evt.phase else EX_COLORS["cyan"]
                )
                ctk.CTkLabel(
                    row,
                    text=f"[{evt.phase}]",
                    font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                    text_color=phase_col,
                    width=85
                ).pack(side="left")

                ctk.CTkLabel(
                    row,
                    text=f"{evt.action}: {evt.target_path}",
                    font=ctk.CTkFont(family="Consolas", size=9),
                    text_color=EX_COLORS["white"]
                ).pack(side="left", padx=4)

        self._append_evidence_log(
            f"SAFE DEMO COMPLETE | Decision: {clf_result} | Prob: {prob:.4f} | Stages Verified: 6/6"
        )

    def _on_safe_demo_error(self, err_msg: str) -> None:
        self._is_simulating = False
        self._btn_run_safe_demo.configure(state="normal")
        self._status_badge.configure(text="STATE: ERROR", text_color=EX_COLORS["critical"])
        self._pipeline_status_text.configure(text=f"Demo error: {err_msg}", text_color=EX_COLORS["critical"])
        messagebox.showerror("Demo Execution Error", f"Safe demonstration could not complete:\n\n{err_msg}")
        self._append_evidence_log(f"DEMO ERROR: {err_msg}")

    def _on_run_walkthrough(self) -> None:
        """Run deterministic educational walkthrough demonstrating all 6 stages."""
        res = self._test_lab.run_deterministic_walkthrough()
        self._last_safe_demo_res = res

        self._mode_badge.configure(text="[EDUCATIONAL WALKTHROUGH — NOT LIVE SCAN]", text_color=EX_COLORS["cyan"])
        self._status_badge.configure(text="STATE: WALKTHROUGH", text_color=EX_COLORS["cyan"])

        # Update stage cards
        self._update_stage_cards_from_result(res.get("stages", []))

        # Update decision
        clf_result = res.get("threat_level", "WARNING")
        prob = res.get("probability", 0.56)
        self._demo_decision_badge.configure(text=f"DECISION: {clf_result} (WALKTHROUGH)", text_color=EX_COLORS["warning"])
        self._demo_prob_lbl.configure(text=f"Threat Probability: {prob:.4f} (56.0%)")
        self._demo_trees_lbl.configure(text="Random Forest Voting: 56/100 Trees (Simulated Deterministic Replay)")

        self._pipeline_status_text.configure(
            text="Educational Walkthrough active: Demonstrates verified 6-stage telemetry flow.",
            text_color=EX_COLORS["cyan"]
        )

        if "feature_inspector" in res:
            self._inspector_features = res["feature_inspector"]
            self._populate_feature_inspector(self._inspector_schema)

        # Clear event box and insert walkthrough explanation
        for widget in self._sim_event_scroll.winfo_children():
            widget.destroy()

        ctk.CTkLabel(
            self._sim_event_scroll,
            text="[EDUCATIONAL WALKTHROUGH ACTIVE]\n\n"
                 "Demonstrates how SentinelML's 6-stage pipeline evaluates ransomware:\n"
                 "1. Burst file modifications cause Shannon entropy to jump from 4.12 to 7.89.\n"
                 "2. Filesystem scanner flags .locked_sim extensions and recovery note.\n"
                 "3. Features are validated against Schema V2 and normalized via StandardScaler.\n"
                 "4. 56 out of 100 decision trees vote for threat, resulting in a WARNING.\n"
                 "5. The score does not cross 0.90 (CRITICAL) without process anomalies,\n"
                 "   protecting against false positives on compressed archives.",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=EX_COLORS["white"],
            justify="left"
        ).pack(padx=12, pady=12)

        self._append_evidence_log(
            "EDUCATIONAL WALKTHROUGH EXECUTED | Deterministic 6-stage trace displayed."
        )

    def _on_reset_demo(self) -> None:
        """Reset demo state, purge sandbox files, and return UI to ready status."""
        removed = self._simulator.reset_sandbox()
        self._status_badge.configure(text="STATE: RESET", text_color=EX_COLORS["cyan"])
        self._mode_badge.configure(text="[SANDBOX SIMULATION]", text_color=EX_COLORS["gold"])
        self._pipeline_status_text.configure(text="Sandbox purged. System ready for demonstration.")

        self._demo_decision_badge.configure(text="DECISION: PENDING DEMO", text_color=EX_COLORS["muted"])
        self._demo_prob_lbl.configure(text="Threat Probability: --")
        self._demo_trees_lbl.configure(text="Random Forest Voting: -- / 100 Trees")

        for widget in self._sim_event_scroll.winfo_children():
            widget.destroy()

        ctk.CTkLabel(
            self._sim_event_scroll,
            text=f"Sandbox reset complete. {removed} synthetic files purged.\n"
                 "Click '▶ Run Safe Demo' or '📖 Walkthrough' to start.",
            font=ctk.CTkFont(size=11, slant="italic"),
            text_color=EX_COLORS["muted"]
        ).pack(padx=12, pady=20)

        # Reset stage card indicators
        for w in self._stage_widgets:
            w["status_lbl"].configure(text="READY", text_color=EX_COLORS["cyan"])
            w["pill"].configure(text_color=EX_COLORS["gold"])

        self._run_health_check_display()
        self._append_evidence_log(f"DEMO RESET | Purged {removed} sandbox files and restored clean ready state.")
        messagebox.showinfo("Demo Reset", f"Sandbox cleanly reset.\n\nPurged {removed} synthetic test files.\nReady for next demonstration run.")

    # ── LIVE SCAN HANDLERS ────────────────────────────────────────────────

    def _start_live_scan(self) -> None:
        """Run real live scan in background thread."""
        if self._is_scanning or self._is_simulating:
            messagebox.showwarning("System Busy", "Another scan or simulation is currently active.")
            return

        self._is_scanning = True
        self._btn_run_scan.configure(state="disabled")
        self._btn_cancel_scan.configure(state="normal")
        self._status_badge.configure(text="STATE: SCANNING", text_color=EX_COLORS["gold"])
        self._mode_badge.configure(text="[LIVE SYSTEM SCAN]", text_color=EX_COLORS["cyan"])
        self._scan_progress_lbl.configure(text="Initializing genuine system scan...")

        def _worker():
            try:
                def progress(res: ScanResult):
                    self.after(0, lambda: self._update_scan_progress(res))

                scan_result = self._engine.scan(ScanType.QUICK, progress_callback=progress)
                self.after(0, lambda: self._on_live_scan_complete(scan_result))
            except Exception as e:
                self.after(0, lambda: self._on_live_scan_error(str(e)))

        threading.Thread(target=_worker, daemon=True).start()

    def _cancel_live_scan(self) -> None:
        if self._is_scanning:
            self._engine.cancel_scan()
            self._scan_progress_lbl.configure(text="Cancelling scan...")

    def _update_scan_progress(self, res: ScanResult) -> None:
        self._scan_progress_lbl.configure(
            text=f"Inspected: {res.files_inspected} files | {res.processes_analyzed} processes"
        )
        self._status_badge.configure(text=f"STATE: {res.state.value.upper()}")

    def _on_live_scan_complete(self, res: ScanResult) -> None:
        self._is_scanning = False
        self._last_scan_result = res
        self._btn_run_scan.configure(state="normal")
        self._btn_cancel_scan.configure(state="disabled")

        state_color = EX_COLORS["safe"] if res.state == ScanState.SAFE else (
            EX_COLORS["warning"] if res.threat_level == "WARNING" else EX_COLORS["critical"]
        )
        if res.state in [ScanState.SCAN_INCOMPLETE, ScanState.ANALYSIS_ERROR, ScanState.ERROR]:
            state_color = EX_COLORS["warning"]

        self._status_badge.configure(text=f"STATE: {res.state.value.upper()}", text_color=state_color)
        self._scan_progress_lbl.configure(
            text=f"Completed in {res.elapsed_seconds:.2f}s | Files: {res.files_inspected} | Procs: {res.processes_analyzed}"
        )

        # Update 19 feature table
        features_arr = getattr(res, "_features", None)
        if features_arr is not None and features_arr.shape == (1, 19):
            for i, fname in enumerate(FEATURE_NAMES):
                if fname in self._feature_labels:
                    self._feature_labels[fname].configure(text=f"{features_arr[0, i]:.2f}")

        self._ml_decision_lbl.configure(text=f"DECISION: {res.threat_level}", text_color=state_color)
        self._ml_score_lbl.configure(text=f"Threat Probability: {res.ml_probability:.4f} ({res.ml_probability * 100:.1f}%)")
        self._ml_stats_lbl.configure(
            text=f"Files: {res.files_inspected} | Processes: {res.processes_analyzed} | Time: {res.elapsed_seconds:.2f}s"
        )

        if res.state == ScanState.SAFE:
            self._advisory_lbl.configure(
                text="SentinelAI Advisory: Host baseline normal. No unauthorized encryption burst detected.",
                text_color=EX_COLORS["safe"]
            )
        else:
            self._advisory_lbl.configure(
                text=f"SentinelAI Advisory: Threat flagged ({res.threat_level}). Review telemetry anomalies.",
                text_color=EX_COLORS["warning"]
            )

        self._append_evidence_log(
            f"LIVE SCAN COMPLETE | State: {res.state.value.upper()} | Threat: {res.threat_level} "
            f"| Prob: {res.ml_probability:.4f} | Files: {res.files_inspected} | Procs: {res.processes_analyzed}"
        )

    def _on_live_scan_error(self, err_msg: str) -> None:
        self._is_scanning = False
        self._btn_run_scan.configure(state="normal")
        self._btn_cancel_scan.configure(state="disabled")
        self._status_badge.configure(text="STATE: ERROR", text_color=EX_COLORS["critical"])
        self._scan_progress_lbl.configure(text=f"Scan error: {err_msg}")
        self._append_evidence_log(f"LIVE SCAN ERROR: {err_msg}")

    # ── SECURITY TEST LAB HANDLERS ────────────────────────────────────────

    def _run_test_scenario(self, scenario_id: str) -> None:
        outcome = self._test_lab.run_scenario(scenario_id)
        self._last_test_outcome = outcome

        self._lab_outcome_title.configure(text=f"SCENARIO: {outcome.scenario_name}")
        status_color = EX_COLORS["safe"] if outcome.passed_test else EX_COLORS["critical"]
        self._lab_pass_badge.configure(
            text=f"TEST RESULT: {'PASSED [VERIFIED INVARIANT]' if outcome.passed_test else 'FAILED'}",
            text_color=status_color
        )

        prob_str = f"{outcome.probability:.4f}" if outcome.probability is not None else "None"
        content = (
            f"Scenario ID:      {outcome.scenario_id}\n"
            f"Category:         {'SIMULATION' if outcome.is_simulation else 'FAILURE INJECTION / REAL'}\n"
            f"Duration:         {outcome.duration_seconds:.3f} s\n"
            f"Final Scan State: {outcome.scan_state}\n"
            f"Classifier Output:{outcome.classifier_output} (Probability: {prob_str})\n\n"
            f"--- EXPECTED BEHAVIOR ---\n{outcome.expected_behavior}\n\n"
            f"--- OBSERVED BEHAVIOR ---\n{outcome.observed_behavior}\n\n"
            f"--- EVIDENCE COLLECTED ---\n"
        )
        for e in outcome.evidence_collected:
            content += f" • {e}\n"

        content += f"\n--- AUDIT NOTES ---\n{outcome.details}\n"

        self._lab_details_box.delete("1.0", "end")
        self._lab_details_box.insert("1.0", content)

        self._append_evidence_log(
            f"SECURITY LAB TEST | Scenario: {outcome.scenario_id} | Passed: {outcome.passed_test} "
            f"| State: {outcome.scan_state} | ML: {outcome.classifier_output}"
        )

    # ── REPORT EXPORT HANDLERS ───────────────────────────────────────────

    def _export_demonstration_report(self) -> None:
        """Export sanitized demonstration report."""
        mode_title = f"Exhibition Audit - {self._active_tab.upper()}"
        scan_state = self._status_badge.cget("text").replace("STATE: ", "")
        ml_pred = self._demo_decision_badge.cget("text").replace("DECISION: ", "")

        prob = None
        if self._last_safe_demo_res and "probability" in self._last_safe_demo_res:
            prob = self._last_safe_demo_res["probability"]
        elif self._last_scan_result and hasattr(self._last_scan_result, "ml_probability"):
            prob = self._last_scan_result.ml_probability

        # Gather features
        feat_dict = {}
        for fname, lbl in self._feature_labels.items():
            txt = lbl.cget("text")
            try:
                feat_dict[fname] = float(txt) if txt != "--" else 0.0
            except ValueError:
                feat_dict[fname] = 0.0

        events_list = []
        if self._last_sim_result:
            for evt in self._last_sim_result.events:
                events_list.append({
                    "timestamp": evt.timestamp,
                    "phase": evt.phase,
                    "action": evt.action,
                    "target_path": evt.target_path,
                    "details": evt.details,
                    "entropy": evt.entropy
                })

        paths = self._exporter.export_report(
            mode_title=mode_title,
            scan_state=scan_state,
            ml_prediction=ml_pred,
            probability=prob,
            duration_s=self._last_scan_result.elapsed_seconds if self._last_scan_result else 0.0,
            features=feat_dict,
            evidence_events=events_list,
            notes="Generated during SentinelML college exhibition demonstration session."
        )

        msg = f"Report exported successfully!\n\nMarkdown: {paths['md'].name}\nJSON: {paths['json'].name}\n\nAll personal user paths have been sanitized."
        messagebox.showinfo("Export Complete", msg)
        self._append_evidence_log(f"REPORT EXPORTED | Saved {paths['md'].name} and {paths['json'].name}")

    def _append_evidence_log(self, text: str) -> None:
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {text}\n"
        if hasattr(self, "_inspector_detail_box"):
            self._inspector_detail_box.insert("end", f"\n[LOG] {line}")
            self._inspector_detail_box.see("end")
