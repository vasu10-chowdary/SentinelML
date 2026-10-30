"""
SentinelML V2 — Unified Dashboard Page
=======================================
Professional cybersecurity monitoring and behavioral detection dashboard:

- System status card with live telemetry metrics
- Fast Live Scan button (genuine read-only host filesystem and process scan)
- Behavioral Risk Meter with calibrated Random Forest tree votes
- 3D Sentinel Core live-state visualization
- Stat tiles (scans, threats, blocked, guard uptime)
- Guard status indicator
- Live event timeline & alert feed with real-time audit trail
- Scan audit history with per-scan evidence inspection
- Incident Evidence & Telemetry Inspector modal
- Incident report generation with scope, coverage and provenance disclosures
"""

import os
import sys
import time
import datetime
import threading
import queue
import tkinter as tk
from tkinter import messagebox, filedialog
from pathlib import Path
from typing import Optional, Dict, Any, List

import customtkinter as ctk
import numpy as np

from constants import COLOURS as C, APP_VERSION
from utils.logging_config import get_gui_logger
from gui.pages.scan_visualizer import ScanVisualizer
from scanner.scan_engine import ScanEngine, ScanType, ScanState, ScanResult
from ml.predictor import MLPredictor, FEATURE_NAMES, normalize_risk_score
from alerts.alert_manager import get_alert_manager
import config as cfg
from livemon import SOCMonitor, SOCTelemetry
from utils.scan_audit import (
    MAX_AUDIT_RECORDS,
    ScanAuditStore,
    build_audit_record,
)

log = get_gui_logger()


def _inconclusive_telemetry_notice() -> str:
    """Completion notice for a genuine ML result with partial platform telemetry."""
    if sys.platform.startswith("linux"):
        platform_phrase = "this Linux"
    elif sys.platform == "darwin":
        platform_phrase = "this macOS"
    else:
        platform_phrase = "this"
    return (
        "Analysis completed \u2013 additional telemetry unavailable on "
        f"{platform_phrase} system."
    )


# Statements that must appear in every exported incident report.
REPORT_LIMITATIONS = (
    "This report is an investigation aid, not a forensic certification, and does not prove malware.",
    "A model probability is an estimate under the trained model, not a diagnosis.",
    "Missing or unavailable evidence must not be read as evidence of absence.",
    "A changed file hash alone does not prove ransomware.",
    "Correlation in time does not establish causation.",
    "The 95.67% accuracy figure is the project's stored offline evaluation result "
    "(models/metrics.json), not a measured real-world ransomware detection rate and "
    "not proof of field accuracy.",
)


# Feature metadata for the evidence inspector
FEATURE_META = {
    "total_processes": ("Process Count", "psutil process enumeration", "processes"),
    "suspicious_process_count": ("Suspicious Process Count", "Uncommon names/paths proxy", "processes"),
    "avg_entropy": ("Average File Entropy", "Shannon entropy on scanned files", "bits/byte"),
    "max_entropy": ("Maximum File Entropy", "Peak Shannon entropy observed", "bits/byte"),
    "high_entropy_region_count": ("High Entropy Regions", "Files/blocks exceeding 7.0 bits/byte", "regions"),
    "malfind_injection_count": ("Code Injection (Malfind)", "PAGE_EXECUTE_READWRITE memory heuristics", "findings"),
    "crypto_dll_count": ("Crypto DLL References", "bcrypt.dll / crypt32.dll loaded", "modules"),
    "cmd_vssadmin_count": ("Shadow Copy Tampering", "vssadmin delete shadows command lines", "commands"),
    "network_connection_count": ("Active Network Connections", "psutil net_connections() count", "connections"),
    "unique_external_ips": ("Unique External IPs", "Remote public endpoint count", "IP addresses"),
    "file_handle_count": ("Open File Handles", "Process handle table enumeration", "handles"),
    "registry_handle_count": ("Registry Handles", "System registry handle proxy", "handles"),
    "orphan_process_count": ("Orphan Processes", "Processes with terminated parent PIDs", "processes"),
    "powershell_process_count": ("PowerShell Instances", "Active powershell.exe / pwsh.exe", "instances"),
    "unsigned_module_count": ("Unsigned Modules", "Untrusted/unsigned binary proxy", "modules"),
    "suspicious_mutex_count": ("Suspicious Mutexes", "Known malware mutex name patterns", "mutexes"),
    "abnormal_privilege_count": ("Abnormal Privileges", "SeDebugPrivilege / elevation heuristics", "privileges"),
    "suspicious_thread_count": ("Suspicious Threads", "Hidden/unbacked thread proxy", "threads"),
    "defender_tampering_count": ("Defender Tampering", "MpPreference / SecurityHealth tampering", "tamper events"),
}

EM_DASH = "\u2014"


class DashboardPage(ctk.CTkFrame):
    """
    Main product dashboard displayed when SentinelML opens.

    Integrates live host scanning, real telemetry, live activity feed,
    transparent incident evidence inspection, and scan audit history.
    """

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=C["bg"], **kwargs)

        self.master = master
        self._main_window = master
        self._config = config

        self._threat_level = "NOT_SCANNED"  # NOT_SCANNED, SAFE, WARNING, CRITICAL, SCAN_INCOMPLETE, ANALYSIS_ERROR
        self._guard_active = False
        self._risk_score = 0.0
        self._scanning = False
        self._is_simulation = False
        self._scans_completed = 0
        self._threats_detected = 0

        self._last_scan_result: Optional[ScanResult] = None
        self._last_host_scan_result: Optional[ScanResult] = None
        self._last_sim_scan_result: Optional[ScanResult] = None
        self._last_sim_result = None
        self._last_demo_details = None
        self._scan_history: List[Dict[str, Any]] = []

        # Persistent scan audit history (latest 10 completed scans).
        audit_cfg = self._config.get("audit") if isinstance(self._config, dict) else None
        audit_path = audit_cfg.get("path") if isinstance(audit_cfg, dict) else None
        self._audit_store = ScanAuditStore(path=audit_path)
        self._scan_started = False
        self._scan_started_at: Optional[float] = None

        self._active_engine: Optional[ScanEngine] = None
        self._last_seen_state = None
        self._active_scan_token: Optional[str] = None
        self._header_row = 0

        self._test_lab = None
        self.visualizer: Optional[ScanVisualizer] = None

        # Thread-safe dispatch queue
        self._ui_queue: queue.Queue = queue.Queue()
        self._cancel_requested_flag: bool = False
        self._scan_completion_percent: int = 0
        self._latest_progress_args = None
        self._scan_progress = None
        self._is_destroyed = False
        self._pending_after_ids = set()
        self._rendered_alerts_sig = None
        self._rendered_history_sig = None
        self._feed_container = None
        self._history_container = None

        # Live SOC monitoring (real host telemetry only)
        self._soc_monitor = SOCMonitor(config=self._config, on_snapshot=self._on_soc_snapshot)
        self._soc_latest: Optional[SOCTelemetry] = None
        self._soc_rendered_seq = 0
        self._soc_health_labels: Dict[str, Any] = {}
        self._soc_scope_text = "Monitored directories · metadata only, depth 1, max 2,000 files"

        self._build()
        self._load_audit_history()

        # Warm-up cache for the ScanVisualizer: built silently 2s after
        # dashboard loads so the first "Fast Live Scan" click is instant.
        self._warmed_visualizer = None

        self.safe_after(30, self._drain_ui_queue)
        self.safe_after(300, self._refresh_activity_feed)
        self.safe_after(600, self._soc_bootstrap)
        self.safe_after(1000, self._soc_tick)
        self.safe_after(2000, self._prewarm_visualizer)
        log.info("Dashboard page constructed.")

    # ── Safe scheduling & thread dispatch ─────────────────────────────────
    def safe_after(self, ms: int, fn, *args, **kwargs):
        """Schedule a callback and track its ID for safe cancellation upon page destruction."""
        if getattr(self, "_is_destroyed", False):
            return None
        aid = None

        def wrapper():
            if aid is not None:
                self._pending_after_ids.discard(aid)
            if not getattr(self, "_is_destroyed", False):
                try:
                    if self.winfo_exists():
                        fn(*args, **kwargs)
                except Exception:
                    pass

        try:
            aid = self.after(ms, wrapper)
        except Exception:
            return None
        self._pending_after_ids.add(aid)
        return aid

    def _dispatch_to_main(self, fn, *args, **kwargs) -> None:
        """Thread-safe UI callback dispatcher to eliminate cross-thread Tk errors."""
        if getattr(self, "_is_destroyed", False):
            return

        # Coalesce high-frequency progress updates to prevent queue backlog
        if fn == self._update_scan_progress:
            self._latest_progress_args = (fn, args, kwargs)
            if threading.current_thread() is threading.main_thread():
                try:
                    self._drain_ui_queue()
                except Exception:
                    pass
            return

        self._ui_queue.put((fn, args, kwargs))
        if threading.current_thread() is threading.main_thread():
            try:
                self._drain_ui_queue()
            except Exception:
                pass
        else:
            try:
                self.safe_after(0, self._drain_ui_queue)
            except Exception:
                pass

    def _drain_ui_queue(self) -> None:
        """Drain queued background worker callbacks in the Tkinter main thread context."""
        if getattr(self, "_is_destroyed", False) or not self.winfo_exists():
            return
        try:
            if self._latest_progress_args is not None:
                p_fn, p_args, p_kwargs = self._latest_progress_args
                self._latest_progress_args = None
                try:
                    p_fn(*p_args, **p_kwargs)
                except Exception as ex:
                    log.error("Error executing coalesced progress callback: %s", ex, exc_info=True)

            while not self._ui_queue.empty():
                try:
                    fn, args, kwargs = self._ui_queue.get_nowait()
                    fn(*args, **kwargs)
                except queue.Empty:
                    break
                except Exception as ex:
                    log.error("Error executing queued UI callback: %s", ex, exc_info=True)
        finally:
            if self.winfo_exists():
                try:
                    self.safe_after(80, self._drain_ui_queue)
                except Exception:
                    pass

    # ── Build UI Layout ───────────────────────────────────────────────────
    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=3)  # 3D core column
        self.grid_columnconfigure(2, weight=2)  # Risk meter column

        # ── Demo Mode Banner (if configured) ──────────────────────────────
        import demo_data
        if demo_data.is_demo_mode():
            demo_banner = ctk.CTkFrame(self, fg_color="#ff6b00", corner_radius=0, height=36)
            demo_banner.grid(row=0, column=0, columnspan=3, sticky="ew", padx=0, pady=0)
            ctk.CTkLabel(
                demo_banner,
                text="DEMO MODE ACTIVE \u2014 SYNTHETIC DEMONSTRATION DATA",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#000000",
            ).pack(pady=8)
            header_row = 1
        else:
            header_row = 0
        self._header_row = header_row
        self.grid_rowconfigure(header_row + 5, weight=1)

        # ── Page Header ──────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=header_row, column=0, columnspan=3, sticky="ew", padx=28, pady=(20, 0))

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left")

        ctk.CTkLabel(
            title_box,
            text="Dashboard",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=C["white"],
        ).pack(side="left")

        ctk.CTkLabel(
            title_box,
            text="Behavioral Ransomware Defense & Real-Time System Telemetry",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
        ).pack(side="left", padx=(14, 0), pady=(4, 0))

        indicators = ctk.CTkFrame(header, fg_color="transparent")
        indicators.pack(side="right")

        self._host_status_label = ctk.CTkLabel(
            indicators,
            text="\u25cf Host: Monitored",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["accent"],
        )
        self._host_status_label.pack(side="left", padx=(0, 16))
        self._sandbox_status_label = self._host_status_label

        self._guard_status_label = ctk.CTkLabel(
            indicators,
            text="\u2b24 Guard: Inactive",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["muted"],
        )
        self._guard_status_label.pack(side="left")

        # ── Status Card (Row 1, Column 0) ─────────────────────────────────
        status_card = ctk.CTkFrame(
            self,
            fg_color=C["panel"],
            corner_radius=12,
            border_width=1,
            border_color=C["border"],
        )
        status_card.grid(row=header_row + 1, column=0, sticky="nsew", padx=(28, 8), pady=(16, 0))
        status_card.grid_columnconfigure(1, weight=1)

        self._status_dot = ctk.CTkLabel(
            status_card,
            text="\u25cf",
            font=ctk.CTkFont(size=30),
            text_color=C["muted"],
        )
        self._status_dot.grid(row=0, column=0, padx=(20, 12), pady=(18, 4), sticky="n")

        content_box = ctk.CTkFrame(status_card, fg_color="transparent")
        content_box.grid(row=0, column=1, sticky="nsew", pady=(18, 4))
        content_box.grid_columnconfigure(0, weight=1)

        title_row = ctk.CTkFrame(content_box, fg_color="transparent")
        title_row.pack(fill="x", anchor="w")

        self._status_title = ctk.CTkLabel(
            title_row,
            text="READY TO SCAN",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color=C["white"],
        )
        self._status_title.pack(side="left")

        self._status_badge = ctk.CTkLabel(
            title_row,
            text="  [NOT YET SCANNED]  ",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C["accent"],
            fg_color="#0a2540",
            corner_radius=4,
            height=22,
        )
        self._status_badge.pack(side="left", padx=(12, 0))

        self._status_desc = ctk.CTkLabel(
            content_box,
            text="System is idle and ready for inspection. Run Fast Live Scan to inspect filesystem entropy and active process behavior.",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
            anchor="w",
            wraplength=420,
            justify="left",
        )
        self._status_desc.pack(fill="x", anchor="w", pady=(6, 6))

        self._live_info_strip = ctk.CTkFrame(content_box, fg_color="transparent")
        self._live_info_strip.pack(fill="x", anchor="w", pady=(0, 8))

        self._stage_badge = ctk.CTkLabel(
            self._live_info_strip,
            text="STAGE: IDLE",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=C["muted"],
            fg_color="#121824",
            corner_radius=4,
            height=20,
            padx=8,
        )
        self._stage_badge.pack(side="left", padx=(0, 10))

        self._active_path_label = ctk.CTkLabel(
            self._live_info_strip,
            text="No active scan in progress",
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
            anchor="w",
            wraplength=340,
        )
        self._active_path_label.pack(side="left", fill="x", expand=True)

        # Dedicated Scan Completion Progress Bar (0% - 100%)
        # Strictly separated from the Behavioral Risk Meter
        self._scan_progress = ctk.CTkProgressBar(
            content_box,
            width=420,
            height=6,
            corner_radius=3,
            progress_color=C["accent"],
            fg_color="#182030",
        )
        self._scan_progress.pack(fill="x", anchor="w", pady=(0, 10))
        self._scan_progress.set(0.0)

        action_strip = ctk.CTkFrame(content_box, fg_color="transparent")
        action_strip.pack(fill="x", anchor="w", pady=(0, 14))

        self._scan_btn = ctk.CTkButton(
            action_strip,
            text="\u26a1 Fast Live Scan",
            font=ctk.CTkFont(family="Segoe UI Symbol", size=12, weight="bold"),
            fg_color=C["accent"],
            hover_color="#00b896",
            text_color="#0d1117",
            corner_radius=6,
            width=140,
            height=34,
            command=self._on_scan,
        )
        self._scan_btn.pack(side="left", padx=(0, 8))

        self._cancel_scan_btn = ctk.CTkButton(
            action_strip,
            text="\u2715 Cancel",
            font=ctk.CTkFont(family="Segoe UI Symbol", size=12, weight="bold"),
            fg_color="transparent",
            hover_color="#161b22",
            text_color="#484f58",
            text_color_disabled="#484f58",
            border_width=1,
            border_color="#262c36",
            corner_radius=6,
            width=85,
            height=34,
            command=self.cancel_scan,
            state="disabled",
        )
        self._cancel_scan_btn.pack(side="left", padx=(0, 8))

        self._evidence_btn = ctk.CTkButton(
            action_strip,
            text="\U0001f4c4 View Incident Report",
            font=ctk.CTkFont(size=12),
            fg_color=C["card"],
            hover_color=C["border"],
            text_color=C["white"],
            border_width=1,
            border_color=C["border"],
            corner_radius=6,
            width=165,
            height=34,
            command=self._open_evidence_dialog,
        )
        self._evidence_btn.pack(side="left")

        self._story_btn = ctk.CTkButton(
            action_strip,
            text="\u25b6 3D Story Mode",
            font=ctk.CTkFont(family="Segoe UI Symbol", size=12, weight="bold"),
            fg_color="#1a4a7a",
            hover_color="#2060a0",
            text_color=C["accent"],
            border_width=1,
            border_color=C["accent"],
            corner_radius=6,
            width=132,
            height=34,
            command=self._open_story_mode,
        )
        self._story_btn.pack(side="left", padx=(8, 0))

        # Removed from normal UI; attributes retained for backwards compatibility
        self._sim_btn = None
        self._clean_btn = None

        # ── 3D Sentinel Shield Core Card (Row 1, Column 1) ────────────────
        core_card = ctk.CTkFrame(
            self,
            fg_color=C["panel"],
            corner_radius=12,
            border_width=1,
            border_color=C["border"],
        )
        core_card.grid(row=header_row + 1, column=1, sticky="nsew", padx=(8, 8), pady=(16, 0))
        core_card.grid_rowconfigure(1, weight=1)
        core_card.grid_columnconfigure(0, weight=1)

        core_top = ctk.CTkFrame(core_card, fg_color="transparent")
        core_top.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            core_top,
            text="SENTINEL CORE 3D",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C["muted"],
        ).pack(side="left")

        self._core_status_badge = ctk.CTkLabel(
            core_top,
            text="\u25cf TELEMETRY ACTIVE",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color="#00d4ff",
            fg_color="#0c223a",
            corner_radius=4,
            height=20,
            padx=8,
        )
        self._core_status_badge.pack(side="right")

        from gui.dashboard_3d import Dashboard3DCore

        self._core_3d = Dashboard3DCore(
            core_card,
            width=360,
            height=205,
        )
        self._core_3d.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # ── Behavioral Risk Meter (Row 1, Column 2) ───────────────────────
        self._build_risk_meter(header_row + 1)

        # ── Stat Tiles Row (Row 2) ────────────────────────────────────────
        tiles_row = ctk.CTkFrame(self, fg_color="transparent")
        tiles_row.grid(row=header_row + 2, column=0, columnspan=3, sticky="new", padx=28, pady=16)
        tiles_row.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="tile")

        self._tile_scans = self._make_tile(tiles_row, "Scans Today", "0", C["accent2"], 0)
        self._tile_threats = self._make_tile(tiles_row, "Threats Found", "0", C["red"], 1)
        self._tile_blocked = self._make_tile(tiles_row, "Blocked / Guard", "0", C["green"], 2)
        self._tile_uptime = self._make_tile(tiles_row, "Guard Uptime", "0m", C["yellow"], 3)

        # ── Live SOC Monitoring Panel (Row 3) ─────────────────────────────
        self._build_soc_panel(header_row + 3)

        # ── Lower Section Header (Row 4) ──────────────────────────────────
        feed_header = ctk.CTkFrame(self, fg_color="transparent")
        feed_header.grid(row=header_row + 4, column=0, columnspan=3, sticky="ew", padx=28, pady=(4, 8))

        self._view_segmented = ctk.CTkSegmentedButton(
            feed_header,
            values=["Live SOC Feed", "Scan Audit History"],
            command=self._on_switch_view,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#121824",
            selected_color="#182c4f",
            selected_hover_color="#233d6b",
            text_color=C["white"],
        )
        self._view_segmented.set("Live SOC Feed")
        self._view_segmented.pack(side="left")

        self._feed_subtitle = ctk.CTkLabel(
            feed_header,
            text=f"\u2014 Real-time security telemetry & alert events",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
        )
        self._feed_subtitle.pack(side="left", padx=(12, 0))

        ctk.CTkButton(
            feed_header,
            text="\u21bb Refresh",
            font=ctk.CTkFont(size=11),
            width=80,
            height=26,
            fg_color=C["panel"],
            hover_color=C["card"],
            text_color=C["muted"],
            border_width=1,
            border_color=C["border"],
            command=self._on_refresh_current_view,
        ).pack(side="right")

        # ── Activity Feed Scrollable Frame (Row 5) ────────────────────────
        self._feed_scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=C["panel"],
            corner_radius=12,
            border_width=1,
            border_color=C["border"],
            height=220,
        )
        self._feed_scroll.grid(row=header_row + 5, column=0, columnspan=3, sticky="nsew", padx=28, pady=(0, 20))
        self._feed_scroll.grid_columnconfigure(0, weight=1)

        # ── Scan Audit History Scrollable Frame (initially hidden) ────────
        self._history_scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=C["panel"],
            corner_radius=12,
            border_width=1,
            border_color=C["border"],
            height=220,
        )
        self._history_scroll.grid_columnconfigure(0, weight=1)

    def _build_risk_meter(self, row: int) -> None:
        """Build the Risk Meter card."""
        risk_frame = ctk.CTkFrame(
            self,
            fg_color=C["panel"],
            corner_radius=12,
            border_width=1,
            border_color=C["border"],
            width=210,
        )
        risk_frame.grid(row=row, column=2, sticky="nsew", padx=(8, 28), pady=(16, 0))
        risk_frame.grid_propagate(False)

        ctk.CTkLabel(
            risk_frame,
            text="BEHAVIORAL RISK METER",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C["muted"],
        ).pack(pady=(16, 4))

        self._risk_score_label = ctk.CTkLabel(
            risk_frame,
            text="--%",
            font=ctk.CTkFont(size=30, weight="bold"),
            text_color=C["muted"],
        )
        self._risk_score_label.pack(pady=(2, 6))

        self._risk_progress = ctk.CTkProgressBar(
            risk_frame,
            width=165,
            height=10,
            corner_radius=5,
            progress_color=C["muted"],
        )
        self._risk_progress.pack(pady=(0, 10))
        self._risk_progress.set(0.0)

        self._risk_level_label = ctk.CTkLabel(
            risk_frame,
            text="NOT SCANNED",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        )
        self._risk_level_label.pack(pady=(0, 4))

        self._tree_votes_label = ctk.CTkLabel(
            risk_frame,
            text="Awaiting Scan Execution",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["muted"],
        )
        self._tree_votes_label.pack(pady=(0, 2))

        ctk.CTkLabel(
            risk_frame,
            text="ML Risk Probability",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["muted"],
        ).pack(pady=(2, 0))

        self._risk_context_label = ctk.CTkLabel(
            risk_frame,
            text="Random Forest RF-19 (100 Trees)",
            font=ctk.CTkFont(size=10),
            text_color=C["muted"],
        )
        self._risk_context_label.pack(pady=(0, 12))

    @staticmethod
    def _make_tile(parent, label: str, value: str, accent: str, col: int) -> ctk.CTkLabel:
        """Create a stat tile and return the value label for updates."""
        card = ctk.CTkFrame(
            parent,
            fg_color=C["panel"],
            corner_radius=10,
            border_width=1,
            border_color=C["border"],
        )
        card.grid(row=0, column=col, padx=(0, 12) if col < 3 else 0, sticky="ew")

        ctk.CTkLabel(
            card,
            text=label,
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
        ).pack(anchor="w", padx=16, pady=(12, 2))

        val_lbl = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=accent,
        )
        val_lbl.pack(anchor="w", padx=16, pady=(0, 14))
        return val_lbl

    # ── Visualizer Management ─────────────────────────────────────────────
    def _close_visualizer(self) -> None:
        """Safely dismiss the 3D visualizer overlay and immediately repaint dashboard."""
        if hasattr(self, "_core_3d") and self._core_3d:
            try:
                self._core_3d.resume()
            except Exception:
                pass

        vis = getattr(self, "visualizer", None)
        if vis:
            self.visualizer = None
            try:
                vis.place_forget()
            except Exception:
                pass
            try:
                self.update_idletasks()
            except Exception:
                pass
            try:
                vis.destroy()
            except Exception:
                pass
            try:
                self.lift()
                self.update_idletasks()
            except Exception:
                pass

        if getattr(self, "_pending_feed_refresh", False):
            self._pending_feed_refresh = False
            self._on_refresh_current_view()

    def _prewarm_visualizer(self) -> None:
        """Pre-create the ScanVisualizer hidden so the first click is instant."""
        if getattr(self, "_is_destroyed", False) or not self.winfo_exists():
            return
        if getattr(self, "visualizer", None) and self.visualizer.winfo_exists():
            return
        warmed = getattr(self, "_warmed_visualizer", None)
        if warmed is not None:
            try:
                if warmed.winfo_exists():
                    return
            except Exception:
                pass
        try:
            log.info("Pre-warming ScanVisualizer in background...")
            vis = ScanVisualizer(
                self,
                on_close=self._close_visualizer,
                on_cancel=self.cancel_scan,
                on_start_scan=self.start_live_host_scan,
                mode="LIVE HOST SCAN",
                initial_state="IDLE",
            )
            self._warmed_visualizer = vis
            log.info("ScanVisualizer pre-warmed and ready.")
        except Exception as e:
            log.warning("Failed to pre-warm ScanVisualizer: %s", e)
            self._warmed_visualizer = None

    # ── 3D Story Mode entry ───────────────────────────────────────────────
    def _open_story_mode(self) -> None:
        """Open the six-scene 3D story mode page (host window or fallback dialog)."""
        mw = getattr(self, "_main_window", None)
        show = getattr(mw, "_show_page", None)
        page_classes = getattr(mw, "_page_classes", None)
        if callable(show) and isinstance(page_classes, dict) and "story_mode" in page_classes:
            try:
                show("story_mode")
                return
            except Exception as e:
                log.error("Failed to navigate to Story Mode: %s", e)

        try:
            from gui.pages.story_mode_page import StoryModePage

            dlg = ctk.CTkToplevel(self.winfo_toplevel())
            dlg.title("SentinelML V2 \u2014 3D Story Mode")
            sw = dlg.winfo_screenwidth()
            sh = dlg.winfo_screenheight()
            dlg_w = min(1180, max(900, int(sw * 0.86)))
            dlg_h = min(780, max(620, int(sh * 0.86)))
            dlg.geometry(f"{dlg_w}x{dlg_h}+{max(0, (sw - dlg_w) // 2)}+{max(0, (sh - dlg_h) // 2)}")
            dlg.minsize(min(900, sw - 40), min(620, sh - 40))
            dlg.configure(fg_color=C["bg"])
            dlg.transient(self.winfo_toplevel())

            page = StoryModePage(dlg, config=self._config, on_exit=dlg.destroy)
            page.pack(fill="both", expand=True)
        except Exception as e:
            log.error("Failed to open 3D Story Mode: %s", e, exc_info=True)
            try:
                messagebox.showerror("Story Mode", f"Could not open 3D Story Mode:\n{e}")
            except Exception:
                pass

    # ── Fast Live Scan (Host Scan) ────────────────────────────────────────
    def _on_scan(self) -> None:
        """Open the interactive 3D Live Analysis Visualizer in IDLE state without starting a scan."""
        if getattr(self, "visualizer", None) and self.visualizer.winfo_exists():
            try:
                self.visualizer.lift()
                return
            except Exception:
                pass

        # Reuse pre-warmed visualizer if available (first click is then instant)
        warmed = getattr(self, "_warmed_visualizer", None)
        if warmed is not None:
            try:
                if warmed.winfo_exists():
                    self._warmed_visualizer = None
                    self.visualizer = warmed
                    self.visualizer.set_scan_state("IDLE")
                    self.visualizer.place(relx=0, rely=0, relwidth=1, relheight=1)
                    if hasattr(self, "_core_3d") and self._core_3d:
                        self._core_3d.pause()
                    try:
                        self.visualizer.lift()
                        self.visualizer.update_idletasks()
                    except Exception:
                        pass
                    log.info("ScanVisualizer opened from pre-warmed cache.")
                    return
            except Exception as e:
                log.warning("Pre-warmed visualizer unusable (%s), rebuilding.", e)
                self._warmed_visualizer = None

        # Cold-create: first open before prewarm fires, or after a reopen
        self.visualizer = ScanVisualizer(
            self,
            on_close=self._close_visualizer,
            on_cancel=self.cancel_scan,
            on_start_scan=self.start_live_host_scan,
            mode="LIVE HOST SCAN",
            initial_state="IDLE",
        )
        self.visualizer.place(relx=0, rely=0, relwidth=1, relheight=1)
        if hasattr(self, "_core_3d") and self._core_3d:
            try:
                self._core_3d.pause()
            except Exception:
                pass
        try:
            self.visualizer.lift()
            self.visualizer.update_idletasks()
        except Exception:
            pass

    def start_live_host_scan(self) -> None:
        """Explicitly launch background scan thread for live host scan when triggered by user."""
        if self._scanning:
            log.warning("Scan already in progress, ignoring duplicate start request.")
            return

        import uuid
        token = str(uuid.uuid4())
        self._active_scan_token = token
        self._cancel_requested_flag = False
        self._scanning = True
        self._is_simulation = False
        self._active_engine = None
        self._scan_started = True
        self._scan_started_at = time.time()

        log.info("User initiated Fast Live Scan (Host) [token=%s]", token)

        # Pause background guard during active on-demand scan
        try:
            from guard.sentinel_guard import get_guard_instance
            get_guard_instance().pause()
        except Exception:
            pass

        self._scan_btn.configure(text="\u26a1 Scanning\u2026", state="disabled")
        if self._sim_btn:
            self._sim_btn.configure(state="disabled")
        if self._clean_btn:
            self._clean_btn.configure(state="disabled")
        self._set_cancel_button_state("scanning")

        if hasattr(self, "_stage_badge"):
            self._stage_badge.configure(text="STAGE: INITIALIZING", text_color=C["accent"])
        if hasattr(self, "_active_path_label"):
            self._active_path_label.configure(text="Enumerating system scan targets...", text_color=C["white"])

        if hasattr(self, "_core_3d") and self._core_3d:
            try:
                self._core_3d.set_state("SCANNING")
            except Exception:
                pass

        if getattr(self, "visualizer", None) and self.visualizer.winfo_exists():
            try:
                self.visualizer.set_scan_state("SCANNING")
            except Exception:
                pass

        thread = threading.Thread(
            target=self._run_scan_thread,
            args=(token,),
            daemon=True,
            name="HostScanThread",
        )
        thread.start()

    def _run_scan_thread(self, token: Optional[str] = None) -> None:
        """Background worker for live host scanning. Never touches Tk directly."""
        try:
            if self._cancel_requested_flag:
                cancel_res = ScanResult(
                    scan_type=ScanType.QUICK,
                    state=ScanState.SCAN_INCOMPLETE,
                    cancelled=True,
                    error_message="Scan cancelled prior to execution",
                )
                self._dispatch_to_main(self._on_scan_cancelled, cancel_res, token)
                return

            # Demo Mode: present clearly-labelled simulated telemetry instead of
            # touching the host. Never masquerade demo data as a live host scan.
            import demo_data
            if demo_data.is_demo_mode():
                log.info("Demo mode: using simulated scan data")
                deadline = time.time() + 2.0
                while time.time() < deadline:
                    if self._cancel_requested_flag:
                        break
                    time.sleep(0.05)
                if self._cancel_requested_flag:
                    cancel_res = ScanResult(
                        scan_type=ScanType.QUICK,
                        state=ScanState.SCAN_INCOMPLETE,
                        cancelled=True,
                        error_message="Scan cancelled by user",
                        is_simulation=True,
                        scan_origin="CONTROLLED_SIMULATION",
                    )
                    self._dispatch_to_main(self._on_scan_cancelled, cancel_res, token)
                    return
                demo_result = demo_data.generate_random_demo_scan()
                demo_sr = ScanResult(
                    scan_type=ScanType.QUICK,
                    state=ScanState.COMPLETE,
                    processes_analyzed=int(demo_result.get("process_count", 0) or 0),
                    ml_executed=True,
                    ml_probability=float(demo_result.get("probability", 0.0) or 0.0),
                    threat_level=demo_result.get("threat_level", "SAFE"),
                    elapsed_seconds=float(demo_result.get("duration", 0.0) or 0.0),
                    is_simulation=True,
                    scan_origin="CONTROLLED_SIMULATION",
                    model_source="DEMO_MODE_SIMULATED_DATA",
                    scan_id=f"SCN-DEMO-{int(time.time() * 1000)}",
                )
                self._dispatch_to_main(
                    self._on_scan_complete,
                    demo_sr.threat_level,
                    demo_sr.ml_probability,
                    demo_sr,
                    True,
                    demo_result,
                    token,
                )
                return

            engine = ScanEngine()
            self._active_engine = engine
            def progress_update(scan_result):
                self._dispatch_to_main(self._update_scan_progress, scan_result, token)

            result = engine.scan(
                ScanType.QUICK,
                progress_callback=progress_update,
                scan_origin="LIVE_HOST_SCAN",
            )
            self._active_engine = None

            if result.cancelled or getattr(self, "_cancel_requested_flag", False):
                result.cancelled = True
                result.state = ScanState.SCAN_INCOMPLETE
                self._dispatch_to_main(self._on_scan_cancelled, result, token)
                return

            # A genuine ML result with partial platform telemetry is a completed
            # analysis, not a failure. Keep it out of the error path while
            # preserving was_successful()'s strict SAFE/THREAT-only contract.
            if (
                result.state in (ScanState.INCONCLUSIVE, ScanState.LIMITED_COVERAGE)
                or getattr(result, "is_inconclusive", False)
            ) and result.ml_executed:
                self._dispatch_to_main(
                    self._on_scan_complete,
                    "INCONCLUSIVE",
                    result.ml_probability,
                    result,
                    False,
                    None,
                    token,
                )
                return

            if not result.was_successful():
                msg = result.error_message or f"Scan incomplete (state={result.state.value})"
                self._dispatch_to_main(self._on_scan_error, msg, result, token)
                return

            self._dispatch_to_main(
                self._on_scan_complete,
                result.threat_level,
                result.ml_probability,
                result,
                False,
                None,
                token,
            )
        except Exception as e:
            self._active_engine = None
            log.error("Scan thread failed: %s", e, exc_info=True)
            self._dispatch_to_main(self._on_scan_error, str(e), None, token)

    # ── Live Progress ─────────────────────────────────────────────────────
    def _update_scan_progress(self, scan_result: ScanResult, token: Optional[str] = None) -> None:
        """Update GUI with live scan progress without blocking the UI thread."""
        try:
            if not self.winfo_exists() or not getattr(self, "_scanning", False):
                return
            if token is not None and token != getattr(self, "_active_scan_token", None):
                return

            vis = getattr(self, "visualizer", None)
            if vis:
                try:
                    vis.update_progress(scan_result)
                except Exception:
                    pass

            state_name = scan_result.state.value.upper()
            files = getattr(scan_result, "files_inspected", 0) or 0
            dirs = getattr(scan_result, "directories_inspected", 0) or 0
            procs = getattr(scan_result, "processes_analyzed", 0) or 0

            if state_name == "ANALYZING":
                pct = 82
            elif state_name in ("COMPLETE", "SAFE"):
                pct = 95
            else:
                pct = min(70, 10 + int(files / 120))

            self._scan_completion_percent = pct
            if getattr(self, "_scan_progress", None):
                try:
                    self._scan_progress.set(min(1.0, pct / 100.0))
                except Exception:
                    pass
            if hasattr(self, "_stage_badge"):
                self._stage_badge.configure(
                    text=f"STAGE: {state_name.replace('_', ' ')} \u2014 {pct}%",
                    text_color=C["accent"],
                )

            current_path = getattr(scan_result, "current_path", "") or ""
            if hasattr(self, "_active_path_label"):
                text = current_path if current_path else f"Inspecting {files:,} files, {dirs:,} directories..."
                try:
                    self._active_path_label.configure(text=text, text_color=C["white"])
                except Exception:
                    pass

            if hasattr(self, "_core_3d") and self._core_3d:
                try:
                    self._core_3d.update_data(scan_result)
                    self._core_3d.update_progress(files=files, procs=procs, stage=state_name)
                except Exception:
                    pass
        except Exception as e:
            log.warning("Failed to update scan progress: %s", e)

    # ── Terminal Callbacks ────────────────────────────────────────────────
    def _on_scan_complete(
        self,
        threat_level: str,
        probability: float,
        scan_result: Optional[ScanResult] = None,
        is_simulation: bool = False,
        sim_details=None,
        token: Optional[str] = None,
    ) -> None:
        """Called on the main thread when a scan completes successfully."""
        if token is not None and token != getattr(self, "_active_scan_token", None):
            log.warning("Ignoring stale scan complete callback with token %s", token)
            return

        self._active_scan_token = None
        self._scanning = False
        self._set_cancel_button_state("idle")
        self._is_simulation = is_simulation
        self._scans_completed += 1

        sim_flag = bool(
            is_simulation
            or getattr(scan_result, "is_simulation", False)
            or getattr(scan_result, "scan_origin", "") == "CONTROLLED_SIMULATION"
        )
        level_u = str(threat_level or "").upper()
        is_inconclusive = level_u in ("INCONCLUSIVE", "LIMITED_COVERAGE")

        if level_u in ("WARNING", "CRITICAL", "THREAT_DETECTED"):
            self._threats_detected += 1

        if scan_result is not None:
            self._last_scan_result = scan_result
            if sim_flag:
                self._last_sim_scan_result = scan_result
                self._last_sim_result = scan_result
            else:
                self._last_host_scan_result = scan_result
            try:
                self._soc_monitor.record_scan(scan_result)
            except Exception:
                pass
        self._last_demo_details = sim_details

        vis = getattr(self, "visualizer", None)
        if vis:
            try:
                if vis.winfo_exists():
                    vis.on_complete(threat_level, probability, scan_result)
            except Exception:
                pass

        # Record in the persistent audit history (single authoritative point).
        origin_val = "CONTROLLED_SIMULATION" if sim_flag else "LIVE_HOST_SCAN"
        demo_model = getattr(scan_result, "model_source", "") == "DEMO_MODE_SIMULATED_DATA"
        self._record_scan_history(
            scan_result=scan_result,
            outcome="completed",
            token=token,
            scan_origin=origin_val,
            model_source="DEMO_MODE_SIMULATED_DATA" if demo_model else None,
        )

        # Update visual threat status
        self.update_threat_status(
            threat_level,
            probability,
            is_simulation=sim_flag,
            details=sim_details,
        )

        # Update stats
        self.update_stats(
            scans=self._scans_completed,
            threats=self._threats_detected,
        )

        # Generate audit alert
        self._generate_scan_alert(threat_level, probability, scan_result, is_simulation=sim_flag)

        # Completion is independent of risk score
        self._scan_completion_percent = 100
        try:
            self._scan_progress.set(1.0)
        except Exception:
            pass
        if hasattr(self, "_stage_badge"):
            if is_inconclusive:
                self._stage_badge.configure(
                    text="STAGE: COMPLETE \u2014 TELEMETRY LIMITED",
                    text_color=C["yellow"],
                )
            else:
                self._stage_badge.configure(text="STAGE: COMPLETE \u2014 100%", text_color=C["green"])
        if hasattr(self, "_active_path_label"):
            if is_inconclusive:
                self._active_path_label.configure(
                    text=_inconclusive_telemetry_notice(),
                    text_color=C["yellow"],
                )
            else:
                self._active_path_label.configure(text="Scan complete. Evidence available.", text_color=C["muted"])

        if hasattr(self, "_core_3d") and self._core_3d:
            try:
                final_state = "THREAT DETECTED" if threat_level in ("CRITICAL", "THREAT_DETECTED") else threat_level
                self._core_3d.set_state(final_state, self._risk_score)
            except Exception:
                pass

        # Re-enable action buttons
        self._scan_btn.configure(text="\u26a1 Fast Live Scan", state="normal")
        if self._sim_btn:
            self._sim_btn.configure(state="normal")
        if self._clean_btn:
            self._clean_btn.configure(state="normal")

        log.info("Scan results displayed to user")

    def _on_scan_cancelled(
        self,
        scan_result: Optional[ScanResult] = None,
        token: Optional[str] = None,
    ) -> None:
        """Called on the main thread when a scan is cancelled."""
        if token is not None and token != getattr(self, "_active_scan_token", None):
            log.warning("Ignoring stale scan cancelled callback with token %s", token)
            return

        self._active_scan_token = None
        self._scanning = False
        self._threat_level = "SCAN_INCOMPLETE"
        self._set_cancel_button_state("idle")

        if scan_result is not None:
            scan_result.cancelled = True
            scan_result.state = ScanState.SCAN_INCOMPLETE
            self._last_scan_result = scan_result
            try:
                self._soc_monitor.record_scan(scan_result)
            except Exception:
                pass

        vis = getattr(self, "visualizer", None)
        if vis:
            try:
                if vis.winfo_exists():
                    vis.on_complete("CANCELLED", 0.0, scan_result)
            except Exception:
                pass

        if hasattr(self, "_core_3d") and self._core_3d:
            try:
                self._core_3d.set_state("SCAN_INCOMPLETE")
            except Exception:
                pass

        self._scan_completion_percent = 0
        try:
            self._scan_progress.set(0.0)
        except Exception:
            pass
        if hasattr(self, "_stage_badge"):
            self._stage_badge.configure(text="STAGE: CANCELLED", text_color=C["orange"])
        if hasattr(self, "_active_path_label"):
            self._active_path_label.configure(text="Scan cancelled by user.", text_color=C["muted"])

        cancel_origin = (
            "CONTROLLED_SIMULATION"
            if scan_result is not None
            and (
                getattr(scan_result, "is_simulation", False)
                or getattr(scan_result, "scan_origin", "") == "CONTROLLED_SIMULATION"
            )
            else "LIVE_HOST_SCAN"
        )
        self._record_scan_history(
            scan_result=scan_result,
            outcome="cancelled",
            token=token,
            scan_origin=cancel_origin,
        )

        self.update_threat_status("SCAN_INCOMPLETE", 0.0, is_simulation=False)
        self._threat_level = "SCAN_INCOMPLETE"

        self._scan_btn.configure(text="\u26a1 Fast Live Scan", state="normal")
        if self._sim_btn:
            self._sim_btn.configure(state="normal")
        if self._clean_btn:
            self._clean_btn.configure(state="normal")

        log.info("Scan cancelled; dashboard marked SCAN_INCOMPLETE")

    def _on_scan_error(
        self,
        error_msg: str,
        scan_result: Optional[ScanResult] = None,
        token: Optional[str] = None,
    ) -> None:
        """Called on the main thread when a scan fails. NEVER reports SAFE."""
        if token is not None and token != getattr(self, "_active_scan_token", None):
            log.warning("Ignoring stale scan error callback with token %s", token)
            return

        self._active_scan_token = None
        self._scanning = False
        self._threat_level = "ERROR"
        self._set_cancel_button_state("idle")

        if scan_result is not None:
            self._last_scan_result = scan_result
            try:
                self._soc_monitor.record_scan(scan_result)
            except Exception:
                pass
        elif self._last_scan_result is not None:
            try:
                self._last_scan_result.error_message = error_msg
            except Exception:
                pass

        vis = getattr(self, "visualizer", None)
        if vis:
            try:
                if vis.winfo_exists():
                    vis.on_complete("ERROR", 0.0, scan_result, error=error_msg)
            except Exception:
                pass

        if hasattr(self, "_core_3d") and self._core_3d:
            try:
                self._core_3d.set_state("ANALYSIS_ERROR")
            except Exception:
                pass

        if hasattr(self, "_stage_badge"):
            self._stage_badge.configure(text="STAGE: ERROR", text_color=C["red"])
        if hasattr(self, "_active_path_label"):
            self._active_path_label.configure(text="No active scan in progress", text_color=C["muted"])

        error_origin = (
            "CONTROLLED_SIMULATION"
            if scan_result is not None
            and (
                getattr(scan_result, "is_simulation", False)
                or getattr(scan_result, "scan_origin", "") == "CONTROLLED_SIMULATION"
            )
            else "LIVE_HOST_SCAN"
        )
        demo_model = getattr(scan_result, "model_source", "") == "DEMO_MODE_SIMULATED_DATA"
        self._record_scan_history(
            scan_result=scan_result,
            outcome="error",
            token=token,
            error_message=error_msg,
            scan_origin=error_origin,
            model_source="DEMO_MODE_SIMULATED_DATA" if demo_model else None,
        )

        self.update_threat_status("ERROR", 0.0, is_simulation=False)
        self._threat_level = "ERROR"

        self._scan_btn.configure(text="\u26a1 Fast Live Scan", state="normal")
        if self._sim_btn:
            self._sim_btn.configure(state="normal")
        if self._clean_btn:
            self._clean_btn.configure(state="normal")

        log.error("Scan failed: %s", error_msg)

    # ── Cancel Button Lifecycle ───────────────────────────────────────────
    def _set_cancel_button_state(self, mode: str) -> None:
        """Set visual and functional state of the Cancel button ('idle', 'scanning', 'cancelling')."""
        if not hasattr(self, "_cancel_scan_btn"):
            return
        try:
            if not self._cancel_scan_btn.winfo_exists():
                return
        except Exception:
            return

        if mode == "scanning":
            self._cancel_scan_btn.configure(
                text="\u2715 Cancel",
                state="normal",
                fg_color="#2b1a1a",
                hover_color="#3d2424",
                border_color="#f85149",
                text_color="#ff7b72",
                text_color_disabled="#8b949e",
                cursor="hand2",
            )
        elif mode == "cancelling":
            self._cancel_scan_btn.configure(
                text="Cancelling\u2026",
                state="disabled",
                fg_color="#1a1515",
                hover_color="#1a1515",
                border_color="#482424",
                text_color="#8b949e",
                text_color_disabled="#8b949e",
                cursor="arrow",
            )
        else:
            self._cancel_scan_btn.configure(
                text="\u2715 Cancel",
                state="disabled",
                fg_color="transparent",
                hover_color="#161b22",
                border_color="#262c36",
                text_color="#484f58",
                text_color_disabled="#484f58",
                cursor="arrow",
            )

    def cancel_scan(self) -> None:
        """Cancel the active host scan."""
        if not getattr(self, "_scanning", False) or getattr(self, "_cancel_requested_flag", False):
            return

        log.info("User requested cancellation of active scan")
        self._cancel_requested_flag = True

        if hasattr(self, "_core_3d") and self._core_3d:
            try:
                self._core_3d.set_state("SCAN_INCOMPLETE")
            except Exception:
                pass

        if self._active_engine:
            try:
                self._active_engine.cancel()
            except Exception:
                pass

        self._set_cancel_button_state("cancelling")
        if hasattr(self, "_stage_badge"):
            self._stage_badge.configure(text="STAGE: CANCELLING", text_color=C["orange"])
        if hasattr(self, "_active_path_label"):
            self._active_path_label.configure(text="Cancellation requested...", text_color=C["muted"])

    # ── Scan Audit History (persistent, latest 10) ────────────────────────
    def _record_scan_history(
        self,
        scan_result=None,
        *,
        outcome: str = "completed",
        token: Optional[str] = None,
        error_message: Optional[str] = None,
        scan_origin: Optional[str] = None,
        model_source: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Single authoritative audit recorder for terminal scan callbacks.

        Only scans registered by ``start_live_host_scan`` are recorded, so a
        callback for a scan that never started cannot create an entry. Duplicate
        callbacks resolve to the same ``scan_id`` and update in place.
        """
        try:
            if not getattr(self, "_scan_started", False):
                log.info("Audit record skipped: no scan start was registered")
                return None

            started_at = getattr(self, "_scan_started_at", None)
            self._scan_started = False
            self._scan_started_at = None

            record = build_audit_record(
                scan_result,
                outcome=outcome,
                started_at=started_at,
                error_message=error_message,
                scan_origin=scan_origin,
                model_source=model_source,
                app_version=APP_VERSION,
            )
            stored, created = self._audit_store.append(record)
            self._load_audit_history()

            for entry in self._scan_history:
                if entry.get("audit_id") == stored.get("audit_id"):
                    entry["_scan_result"] = scan_result
                    break

            if getattr(self, "_view_segmented", None) and self._view_segmented.get() == "Scan Audit History":
                self._render_scan_history_table(force=True)

            log.info(
                "Scan audit %s %s (%s)",
                stored.get("audit_id"),
                "created" if created else "updated",
                stored.get("classification"),
            )
            return stored
        except Exception:
            log.exception("Failed to record scan audit history")
            return None

    def _load_audit_history(self) -> None:
        """Load persisted audit records and keep live ScanResult objects in memory."""
        try:
            records = self._audit_store.records()
        except Exception:
            log.exception("Failed to read persisted scan audit history")
            records = []

        live_results = {
            entry.get("audit_id"): entry.get("_scan_result")
            for entry in self._scan_history
            if isinstance(entry, dict) and entry.get("_scan_result") is not None
        }
        entries: List[Dict[str, Any]] = []
        for rec in records:
            entry = dict(rec)
            live = live_results.get(entry.get("audit_id"))
            if live is not None:
                entry["_scan_result"] = live
            entries.append(entry)
        self._scan_history = entries
        self._update_history_subtitle()

    def _update_history_subtitle(self) -> None:
        lbl = getattr(self, "_feed_subtitle", None)
        if lbl is None:
            return
        try:
            viewing_history = (
                getattr(self, "_view_segmented", None) is not None
                and self._view_segmented.get() == "Scan Audit History"
            )
            if viewing_history:
                lbl.configure(
                    text=(
                        f"\u2014 {len(self._scan_history)} of {MAX_AUDIT_RECORDS} "
                        "persisted audit records (newest first)"
                    )
                )
        except Exception:
            pass

    @staticmethod
    def _audit_items_text(entry: Dict[str, Any]) -> str:
        files = entry.get("files_examined")
        procs = entry.get("processes_examined")
        bits = []
        if files is not None:
            try:
                bits.append(f"{int(files):,} files")
            except Exception:
                bits.append("files N/A")
        if procs is not None:
            try:
                bits.append(f"{int(procs):,} procs")
            except Exception:
                bits.append("procs N/A")
        return " \u00b7 ".join(bits) if bits else "N/A"

    @staticmethod
    def _audit_duration_text(entry: Dict[str, Any]) -> str:
        value = entry.get("duration_s")
        if value is None:
            return "N/A"
        try:
            return f"{float(value):.2f}s"
        except Exception:
            return "N/A"

    @staticmethod
    def _audit_severity_colour(severity: str) -> str:
        return {
            "CRITICAL": C["red"],
            "MEDIUM": C["yellow"],
            "NONE": C["green"],
            "UNKNOWN": C["orange"],
        }.get(severity, C["muted"])

    def _render_scan_history_table(self, force: bool = False) -> None:
        """Render the persistent audit table (newest first) without clearing records."""
        try:
            sig = tuple(
                (
                    e.get("audit_id"),
                    e.get("classification"),
                    e.get("completed_at"),
                    e.get("files_examined"),
                    e.get("processes_examined"),
                    e.get("findings"),
                )
                for e in self._scan_history
            ) + (
                getattr(self._audit_store, "load_error", ""),
                getattr(self._audit_store, "last_error", ""),
            )
            if (
                not force
                and sig == getattr(self, "_rendered_history_sig", None)
                and getattr(self, "_history_container", None) is not None
            ):
                return

            new_container = ctk.CTkFrame(self._history_scroll, fg_color="transparent")

            summary = ctk.CTkFrame(new_container, fg_color="transparent")
            summary.pack(fill="x", padx=4, pady=(2, 6))
            ctk.CTkLabel(
                summary,
                text=f"RECORDS: {len(self._scan_history)} / {MAX_AUDIT_RECORDS}",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=C["accent2"],
            ).pack(side="left")
            ctk.CTkLabel(
                summary,
                text="  Completed scan attempts only \u00b7 Live SOC refreshes are never counted",
                font=ctk.CTkFont(size=10),
                text_color=C["muted"],
            ).pack(side="left")

            load_error = str(getattr(self._audit_store, "load_error", "") or "")
            save_error = str(getattr(self._audit_store, "last_error", "") or "")
            load_error = load_error or save_error
            if load_error:
                ctk.CTkLabel(
                    summary,
                    text=f"Storage notice: {load_error}",
                    font=ctk.CTkFont(size=10),
                    text_color=C["yellow"],
                    anchor="e",
                    justify="right",
                    wraplength=380,
                ).pack(side="right")

            if not self._scan_history:
                empty_box = ctk.CTkFrame(new_container, fg_color="transparent")
                empty_box.pack(fill="both", expand=True, pady=30)
                ctk.CTkLabel(
                    empty_box,
                    text="No completed scans recorded yet.",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=C["muted"],
                ).pack()
                ctk.CTkLabel(
                    empty_box,
                    text=(
                        "Run a Fast Live Scan. The latest 10 completed scans are saved to "
                        "scan_audit_history.json and remain available after restart."
                    ),
                    font=ctk.CTkFont(size=12),
                    text_color=C["muted"],
                ).pack(pady=(4, 0))
            else:
                hdr_frame = ctk.CTkFrame(new_container, fg_color="#121824", corner_radius=6)
                hdr_frame.pack(fill="x", padx=4, pady=(2, 6))
                hdr_frame.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

                col_defs = [
                    ("SCAN TIME", 150, "w"),
                    ("RESULT", 100, "w"),
                    ("SEVERITY", 95, "w"),
                    ("DURATION", 80, "w"),
                    ("ITEMS EXAMINED", 165, "w"),
                    ("FINDINGS", 80, "w"),
                    ("DETAILS", 80, "e"),
                ]
                for i, (name, width, anchor) in enumerate(col_defs):
                    ctk.CTkLabel(
                        hdr_frame,
                        text=name,
                        font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                        text_color=C["muted"],
                        anchor=anchor,
                        width=width,
                    ).grid(row=0, column=i, padx=6, pady=6, sticky="ew")

                for idx, entry in enumerate(self._scan_history):
                    is_latest = (idx == 0)
                    row_bg = "#111a2d" if is_latest else "#0e1422"
                    row_f = ctk.CTkFrame(
                        new_container,
                        fg_color=row_bg,
                        corner_radius=6,
                        border_width=1 if is_latest else 0,
                        border_color=C["accent"] if is_latest else "#0e1422",
                    )
                    row_f.pack(fill="x", padx=4, pady=3)
                    row_f.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

                    time_f = ctk.CTkFrame(row_f, fg_color="transparent")
                    time_f.grid(row=0, column=0, padx=6, pady=8, sticky="w")
                    ctk.CTkLabel(
                        time_f,
                        text=str(entry.get("completed_at") or "N/A"),
                        font=ctk.CTkFont(family="Consolas", size=10, weight="bold" if is_latest else "normal"),
                        text_color=C["accent"] if is_latest else C["white"],
                        anchor="w",
                    ).pack(side="left")
                    if is_latest:
                        ctk.CTkLabel(
                            time_f,
                            text=" LATEST ",
                            font=ctk.CTkFont(family="Consolas", size=8, weight="bold"),
                            text_color="#0d1117",
                            fg_color=C["accent"],
                            corner_radius=3,
                            height=16,
                        ).pack(side="left", padx=(6, 0))

                    classification = str(entry.get("classification") or "INCONCLUSIVE")
                    v_color = {
                        "SAFE": C["green"],
                        "WARNING": C["yellow"],
                        "CRITICAL": C["red"],
                        "FAILED": C["red"],
                        "INCONCLUSIVE": C["orange"],
                    }.get(classification, C["muted"])
                    v_bg = {
                        "SAFE": "#0c281e",
                        "WARNING": "#2b2010",
                        "CRITICAL": "#2b1010",
                        "FAILED": "#2b1010",
                        "INCONCLUSIVE": "#2b1e10",
                    }.get(classification, "#182030")

                    v_frame = ctk.CTkFrame(row_f, fg_color=v_bg, corner_radius=4)
                    v_frame.grid(row=0, column=1, padx=6, pady=6, sticky="w")
                    ctk.CTkLabel(
                        v_frame,
                        text=f" {classification} ",
                        font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                        text_color=v_color,
                        height=20,
                    ).pack(padx=4, pady=1)

                    severity = str(entry.get("severity") or "UNKNOWN")
                    ctk.CTkLabel(
                        row_f,
                        text=severity,
                        font=ctk.CTkFont(size=10, weight="bold"),
                        text_color=self._audit_severity_colour(severity),
                        anchor="w",
                        width=95,
                    ).grid(row=0, column=2, padx=6, pady=8, sticky="w")

                    ctk.CTkLabel(
                        row_f,
                        text=self._audit_duration_text(entry),
                        font=ctk.CTkFont(family="Consolas", size=11),
                        text_color=C["muted"],
                        anchor="w",
                        width=80,
                    ).grid(row=0, column=3, padx=6, pady=8, sticky="w")

                    ctk.CTkLabel(
                        row_f,
                        text=self._audit_items_text(entry),
                        font=ctk.CTkFont(size=11),
                        text_color=C["white"],
                        anchor="w",
                        width=165,
                    ).grid(row=0, column=4, padx=6, pady=8, sticky="w")

                    findings = entry.get("findings")
                    findings_text = "N/A" if findings is None else str(findings)
                    ctk.CTkLabel(
                        row_f,
                        text=findings_text,
                        font=ctk.CTkFont(family="Consolas", size=11),
                        text_color=C["muted"] if findings is None else C["white"],
                        anchor="w",
                        width=80,
                    ).grid(row=0, column=5, padx=6, pady=8, sticky="w")

                    ctk.CTkButton(
                        row_f,
                        text="Details",
                        font=ctk.CTkFont(size=10),
                        width=76,
                        height=24,
                        fg_color=C["card"],
                        hover_color=C["border"],
                        text_color=C["white"],
                        border_width=1,
                        border_color=C["border"],
                        command=lambda r=entry: self._open_audit_detail(r),
                    ).grid(row=0, column=6, padx=(6, 10), pady=6, sticky="e")

            new_container.pack(fill="x", expand=True)

            old_container = getattr(self, "_history_container", None)
            if old_container and old_container.winfo_exists():
                try:
                    old_container.destroy()
                except Exception:
                    pass

            self._history_container = new_container
            self._rendered_history_sig = sig
        except Exception as e:
            log.error("Failed to render scan history table: %s", e)

    def _open_audit_detail(self, record: Dict[str, Any]) -> None:
        """Detail view for one persisted audit record."""
        if not isinstance(record, dict):
            return
        try:
            win = ctk.CTkToplevel(self)
            win.title("Scan Audit Details")
            win.geometry("680x640")
            win.minsize(520, 480)
            win.configure(fg_color=C["bg"])
            win.transient(self.winfo_toplevel())

            header = ctk.CTkFrame(win, fg_color=C["panel"], corner_radius=10)
            header.pack(fill="x", padx=16, pady=(16, 8))
            ctk.CTkLabel(
                header,
                text="SCAN AUDIT RECORD",
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                text_color=C["muted"],
            ).pack(anchor="w", padx=14, pady=(10, 0))
            classification = str(record.get("classification") or "INCONCLUSIVE")
            ctk.CTkLabel(
                header,
                text=classification,
                font=ctk.CTkFont(size=22, weight="bold"),
                text_color={
                    "SAFE": C["green"],
                    "WARNING": C["yellow"],
                    "CRITICAL": C["red"],
                    "FAILED": C["red"],
                    "INCONCLUSIVE": C["orange"],
                }.get(classification, C["muted"]),
            ).pack(anchor="w", padx=14)
            ctk.CTkLabel(
                header,
                text=str(record.get("audit_id") or ""),
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=C["muted"],
            ).pack(anchor="w", padx=14, pady=(0, 10))

            body = ctk.CTkScrollableFrame(win, fg_color=C["panel"], corner_radius=10)
            body.pack(fill="both", expand=True, padx=16, pady=(0, 8))
            body.grid_columnconfigure(0, weight=0)
            body.grid_columnconfigure(1, weight=1)

            def _pct(value):
                if value is None:
                    return "N/A"
                try:
                    return f"{float(value) * 100:.1f}%"
                except Exception:
                    return "N/A"

            def _count(value):
                if value is None:
                    return "N/A"
                try:
                    return f"{int(value):,}"
                except Exception:
                    return "N/A"

            missing = record.get("missing_features") or []
            fields = [
                ("Scan ID", record.get("scan_id") or "N/A"),
                ("Scan type", record.get("scan_type") or "N/A"),
                ("Started", record.get("started_at") or "N/A"),
                ("Completed", record.get("completed_at") or "N/A"),
                ("Duration", self._audit_duration_text(record)),
                ("Severity", record.get("severity") or "N/A"),
                ("ML probability", _pct(record.get("probability"))),
                ("Files examined", _count(record.get("files_examined"))),
                ("Processes examined", _count(record.get("processes_examined"))),
                ("Findings", _count(record.get("findings"))),
                ("Telemetry coverage", _pct(record.get("coverage_ratio"))),
                ("Provenance", record.get("provenance") or "N/A"),
                ("Model source", record.get("model_source") or "N/A"),
                ("App version", record.get("app_version") or "N/A"),
                ("Missing features", ", ".join(str(m) for m in missing) if missing else "None recorded"),
                ("Explanation", record.get("error") or "No error or incomplete-scan condition recorded."),
                ("Record source", record.get("source") or "SCAN_AUDIT"),
            ]
            for row_idx, (label, value) in enumerate(fields):
                ctk.CTkLabel(
                    body,
                    text=label.upper(),
                    font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                    text_color=C["muted"],
                    anchor="nw",
                    width=170,
                ).grid(row=row_idx, column=0, padx=(10, 12), pady=5, sticky="nw")
                ctk.CTkLabel(
                    body,
                    text=str(value),
                    font=ctk.CTkFont(size=12),
                    text_color=C["white"],
                    anchor="w",
                    justify="left",
                    wraplength=420,
                ).grid(row=row_idx, column=1, padx=(0, 12), pady=5, sticky="ew")

            ctk.CTkLabel(
                win,
                text=(
                    "ML probability is a probabilistic model output. The 95.67% figure is an "
                    "offline benchmark, not a measured real-world detection rate."
                ),
                font=ctk.CTkFont(size=10),
                text_color=C["muted"],
                wraplength=620,
                justify="left",
            ).pack(anchor="w", padx=18)

            actions = ctk.CTkFrame(win, fg_color="transparent")
            actions.pack(fill="x", padx=16, pady=(6, 14))

            live_result = record.get("_scan_result")
            evidence_btn = ctk.CTkButton(
                actions,
                text="Open full evidence",
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color=C["accent"],
                hover_color="#00b894",
                text_color="#04120e",
                command=lambda r=live_result: self._open_audit_evidence(r),
            )
            evidence_btn.pack(side="left")
            if live_result is None:
                evidence_btn.configure(state="disabled")
                ctk.CTkLabel(
                    actions,
                    text="Full evidence is attached only to scans run in this session.",
                    font=ctk.CTkFont(size=10),
                    text_color=C["muted"],
                ).pack(side="left", padx=(10, 0))

            ctk.CTkButton(
                actions,
                text="Close",
                font=ctk.CTkFont(size=12),
                width=90,
                fg_color=C["card"],
                hover_color=C["border"],
                text_color=C["white"],
                border_width=1,
                border_color=C["border"],
                command=win.destroy,
            ).pack(side="right")

            win.after(50, win.lift)
            win.after(80, win.focus_force)
        except Exception:
            log.exception("Failed to open scan audit detail view")

    def _open_audit_evidence(self, scan_result) -> None:
        if scan_result is None:
            return
        try:
            is_sim = bool(
                getattr(scan_result, "is_simulation", False)
                or getattr(scan_result, "scan_origin", "") == "CONTROLLED_SIMULATION"
            )
            self._open_evidence_dialog(scan_result, is_sim)
        except Exception:
            log.exception("Failed to open evidence dialog for audit record")

    def _on_switch_view(self, value: str) -> None:
        """Toggle between Live SOC Feed and Scan Audit History without destroying visible records."""
        if value == "Live SOC Feed":
            if hasattr(self, "_history_scroll"):
                self._history_scroll.grid_remove()
            self._feed_scroll.grid(row=self._header_row + 5, column=0, columnspan=3, sticky="nsew", padx=28, pady=(0, 20))
            if hasattr(self, "_feed_subtitle"):
                self._feed_subtitle.configure(text="\u2014 Real-time security telemetry & alert events")
            self._refresh_activity_feed()
        else:
            self._feed_scroll.grid_remove()
            if hasattr(self, "_history_scroll"):
                self._history_scroll.grid(row=self._header_row + 5, column=0, columnspan=3, sticky="nsew", padx=28, pady=(0, 20))
            self._load_audit_history()
            self._render_scan_history_table(force=True)

    def _on_refresh_current_view(self) -> None:
        current = self._view_segmented.get() if hasattr(self, "_view_segmented") else "Live SOC Feed"
        if current == "Live SOC Feed":
            self._refresh_activity_feed(force=True)
        else:
            try:
                self._audit_store.reload()
            except Exception:
                log.exception("Failed to reload persisted scan audit history")
            self._load_audit_history()
            self._render_scan_history_table(force=True)

    # ── Live Activity Feed ────────────────────────────────────────────────
    def _refresh_activity_feed(self, force: bool = False) -> None:
        """Load and render real alerts and events from AlertManager without clearing visible history."""
        try:
            manager = get_alert_manager()
            alerts = manager.get_alerts(limit=25)

            sig = tuple((a.get("timestamp"), a.get("title"), a.get("severity")) for a in alerts)
            if not force and sig == getattr(self, "_rendered_alerts_sig", None) and getattr(self, "_feed_container", None) is not None:
                return

            new_container = ctk.CTkFrame(self._feed_scroll, fg_color="transparent")

            if not alerts:
                empty_box = ctk.CTkFrame(new_container, fg_color="transparent")
                empty_box.pack(fill="both", expand=True, pady=30)
                ctk.CTkLabel(
                    empty_box,
                    text="No recent security alerts recorded.",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=C["muted"],
                ).pack()
                ctk.CTkLabel(
                    empty_box,
                    text="Run a 'Fast Live Scan' to inspect the host.",
                    font=ctk.CTkFont(size=12),
                    text_color=C["muted"],
                ).pack(pady=(4, 0))
            else:
                for alert in alerts:
                    self._render_alert_card(alert, parent=new_container)

            new_container.pack(fill="x", expand=True)

            old_container = getattr(self, "_feed_container", None)
            if old_container and old_container.winfo_exists():
                try:
                    old_container.destroy()
                except Exception:
                    pass

            self._feed_container = new_container
            self._rendered_alerts_sig = sig
        except Exception as e:
            log.error("Failed to refresh activity feed: %s", e)

    def _render_alert_card(self, alert: Dict[str, Any], parent=None) -> None:
        """Render a single alert card in the feed."""
        target_parent = parent if parent is not None else (getattr(self, "_feed_container", None) or self._feed_scroll)

        severity = str(alert.get("severity", "INFO")).upper()
        sev_color = {
            "CRITICAL": C["red"],
            "HIGH": C["orange"],
            "MEDIUM": C["yellow"],
            "WARNING": C["yellow"],
            "LOW": C["accent2"],
            "INFO": C["muted"],
        }.get(severity, C["muted"])
        sev_bg = {
            "CRITICAL": "#2b1010",
            "HIGH": "#2b1e10",
            "MEDIUM": "#2b2010",
            "WARNING": "#2b2010",
            "LOW": "#0c223a",
            "INFO": "#182030",
        }.get(severity, "#182030")

        card = ctk.CTkFrame(
            target_parent,
            fg_color="#0e1422",
            corner_radius=8,
            border_width=1,
            border_color="#1c2636",
        )
        card.pack(fill="x", padx=4, pady=3)
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            card,
            text=f" {severity} ",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=sev_color,
            fg_color=sev_bg,
            corner_radius=4,
            height=18,
            width=76,
        ).grid(row=0, column=0, padx=(10, 8), pady=(8, 2), sticky="nw")

        ctk.CTkLabel(
            card,
            text=str(alert.get("title", "Security Event")),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["white"],
            anchor="w",
        ).grid(row=0, column=1, padx=(0, 10), pady=(8, 2), sticky="w")

        ctk.CTkLabel(
            card,
            text=str(alert.get("message", "")),
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
            anchor="w",
            justify="left",
            wraplength=760,
        ).grid(row=1, column=1, padx=(0, 10), pady=(0, 2), sticky="w")

        meta_bits = []
        if alert.get("source"):
            meta_bits.append(f"Source: {alert.get('source')}")
        if alert.get("category"):
            meta_bits.append(f"Category: {alert.get('category')}")
        if alert.get("timestamp"):
            meta_bits.append(f"Time: {alert.get('timestamp')}")
        ctk.CTkLabel(
            card,
            text="   \u2022   ".join(meta_bits),
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["muted"],
            anchor="w",
        ).grid(row=2, column=1, padx=(0, 10), pady=(0, 8), sticky="w")

    # ── Classification Model ──────────────────────────────────────────────
    def _classify_result(
        self,
        level: str,
        probability,
        scan_result: Optional[ScanResult],
        is_simulation: bool = False,
    ) -> Dict[str, Any]:
        """Build a unified display classification from a scan result and probability."""
        prob, pct, status = normalize_risk_score(probability)
        if status != "VALID":
            return {
                "tag": "ERROR",
                "title": "SCAN ERROR",
                "badge": "  [INCOMPLETE]  ",
                "risk_label": "ERROR",
                "desc": "Analysis failed: model output violated the probability contract. No security classification available.",
                "color": C["orange"],
                "desc_color": C["red"],
                "badge_color": "#f59e0b",
                "badge_bg": "#2b1010",
                "is_borderline": False,
                "borderline_note": "",
                "is_simulation": False,
                "valid": False,
                "prob": 0.0,
                "pct": 0,
            }

        level_u = str(level or "").upper()
        sim = bool(
            is_simulation
            or getattr(scan_result, "is_simulation", False)
            or getattr(scan_result, "scan_origin", "") == "CONTROLLED_SIMULATION"
        )

        # 0. Error / incomplete / inconclusive terminal states
        if level_u in ("ERROR", "ANALYSIS_ERROR") or getattr(scan_result, "state", None) in (
            ScanState.ERROR,
            ScanState.ANALYSIS_ERROR,
        ):
            err = getattr(scan_result, "error_message", "") or "Analysis failed"
            return {
                "tag": "ERROR",
                "title": "SCAN ERROR",
                "badge": "  [INCOMPLETE]  ",
                "risk_label": "ERROR",
                "desc": f"Analysis failed: {err}. No security classification can be determined.",
                "color": C["orange"],
                "desc_color": C["red"],
                "badge_color": "#f59e0b",
                "badge_bg": "#2b1010",
                "is_borderline": False,
                "borderline_note": "",
                "is_simulation": sim,
                "valid": True,
                "prob": prob,
                "pct": pct,
            }

        if (
            level_u in ("SCAN_INCOMPLETE", "CANCELLED")
            or getattr(scan_result, "cancelled", False)
            or getattr(scan_result, "state", None) == ScanState.SCAN_INCOMPLETE
        ):
            return {
                "tag": "CANCELLED",
                "title": "SCAN CANCELLED",
                "badge": "  [INCOMPLETE \u2014 CANCELLED]  ",
                "risk_label": "CANCELLED",
                "desc": "Scan was stopped before completion. Partial results discarded to prevent false safety claims.",
                "color": C["orange"],
                "desc_color": C["white"],
                "badge_color": "#f59e0b",
                "badge_bg": "#2b1e10",
                "is_borderline": False,
                "borderline_note": "",
                "is_simulation": sim,
                "valid": True,
                "prob": prob,
                "pct": pct,
            }

        if (
            level_u in ("INCONCLUSIVE", "LIMITED_COVERAGE")
            or getattr(scan_result, "is_inconclusive", False)
            or getattr(scan_result, "state", None) in (ScanState.INCONCLUSIVE, ScanState.LIMITED_COVERAGE)
        ):
            total = len(FEATURE_NAMES)
            missing = [str(f) for f in (getattr(scan_result, "missing_features", None) or [])]
            availability = dict(getattr(scan_result, "telemetry_availability", None) or {})
            if not missing and availability:
                missing = [
                    name
                    for name, status in availability.items()
                    if str(status).startswith(("UNAVAILABLE", "RESTRICTED"))
                ]
            missing_count = len(missing)
            available_count = max(0, total - missing_count)
            measured = sum(
                1 for status in availability.values()
                if str(status).startswith("GENUINE_MEASURED")
            )
            proxy = sum(
                1 for status in availability.values()
                if str(status).startswith(("HEURISTIC_PROXY", "SUBSTITUTED"))
            )
            prediction = str(getattr(scan_result, "ml_prediction", "") or "").upper()
            if prediction == "LOW":
                prediction = "SAFE"
            if prediction not in ("SAFE", "WARNING", "CRITICAL"):
                prediction = (
                    "CRITICAL" if prob >= 0.90
                    else "WARNING" if prob >= 0.50
                    else "SAFE"
                )
            coverage = (
                f" ({measured} measured, {proxy} heuristic/substituted)"
                if availability
                else ""
            )
            unavailable = (
                " Unavailable: "
                + ", ".join(
                    name.replace("_count", "").replace("_", " ") for name in missing
                )
                + "."
                if missing
                else ""
            )
            return {
                "tag": "INCONCLUSIVE",
                "title": "INCONCLUSIVE \u2014 LIMITED COVERAGE",
                "badge": "  [LIMITED COVERAGE]  ",
                "risk_label": "INCONCLUSIVE",
                "desc": (
                    f"{_inconclusive_telemetry_notice()}\n"
                    f"ML probability: {pct}% ({prob:.2f}, actual model output). "
                    f"ML prediction: {prediction} (model output only).\n"
                    f"Final security assessment: INCONCLUSIVE \u2014 "
                    f"{missing_count} of {total} sensors unavailable.\n"
                    f"Available telemetry: {available_count} of {total} sensors"
                    f"{coverage}.{unavailable}"
                ),
                "color": C["yellow"],
                "desc_color": C["white"],
                "badge_color": C["yellow"],
                "badge_bg": "#2b2010",
                "is_borderline": False,
                "borderline_note": "",
                "is_simulation": sim,
                "valid": True,
                "prob": prob,
                "pct": pct,
            }

        # 1. Simulation results
        if sim:
            if level_u in ("CRITICAL", "THREAT_DETECTED"):
                sim_level = "CRITICAL"
            elif level_u in ("SAFE", "LOW"):
                sim_level = "SAFE"
            elif level_u == "WARNING":
                sim_level = "WARNING"
            else:
                sim_level = "CRITICAL" if prob >= 0.90 else "WARNING"
            if sim_level == "CRITICAL":
                sim_color = C["red"]
            elif sim_level == "SAFE":
                sim_color = C["green"]
            else:
                sim_color = C["yellow"]
            return {
                "tag": f"{sim_level} [SIMULATION]",
                "title": f"{sim_level} [SIMULATION]",
                "badge": "  [SANDBOX SIMULATION]  ",
                "risk_label": f"{sim_level} (SIM)",
                "desc": (
                    "Controlled behavioral simulation in temp_sandbox/: elevated Shannon entropy and rapid "
                    f"file modification evaluated. ML Probability: {prob * 100:.1f}%. Host files unaffected."
                ),
                "color": sim_color,
                "desc_color": C["white"],
                "badge_color": "#f59e0b",
                "badge_bg": "#2b2010",
                "is_borderline": False,
                "borderline_note": "",
                "is_simulation": True,
                "valid": True,
                "prob": prob,
                "pct": pct,
            }

        # 2. Live host threats
        if level_u in ("CRITICAL", "THREAT_DETECTED") or prob >= 0.90:
            return {
                "tag": "CRITICAL",
                "title": "SYSTEM CRITICAL",
                "badge": "  [LIVE HOST SCAN]  ",
                "risk_label": "CRITICAL",
                "desc": "High-confidence ransomware heuristics detected on host! Immediate defensive isolation advised.",
                "color": C["red"],
                "desc_color": C["red"],
                "badge_color": C["red"],
                "badge_bg": "#2b1010",
                "is_borderline": False,
                "borderline_note": "",
                "is_simulation": False,
                "valid": True,
                "prob": prob,
                "pct": pct,
            }

        if level_u == "WARNING" or prob >= 0.50:
            is_borderline = prob <= 0.55
            note = (
                f" Borderline note: ML probability ({prob * 100:.1f}%) is within 5% of the 50.0% decision threshold."
                if is_borderline
                else ""
            )
            return {
                "tag": "WARNING",
                "title": "SYSTEM WARNING",
                "badge": "  [LIVE HOST SCAN]  ",
                "risk_label": "WARNING",
                "desc": (
                    f"Suspicious behavioral signals observed during host scan (ML Risk: {prob * 100:.1f}%)."
                    f"{note} Review incident evidence."
                ),
                "color": C["yellow"],
                "desc_color": C["white"],
                "badge_color": C["yellow"],
                "badge_bg": "#2b2010",
                "is_borderline": is_borderline,
                "borderline_note": note,
                "is_simulation": False,
                "valid": True,
                "prob": prob,
                "pct": pct,
            }

        # 3. Clean results (prob < 0.50)
        access_denied = getattr(scan_result, "access_denied", 0) or 0
        fs_errors = getattr(scan_result, "filesystem_errors", 0) or 0
        is_partial = scan_result is not None and (access_denied + fs_errors) > 0
        is_quick = scan_result is not None and getattr(scan_result, "scan_type", None) == ScanType.QUICK

        if is_partial:
            is_borderline = prob >= 0.40
            note = (
                f" Borderline note: score ({prob * 100:.1f}%) is within 10% of the 50.0% decision threshold."
                if is_borderline
                else ""
            )
            return {
                "tag": "NO THREATS DETECTED \u2014 LIMITED SCAN",
                "title": "NO THREATS DETECTED \u2014 LIMITED SCAN",
                "badge": "  [LIVE HOST SCAN \u2014 LIMITED]  ",
                "risk_label": "LIMITED (PARTIAL)",
                "desc": (
                    f"No threats detected in accessible files. Caution: {access_denied + fs_errors} path(s) "
                    f"had access denied or errors. Full coverage not guaranteed.{note}"
                ),
                "color": C["yellow"],
                "desc_color": C["white"],
                "badge_color": C["yellow"],
                "badge_bg": "#2b2010",
                "is_borderline": is_borderline,
                "borderline_note": note,
                "is_simulation": False,
                "valid": True,
                "prob": prob,
                "pct": pct,
            }

        if is_quick:
            is_borderline = prob >= 0.40
            note = (
                f" Borderline note: score ({prob * 100:.1f}%) is within 10% of the 50.0% decision boundary."
                if is_borderline
                else ""
            )
            return {
                "tag": "NO THREATS DETECTED \u2014 LIMITED SCAN",
                "title": "NO THREATS DETECTED \u2014 LIMITED SCAN",
                "badge": "  [LIVE HOST SCAN \u2014 LIMITED]  ",
                "risk_label": "CLEAN (LIMITED)",
                "desc": (
                    "Quick Scan (depth=1) clean across monitored roots and running processes. "
                    "Noise folders excluded. Synthetic baseline ML model: probabilistic estimation only."
                    f"{note}"
                ),
                "color": C["green"],
                "desc_color": C["white"],
                "badge_color": C["accent2"],
                "badge_bg": "#0c223a",
                "is_borderline": is_borderline,
                "borderline_note": note,
                "is_simulation": False,
                "valid": True,
                "prob": prob,
                "pct": pct,
            }

        is_borderline = prob >= 0.40
        note = (
            f" Borderline note: score ({prob * 100:.1f}%) is within 10% of the 50.0% decision boundary."
            if is_borderline
            else ""
        )
        return {
            "tag": "SYSTEM SAFE",
            "title": "SYSTEM SAFE",
            "badge": "  [LIVE HOST SCAN]  ",
            "risk_label": "SAFE",
            "desc": f"Full System Scan clean across monitored roots and running processes.{note}",
            "color": C["green"],
            "desc_color": C["white"],
            "badge_color": C["accent"],
            "badge_bg": "#0a2540",
            "is_borderline": is_borderline,
            "borderline_note": note,
            "is_simulation": False,
            "valid": True,
            "prob": prob,
            "pct": pct,
        }

    # ── Public API ────────────────────────────────────────────────────────
    def update_stats(
        self,
        scans: Optional[int] = None,
        threats: Optional[int] = None,
        blocked: Optional[int] = None,
        uptime_s: Optional[int] = None,
    ) -> None:
        """Update stat tiles. Omitted values preserve current counters."""
        if scans is not None:
            self._scans_completed = scans
        if threats is not None:
            self._threats_detected = threats
        if blocked is not None:
            self._blocked_count = blocked

        try:
            self._tile_scans.configure(text=str(self._scans_completed))
            self._tile_threats.configure(text=str(self._threats_detected))
            self._tile_blocked.configure(text=str(getattr(self, "_blocked_count", 0)))
            if uptime_s is not None:
                minutes = int(uptime_s) // 60
                self._tile_uptime.configure(text=f"{minutes}m")
        except Exception:
            pass

    def update_threat_status(
        self,
        level: str,
        probability: float = 0.0,
        is_simulation: bool = False,
        details=None,
    ) -> None:
        """Update all status surfaces from the authoritative classification model."""
        cls = self._classify_result(level, probability, getattr(self, "_last_scan_result", None), is_simulation)

        self._threat_level = "ANALYSIS_ERROR" if not cls["valid"] else level
        if cls["valid"]:
            self._risk_score = cls["prob"]
            self._is_simulation = cls["is_simulation"]
        else:
            self._is_simulation = bool(is_simulation)

        try:
            self._status_dot.configure(text_color=cls["color"])
            self._status_title.configure(text=cls["title"], text_color=cls["color"])
            self._status_badge.configure(
                text=cls["badge"],
                text_color=cls["badge_color"],
                fg_color=cls["badge_bg"],
            )
            self._status_desc.configure(text=cls["desc"], text_color=cls["desc_color"])
        except Exception:
            pass

        show_err = (not cls["valid"]) or cls["tag"] == "ERROR"
        try:
            if not show_err:
                self._risk_score_label.configure(text=f"{cls['pct']}%", text_color=cls["color"])
                self._risk_progress.configure(progress_color=cls["color"])
                self._risk_progress.set(cls["prob"])
            else:
                self._risk_score_label.configure(text="ERR", text_color=C["orange"])
                self._risk_progress.configure(progress_color=C["orange"])
                self._risk_progress.set(0.0)
            self._risk_level_label.configure(text=cls["risk_label"], text_color=cls["color"])
            if not show_err:
                self._tree_votes_label.configure(
                    text=f"{cls['pct']} malicious / {100 - cls['pct']} benign tree votes"
                )
            else:
                self._tree_votes_label.configure(text="Contract violation recorded")
        except Exception:
            pass

        if hasattr(self, "_core_3d") and self._core_3d:
            try:
                if cls["valid"]:
                    if cls["tag"] == "INCONCLUSIVE":
                        core_state = "INCONCLUSIVE"
                    elif cls["is_simulation"]:
                        core_state = "WARNING"
                    elif level in ("CRITICAL", "THREAT_DETECTED") or cls["prob"] >= 0.90:
                        core_state = "THREAT DETECTED"
                    elif level == "WARNING" or cls["prob"] >= 0.50:
                        core_state = "WARNING"
                    elif level in ("SCAN_INCOMPLETE", "CANCELLED"):
                        core_state = "SCAN_INCOMPLETE"
                    else:
                        core_state = "SAFE"
                    self._core_3d.set_state(core_state, cls["prob"])
                else:
                    self._core_3d.set_state("ANALYSIS_ERROR")
            except Exception:
                pass

        # Mirror authoritative state into the sidebar when hosted by MainWindow
        try:
            mw = getattr(self, "_main_window", None)
            if mw and hasattr(mw, "update_sidebar_status"):
                sidebar_map = {
                    "SYSTEM SAFE": ("SAFE", C["green"]),
                    "NO THREATS DETECTED \u2014 LIMITED SCAN": ("LIMITED SCAN", C["yellow"]),
                    "SIMULATION": ("SIMULATION", C["yellow"]),
                    "SYSTEM WARNING": ("WARNING", C["yellow"]),
                    "SYSTEM CRITICAL": ("CRITICAL", C["red"]),
                    "SCAN CANCELLED": ("CANCELLED", C["orange"]),
                    "SCAN ERROR": ("ERROR", C["red"]),
                    "INCONCLUSIVE \u2014 LIMITED COVERAGE": ("INCONCLUSIVE", C["yellow"]),
                }
                key = cls["title"]
                text, color = sidebar_map.get(key, (key, cls["color"]))
                mw.update_sidebar_status(text, color)
        except Exception:
            pass

    def update_guard_status(self, active: bool) -> None:
        """Update guard status indicator."""
        self._guard_active = active
        try:
            if active:
                self._guard_status_label.configure(text="\u2b24 Guard: Active", text_color=C["green"])
            else:
                self._guard_status_label.configure(text="\u2b24 Guard: Inactive", text_color=C["muted"])
        except Exception:
            pass

    # ── Alerts ────────────────────────────────────────────────────────────
    def _generate_scan_alert(
        self,
        threat_level: str,
        probability: float,
        scan_result=None,
        is_simulation: bool = False,
    ) -> None:
        """Persist structured alert into AlertManager."""
        try:
            norm_prob, norm_pct, _ = normalize_risk_score(probability)

            if threat_level in (
                "SAFE",
                "LOW",
                "SCAN_INCOMPLETE",
                "CANCELLED",
                "ERROR",
                "INCONCLUSIVE",
                "LIMITED_COVERAGE",
            ):
                return

            manager = get_alert_manager()

            severity_map = {
                "CRITICAL": "CRITICAL",
                "WARNING": "HIGH",
            }
            title_map = {
                "CRITICAL": "\u26a0 RANSOMWARE DETECTED",
                "WARNING": "Suspicious Activity Detected",
            }

            files_cnt = getattr(scan_result, "files_inspected", 0) if scan_result else 0
            dirs_cnt = getattr(scan_result, "directories_inspected", 0) if scan_result else 0
            procs_cnt = getattr(scan_result, "processes_analyzed", 0) if scan_result else 0
            evidence = f"Scanned {files_cnt} files, {dirs_cnt} directories, and {procs_cnt} processes. "

            if is_simulation:
                title = f"[SIMULATION] {title_map.get(threat_level, 'Threat Detected')}"
                message = (
                    f"Sandbox simulation triggered {threat_level} classification. "
                    f"ML Probability: {norm_pct}%. Result: {threat_level} [SIMULATION]. {evidence}"
                )
                source = "Sandbox Simulation"
                category = "simulation"
            else:
                title = title_map.get(threat_level, "Threat Detected")
                message = (
                    f"{title} with {norm_pct}% confidence. {evidence}"
                    f"Threat classification: {threat_level} (ML: {norm_pct}%)."
                )
                source = "Fast Live Scan"
                category = "scanner"

            metadata = {
                "threat_level": threat_level,
                "probability": norm_prob,
                "scan_id": getattr(scan_result, "scan_id", "") if scan_result else "",
                "files_scanned": files_cnt,
                "dirs_scanned": dirs_cnt,
                "processes_scanned": procs_cnt,
                "elapsed_seconds": getattr(scan_result, "elapsed_seconds", 0.0) if scan_result else 0.0,
                "is_simulation": bool(is_simulation),
            }

            manager.add_alert(
                severity=severity_map.get(threat_level, "MEDIUM"),
                category=category,
                title=title,
                message=message,
                source=source,
                metadata=metadata,
            )
            log.info("Alert generated for threat level: %s", threat_level)
        except Exception as e:
            log.error("Failed to generate alert: %s", e)

    # ── Incident Report Generation ────────────────────────────────────────
    def _generate_incident_report(self, target_result=None) -> None:
        """Backwards-compatible entry point used by the evidence dialog export button."""
        mw = getattr(self, "_main_window", None)
        include_ai = False
        if mw is not None and getattr(mw, "ai_copilot", None):
            try:
                include_ai = messagebox.askyesno(
                    "SentinelAI",
                    "Include an AI-generated summary in this report? (This may take a few seconds)",
                )
            except Exception:
                include_ai = False

        if include_ai:
            self.update_idletasks()

            def _async_report():
                try:
                    ai_summary = mw.ai_copilot.explain_scan(
                        target_result if target_result is not None else self._last_scan_result
                    )
                    self._dispatch_to_main(
                        lambda s=ai_summary: self._do_generate_report(s, target_result=target_result)
                    )
                except Exception as e:
                    self._dispatch_to_main(
                        lambda msg=f"AI failed: {e}": self._do_generate_report(msg, target_result=target_result)
                    )

            threading.Thread(target=_async_report, daemon=True, name="ReportAIThread").start()
        else:
            self._do_generate_report(None, target_result=target_result)

    def _report_scope(self, result) -> Dict[str, str]:
        """Return the exact scope/coverage disclosure block for a result."""
        is_sim = bool(
            getattr(result, "is_simulation", False)
            or getattr(result, "scan_origin", "") == "CONTROLLED_SIMULATION"
        )
        scan_type = getattr(result, "scan_type", None)

        if is_sim:
            return {
                "scope": "Controlled Sandbox Simulation",
                "coverage": "Isolated temporary sandbox directory (temp_sandbox/)",
                "excluded": "Noise/build directories",
                "limitation": "Sandbox execution does not assess live host files",
            }
        if scan_type == ScanType.FULL:
            return {
                "scope": "Full System Scan (Deep: Target Depth = 6)",
                "coverage": "Monitored root directories plus User Home Root Directory",
                "excluded": "Noise/build directories",
                "limitation": "Depth=6 audits nested subfolders",
            }
        if scan_type == ScanType.QUICK:
            return {
                "scope": "Fast Live Scan (Quick: Target Depth = 1)",
                "coverage": "Monitored root directories",
                "excluded": "Noise/build directories",
                "limitation": "Depth=1 focuses on surface drops",
            }
        return {
            "scope": "Custom Target Scan",
            "coverage": "Operator-selected target directories",
            "excluded": "Noise/build directories",
            "limitation": "Only explicitly selected targets are inspected",
        }

    def _do_generate_report(self, ai_summary: str = None, target_result=None) -> None:
        """Write the incident report to a user-selected path."""
        try:
            result = target_result if target_result is not None else getattr(self, "_last_scan_result", None)

            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"SentinelML_Incident_Report_{ts}.txt"

            report_path = filedialog.asksaveasfilename(
                title="Save SentinelML Incident Report",
                initialfile=default_name,
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            )
            if not report_path:
                return

            import socket
            import platform
            hostname = socket.gethostname()
            os_info = platform.system() + " " + platform.release()

            if result is not None:
                raw_prob = getattr(result, "ml_probability", 0.0)
                is_sim = bool(
                    getattr(result, "is_simulation", False)
                    or getattr(result, "scan_origin", "") == "CONTROLLED_SIMULATION"
                )
            else:
                raw_prob = 0.0
                is_sim = False

            if result is not None:
                threat_level = getattr(result, "threat_level", "SAFE")
                cls = self._classify_result(threat_level, raw_prob, result, is_sim)
                origin = "CONTROLLED_SIMULATION" if is_sim else (getattr(result, "scan_origin", "") or "LIVE_HOST_SCAN")
                execution = "Controlled Sandbox Simulation" if is_sim else "Live Host Scan"
                scope = self._report_scope(result)
                scan_id = getattr(result, "scan_id", "") or getattr(result, "_scan_id", "") or "N/A"
                model_source = getattr(result, "model_source", "EXPERIMENTAL_SYNTHETIC_BASELINE_V1")
                ml_prob, ml_pct, _ = normalize_risk_score(raw_prob)
                trees_mal = ml_pct
                trees_ben = 100 - trees_mal
            else:
                cls = self._classify_result("SAFE", 0.0, None, False)
                origin = "LIVE_HOST_SCAN"
                execution = "Live Host Scan"
                scope = self._report_scope(None)
                scan_id = "N/A"
                model_source = "EXPERIMENTAL_SYNTHETIC_BASELINE_V1"
                ml_prob, ml_pct = 0.0, 0
                trees_mal, trees_ben = 0, 100

            report = "SENTINELML V2 INCIDENT REPORT\n"
            report += "===============================\n"
            report += f"Timestamp    : {datetime.datetime.now().isoformat()}\n"
            report += f"Hostname     : {hostname}\n"
            report += f"Platform     : {os_info}\n"
            report += f"Scan ID             : {scan_id}\n"
            report += f"Scan Origin  : {origin}\n"
            report += f"Execution Mode: {execution}\n"
            report += f"Threat Level        : {cls['tag']}\n"

            if cls.get("borderline_note"):
                report += f"Borderline Notice   :{cls['borderline_note']}\n"

            report += "\nSCAN SCOPE & COVERAGE\n---------------------\n"
            report += f"Scan Scope Mode     : {scope['scope']}\n"
            report += f"Coverage Definition : {scope['coverage']}\n"
            report += f"Excluded Folders    : {scope['excluded']}\n"
            report += f"Coverage Limitation : {scope['limitation']}\n"

            report += "\nMODEL PROVENANCE\n----------------\n"
            report += "Model Architecture  : RandomForestClassifier (100 Trees, StandardScaler)\n"
            report += f"Model Provenance    : {model_source}\n"
            report += f"ML Malicious Score  : {ml_prob:.4f} ({ml_pct}% probability)\n"
            report += f"Tree Consensus      : {trees_mal} malicious / {trees_ben} benign\n"

            if result is not None:
                report += "\nSCAN STATISTICS\n---------------\n"
                report += f"Scan State          : {getattr(result, 'state', None).value if getattr(result, 'state', None) else 'UNKNOWN'}\n"
                report += f"Files Inspected     : {getattr(result, 'files_inspected', 0)}\n"
                report += f"Directories         : {getattr(result, 'directories_inspected', 0)}\n"
                report += f"Processes Analyzed  : {getattr(result, 'processes_analyzed', 0)}\n"
                report += f"Access Denied       : {getattr(result, 'access_denied', 0)}\n"
                report += f"Filesystem Errors   : {getattr(result, 'filesystem_errors', 0)}\n"
                report += f"Duration            : {getattr(result, 'elapsed_seconds', 0.0):.2f} seconds\n"

                if getattr(result, "error_message", None):
                    report += f"Errors              : {result.error_message}\n"

                features = getattr(result, "_features", None)
                if features is not None and hasattr(features, "shape") and features.shape == (1, 19):
                    report += "\nML FEATURES (19)\n----------------\n"
                    for name, val in zip(FEATURE_NAMES, features[0].tolist()):
                        report += f"  {name}: {val:.4f}\n"
            else:
                report += "\nNo completed scan result available.\n"

            if ai_summary:
                report += f"\nSENTINELAI ANALYSIS\n-------------------\n{ai_summary}\n"

            report += "\nTELEMETRY & EVIDENCE\n--------------------\n"
            if result is not None:
                coverage = getattr(result, "telemetry_coverage_ratio", None)
                missing = list(getattr(result, "missing_features", []) or [])
                report += ("Sensor Coverage     : "
                           + (f"{coverage * 100:.0f}% of 19 inputs measured"
                              if coverage is not None else "UNAVAILABLE")
                           + "\n")
                report += ("Missing Sensors     : "
                           + (", ".join(missing) if missing else "none reported")
                           + "\n")
            else:
                report += "Sensor Coverage     : UNAVAILABLE — no completed scan result\n"
                report += "Missing Sensors     : UNAVAILABLE\n"
            report += ("Evidence Provenance : "
                       + ("SIMULATED — scripted values, not host measurements.\n" if is_sim
                          else "MEASURED (live host observations).\n"))

            report += "\nLIMITATIONS & UNCERTAINTY\n-------------------------\n"
            for line in REPORT_LIMITATIONS:
                report += f"- {line}\n"

            report += "\nRECOMMENDED NEXT STEPS\n----------------------\n"
            try:
                from exhibition.incident_report import NEXT_STEPS as _NEXT_STEPS
            except Exception:
                _NEXT_STEPS = []
            for i, step in enumerate(_NEXT_STEPS, 1):
                report += f"{i}. {step}\n"

            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report)

            # Also write a machine-readable, provenance-tagged copy alongside.
            self._export_structured_incident(result, report_path, ai_summary)

            if messagebox.askyesno(
                "Report Saved",
                f"Report saved successfully to:\n{report_path}\n\nWould you like to open it now?",
            ):
                import webbrowser
                webbrowser.open(report_path)
        except Exception as e:
            log.error("Failed to generate report: %s", e, exc_info=True)

    def _export_structured_incident(self, result, report_path: str, ai_summary: str = None) -> None:
        """Write the JSON + Markdown investigation report next to the text report."""
        try:
            from pathlib import Path as _Path
            from exhibition.evidence_correlation import EvidenceCorrelator
            from exhibition.report_exporter import ExhibitionReportExporter

            correlator = EvidenceCorrelator()
            if result is not None:
                correlator.add_scan_result(result)
            try:
                manager = get_alert_manager()
                for alert in (manager.get_alerts(limit=25) or []):
                    correlator.add_alert(alert)
            except Exception:
                pass

            target = _Path(report_path)
            paths = ExhibitionReportExporter().export_incident_report(
                scan_result=result,
                correlator=correlator,
                ai_summary=ai_summary,
                output_dir=target.parent,
                stem=target.stem,
            )
            log.info("Structured incident report written: %s, %s",
                     paths["json"].name, paths["md"].name)
        except Exception as exc:
            log.error("Structured incident report export failed: %s", exc)

    # ── Evidence Inspector ────────────────────────────────────────────────
    def _open_evidence_dialog(self, scan_result=None, is_sim_override=None):
        """Open the Incident Evidence & Telemetry Inspector modal."""
        scan_res = scan_result if scan_result is not None else getattr(self, "_last_scan_result", None)
        if scan_res is None:
            try:
                messagebox.showinfo(
                    "No Evidence Available",
                    "No completed scan result is available yet. Run a Fast Live Scan first.",
                )
            except Exception:
                pass
            return None

        is_sim = bool(
            is_sim_override
            if is_sim_override is not None
            else (
                getattr(scan_res, "is_simulation", False)
                or getattr(scan_res, "scan_origin", "") == "CONTROLLED_SIMULATION"
            )
        )

        dlg = ctk.CTkToplevel(self)
        try:
            if is_sim:
                dlg.title("SentinelML V2 \u2014 Simulated Ransomware Evidence & Sandbox Telemetry")
            else:
                dlg.title("SentinelML V2 \u2014 Live Host Detection Evidence & Telemetry Inspector")

            screen_w = dlg.winfo_screenwidth()
            screen_h = dlg.winfo_screenheight()
            dlg_w = min(880, max(680, int(screen_w * 0.85)))
            dlg_h = min(640, max(520, int(screen_h * 0.82)))
            pos_x = max(0, (screen_w - dlg_w) // 2)
            pos_y = max(0, (screen_h - dlg_h) // 2)
            dlg.geometry(f"{dlg_w}x{dlg_h}+{pos_x}+{pos_y}")
            dlg.minsize(min(680, max(320, screen_w - 40)), min(480, max(240, screen_h - 40)))
            dlg.configure(fg_color=C["bg"])
            try:
                dlg.transient(self.winfo_toplevel())
            except Exception:
                pass

            # Fixed action bar (always visible)
            btn_bar = ctk.CTkFrame(dlg, fg_color="#0e1422", corner_radius=0, height=52)
            btn_bar.pack(side="bottom", fill="x")

            ctk.CTkButton(
                btn_bar,
                text="\U0001f4c4 Export Full Incident Report",
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color=C["accent"],
                hover_color="#00b896",
                text_color="#0d1117",
                height=34,
                command=lambda: self._generate_incident_report(target_result=scan_res),
            ).pack(side="left", padx=20, pady=9)

            ctk.CTkButton(
                btn_bar,
                text="\u2715 Close",
                font=ctk.CTkFont(size=12),
                fg_color=C["card"],
                hover_color=C["border"],
                text_color=C["white"],
                border_width=1,
                border_color=C["border"],
                height=34,
                width=100,
                command=dlg.destroy,
            ).pack(side="right", padx=20, pady=9)

            scroll = ctk.CTkScrollableFrame(dlg, fg_color="transparent")
            scroll.pack(side="top", fill="both", expand=True, padx=20, pady=(20, 6))
            scroll.grid_columnconfigure(0, weight=1)

            raw_prob = getattr(scan_res, "ml_probability", 0.0)
            ml_prob, ml_pct, _ = normalize_risk_score(raw_prob)
            threat_lvl = getattr(scan_res, "threat_level", "UNKNOWN")
            cls = self._classify_result(threat_lvl, raw_prob, scan_res, is_sim)
            elapsed = getattr(scan_res, "elapsed_seconds", 0.0)
            scan_id_val = getattr(scan_res, "scan_id", "") or getattr(scan_res, "_scan_id", "N/A")

            # 1. Summary
            summary = ctk.CTkFrame(scroll, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"])
            summary.pack(fill="x", pady=(0, 10))
            ctk.CTkLabel(
                summary,
                text=("SIMULATED EVIDENCE \u2014 CONTROLLED SANDBOX" if is_sim else "LIVE HOST SCAN EVIDENCE"),
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=C["yellow"] if is_sim else C["accent"],
            ).pack(anchor="w", padx=14, pady=(12, 4))
            ctk.CTkLabel(
                summary,
                text=cls["title"],
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color=cls["color"],
            ).pack(anchor="w", padx=14)
            ctk.CTkLabel(
                summary,
                text=(
                    f"Scan ID: {scan_id_val}\n"
                    f"Classification: {cls['tag']}   |   ML Risk Probability: {ml_pct}% ({ml_prob:.4f})   |   "
                    f"Duration: {elapsed:.2f}s   |   State: {getattr(scan_res, 'state', None).value if getattr(scan_res, 'state', None) else 'UNKNOWN'}"
                ),
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=C["white"],
                justify="left",
                anchor="w",
                wraplength=760,
            ).pack(anchor="w", padx=14, pady=(4, 12))

            # 2. Classification narrative
            narrative = ctk.CTkFrame(scroll, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"])
            narrative.pack(fill="x", pady=(0, 10))
            ctk.CTkLabel(
                narrative,
                text="CLASSIFICATION NARRATIVE",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=C["muted"],
            ).pack(anchor="w", padx=14, pady=(10, 2))
            ctk.CTkLabel(
                narrative,
                text=cls["desc"],
                font=ctk.CTkFont(size=11),
                text_color=C["white"],
                justify="left",
                anchor="w",
                wraplength=760,
            ).pack(anchor="w", padx=14, pady=(0, 10))

            # 3. Scope & disclosures
            scope = self._report_scope(scan_res)
            disclosures = ctk.CTkFrame(scroll, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"])
            disclosures.pack(fill="x", pady=(0, 10))
            ctk.CTkLabel(
                disclosures,
                text="SCOPE, COVERAGE & DISCLOSURES",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=C["muted"],
            ).pack(anchor="w", padx=14, pady=(10, 2))
            ctk.CTkLabel(
                disclosures,
                text=(
                    f"Scan Scope Mode     : {scope['scope']}\n"
                    f"Coverage Definition : {scope['coverage']}\n"
                    f"Excluded Folders    : {scope['excluded']}\n"
                    f"Coverage Limitation : {scope['limitation']}\n"
                    f"Model Provenance    : {getattr(scan_res, 'model_source', 'EXPERIMENTAL_SYNTHETIC_BASELINE_V1')}"
                ),
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=C["muted"],
                justify="left",
                anchor="w",
                wraplength=760,
            ).pack(anchor="w", padx=14, pady=(0, 10))

            # 4. Telemetry
            telemetry = ctk.CTkFrame(scroll, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"])
            telemetry.pack(fill="x", pady=(0, 10))
            ctk.CTkLabel(
                telemetry,
                text="LIVE TELEMETRY",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=C["muted"],
            ).pack(anchor="w", padx=14, pady=(10, 2))
            ctk.CTkLabel(
                telemetry,
                text=(
                    f"Files Inspected     : {getattr(scan_res, 'files_inspected', 0):,}\n"
                    f"Directories         : {getattr(scan_res, 'directories_inspected', 0):,}\n"
                    f"Processes Analyzed  : {getattr(scan_res, 'processes_analyzed', 0):,}\n"
                    f"Access Denied       : {getattr(scan_res, 'access_denied', 0)}\n"
                    f"Filesystem Errors   : {getattr(scan_res, 'filesystem_errors', 0)}"
                ),
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=C["white"],
                justify="left",
                anchor="w",
            ).pack(anchor="w", padx=14, pady=(0, 10))

            # 5. Feature vector
            features = getattr(scan_res, "_features", None)
            if features is not None and hasattr(features, "shape") and features.shape == (1, 19):
                feat_card = ctk.CTkFrame(scroll, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"])
                feat_card.pack(fill="x", pady=(0, 10))
                ctk.CTkLabel(
                    feat_card,
                    text="19 BEHAVIORAL FEATURES",
                    font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                    text_color=C["muted"],
                ).pack(anchor="w", padx=14, pady=(10, 2))
                lines = []
                for name, val in zip(FEATURE_NAMES, features[0].tolist()):
                    label, method, unit = FEATURE_META.get(name, (name, "", ""))
                    lines.append(f"{label:<30}: {val:>10.4f}  {unit}")
                ctk.CTkLabel(
                    feat_card,
                    text="\n".join(lines),
                    font=ctk.CTkFont(family="Consolas", size=9),
                    text_color=C["white"],
                    justify="left",
                    anchor="w",
                ).pack(anchor="w", padx=14, pady=(0, 10))

            # 6. Tree votes
            votes = ctk.CTkFrame(scroll, fg_color=C["panel"], corner_radius=10, border_width=1, border_color=C["border"])
            votes.pack(fill="x", pady=(0, 10))
            ctk.CTkLabel(
                votes,
                text="RANDOM FOREST CONSENSUS (100 TREES)",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=C["muted"],
            ).pack(anchor="w", padx=14, pady=(10, 2))
            trees_mal = ml_pct
            trees_ben = 100 - trees_mal
            ctk.CTkLabel(
                votes,
                text=f"Malicious votes: {trees_mal}   |   Benign votes: {trees_ben}",
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=C["white"],
                anchor="w",
            ).pack(anchor="w", padx=14, pady=(0, 10))

            dlg.update_idletasks()
            try:
                dlg.lift()
            except Exception:
                pass
            return dlg
        except Exception as e:
            log.error("Failed to open evidence dialog: %s", e, exc_info=True)
            try:
                dlg.destroy()
            except Exception:
                pass
            return None

    # ── Live SOC monitoring panel ─────────────────────────────────────────
    def _build_soc_panel(self, row: int) -> None:
        """Compact status strip for the background SOC refresh loop."""
        card = ctk.CTkFrame(
            self,
            fg_color=C["panel"],
            corner_radius=12,
            border_width=1,
            border_color=C["border"],
        )
        card.grid(row=row, column=0, columnspan=3, sticky="ew", padx=28, pady=(16, 0))
        card.grid_columnconfigure(0, weight=3)
        card.grid_columnconfigure(1, weight=2)

        left = ctk.CTkFrame(card, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(18, 10), pady=(12, 12))
        left.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="socinfo")

        hdr = ctk.CTkFrame(left, fg_color="transparent")
        hdr.grid(row=0, column=0, columnspan=4, sticky="ew")

        self._soc_dot = ctk.CTkLabel(
            hdr, text="\u25cf", font=ctk.CTkFont(size=14), text_color=C["muted"],
        )
        self._soc_dot.pack(side="left")

        self._soc_state = ctk.CTkLabel(
            hdr,
            text="SOC MONITORING",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["white"],
        )
        self._soc_state.pack(side="left", padx=(6, 10))

        self._soc_subtitle = ctk.CTkLabel(
            hdr,
            text="Auto-refresh off",
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
        )
        self._soc_subtitle.pack(side="left")

        self._soc_refresh_btn = ctk.CTkButton(
            hdr,
            text="\u21bb Refresh now",
            font=ctk.CTkFont(size=10),
            width=104,
            height=24,
            fg_color=C["card"],
            hover_color="#22303f",
            text_color=C["white"],
            border_width=1,
            border_color=C["border"],
            command=self._soc_refresh_now,
        )
        self._soc_refresh_btn.pack(side="right")

        self._soc_toggle_btn = ctk.CTkButton(
            hdr,
            text="Start",
            font=ctk.CTkFont(size=10, weight="bold"),
            width=72,
            height=24,
            fg_color=C["accent"],
            hover_color="#00b894",
            text_color="#04120e",
            command=self._soc_toggle,
        )
        self._soc_toggle_btn.pack(side="right", padx=(0, 8))

        self._soc_last_label = self._soc_info_cell(left, 0, "LAST SUCCESSFUL UPDATE")
        self._soc_next_label = self._soc_info_cell(left, 1, "NEXT REFRESH")
        self._soc_quality_label = self._soc_info_cell(left, 2, "DATA QUALITY")
        self._soc_threat_label = self._soc_info_cell(left, 3, "THREATS (24 H)")

        health = ctk.CTkFrame(left, fg_color="transparent")
        health.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(10, 0))
        ctk.CTkLabel(
            health,
            text="TELEMETRY",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=C["muted"],
        ).pack(side="left", padx=(0, 10))
        for key, label in (
            ("process_enumeration", "Processes"),
            ("system_cpu_memory", "CPU/Mem"),
            ("file_metadata", "Files"),
            ("network_connections", "Network"),
            ("event_log", "Event log"),
            ("registry", "Registry"),
            ("security_services", "Services"),
        ):
            chip = ctk.CTkLabel(
                health,
                text=f"\u25cf {label}",
                font=ctk.CTkFont(size=10),
                text_color=C["muted"],
            )
            chip.pack(side="left", padx=(0, 12))
            self._soc_health_labels[key] = chip

        self._soc_warning = ctk.CTkLabel(
            left,
            text="",
            font=ctk.CTkFont(size=10),
            text_color=C["muted"],
            anchor="w",
            justify="left",
            wraplength=720,
        )
        self._soc_warning.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(8, 0))

        right = ctk.CTkFrame(card, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(0, 18), pady=(12, 12))
        ctk.CTkLabel(
            right,
            text="RECENT SOC EVENTS",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=C["muted"],
        ).pack(anchor="w")
        self._soc_event_labels: List[Any] = []
        for _ in range(3):
            lbl = ctk.CTkLabel(
                right,
                text="\u2014",
                font=ctk.CTkFont(size=10),
                text_color=C["muted"],
                anchor="w",
                justify="left",
                wraplength=420,
            )
            lbl.pack(anchor="w", fill="x", pady=(4, 0))
            self._soc_event_labels.append(lbl)

    def _soc_info_cell(self, parent, col: int, title: str):
        box = ctk.CTkFrame(parent, fg_color="transparent")
        box.grid(row=1, column=col, sticky="w", pady=(10, 0), padx=(0, 8))
        ctk.CTkLabel(
            box,
            text=title,
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=C["muted"],
            anchor="w",
        ).pack(anchor="w")
        value = ctk.CTkLabel(
            box,
            text="\u2014",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=C["white"],
            anchor="w",
        )
        value.pack(anchor="w")
        return value

    def _soc_bootstrap(self) -> None:
        """Start the refresh loop only when the loaded config carries SOC settings."""
        if self._is_destroyed:
            return
        soc_cfg = self._config.get("soc") if isinstance(self._config, dict) else None
        if isinstance(soc_cfg, dict):
            depth = soc_cfg.get("file_depth", 1)
            max_files = soc_cfg.get("max_files", 2000)
            self._soc_scope_text = (
                f"File scope: monitored directories only \u00b7 metadata only "
                f"(size + mtime) \u00b7 depth {depth} \u00b7 max {int(max_files):,} files per cycle"
            )
            self._soc_monitor.apply_config(self._config)
            if soc_cfg.get("auto_refresh", True):
                self._soc_start()
        try:
            self._render_soc_status()
        except Exception as exc:
            log.debug("SOC bootstrap render failed: %s", exc)

    def _soc_start(self) -> None:
        if self._is_destroyed:
            return
        self._soc_monitor.apply_config(self._config)
        if self._soc_monitor.start():
            log.info("Live SOC monitoring started (interval=%ss)", self._soc_monitor.interval_seconds)
        try:
            self._render_soc_status()
        except Exception:
            pass

    def _soc_stop(self) -> None:
        self._soc_monitor.stop()
        try:
            self._render_soc_status()
        except Exception:
            pass

    def stop_soc(self, wait: bool = True) -> None:
        """Stop background SOC collection; called from application shutdown."""
        try:
            self._soc_monitor.stop(join_timeout=3.0 if wait else 0.0)
        except Exception:
            log.exception("Failed to stop SOC monitor")
        try:
            self._render_soc_status()
        except Exception:
            pass

    def _soc_toggle(self) -> None:
        if self._soc_monitor.running:
            self._soc_stop()
        else:
            self._soc_start()

    def _soc_refresh_now(self) -> None:
        if not self._soc_monitor.running:
            self._soc_start()
            return
        if self._soc_monitor.refresh_now():
            self._set_soc_note("Refresh requested \u2014 collecting host telemetry\u2026", C["accent2"])
        else:
            self._set_soc_note(
                "A refresh is already running; the queued pass starts when it finishes.",
                C["muted"],
            )
        try:
            self._render_soc_status()
        except Exception:
            pass

    def _soc_tick(self) -> None:
        if self._is_destroyed:
            return
        try:
            self._render_soc_status()
        except Exception as exc:
            log.debug("SOC status render failed: %s", exc)
        self.safe_after(1000, self._soc_tick)

    def _set_soc_note(self, text: str, colour: str) -> None:
        lbl = getattr(self, "_soc_warning", None)
        if lbl is None:
            return
        try:
            lbl.configure(text=text, text_color=colour)
        except Exception:
            pass

    @staticmethod
    def _fmt_age(age) -> str:
        if age is None:
            return "\u2014"
        try:
            age = max(0.0, float(age))
        except Exception:
            return "\u2014"
        if age < 5:
            return "just now"
        if age < 60:
            return f"{int(age)} s ago"
        if age < 3600:
            return f"{int(age // 60)} min ago"
        return f"{int(age // 3600)} h ago"

    @staticmethod
    def _fmt_countdown(seconds) -> str:
        if seconds is None:
            return "\u2014"
        try:
            seconds = max(0.0, float(seconds))
        except Exception:
            return "\u2014"
        if seconds < 1:
            return "due now"
        if seconds < 60:
            return f"in {int(round(seconds))} s"
        return f"in {int(seconds // 60)} min {int(seconds % 60)} s"

    def _render_soc_status(self) -> None:
        if self._is_destroyed:
            return
        status = self._soc_monitor.get_status()
        running = bool(status.get("running"))
        collecting = bool(status.get("collecting"))
        stale = bool(status.get("stale"))
        quality = str(status.get("quality") or "NO_DATA")
        failures = int(status.get("consecutive_failures") or 0)
        interval = int(status.get("interval_s") or 60)

        if collecting:
            label, colour = "COLLECTING", C["accent2"]
        elif running and (stale or failures):
            label, colour = ("STALE", C["red"]) if stale else ("DEGRADED", C["red"])
        elif running:
            label, colour = "MONITORING", C["green"]
        else:
            label, colour = "STOPPED", C["muted"]

        self._soc_dot.configure(text="\u25cf", text_color=colour)
        self._soc_state.configure(text=label, text_color=colour)

        classification = str(status.get("classification") or "NOT_SCANNED")
        if running:
            self._soc_subtitle.configure(
                text=f"Auto-refresh every {interval} s \u00b7 latest scan: {classification}"
            )
        else:
            self._soc_subtitle.configure(text="Auto-refresh off \u00b7 latest scan: " + classification)

        self._soc_toggle_btn.configure(
            text="Stop" if running else "Start",
            fg_color=C["card"] if running else C["accent"],
            hover_color="#22303f" if running else "#00b894",
            text_color=C["white"] if running else "#04120e",
        )
        self._soc_last_label.configure(text=self._fmt_age(status.get("last_success_age_s")))
        self._soc_next_label.configure(
            text=self._fmt_countdown(status.get("next_refresh_in_s")) if running else "\u2014"
        )
        q_colour = {
            "LIVE": C["green"],
            "PARTIAL": C["yellow"],
            "FAILED": C["red"],
        }.get(quality, C["muted"])
        self._soc_quality_label.configure(text=quality.replace("_", " "), text_color=q_colour)

        snapshot = self._soc_latest
        if snapshot is not None:
            threats24 = int((snapshot.threats or {}).get("threats_24h", 0) or 0)
            self._soc_threat_label.configure(
                text=f"{threats24} crit/high",
                text_color=C["red"] if threats24 else C["green"],
            )

        if stale:
            self._set_soc_note(
                "Stale telemetry: no successful refresh within the expected window. "
                "Values shown are the last known snapshot, not current state.",
                C["red"],
            )
        elif failures and running:
            detail = str(status.get("last_error") or "unknown error")
            self._set_soc_note(
                f"Telemetry refresh failed {failures}x \u2014 {detail}. "
                "Unreadable sources are shown as unavailable, never as zero.",
                C["yellow"],
            )
        elif not running:
            self._set_soc_note(
                "Live refresh is stopped. Start it to collect host telemetry every "
                f"{interval} s, or use Refresh now for a single pass.",
                C["muted"],
            )
        else:
            self._set_soc_note(self._soc_scope_text, C["muted"])

    def _on_soc_snapshot(self, snapshot: SOCTelemetry) -> None:
        """Monitor callback (worker thread) — hand off to the Tk main thread."""
        self._dispatch_to_main(self._render_soc_snapshot, snapshot)

    def _render_soc_snapshot(self, snapshot: SOCTelemetry) -> None:
        if self._is_destroyed or snapshot is None:
            return
        if snapshot.seq < self._soc_rendered_seq:
            # A slow background pass must never overwrite a newer snapshot.
            return
        self._soc_rendered_seq = snapshot.seq
        self._soc_latest = snapshot

        status_colours = {
            "available": C["green"],
            "permission_required": C["yellow"],
            "unavailable": C["muted"],
            "error": C["red"],
        }
        suffixes = {
            "permission_required": " (perm)",
            "unavailable": " (n/a)",
            "error": " (err)",
        }
        for key, chip in self._soc_health_labels.items():
            view = (snapshot.capabilities or {}).get(key)
            if not view:
                continue
            status = str(view.get("status", "unavailable"))
            label = str(view.get("label", key))
            chip.configure(
                text=f"\u25cf {label}{suffixes.get(status, '')}",
                text_color=status_colours.get(status, C["muted"]),
            )

        try:
            events = self._soc_monitor.events(limit=3)
        except Exception:
            events = []
        if not events:
            events = list(snapshot.events or [])[:3]
        for idx, lbl in enumerate(self._soc_event_labels):
            if idx < len(events):
                event = events[idx]
                ts = str(event.get("timestamp", ""))
                if len(ts) >= 16 and ts[10] in (" ", "T"):
                    ts = ts[11:16]
                title = str(event.get("title", "Event"))
                severity = str(event.get("severity", "INFO")).upper()
                sev_colour = {
                    "CRITICAL": C["red"],
                    "HIGH": C["orange"],
                    "MEDIUM": C["yellow"],
                }.get(severity, C["muted"])
                lbl.configure(text=f"{ts}  {title}" if ts else title, text_color=sev_colour)
            else:
                lbl.configure(text="\u2014", text_color=C["muted"])

        self._render_soc_status()

    # ── Lifecycle ─────────────────────────────────────────────────────────
    def destroy(self) -> None:
        """Cancel timers and destroy child visualizers before frame destruction."""
        if getattr(self, "_is_destroyed", False):
            try:
                super().destroy()
            except Exception:
                pass
            return

        self._is_destroyed = True
        for aid in list(self._pending_after_ids):
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        self._pending_after_ids.clear()

        try:
            self._soc_monitor.destroy()
        except Exception:
            pass

        for attr in ("_warmed_visualizer", "visualizer"):
            vis = getattr(self, attr, None)
            if vis is not None:
                try:
                    vis.destroy()
                except Exception:
                    pass
                setattr(self, attr, None)

        core = getattr(self, "_core_3d", None)
        if core is not None:
            try:
                core.destroy()
            except Exception:
                pass

        try:
            super().destroy()
        except Exception:
            pass
