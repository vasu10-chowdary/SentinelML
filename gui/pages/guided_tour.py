"""
SentinelML V2 — Guided Exhibition Presentation
============================================
An optional, linear, examiner-facing walkthrough with a clear beginning,
middle and end. Eight stages narrate the project from introduction to
conclusion, while genuinely executing the real pipeline where it matters
(live scan, scenario, timeline, ML result, report).

Controls:
  * Back / Next — navigate stages (Back disabled on stage 1).
  * Progress indicator — "Stage X / 8" with a slim segmented bar.
  * Exit — leave the tour and return to the Exhibition Lab.
  * Restart — return to stage 1 at any time.

Threading contract (hard rule): every ScanEngine/ScenarioRunner operation runs
on a daemon worker thread; results are marshalled to the Tk main thread through
a thread-safe queue drained via ``safe_after``. A per-run token guards stale
callbacks and a destroyed-page flag halts every deferred update on close.
"""

from __future__ import annotations

import logging
import platform
import queue
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import customtkinter as ctk

from constants import APP_VERSION
from gui.exhibition_theme import (
    EX_COLORS,
    severity_color,
    source_color,
    source_label,
    classify_origin_badge,
)
from exhibition.scenario_lab import ScenarioRunner, ScenarioResult, SCENARIOS, SCENARIOS_BY_KEY
from exhibition.investigation_timeline import InvestigationEvent
from exhibition.result_explainer import format_explanation_text
from scanner.live_scanner import get_platform_feature_availability
from ml.predictor import MLPredictor

log = logging.getLogger("sentinel.gui.guided_tour")

# Stage definitions: (key, short title, builder method name).
STAGES = [
    ("intro",      "Introduction & System Health", "_stage_intro"),
    ("platform",   "Platform Capabilities & Telemetry", "_stage_platform"),
    ("scan",       "Live System Scan", "_stage_scan"),
    ("scenarios",  "Interactive Scenario Selection", "_stage_scenarios"),
    ("timeline",  "Threat Investigation Timeline", "_stage_timeline"),
    ("result",    "ML Result & Supporting Evidence", "_stage_result"),
    ("report",    "Incident Report Generation", "_stage_report"),
    ("closing",   "Architecture, Limitations & Conclusion", "_stage_closing"),
]


class GuidedTourPage(ctk.CTkFrame):
    """Guided 8-stage exhibition presentation."""

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=EX_COLORS["bg"], **kwargs)
        self._config = config
        self._is_destroyed = False

        # Threading primitives (Dashboard-style)
        self._ui_queue: queue.Queue = queue.Queue()
        self._pending_after_ids: set = set()
        self._active_token: Optional[str] = None
        self._cancel_requested = False
        self._is_running = False

        self._runner = ScenarioRunner()
        self._runner.bind_sink(self._on_scenario_event)
        self._last_result: Optional[ScenarioResult] = None
        self._report_text = ""

        self._stage_index = 0
        self._stage_builders = {
            "intro": self._stage_intro,
            "platform": self._stage_platform,
            "scan": self._stage_scan,
            "scenarios": self._stage_scenarios,
            "timeline": self._stage_timeline,
            "result": self._stage_result,
            "report": self._stage_report,
            "closing": self._stage_closing,
        }

        self._build_ui()
        self.safe_after(30, self._drain_ui_queue)
        self._render_stage()

    # ======================================================================
    # Threading / UI-safety
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
                    log.warning("Tour UI queue callback failed: %s", exc)
                count += 1
                if count > 200:
                    break
        finally:
            if not getattr(self, "_is_destroyed", False):
                self.safe_after(80, self._drain_ui_queue)

    def destroy(self) -> None:
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
    # UI skeleton
    # ======================================================================
    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Header
        header = ctk.CTkFrame(self, fg_color=EX_COLORS["header"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text="🎯  SENTINELML V2  —  GUIDED EXHIBITION TOUR",
                     font=ctk.CTkFont("Segoe UI", 18, weight="bold"),
                     text_color=EX_COLORS["white"]).grid(row=0, column=0, padx=20, pady=12, sticky="w")

        self._progress_lbl = ctk.CTkLabel(header, text="Stage 1 / 8",
                                          font=ctk.CTkFont("Consolas", 12, weight="bold"),
                                          text_color=EX_COLORS["gold"])
        self._progress_lbl.grid(row=0, column=1, padx=10, pady=12, sticky="w")

        exit_btn = ctk.CTkButton(header, text="✖ Exit Tour", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                                 fg_color="#3d5070", hover_color="#4a6090", text_color=EX_COLORS["white"],
                                 height=32, command=self._exit_tour)
        exit_btn.grid(row=0, column=2, padx=16, pady=10, sticky="e")

        # Progress indicator bar (visual presentation progress)
        self._progress_bar = ctk.CTkProgressBar(self, progress_color=EX_COLORS["gold"],
                                                 fg_color=EX_COLORS["card_border"], height=6)
        self._progress_bar.grid(row=1, column=0, sticky="ew", padx=0, pady=0)
        # Content
        self._content = ctk.CTkFrame(self, fg_color=EX_COLORS["bg"])
        self._content.grid(row=2, column=0, sticky="nsew", padx=14, pady=(6, 6))
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

        # Footer nav
        footer = ctk.CTkFrame(self, fg_color=EX_COLORS["card"], corner_radius=0,
                              border_width=1, border_color=EX_COLORS["card_border"])
        footer.grid(row=3, column=0, sticky="ew")
        footer.grid_columnconfigure(1, weight=1)

        self._back_btn = ctk.CTkButton(footer, text="← Back", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                                       fg_color="#243552", hover_color="#2a5a8a", text_color=EX_COLORS["white"],
                                       height=34, state="disabled", command=self._go_back)
        self._back_btn.grid(row=0, column=0, padx=16, pady=10)

        self._stage_title_lbl = ctk.CTkLabel(footer, text="", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                                             text_color=EX_COLORS["white"])
        self._stage_title_lbl.grid(row=0, column=1, sticky="w")

        self._next_btn = ctk.CTkButton(footer, text="Next →", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                                       fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"],
                                       text_color="#000000", height=34, command=self._go_next)
        self._next_btn.grid(row=0, column=2, padx=16, pady=10, sticky="e")

        restart_btn = ctk.CTkButton(footer, text="↻ Restart", font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                                    fg_color="#1a4a7a", hover_color="#2060a0", text_color=EX_COLORS["cyan"],
                                    height=34, command=self._restart)
        restart_btn.grid(row=0, column=3, padx=(0, 16), pady=10, sticky="e")

    # ======================================================================
    # Stage navigation
    # ======================================================================
    def _render_stage(self) -> None:
        if getattr(self, "_is_destroyed", False):
            return
        for w in list(self._content.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass
        key, title, builder = STAGES[self._stage_index]
        self._stage_title_lbl.configure(text=title)
        self._progress_lbl.configure(text=f"Stage {self._stage_index + 1} / 8")
        try:
            self._progress_bar.set((self._stage_index + 1) / 8.0)
        except Exception:
            pass
        self._back_btn.configure(state="normal" if self._stage_index > 0 else "disabled")
        if self._stage_index == len(STAGES) - 1:
            self._next_btn.configure(text="↻ Restart Tour")
        else:
            self._next_btn.configure(text="Next →")
        try:
            self._stage_builders[key]()
        except Exception as exc:
            log.error("Stage %s render failed: %s", key, exc, exc_info=True)
            ctk.CTkLabel(self._content, text=f"Stage failed to render: {exc}",
                         text_color=EX_COLORS["error"]).pack(padx=20, pady=20, anchor="w")

    def _go_next(self) -> None:
        if self._stage_index == len(STAGES) - 1:
            self._restart()
            return
        if self._is_running:
            return  # don't navigate mid-run; let the examiner finish/cancel
        self._stage_index += 1
        self._render_stage()

    def _go_back(self) -> None:
        if self._is_running:
            return
        if self._stage_index > 0:
            self._stage_index -= 1
            self._render_stage()

    def _restart(self) -> None:
        if self._is_running:
            self._cancel_requested = True
        self._stage_index = 0
        self._render_stage()

    def _exit_tour(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("exhibition_lab")
        else:
            self._back_to_dashboard_safe()

    def _back_to_dashboard_safe(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("dashboard")

    # ======================================================================
    # Stage builders
    # ======================================================================
    def _scroll_body(self) -> ctk.CTkScrollableFrame:
        body = ctk.CTkScrollableFrame(self._content, fg_color=EX_COLORS["panel_dark"])
        body.pack(fill="both", expand=True, padx=10, pady=10)
        body.grid_columnconfigure(0, weight=1)
        return body

    def _section_title(self, parent, text, color=EX_COLORS["gold"]) -> None:
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont("Segoe UI", 15, weight="bold"), text_color=color, anchor="w").pack(fill="x", padx=16, pady=(14, 4))

    def _paragraph(self, parent, text, color=EX_COLORS["muted"]) -> ctk.CTkLabel:
        lbl = ctk.CTkLabel(parent, text=text, font=ctk.CTkFont("Segoe UI", 12), text_color=color, anchor="w", justify="left", wraplength=860)
        lbl.pack(fill="x", padx=16, pady=(0, 6))
        return lbl

    def _stage_intro(self) -> None:
        body = self._scroll_body()
        self._section_title(body, "1. Project Introduction & System Health", EX_COLORS["cyan"])
        self._paragraph(body,
            "SentinelML V2 is a memory-forensics-inspired ransomware recovery predictor. It observes "
            "user-space behavioral telemetry (running processes, file entropy, network sockets, handle "
            "counts), assembles a 19-feature behavioural vector, and evaluates it with a Random Forest "
            "classifier to produce an honest, thresholded security classification.")
        self._paragraph(body,
            "This guided tour narrates the system from health check to conclusion, while genuinely "
            "executing the real pipeline. Scripted demonstration data is always labelled as SIMULATED — "
            "it is never presented as a live malware detection.")
        self._section_title(body, "System Health (genuine status)", EX_COLORS["gold"])
        health = self._collect_health_text()
        ctk.CTkLabel(body, text=health, font=ctk.CTkFont("Consolas", 10), text_color=EX_COLORS["white"],
                     anchor="w", justify="left").pack(fill="x", padx=16, pady=(0, 10))
        self._paragraph(body,
            "Press Next → to examine platform capabilities and telemetry coverage.", EX_COLORS["white"])

    def _stage_platform(self) -> None:
        body = self._scroll_body()
        self._section_title(body, "2. Platform Capabilities & Telemetry Coverage", EX_COLORS["cyan"])
        self._paragraph(body,
            "The 19-feature schema is the contract between telemetry and model. Not every feature is "
            "directly measurable on every platform. SentinelML reports each sensor's status honestly: "
            "GENUINE_MEASURED, HEURISTIC_PROXY, SUBSTITUTED, UNAVAILABLE_PLATFORM, or RESTRICTED_PERMISSION. "
            "Missing measurements are shown as Unavailable — never silently treated as zeros.")
        try:
            avail = get_platform_feature_availability() or {}
        except Exception as exc:
            avail = {}
            self._paragraph(body, f"Sensor enumeration failed: {exc}", EX_COLORS["error"])
        genuine = sum(1 for s in avail.values() if s == "GENUINE_MEASURED")
        proxy = sum(1 for s in avail.values() if s.startswith("HEURISTIC_PROXY") or s.startswith("SUBSTITUTED"))
        unavail = [f for f, s in avail.items() if s.startswith("UNAVAILABLE") or s.startswith("RESTRICTED")]
        self._paragraph(body,
            f"On this host ({sys.platform}): {len(avail)}/19 sensors reported — {genuine} directly measured, "
            f"{proxy} heuristic-proxy/substituted, {len(unavail)} unavailable/restricted"
            + (f" ({', '.join(unavail)})." if unavail else "."),
            EX_COLORS["white"])
        self._section_title(body, "Sensor Availability Map", EX_COLORS["white"])
        order = ["GENUINE_MEASURED", "HEURISTIC_PROXY", "SUBSTITUTED", "UNAVAILABLE_PLATFORM", "RESTRICTED_PERMISSION"]
        lines = []
        for status in order:
            feats = [f for f, s in avail.items() if s == status]
            if feats:
                lines.append(f"[{status}] ({len(feats)}): {', '.join(feats)}")
        if not lines:
            lines.append("Unavailable on this platform.")
        ctk.CTkLabel(body, text="\n".join(lines), font=ctk.CTkFont("Consolas", 10),
                     text_color=EX_COLORS["white"], anchor="w", justify="left").pack(fill="x", padx=16, pady=(0, 10))
        self._paragraph(body, "Press Next → to run a genuine live system scan.", EX_COLORS["white"])

    def _stage_scan(self) -> None:
        body = self._scroll_body()
        self._section_title(body, "3. Live System Scan", EX_COLORS["cyan"])
        self._paragraph(body,
            "This stage runs a real QUICK scan of this host's monitored directories and process table "
            "(Scenario A: Benign System Activity). No files are created, modified or deleted. Watch the "
            "event stream for genuine observations.")
        bar = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8)
        bar.pack(fill="x", padx=16, pady=(0, 8))
        self._scan_status_lbl = ctk.CTkLabel(bar, text="Click ▶ Start Scan to begin.",
                                            font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                                            text_color=EX_COLORS["white"])
        self._scan_status_lbl.pack(side="left", padx=10, pady=8)
        self._scan_start_btn = ctk.CTkButton(bar, text="▶ Start Scan", font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                                             fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"],
                                             text_color="#000000", height=30, command=lambda: self._run_scenario("A"))
        self._scan_start_btn.pack(side="left", padx=6, pady=8)
        self._scan_cancel_btn = ctk.CTkButton(bar, text="✖ Cancel", font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                                              fg_color="#3d5070", hover_color="#4a6090", text_color=EX_COLORS["white"],
                                              height=30, state="disabled", command=self._on_cancel)
        self._scan_cancel_btn.pack(side="left", padx=6, pady=8)

        self._tour_stream = ctk.CTkScrollableFrame(body, fg_color=EX_COLORS["card"], height=260)
        self._tour_stream.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        self._tour_stream.grid_columnconfigure(0, weight=1)
        self._tour_stream_placeholder = ctk.CTkLabel(
            self._tour_stream, text="Awaiting scan…", font=ctk.CTkFont("Segoe UI", 11, slant="italic"),
            text_color=EX_COLORS["muted"])
        self._tour_stream_placeholder.pack(padx=10, pady=14, anchor="w")

        self._scan_result_lbl = ctk.CTkLabel(body, text="", font=ctk.CTkFont("Segoe UI", 11),
                                             text_color=EX_COLORS["muted"], anchor="w", justify="left", wraplength=860)
        self._scan_result_lbl.pack(fill="x", padx=16, pady=(0, 10))
        self._paragraph(body,
            "Once the scan completes, press Next → to select an interactive scenario.", EX_COLORS["white"])

    def _stage_scenarios(self) -> None:
        body = self._scroll_body()
        self._section_title(body, "4. Interactive Scenario Selection", EX_COLORS["cyan"])
        self._paragraph(body,
            "Choose a scenario to explore how SentinelML behaves across the threat spectrum. Scenario B "
            "evaluates a scripted suspicious vector in memory (clearly SIMULATED); C replays harmless "
            "ransomware-like file activity in temp_sandbox/; D injects a sensor outage for an INCONCLUSIVE "
            "result; E demonstrates cancellation and recovery. A is the benign baseline you just ran.")
        self._scenario_btns: Dict[str, ctk.CTkButton] = {}
        grid = ctk.CTkFrame(body, fg_color="transparent")
        grid.pack(fill="x", padx=16, pady=(0, 8))
        for i, spec in enumerate(SCENARIOS):
            r, c = divmod(i, 1)
            card = ctk.CTkFrame(grid, fg_color=EX_COLORS["card"], corner_radius=8,
                                border_width=1, border_color=EX_COLORS["card_border"])
            card.pack(fill="x", padx=4, pady=4)
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=f"{spec.key}. {spec.name}  [{spec.mode}]",
                         font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                         text_color=EX_COLORS["white"], anchor="w").pack(fill="x", padx=10, pady=(8, 2))
            ctk.CTkLabel(card, text=spec.purpose, font=ctk.CTkFont("Segoe UI", 10),
                         text_color=EX_COLORS["muted"], anchor="w", justify="left",
                         wraplength=820).pack(fill="x", padx=10, pady=(0, 2))
            btn = ctk.CTkButton(card, text=f"▶ Run Scenario {spec.key}", font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                                fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"],
                                text_color="#000000", height=30,
                                command=lambda k=spec.key: self._run_scenario(k))
            btn.pack(anchor="w", padx=10, pady=(2, 8))
            self._scenario_btns[spec.key] = btn

        self._scn_status_lbl = ctk.CTkLabel(body, text="", font=ctk.CTkFont("Segoe UI", 11),
                                            text_color=EX_COLORS["muted"], anchor="w", justify="left", wraplength=860)
        self._scn_status_lbl.pack(fill="x", padx=16, pady=(0, 8))
        self._tour_stream2 = ctk.CTkScrollableFrame(body, fg_color=EX_COLORS["card"], height=220)
        self._tour_stream2.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        self._tour_stream2.grid_columnconfigure(0, weight=1)
        self._tour_stream2_placeholder = ctk.CTkLabel(
            self._tour_stream2, text="Select a scenario above to run it.", font=ctk.CTkFont("Segoe UI", 11, slant="italic"),
            text_color=EX_COLORS["muted"])
        self._tour_stream2_placeholder.pack(padx=10, pady=14, anchor="w")
        self._paragraph(body, "After a scenario runs, press Next → to inspect its investigation timeline.", EX_COLORS["white"])

    def _stage_timeline(self) -> None:
        body = self._scroll_body()
        self._section_title(body, "5. Threat Investigation Timeline", EX_COLORS["cyan"])
        if self._last_result is None:
            self._paragraph(body,
                "No scenario has been run yet. Go Back to the Live System Scan or Scenario Selection "
                "stage and run one first.", EX_COLORS["warning"])
            return
        tl = self._last_result.timeline
        self._paragraph(body,
            f"{len(tl)} events recorded (ordered={tl.is_ordered()}). Each event carries a provenance tag "
            f"(MEASURED / SIMULATED / FAILURE INJECTION / APPLICATION) so scripted data is never mistaken "
            f"for a live observation.", EX_COLORS["white"])
        scroll = ctk.CTkScrollableFrame(body, fg_color=EX_COLORS["card"])
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        scroll.grid_columnconfigure(0, weight=1)
        for evt in tl.events:
            row = ctk.CTkFrame(scroll, fg_color=EX_COLORS["panel_dark"], corner_radius=4)
            row.pack(fill="x", padx=4, pady=2)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=f"#{evt.seq}", font=ctk.CTkFont("Consolas", 9, weight="bold"),
                         text_color=EX_COLORS["gold"], width=32).grid(row=0, column=0, padx=4, pady=4)
            ctk.CTkLabel(row, text=source_label(evt.source), font=ctk.CTkFont("Consolas", 8, weight="bold"),
                         text_color=source_color(evt.source), width=120).grid(row=0, column=1, sticky="w", padx=4, pady=4)
            ctk.CTkLabel(row, text=f"{evt.timestamp}  {evt.title}", font=ctk.CTkFont("Segoe UI", 10),
                         text_color=EX_COLORS["white"], anchor="w").grid(row=0, column=2, sticky="ew", padx=4, pady=4)
            ctk.CTkLabel(row, text=evt.detail, font=ctk.CTkFont("Segoe UI", 9),
                         text_color=EX_COLORS["muted"], anchor="w", justify="left",
                         wraplength=780).grid(row=1, column=1, columnspan=2, sticky="ew", padx=4, pady=(0, 3))
        self._paragraph(body, "Press Next → to see the ML result and supporting evidence.", EX_COLORS["white"])

    def _stage_result(self) -> None:
        body = self._scroll_body()
        self._section_title(body, "6. ML Result & Supporting Evidence", EX_COLORS["cyan"])
        if self._last_result is None:
            self._paragraph(body, "No scenario result available. Go Back and run a scenario first.", EX_COLORS["warning"])
            return
        r = self._last_result
        ex = r.explanation or {}
        cls = ex.get("classification") or r.classification or r.outcome_label
        # Headline
        head = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8)
        head.pack(fill="x", padx=16, pady=(0, 8))
        head.grid_columnconfigure(2, weight=1)
        ctk.CTkLabel(head, text=str(cls), font=ctk.CTkFont("Segoe UI", 22, weight="bold"),
                     text_color=severity_color(cls)).grid(row=0, column=0, padx=14, pady=10)
        badge_text, badge_color = classify_origin_badge(r.data_origin, r.is_simulation)
        ctk.CTkLabel(head, text=badge_text, font=ctk.CTkFont("Consolas", 11, weight="bold"),
                     text_color=badge_color, fg_color="#1e3a6e", corner_radius=6, padx=10).grid(row=0, column=1, padx=8, pady=10)
        prob = ex.get("probability")
        prob_txt = (f"Model probability: {float(prob):.4f} ({float(prob)*100:.1f}%)"
                    if prob is not None else "Model probability: Not available")
        ctk.CTkLabel(head, text=prob_txt, font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                     text_color=EX_COLORS["cyan"]).grid(row=0, column=2, sticky="e", padx=14, pady=10)
        if ex.get("probability_note"):
            self._paragraph(body, str(ex["probability_note"]), EX_COLORS["muted"])
        detail = ex.get("classification_detail") or {}
        if detail.get("description"):
            self._paragraph(body, str(detail["description"]), EX_COLORS["white"])

        # Indicators
        self._section_title(body, "Observed Indicators", EX_COLORS["cyan"])
        inds = ex.get("indicators", []) or []
        if inds:
            self._paragraph(body, "\n".join(
                f"{'▲' if i.get('status')=='ELEVATED' else '•'} {i.get('display_name', i.get('feature','?'))} = "
                f"{i.get('value','?')} (baseline {i.get('baseline','?')}) — {i.get('status','')} [{i.get('origin','')}]"
                for i in inds), EX_COLORS["white"])
        else:
            self._paragraph(body, "No elevated indicators; all at nominal baseline.", EX_COLORS["muted"])

        # Telemetry gaps
        self._section_title(body, "Telemetry — Available & Missing", EX_COLORS["inconclusive"])
        gaps = ex.get("telemetry_gaps", {}) or {}
        unavail = gaps.get("unavailable", []) or []
        sub = gaps.get("substituted_or_proxy", []) or []
        gap_txt = (f"Coverage ratio: {gaps.get('coverage_ratio','n/a')}  |  Available sensors: {gaps.get('available_feature_count','n/a')}")
        if unavail:
            gap_txt += "\nUnavailable / restricted: " + ", ".join(g.get("feature", "?") for g in unavail)
        if sub:
            gap_txt += "\nHeuristic-proxy / substituted: " + ", ".join(g.get("feature", "?") for g in sub)
        if not unavail and not sub:
            gap_txt += "\nAll 19 sensors available on this platform."
        self._paragraph(body, gap_txt, EX_COLORS["white"])

        # Evidence
        self._section_title(body, "Supporting Evidence (timestamps)", EX_COLORS["white"])
        ev = ex.get("evidence", []) or []
        if ev:
            self._paragraph(body, "\n".join(
                f"[{e.get('timestamp','')}] {e.get('text','')} ({source_label(e.get('source','REAL'))})"
                for e in ev[:15]), EX_COLORS["white"])
        else:
            self._paragraph(body, "No timestamped evidence recorded.", EX_COLORS["muted"])

        # Next steps
        self._section_title(body, "Recommended Next Steps", EX_COLORS["gold"])
        steps = ex.get("next_steps", []) or []
        self._paragraph(body, "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps)) if steps
                        else "Review the evidence and re-run the scan.", EX_COLORS["white"])

        # Limitations
        self._section_title(body, "Limitations", EX_COLORS["warning"])
        lims = ex.get("limitations", []) or list(r.limitations or [])
        self._paragraph(body, "\n".join(f"• {l}" for l in lims) if lims else "None reported.", EX_COLORS["muted"])
        self._paragraph(body, "Press Next → to generate an incident report.", EX_COLORS["white"])

    def _stage_report(self) -> None:
        body = self._scroll_body()
        self._section_title(body, "7. Incident Report Generation", EX_COLORS["cyan"])
        if self._last_result is None:
            self._paragraph(body, "No scenario result to report. Go Back and run a scenario first.", EX_COLORS["warning"])
            return
        r = self._last_result
        try:
            parts = [r.report_text(), "", "=" * 70, "DETECTION RESULT EXPLANATION", "=" * 70,
                     format_explanation_text(r.explanation or {})]
            self._report_text = "\n".join(parts)
        except Exception as exc:
            self._report_text = f"Report generation failed: {exc}"
        self._paragraph(body,
            "The incident report combines the scenario outcome, timeline summary, evidence, and the full "
            "detection-result explanation into a single plain-text artefact. Review the preview, then save it.",
            EX_COLORS["white"])
        preview = ctk.CTkScrollableFrame(body, fg_color=EX_COLORS["card"], height=320)
        preview.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        preview.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(preview, text=self._report_text, font=ctk.CTkFont("Consolas", 9),
                     text_color=EX_COLORS["white"], anchor="w", justify="left").pack(fill="x", padx=10, pady=10)
        bar = ctk.CTkFrame(body, fg_color="transparent")
        bar.pack(fill="x", padx=16, pady=(0, 10))
        ctk.CTkButton(bar, text="💾 Save Report…", font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                      fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"], text_color="#000000",
                      height=30, command=self._save_report).pack(side="left")
        self._paragraph(body, "Press Next → for the architecture, limitations, and conclusion.", EX_COLORS["white"])

    def _stage_closing(self) -> None:
        body = self._scroll_body()
        self._section_title(body, "8. Architecture, Limitations & Conclusion", EX_COLORS["cyan"])
        self._section_title(body, "System Architecture", EX_COLORS["gold"])
        self._paragraph(body,
            "Telemetry (scanner/) → 19-feature vector (ml/) → StandardScaler + Random Forest → thresholded "
            "classification → unified classification + honest limitations (exhibition/). A robust worker/"
            "main-thread marshalling pattern keeps the Tk UI responsive and never touches widgets from a "
            "background thread. Cancellation, stale-callback tokens, and a destroyed-page flag make scans safe "
            "to interrupt at any phase boundary.", EX_COLORS["white"])
        self._section_title(body, "Safety Invariants", EX_COLORS["gold"])
        self._paragraph(body,
            "• A failed, cancelled, incomplete or insufficiently-validated scan NEVER silently becomes SAFE.\n"
            "• Scripted/sandbox results are labelled SIMULATED and never presented as live detections.\n"
            "• Missing telemetry is reported as Unavailable, not zero.\n"
            "• SentinelAI is advisory only and can never override the authoritative scan outcome.\n"
            "• The trained model and scaler are read-only — never retrained or replaced by this app.", EX_COLORS["white"])
        self._section_title(body, "Known Limitations", EX_COLORS["warning"])
        self._paragraph(body,
            "• User-space behavioral monitoring only — no kernel-level protection or real-time blocking.\n"
            "• Model is EXPERIMENTAL_SYNTHETIC_BASELINE_V1; scores are behavioural risk, not definitive IDs.\n"
            "• Several of the 19 features are heuristic proxies on this platform.\n"
            "• Quick scans (depth=1) cannot guarantee absence of unknown malware.", EX_COLORS["white"])
        self._section_title(body, "Conclusion", EX_COLORS["safe"])
        self._paragraph(body,
            "SentinelML V2 delivers an interactive, technically credible ransomware-recovery predictor that an "
            "examiner can explore end-to-end: genuine telemetry, real model inference, an honest investigation "
            "timeline, transparent explanations, and a guided narrative — with simulation clearly separated "
            "from reality throughout.", EX_COLORS["white"])
        self._paragraph(body, "Press ↻ Restart Tour to begin again, or ✖ Exit Tour to return to the lab.", EX_COLORS["muted"])

    # ======================================================================
    # Scenario execution (shared by scan & scenario stages)
    # ======================================================================
    def _run_scenario(self, key: str) -> None:
        if self._is_running:
            return
        token = str(uuid.uuid4())
        self._active_token = token
        self._cancel_requested = False
        self._is_running = True
        self._set_stage_running(True, key)
        self._clear_tour_stream()
        threading.Thread(target=self._run_scenario_thread, args=(key, token),
                         daemon=True, name="GuidedTourScenario").start()

    def _run_scenario_thread(self, key: str, token: str) -> None:
        try:
            self._runner.reset()
            result = self._runner.run(
                key, cancel_check=lambda: self._cancel_requested or token != self._active_token)
            if token != self._active_token:
                return
            self._dispatch_to_main(self._on_scenario_complete, result, token)
        except Exception as exc:
            log.error("Guided tour scenario %s failed: %s", key, exc, exc_info=True)
            if token == self._active_token:
                self._dispatch_to_main(self._on_scenario_error, str(exc), token)

    def _on_scenario_event(self, evt: InvestigationEvent) -> None:
        self._dispatch_to_main(self._append_tour_event, evt)

    def _append_tour_event(self, evt: InvestigationEvent) -> None:
        if getattr(self, "_is_destroyed", False) or not self.winfo_exists():
            return
        stream = self._current_tour_stream()
        if stream is None:
            return
        placeholder = getattr(self, "_tour_stream_placeholder", None) or getattr(self, "_tour_stream2_placeholder", None)
        if placeholder is not None:
            try:
                placeholder.destroy()
            except Exception:
                pass
        row = ctk.CTkFrame(stream, fg_color=EX_COLORS["panel_dark"], corner_radius=4)
        row.pack(fill="x", padx=4, pady=2)
        row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(row, text=f"[{evt.timestamp}] {source_label(evt.source)} — {evt.title}",
                     font=ctk.CTkFont("Consolas", 9), text_color=source_color(evt.source),
                     anchor="w").grid(row=0, column=0, sticky="ew", padx=8, pady=3)
        ctk.CTkLabel(row, text=evt.detail, font=ctk.CTkFont("Segoe UI", 9),
                     text_color=EX_COLORS["muted"], anchor="w", justify="left",
                     wraplength=820).grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 3))
        try:
            stream._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass
        self._set_stage_status(f"[{evt.timestamp}] {evt.title}")

    def _current_tour_stream(self):
        if self._stage_index == 2 and hasattr(self, "_tour_stream"):
            return self._tour_stream
        if self._stage_index == 3 and hasattr(self, "_tour_stream2"):
            return self._tour_stream2
        return None

    def _clear_tour_stream(self) -> None:
        stream = self._current_tour_stream()
        if stream is None:
            return
        for w in list(stream.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass

    def _set_stage_running(self, running: bool, key: str) -> None:
        if self._stage_index == 2:
            self._scan_start_btn.configure(state="disabled" if running else "normal")
            self._scan_cancel_btn.configure(state="normal" if running else "disabled")
            self._scan_status_lbl.configure(
                text=f"Running Scenario {key} (real host scan)…" if running else "Scan finished.",
                text_color=EX_COLORS["cyan"] if running else EX_COLORS["muted"])
        elif self._stage_index == 3:
            for k, b in getattr(self, "_scenario_btns", {}).items():
                b.configure(state="disabled" if running else "normal")
            self._scn_status_lbl.configure(
                text=f"Running Scenario {key}…" if running else "Scenario finished.",
                text_color=EX_COLORS["cyan"] if running else EX_COLORS["muted"])

    def _set_stage_status(self, text: str) -> None:
        if self._stage_index == 2 and hasattr(self, "_scan_status_lbl"):
            self._scan_status_lbl.configure(text=text, text_color=EX_COLORS["white"])
        elif self._stage_index == 3 and hasattr(self, "_scn_status_lbl"):
            self._scn_status_lbl.configure(text=text, text_color=EX_COLORS["white"])

    def _on_scenario_complete(self, result: ScenarioResult, token: str) -> None:
        if getattr(self, "_is_destroyed", False) or token != self._active_token:
            return
        self._is_running = False
        self._cancel_requested = False
        self._last_result = result
        self._set_stage_running(False, result.scenario_key)
        # Inline outcome summary on the active stage
        cls = result.classification or result.outcome_label
        badge_text, badge_color = classify_origin_badge(result.data_origin, result.is_simulation)
        prob = result.probability
        prob_txt = f"probability {prob:.4f}" if prob is not None else "probability not available"
        summary = (f"Outcome: {result.outcome_label} ({cls})  •  {badge_text}  •  {prob_txt}  •  "
                   f"{result.duration_seconds:.2f}s")
        if self._stage_index == 2 and hasattr(self, "_scan_result_lbl"):
            self._scan_result_lbl.configure(text=summary, text_color=severity_color(cls))
        elif self._stage_index == 3 and hasattr(self, "_scn_status_lbl"):
            self._scn_status_lbl.configure(text=summary, text_color=severity_color(cls))

    def _on_scenario_error(self, message: str, token: str) -> None:
        if getattr(self, "_is_destroyed", False) or token != self._active_token:
            return
        self._is_running = False
        self._cancel_requested = False
        self._set_stage_running(False, "?")
        self._set_stage_status(f"Scenario error: {message}")

    def _on_cancel(self) -> None:
        if not self._is_running:
            return
        self._cancel_requested = True
        if self._stage_index == 2:
            self._scan_cancel_btn.configure(state="disabled", text="Cancelling…")
        self._set_stage_status("Cancellation requested — stopping at the next safe phase boundary…")

    # ======================================================================
    # Report save
    # ======================================================================
    def _save_report(self) -> None:
        if not self._report_text:
            return
        try:
            from tkinter import filedialog, messagebox
        except Exception:
            return
        r = self._last_result
        path = filedialog.asksaveasfilename(
            title="Save Guided Tour Incident Report", defaultextension=".txt",
            initialfile=f"sentinelml_tour_report_{r.scenario_key if r else 'x'}.txt",
            filetypes=[("Text Report", "*.txt"), ("All Files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._report_text)
            try:
                messagebox.showinfo("Report Saved", f"Report saved to:\n{path}")
            except Exception:
                pass
        except Exception as exc:
            try:
                messagebox.showerror("Save Failed", str(exc))
            except Exception:
                pass

    # ======================================================================
    # Health text for intro stage
    # ======================================================================
    def _collect_health_text(self) -> str:
        lines = []
        lines.append(f"OS: {platform.system()} {platform.release()} ({platform.machine()})")
        lines.append(f"Platform: {sys.platform}   Python: {platform.python_version()}   App: v{APP_VERSION}")
        try:
            p = MLPredictor()
            loaded = p.is_loaded()
            if not loaded:
                loaded = p.load_model()
            mi = p.get_model_info()
            lines.append(f"Random Forest model: {'LOADED' if loaded else 'NOT LOADED'} "
                         f"(type={mi.get('type','?')}, features={mi.get('expected_features','?')})")
            lines.append(f"Thresholds: WARNING >= {mi.get('threshold_warning',0.5)}, CRITICAL >= {mi.get('threshold_critical',0.9)}")
        except Exception as exc:
            lines.append(f"Model status unavailable: {exc}")
        try:
            avail = get_platform_feature_availability() or {}
            genuine = sum(1 for s in avail.values() if s == "GENUINE_MEASURED")
            proxy = sum(1 for s in avail.values() if s.startswith("HEURISTIC_PROXY") or s.startswith("SUBSTITUTED"))
            unavail = [f for f, s in avail.items() if s.startswith("UNAVAILABLE") or s.startswith("RESTRICTED")]
            lines.append(f"Telemetry: {len(avail)}/19 sensors — {genuine} measured, {proxy} proxy/substituted, "
                         f"{len(unavail)} unavailable/restricted")
        except Exception as exc:
            lines.append(f"Telemetry status unavailable: {exc}")
        lines.append("Scope: user-space behavioral monitoring (no kernel-level protection).")
        return "\n".join(lines)
