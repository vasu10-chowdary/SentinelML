"""
SentinelML V2 — Explainable AI Observatory (Tk page)
==================================================
Displays the actual prediction probability, classification and the 19 model
input features, distinguishing MEASURED values, UNAVAILABLE sensors and
SIMULATED inputs. Shows global model-level feature importance (Gini) only when
it can be derived from the trained forest — clearly labelled as a model
aggregate, NOT a per-prediction explanation.

Invariants (enforced via exhibition.ai_observatory):
  * The model, scaler, feature order and thresholds are read-only and never
    retrained or replaced.
  * A missing / error / incomplete scan is NEVER converted into SAFE.
  * Simulated-vector results are badged SIMULATED and never presented as real
    detections.

Threading: the "Measure now" path runs a real ScanEngine scan on a daemon
worker thread; results are marshalled to the Tk main thread via the
queue + dispatch + token + safe_after pattern. No widget is touched off the
main thread.
"""

from __future__ import annotations

import logging
import queue
import threading
import uuid
from typing import Any, Optional

import customtkinter as ctk
import numpy as np

from constants import APP_VERSION
from gui.exhibition_theme import EX_COLORS, severity_color
from ml.predictor import MLPredictor, FEATURE_NAMES
from scanner.scan_engine import ScanEngine, ScanType
from exhibition.ai_observatory import (
    STATUS_ERROR,
    STATUS_MEASURED,
    STATUS_UNAVAILABLE,
    STATUS_SIMULATED,
    classification_from_prediction,
    classification_from_scan,
    coverage_summary,
    feature_rows,
    global_feature_importance,
    importance_disclaimer,
    model_availability,
    plain_english,
)

log = logging.getLogger("sentinel.gui.ai_observatory")


class AIObservatoryPage(ctk.CTkFrame):
    """Explainable AI Observatory page."""

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=EX_COLORS["bg"], **kwargs)
        self._config = config
        self._is_destroyed = False

        # Threading primitives
        self._ui_queue: queue.Queue = queue.Queue()
        self._pending_after_ids: set = set()
        self._active_token: Optional[str] = None
        self._cancel_requested = False
        self._is_scanning = False

        self._predictor = MLPredictor()
        self._predictor.load_model()
        self._feature_rows: list = []
        self._model_badge_text = "MODEL: …"

        self._build_ui()
        self._render_model_badge()
        self.safe_after(30, self._drain_ui_queue)
        self.safe_after(120, self._render_feature_importance)

    def _render_model_badge(self) -> None:
        avail = model_availability(self._predictor)
        if not avail["model_loaded"]:
            self._model_badge_text = "MODEL: NOT LOADED"
            self._status_badge.configure(
                text="MODEL: NOT LOADED — predictions unavailable", text_color=EX_COLORS["error"])
            return
        scaler = "scaler ✓" if avail["scaler_loaded"] else "scaler ✗"
        self._model_badge_text = (f"{avail['model_type']} · {scaler} · {avail['feature_count']} features · "
                                  f"W≥{avail['threshold_warning']:.2f} / C≥{avail['threshold_critical']:.2f}")
        self._status_badge.configure(text=f"MODEL: {self._model_badge_text}", text_color=EX_COLORS["cyan"])

    # ── threading / safety ───────────────────────────────────────────────
    def safe_after(self, ms: int, fn, *args, **kwargs):
        if getattr(self, "_is_destroyed", False):
            return None
        aid_holder = [None]

        def wrapper():
            if getattr(self, "_is_destroyed", False):
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
            self._pending_after_ids.add(aid)
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
                    log.warning("Observatory UI queue callback failed: %s", exc)
                count += 1
                if count > 200:
                    break
        finally:
            if not getattr(self, "_is_destroyed", False):
                self.safe_after(80, self._drain_ui_queue)

    def destroy(self) -> None:
        self._is_destroyed = True
        self._cancel_requested = True
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

    # ── UI ───────────────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = ctk.CTkFrame(self, fg_color=EX_COLORS["header"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            header, text="📊  SENTINELML V2  —  EXPLAINABLE AI OBSERVATORY",
            font=ctk.CTkFont("Segoe UI", 18, weight="bold"),
            text_color=EX_COLORS["white"]).grid(row=0, column=0, padx=20, pady=12, sticky="w")
        self._status_badge = ctk.CTkLabel(
            header, text="MODEL: …", font=ctk.CTkFont("Consolas", 11, weight="bold"),
            text_color=EX_COLORS["cyan"], fg_color="#1e3a6e", corner_radius=6, padx=12)
        self._status_badge.grid(row=0, column=1, padx=8, pady=12, sticky="w")
        ctk.CTkButton(
            header, text="← Back to Lab", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#1a4a7a", hover_color="#2060a0", text_color=EX_COLORS["cyan"],
            height=32, command=self._back_to_lab).grid(row=0, column=2, padx=16, pady=10, sticky="e")

        # Control bar
        bar = ctk.CTkFrame(self, fg_color=EX_COLORS["card"], corner_radius=8,
                           border_width=1, border_color=EX_COLORS["card_border"])
        bar.grid(row=1, column=0, sticky="ew", padx=14, pady=(10, 6))
        bar.grid_columnconfigure(3, weight=1)
        ctk.CTkLabel(bar, text="Input source:", font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                     text_color=EX_COLORS["muted"]).grid(row=0, column=0, padx=(12, 4), pady=8)
        self._source_seg = ctk.CTkSegmentedButton(
            bar, values=["Measure now", "Simulated suspicious", "Benign baseline"],
            command=lambda v: None, selected_color=EX_COLORS["gold"],
            selected_hover_color=EX_COLORS["gold_hover"], text_color=EX_COLORS["white"], fg_color=EX_COLORS["panel_dark"])
        self._source_seg.set("Measure now")
        self._source_seg.grid(row=0, column=1, padx=6, pady=8)
        self._run_btn = ctk.CTkButton(
            bar, text="▶ Run", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"], text_color="#000000",
            height=32, command=self._on_run)
        self._run_btn.grid(row=0, column=2, padx=6, pady=8)
        self._info_lbl = ctk.CTkLabel(
            bar, text="Choose an input source and press Run. Real scans run on this host.",
            font=ctk.CTkFont("Segoe UI", 10, slant="italic"), text_color=EX_COLORS["muted"], anchor="w")
        self._info_lbl.grid(row=0, column=3, padx=12, pady=8, sticky="ew")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 10))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        # Left: 19 features
        left = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                           border_width=1, border_color=EX_COLORS["card_border"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(left, text="MODEL INPUT FEATURES (19) — exact trained order",
                     font=ctk.CTkFont("Segoe UI", 13, weight="bold"),
                     text_color=EX_COLORS["gold"]).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))
        feat_scroll = ctk.CTkScrollableFrame(left, fg_color=EX_COLORS["panel_dark"])
        feat_scroll.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        feat_scroll.grid_columnconfigure(2, weight=1)
        self._feat_value_lbls = {}
        self._feat_status_lbls = {}
        self._feat_name_lbls = {}
        for i, name in enumerate(FEATURE_NAMES):
            ctk.CTkLabel(feat_scroll, text=f"[{i:02d}]", font=ctk.CTkFont("Consolas", 11), text_color=EX_COLORS["muted"], width=40).grid(row=i, column=0, sticky="w", padx=2, pady=1)
            name_lbl = ctk.CTkLabel(feat_scroll, text=name, font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=EX_COLORS["white"])
            name_lbl.grid(row=i, column=1, sticky="w", padx=2, pady=1)
            name_lbl.bind("<Button-1>", lambda _e, n=name: self._on_feature_click(n))
            vlbl = ctk.CTkLabel(feat_scroll, text="—", font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=EX_COLORS["gold"], width=90, anchor="e")
            vlbl.grid(row=i, column=2, sticky="ew", padx=4, pady=1)
            slbl = ctk.CTkLabel(feat_scroll, text="", font=ctk.CTkFont("Consolas", 10, weight="bold"), width=110, anchor="w")
            slbl.grid(row=i, column=3, padx=4, pady=1)
            self._feat_value_lbls[name] = vlbl
            self._feat_status_lbls[name] = slbl
            self._feat_name_lbls[name] = name_lbl
        self._clear_feature_table()
        self._feat_detail_lbl = ctk.CTkLabel(
            left, text="Select an input to read what it means in plain English.",
            font=ctk.CTkFont("Segoe UI", 10, slant="italic"), text_color=EX_COLORS["muted"],
            anchor="w", justify="left", wraplength=520)
        self._feat_detail_lbl.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 8))

        # Right: prediction + importance
        right = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                            border_width=1, border_color=EX_COLORS["card_border"])
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right.grid_rowconfigure(6, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="PREDICTION", font=ctk.CTkFont("Segoe UI", 13, weight="bold"),
                     text_color=EX_COLORS["cyan"]).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))
        pred = ctk.CTkFrame(right, fg_color=EX_COLORS["panel_dark"], corner_radius=6)
        pred.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 6))
        pred.grid_columnconfigure(1, weight=1)
        self._cls_lbl = ctk.CTkLabel(pred, text="—", font=ctk.CTkFont("Segoe UI", 22, weight="bold"),
                                     text_color=EX_COLORS["muted"])
        self._cls_lbl.grid(row=0, column=0, padx=14, pady=10)
        self._origin_lbl = ctk.CTkLabel(pred, text="", font=ctk.CTkFont("Consolas", 10, weight="bold"),
                                        text_color=EX_COLORS["muted"], fg_color="#1e3a6e",
                                        corner_radius=6, padx=10)
        self._origin_lbl.grid(row=0, column=1, padx=8, pady=10, sticky="w")
        self._prob_lbl = ctk.CTkLabel(pred, text="Model probability: —", font=ctk.CTkFont("Segoe UI", 13, weight="bold"), text_color=EX_COLORS["white"], anchor="e")
        self._prob_lbl.grid(row=0, column=2, padx=14, pady=10, sticky="e")
        self._note_lbl = ctk.CTkLabel(right, text="", font=ctk.CTkFont("Segoe UI", 11, slant="italic"), text_color=EX_COLORS["muted"], anchor="w", wraplength=400, justify="left")
        self._note_lbl.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 2))
        self._threshold_lbl = ctk.CTkLabel(
            right,
            text=("Thresholds: WARNING ≥ 0.50 · CRITICAL ≥ 0.90 (unchanged)\n"
                  "Benchmark: 95.67% accuracy is the project's stored offline evaluation "
                  "(models/metrics.json) — not a real-world ransomware detection rate."),
            font=ctk.CTkFont("Segoe UI", 11), text_color=EX_COLORS["muted"],
            anchor="w", justify="left", wraplength=400,
        )
        self._threshold_lbl.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 2))
        self._coverage_lbl = ctk.CTkLabel(
            right, text="Coverage: no scan yet (0 of 19 inputs measured).",
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"), text_color=EX_COLORS["muted"],
            anchor="w", justify="left", wraplength=400)
        self._coverage_lbl.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 4))

        ctk.CTkLabel(right, text="GLOBAL FEATURE IMPORTANCE (model-level)",
                     font=ctk.CTkFont("Segoe UI", 13, weight="bold"), text_color=EX_COLORS["gold"]).grid(row=5, column=0, sticky="w", padx=12, pady=(6, 2))
        self._imp_scroll = ctk.CTkScrollableFrame(right, fg_color=EX_COLORS["panel_dark"])
        self._imp_scroll.grid(row=6, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._imp_scroll.grid_columnconfigure(1, weight=1)
        self._imp_disclaimer = ctk.CTkLabel(self._imp_scroll, text="", font=ctk.CTkFont("Segoe UI", 10, slant="italic"), text_color=EX_COLORS["muted"], anchor="w", justify="left", wraplength=360)
        self._imp_disclaimer.pack(fill="x", padx=8, pady=6, anchor="w")

    def _clear_feature_table(self) -> None:
        for name in FEATURE_NAMES:
            self._feat_value_lbls[name].configure(text="—", text_color=EX_COLORS["muted"])
            self._feat_status_lbls[name].configure(text="", text_color=EX_COLORS["muted"])

    def _on_feature_click(self, name: str) -> None:
        if self._is_destroyed:
            return
        idx = FEATURE_NAMES.index(name)
        self._feat_detail_lbl.configure(
            text=f"[{idx:02d}] {name} — {plain_english(name)}",
            text_color=EX_COLORS["white"])

    # ── run ──────────────────────────────────────────────────────────────
    def _on_run(self) -> None:
        if self._is_scanning:
            return
        source = self._source_seg.get()
        if source == "Measure now":
            self._start_real_scan()
        else:
            vector = None
            if source == "Simulated suspicious":
                try:
                    from exhibition.scenario_lab import SUSPICIOUS_VECTOR
                    vector = np.array(SUSPICIOUS_VECTOR, dtype=np.float64)
                except Exception as exc:
                    self._info_lbl.configure(text=f"Could not load simulated vector: {exc}",
                                             text_color=EX_COLORS["error"])
                    return
                self._info_lbl.configure(text="Evaluating a scripted suspicious vector in memory (SIMULATED).",
                                         text_color=EX_COLORS["warning"])
            else:  # Benign baseline
                vector = np.zeros((1, 19), dtype=np.float64)
                self._info_lbl.configure(text="Evaluating a benign baseline vector (SIMULATED).",
                                         text_color=EX_COLORS["muted"])
            self._render_simulated(vector, source)

    def _render_simulated(self, vector, source: str) -> None:
        rows = feature_rows(vector, None, source="simulated")
        self._render_feature_rows(rows, simulated=True)
        pred = self._predictor.predict(vector)
        if pred is None:
            level, prob, ml_executed = None, None, False
        else:
            level, prob = pred
            ml_executed = True
        label, prob2, note = classification_from_prediction(level, prob, ml_executed)
        self._render_prediction(label, prob2, note,
                                origin=("SIMULATED SUSPICIOUS VECTOR" if source == "Simulated suspicious"
                                        else "SIMULATED BASELINE VECTOR"),
                                origin_color=EX_COLORS["simulated"], is_sim=True)

    def _start_real_scan(self) -> None:
        token = str(uuid.uuid4())
        self._active_token = token
        self._cancel_requested = False
        self._is_scanning = True
        self._run_btn.configure(state="disabled")
        self._info_lbl.configure(text="Running a real QUICK scan of this host…", text_color=EX_COLORS["cyan"])
        self._status_badge.configure(
            text=f"STATE: SCANNING · {getattr(self, '_model_badge_text', '')}", text_color=EX_COLORS["cyan"])
        threading.Thread(target=self._scan_thread, args=(token,), daemon=True,
                         name="AIObsScan").start()

    def _scan_thread(self, token: str) -> None:
        engine = ScanEngine()
        last_emit = [0.0]

        def progress(res):
            if self._cancel_requested or token != self._active_token:
                engine.cancel()
                return
            import time
            now = time.time()
            if now - last_emit[0] >= 0.5:
                last_emit[0] = now
                self._dispatch_to_main(self._on_scan_progress, res.files_inspected, res.processes_analyzed, token)

        try:
            result = engine.scan(ScanType.QUICK, progress_callback=progress, scan_origin="LIVE_HOST_SCAN")
        except Exception as exc:
            if token == self._active_token:
                self._dispatch_to_main(self._on_scan_error, str(exc), token)
            return
        if token != self._active_token:
            return
        self._dispatch_to_main(self._on_scan_complete, result, token)

    def _on_scan_progress(self, files: int, procs: int, token: str) -> None:
        if token != self._active_token or self._is_destroyed:
            return
        self._info_lbl.configure(text=f"Scanning… {files} files · {procs} processes", text_color=EX_COLORS["cyan"])

    def _on_scan_complete(self, result, token: str) -> None:
        if self._is_destroyed or token != self._active_token:
            return
        self._is_scanning = False
        self._run_btn.configure(state="normal")
        features = getattr(result, "_features", None)
        availability = getattr(result, "telemetry_availability", {}) or {}
        rows = feature_rows(features, availability, source="real")
        self._render_feature_rows(rows)
        label, prob, note = classification_from_scan(result)
        cancelled = bool(getattr(result, "cancelled", False))
        simulated = bool(getattr(result, "is_simulation", False)) or \
            str(getattr(result, "scan_origin", "")).upper() == "CONTROLLED_SIMULATION"
        if simulated:
            origin, origin_color = "SIMULATED — NOT A REAL MEASUREMENT", EX_COLORS["simulated"]
        elif cancelled:
            origin, origin_color = "REAL SCAN (CANCELLED)", EX_COLORS["cancelled"]
        else:
            origin, origin_color = "REAL MEASUREMENT", EX_COLORS["real"]
        self._render_prediction(label, prob, note, origin=origin,
                                origin_color=origin_color, is_sim=simulated)
        state_name = str(getattr(getattr(result, "state", None), "value", result.state)) if result.state else ""
        self._status_badge.configure(
            text=f"STATE: {state_name or label} · {getattr(self, '_model_badge_text', '')}",
            text_color=severity_color(label))
        if cancelled:
            self._info_lbl.configure(text="Scan cancelled — results are incomplete and not a safety claim.",
                                     text_color=EX_COLORS["warning"])
        elif simulated:
            self._info_lbl.configure(text="Controlled simulation result — labelled SIMULATED, not a live detection.",
                                     text_color=EX_COLORS["simulated"])
        else:
            self._info_lbl.configure(text="Real scan complete. See prediction and features at left.",
                                      text_color=EX_COLORS["muted"])

    def _on_scan_error(self, message: str, token: str) -> None:
        if self._is_destroyed or token != self._active_token:
            return
        self._is_scanning = False
        self._run_btn.configure(state="normal")
        # No readings exist for a failed scan: show ERROR rows, never zero values.
        self._render_feature_rows(feature_rows(None, None, source="error"))
        self._render_prediction("ERROR", None, f"Scan error: {message}",
                                origin="REAL SCAN (FAILED)", origin_color=EX_COLORS["error"], is_sim=False)
        self._coverage_lbl.configure(text="Coverage: none — the scan failed, so no inputs are measured.",
                                     text_color=EX_COLORS["error"])
        self._status_badge.configure(text=f"STATE: ERROR · {getattr(self, '_model_badge_text', '')}",
                                     text_color=EX_COLORS["error"])
        self._info_lbl.configure(text=f"Scan error: {message}", text_color=EX_COLORS["error"])

    # ── rendering ────────────────────────────────────────────────────────
    def _render_feature_rows(self, rows, simulated: bool = False) -> None:
        status_color = {STATUS_MEASURED: EX_COLORS["real"], STATUS_UNAVAILABLE: EX_COLORS["inconclusive"],
                        STATUS_SIMULATED: EX_COLORS["simulated"], STATUS_ERROR: EX_COLORS["error"],
                        "INJECTED": EX_COLORS["injected"]}
        self._feature_rows = list(rows or [])
        for r in self._feature_rows:
            name = r["name"]
            vlbl = self._feat_value_lbls[name]
            slbl = self._feat_status_lbls[name]
            v = r["value"]
            if v is None:
                vlbl.configure(text="—", text_color=EX_COLORS["muted"])
            else:
                vlbl.configure(text=f"{v:.4g}", text_color=EX_COLORS["white"])
            slbl.configure(text=r["status"], text_color=status_color.get(r["status"], EX_COLORS["muted"]))
        self._render_coverage(simulated=simulated)

    def _render_coverage(self, simulated: bool = False) -> None:
        cov = coverage_summary(getattr(self, "_feature_rows", []))
        if simulated:
            self._coverage_lbl.configure(
                text=(f"Coverage: SIMULATED input — {cov['total']} of 19 inputs are scripted values, "
                      "not sensor measurements."),
                text_color=EX_COLORS["simulated"])
            return
        if cov["error"]:
            self._coverage_lbl.configure(
                text="Coverage: none — the scan failed, so no inputs are measured.",
                text_color=EX_COLORS["error"])
            return
        color = EX_COLORS["safe"] if cov["coverage_ratio"] >= 0.99 else EX_COLORS["warning"]
        missing_txt = ""
        if cov["not_measured"]:
            preview = ", ".join(cov["not_measured"][:3])
            more = f" +{len(cov['not_measured']) - 3} more" if len(cov["not_measured"]) > 3 else ""
            missing_txt = f" · unavailable: {preview}{more}"
        self._coverage_lbl.configure(
            text=(f"Coverage: {cov['measured']} of {cov['total']} inputs measured "
                  f"({cov['coverage_ratio'] * 100:.0f}%){missing_txt}"),
            text_color=color)

    def _render_prediction(self, label, prob, note, origin, origin_color, is_sim) -> None:
        color = severity_color(label) if label not in ("NOT AVAILABLE", "ERROR") else EX_COLORS["error"]
        if label == "NOT AVAILABLE":
            color = EX_COLORS["muted"]
        self._cls_lbl.configure(text=str(label), text_color=color)
        self._origin_lbl.configure(text=origin, text_color=origin_color)
        if prob is None:
            self._prob_lbl.configure(text="Model probability: Not available", text_color=EX_COLORS["muted"])
        else:
            self._prob_lbl.configure(text=f"Model probability: {float(prob):.4f} ({float(prob)*100:.1f}%)",
                                     text_color=EX_COLORS["cyan"])
        self._note_lbl.configure(text=note or ("Simulated input — not a real detection." if is_sim else ""))

    def _render_feature_importance(self) -> None:
        if self._is_destroyed:
            return
        # remove disclaimer placeholder content
        pairs = global_feature_importance(self._predictor)
        for w in list(self._imp_scroll.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass
        if pairs is None:
            ctk.CTkLabel(self._imp_scroll, text="Feature importance unavailable (model not loaded or not a forest).",
                         font=ctk.CTkFont("Segoe UI", 10, slant="italic"),
                         text_color=EX_COLORS["muted"], anchor="w", wraplength=360).pack(fill="x", padx=8, pady=8, anchor="w")
            ctk.CTkLabel(self._imp_scroll, text=importance_disclaimer(), font=ctk.CTkFont("Segoe UI", 8, slant="italic"),
                         text_color=EX_COLORS["muted"], anchor="w", justify="left", wraplength=360).pack(fill="x", padx=8, pady=4, anchor="w")
            return
        max_imp = max((p[1] for p in pairs), default=0.0) or 1.0
        for name, imp in pairs:
            row = ctk.CTkFrame(self._imp_scroll, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=1)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=f"{imp*100:5.1f}%", font=ctk.CTkFont("Consolas", 11), text_color=EX_COLORS["muted"], width=52).grid(row=0, column=0, sticky="w", padx=2)
            bar = ctk.CTkProgressBar(row, progress_color=EX_COLORS["gold"], fg_color=EX_COLORS["card"],
                                     height=10, width=200)
            bar.set(max(0.0, min(1.0, imp / max_imp)))
            bar.grid(row=0, column=1, sticky="ew", padx=6, pady=3)
            ctk.CTkLabel(row, text=name, font=ctk.CTkFont("Consolas", 11), text_color=EX_COLORS["white"]).grid(row=0, column=2, sticky="e", padx=2)
        ctk.CTkLabel(self._imp_scroll, text=importance_disclaimer(), font=ctk.CTkFont("Segoe UI", 8, slant="italic"),
                     text_color=EX_COLORS["muted"], anchor="w", justify="left", wraplength=360).pack(fill="x", padx=8, pady=6, anchor="w")

    # ── navigation ───────────────────────────────────────────────────────
    def _back_to_lab(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("exhibition_lab")
