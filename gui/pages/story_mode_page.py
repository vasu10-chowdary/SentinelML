"""
SentinelML V2 — Inside a Ransomware Investigation (3D Story Mode)
=================================================================
A six-chapter guided narrative built on StoryMode3D: Normal System,
Suspicious Activity, AI Analysis, Threat Assessment, Investigation, and
Response. Reachable from the Dashboard.

The page stays honest about provenance: scene 2 is a simulation, scene 4
shows a live verdict only for valid measured scans, and scene 5 correlates
real evidence when it exists (falling back to a clearly labelled simulated
sample). SentinelML advises; it never blocks or restores files.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

import customtkinter as ctk

from exhibition.evidence_correlation import EvidenceCorrelator, demo_correlator
from gui.exhibition_theme import EX_COLORS
from gui.story_mode_3d import (
    StoryMode3D,
    STORY_SCENES,
    SCENE_TITLES,
    SCENE_NORMAL,
    SCENE_SUSPICIOUS,
    SCENE_AI,
    SCENE_VERDICT,
    SCENE_INVESTIGATION,
    SCENE_RESPONSE,
    PROVENANCE_COLORS,
    _status_color,
)

_UNSAFE = {"CANCELLED", "SCAN_INCOMPLETE", "INCOMPLETE", "ERROR",
           "ANALYSIS_ERROR", "INCONCLUSIVE", "NOT_SCANNED", "IDLE"}

_EVIDENCE_DISPLAY_LIMIT = 6

_CHAPTERS: List[Dict[str, str]] = [
    {
        "id": SCENE_NORMAL,
        "title": "Normal System",
        "body": (
            "A workstation running its usual workload. SentinelML reads "
            "process and file counters without changing anything. The counters "
            "on screen are measured; the file icons are illustrations, not a "
            "directory listing."
        ),
        "fact": "Measured numbers and illustrative objects are labelled separately.",
    },
    {
        "id": SCENE_SUSPICIOUS,
        "title": "Suspicious Activity",
        "body": (
            "Simulated ransomware-like behaviour: rapid high-entropy writes "
            "and shadow-copy tampering signals. The animation is a harmless "
            "drawing — no ransomware runs, and no host file is touched or "
            "encrypted."
        ),
        "fact": "Everything in this scene is simulated and labelled as such.",
    },
    {
        "id": SCENE_AI,
        "title": "AI Analysis",
        "body": (
            "The real pipeline: 19 behavioural features, then the fitted "
            "StandardScaler, then the 100-tree Random Forest, producing a "
            "malicious probability. The animation diagrams the stages; it does "
            "not show the model's internal computation."
        ),
        "fact": "The model and scaler are the trained artefacts shipped with SentinelML.",
    },
    {
        "id": SCENE_VERDICT,
        "title": "Threat Assessment",
        "body": (
            "A live result appears here only when a valid measured scan "
            "exists. Thresholds: 0.50 raises a warning, 0.90 is critical. The "
            "inset example is simulated and kept separate. A prediction is not "
            "proof, and failed or partial scans are never reported as SAFE."
        ),
        "fact": "Without a valid scan the gauge stays empty — no verdict is implied.",
    },
    {
        "id": SCENE_INVESTIGATION,
        "title": "Investigation",
        "body": (
            "Evidence from the latest scan, any scenario timeline, and integrity "
            "comparisons is correlated here. Every item carries provenance: "
            "measured, simulated, heuristic, unavailable, or error. Correlation "
            "is not causation."
        ),
        "fact": "A changed hash shows content changed, not what changed it.",
    },
    {
        "id": SCENE_RESPONSE,
        "title": "Response Guidance",
        "body": (
            "Preserve the evidence, investigate the affected files, isolate the "
            "host, and restore only from a trusted backup. SentinelML provides "
            "guidance; containment and remediation remain operator decisions."
        ),
        "fact": "SentinelML does not block, quarantine, or restore files.",
    },
]


class StoryModePage(ctk.CTkFrame):
    """Guided six-scene narrative with a Dashboard entry point."""

    AUTO_ADVANCE_MS = 8000

    def __init__(self, master, config: dict,
                 on_exit: Optional[Callable[[], None]] = None, **kwargs):
        super().__init__(master, fg_color=EX_COLORS["bg"], **kwargs)
        self._config = config
        self._on_exit = on_exit
        self._is_destroyed = False
        self._pending_after: set = set()
        self._auto_after_id: Optional[str] = None
        self._playing = False
        self._started = False
        self._index = 0
        self._last_scan_result: Optional[Any] = None
        self._evidence_rows: List[Dict[str, Any]] = []
        self._evidence_is_sample = False
        self._evidence_buttons: List[Any] = []
        self._selected_evidence: Optional[int] = None

        self._build_ui()
        self._set_chapter(0)
        self._safe_after(300, self._poll_app_state)

    # --- Scheduling ----------------------------------------------------------

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

    def _cancel_auto(self) -> None:
        if self._auto_after_id is not None:
            try:
                self.after_cancel(self._auto_after_id)
            except Exception:
                pass
            self._auto_after_id = None

    def _schedule_auto(self) -> None:
        self._cancel_auto()
        if not self._playing or self._is_destroyed:
            return
        holder = [None]

        def tick():
            try:
                self._pending_after.discard(holder[0])
            except Exception:
                pass
            if self._is_destroyed or not self._playing:
                return
            if self._index >= len(STORY_SCENES) - 1:
                self._set_playing(False)
                return
            self._set_chapter(self._index + 1)
            self._schedule_auto()

        try:
            self._auto_after_id = self.after(self.AUTO_ADVANCE_MS, tick)
            holder[0] = self._auto_after_id
            self._pending_after.add(self._auto_after_id)
        except Exception:
            self._auto_after_id = None

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
            header,
            text="SENTINELML V2  \u2014  RANSOMWARE INVESTIGATION",
            font=ctk.CTkFont("Segoe UI", 16, weight="bold"),
            text_color=EX_COLORS["white"],
        ).grid(row=0, column=0, padx=20, pady=(10, 2), sticky="w")

        self._status_badge = ctk.CTkLabel(
            header, text="STATUS: IDLE",
            font=ctk.CTkFont("Consolas", 12, weight="bold"),
            text_color=EX_COLORS["cyan"], fg_color="#1e3a6e",
            corner_radius=6, padx=12)
        self._status_badge.grid(row=0, column=1, padx=8, pady=(10, 2), sticky="w")

        ctk.CTkButton(
            header, text="Back to Dashboard",
            font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#1a4a7a", hover_color="#2060a0",
            text_color=EX_COLORS["cyan"], height=30, width=160,
            command=self._back_to_dashboard,
        ).grid(row=0, column=2, padx=16, pady=(10, 2), sticky="e")

        self._motion_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(
            header, text="Reduced motion",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=EX_COLORS["muted"],
            progress_color=EX_COLORS["cyan"], button_color=EX_COLORS["white"],
            variable=self._motion_var, command=self._toggle_reduced_motion,
            width=120,
        ).grid(row=1, column=0, padx=(20, 8), pady=(0, 8), sticky="w")

        ctk.CTkButton(
            header, text="\U0001f9ea Investigation Suite",
            font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a",
            text_color=EX_COLORS["white"], height=28, width=170,
            command=self._open_investigation_suite,
        ).grid(row=1, column=1, padx=8, pady=(0, 8), sticky="e")

        ctk.CTkButton(
            header, text="🎯 Challenge Mode",
            font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#1a4a7a", hover_color="#2060a0",
            text_color=EX_COLORS["gold"], height=28, width=160,
            command=self._open_challenge,
        ).grid(row=1, column=2, padx=16, pady=(0, 8), sticky="e")

    def _open_investigation_suite(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("exhibition_lab")

    def _open_challenge(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("challenge_mode")

    def _build_body(self) -> None:
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        body.grid_columnconfigure(0, weight=5)
        body.grid_columnconfigure(1, weight=3)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        chapter_bar = ctk.CTkFrame(left, fg_color=EX_COLORS["card"],
                                   corner_radius=8, border_width=1,
                                   border_color=EX_COLORS["card_border"])
        chapter_bar.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        for col in range(3):
            chapter_bar.grid_columnconfigure(col, weight=1)

        self._chapter_btns: Dict[str, ctk.CTkButton] = {}
        for i, chapter in enumerate(_CHAPTERS):
            label = f"{i + 1}  {chapter['title']}"
            btn = ctk.CTkButton(
                chapter_bar, text=label,
                font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                fg_color="#243552", hover_color="#2a5a8a",
                text_color=EX_COLORS["white"], height=30,
                command=lambda idx=i: self._set_chapter(idx),
            )
            btn.grid(row=i // 3, column=i % 3, padx=3, pady=3, sticky="ew")
            self._chapter_btns[chapter["id"]] = btn

        canvas_frame = ctk.CTkFrame(left, fg_color=EX_COLORS["panel_dark"],
                                    corner_radius=8, border_width=1,
                                    border_color=EX_COLORS["card_border"])
        canvas_frame.grid(row=1, column=0, sticky="nsew")
        canvas_frame.grid_rowconfigure(0, weight=1)
        canvas_frame.grid_columnconfigure(0, weight=1)

        try:
            from ml.predictor import FEATURE_NAMES as _MODEL_FEATURES
        except Exception:
            _MODEL_FEATURES = []

        self._canvas = StoryMode3D(canvas_frame, width=720, height=470,
                                   reduced_motion=False,
                                   on_select=self._on_object_click,
                                   feature_names=_MODEL_FEATURES)
        self._canvas.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

        progress = ctk.CTkFrame(left, fg_color="transparent")
        progress.grid(row=2, column=0, sticky="ew", pady=(4, 0))
        progress.grid_columnconfigure(0, weight=1)
        self._progress = ctk.CTkProgressBar(
            progress, height=8, corner_radius=4,
            progress_color=EX_COLORS["gold"], fg_color="#1e3a6e")
        self._progress.grid(row=0, column=0, sticky="ew", padx=(2, 8))
        self._progress.set(0)
        self._progress_lbl = ctk.CTkLabel(
            progress, text="Scene 1 of 6",
            font=ctk.CTkFont("Consolas", 10),
            text_color=EX_COLORS["muted"], width=90)
        self._progress_lbl.grid(row=0, column=1, sticky="e")

        right = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                             border_width=1, border_color=EX_COLORS["card_border"])
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(2, weight=1)

        self._kicker = ctk.CTkLabel(
            right, text="CHAPTER 1 / 6",
            font=ctk.CTkFont("Consolas", 11, weight="bold"),
            text_color=EX_COLORS["gold"], anchor="w")
        self._kicker.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 0))

        self._chapter_title = ctk.CTkLabel(
            right, text="Normal System",
            font=ctk.CTkFont("Segoe UI", 20, weight="bold"),
            text_color=EX_COLORS["white"], anchor="w")
        self._chapter_title.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 6))

        self._chapter_body = ctk.CTkLabel(
            right, text="", font=ctk.CTkFont("Segoe UI", 13),
            text_color=EX_COLORS["muted"], anchor="nw", justify="left",
            wraplength=330)
        self._chapter_body.grid(row=2, column=0, sticky="new", padx=14, pady=(0, 6))

        self._chapter_fact = ctk.CTkLabel(
            right, text="", font=ctk.CTkFont("Segoe UI", 12, slant="italic"),
            text_color=EX_COLORS["cyan"], anchor="w", justify="left",
            wraplength=330)
        self._chapter_fact.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 8))

        self._evidence_header = ctk.CTkLabel(
            right, text="EVIDENCE",
            font=ctk.CTkFont("Consolas", 10, weight="bold"),
            text_color=EX_COLORS["gold"], anchor="w")
        self._evidence_header.grid(row=4, column=0, sticky="ew", padx=14, pady=(0, 2))

        self._evidence_frame = ctk.CTkFrame(
            right, fg_color=EX_COLORS["panel_dark"], corner_radius=6,
            border_width=1, border_color=EX_COLORS["card_border"])
        self._evidence_frame.grid(row=5, column=0, sticky="ew", padx=14, pady=(0, 6))
        self._evidence_frame.grid_columnconfigure(0, weight=1)

        self._detail_label = ctk.CTkLabel(
            right, text="Click a 3D object to inspect it.",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=EX_COLORS["muted"], anchor="w", justify="left",
            wraplength=330)
        self._detail_label.grid(row=6, column=0, sticky="ew", padx=14, pady=(0, 8))

        controls = ctk.CTkFrame(right, fg_color="transparent")
        controls.grid(row=7, column=0, sticky="ew", padx=10, pady=(0, 10))
        for col in range(4):
            controls.grid_columnconfigure(col, weight=1)

        self._prev_btn = ctk.CTkButton(
            controls, text="Previous", height=32,
            font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a",
            text_color=EX_COLORS["white"], command=self.previous_chapter)
        self._prev_btn.grid(row=0, column=0, padx=3, sticky="ew")

        self._play_btn = ctk.CTkButton(
            controls, text="Start", height=32,
            font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
            fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"],
            text_color="#000000", command=self._on_play_clicked)
        self._play_btn.grid(row=0, column=1, padx=3, sticky="ew")

        self._next_btn = ctk.CTkButton(
            controls, text="Next", height=32,
            font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
            fg_color="#1a4a7a", hover_color="#2060a0",
            text_color=EX_COLORS["cyan"], command=self.next_chapter)
        self._next_btn.grid(row=0, column=2, padx=3, sticky="ew")

        self._restart_btn = ctk.CTkButton(
            controls, text="Restart", height=32,
            font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a",
            text_color=EX_COLORS["white"], command=self.restart_story)
        self._restart_btn.grid(row=0, column=3, padx=3, sticky="ew")

        self._set_evidence_visible(False)

    # --- Chapter navigation --------------------------------------------------

    def _set_chapter(self, index: int) -> None:
        index = max(0, min(len(_CHAPTERS) - 1, int(index)))
        self._index = index
        chapter = _CHAPTERS[index]
        scene = chapter["id"]

        try:
            self._canvas.set_scene(scene)
        except Exception:
            pass

        for cid, btn in self._chapter_btns.items():
            active = cid == scene
            try:
                btn.configure(
                    fg_color=EX_COLORS["gold"] if active else "#243552",
                    hover_color=EX_COLORS["gold_hover"] if active else "#2a5a8a",
                    text_color="#000000" if active else EX_COLORS["white"])
            except Exception:
                pass

        try:
            self._kicker.configure(text=f"CHAPTER {index + 1} / {len(_CHAPTERS)}")
            self._chapter_title.configure(text=chapter["title"])
            self._chapter_body.configure(text=chapter["body"])
            self._chapter_fact.configure(text=chapter["fact"])
            self._progress.set((index + 1) / len(_CHAPTERS))
            self._progress_lbl.configure(
                text=f"Scene {index + 1} of {len(_CHAPTERS)}")
            self._prev_btn.configure(state="normal" if index > 0 else "disabled")
            self._next_btn.configure(
                state="normal" if index < len(_CHAPTERS) - 1 else "disabled")
            self._detail_label.configure(
                text=("Select an evidence item to inspect it."
                      if scene == SCENE_INVESTIGATION
                      else "Click a 3D object to inspect it."))
        except Exception:
            pass

        is_investigation = scene == SCENE_INVESTIGATION
        self._set_evidence_visible(is_investigation)
        if is_investigation:
            self._render_evidence_list()

        self._update_play_button()
        if index >= len(_CHAPTERS) - 1 and self._playing:
            self._set_playing(False)

    def next_chapter(self) -> None:
        if self._index < len(_CHAPTERS) - 1:
            self._set_chapter(self._index + 1)
            if self._playing:
                self._schedule_auto()

    def previous_chapter(self) -> None:
        if self._index > 0:
            self._set_chapter(self._index - 1)
            if self._playing:
                self._schedule_auto()

    def restart_story(self) -> None:
        self._started = True
        self._set_chapter(0)
        if self._playing:
            self._schedule_auto()
        self._update_play_button()

    def _on_play_clicked(self) -> None:
        if not self._started:
            self._started = True
            self._set_chapter(0)
            self._set_playing(True)
        else:
            self._set_playing(not self._playing)

    def _update_play_button(self) -> None:
        if not self._started:
            text = "Start"
        elif self._playing:
            text = "Pause"
        else:
            text = "Resume"
        try:
            self._play_btn.configure(text=text)
        except Exception:
            pass

    def _set_playing(self, playing: bool) -> None:
        self._playing = playing
        if playing:
            self._started = True
        self._update_play_button()
        if playing:
            if self._index >= len(_CHAPTERS) - 1:
                self._set_chapter(0)
            self._schedule_auto()
        else:
            self._cancel_auto()

    # --- Motion --------------------------------------------------------------

    def _toggle_reduced_motion(self) -> None:
        try:
            self._canvas.set_reduced_motion(bool(self._motion_var.get()))
        except Exception:
            pass

    # --- Object / evidence detail -------------------------------------------

    def _on_object_click(self, scene: str, label: str,
                         meta: Optional[dict] = None) -> None:
        if scene == SCENE_INVESTIGATION and meta and "index" in meta:
            self._show_evidence_detail(int(meta["index"]))
            return
        title = SCENE_TITLES.get(scene, scene)
        try:
            self._detail_label.configure(text=f"{title}: {label}")
        except Exception:
            pass

    def _set_evidence_visible(self, visible: bool) -> None:
        try:
            if visible:
                self._evidence_header.grid()
                self._evidence_frame.grid()
            else:
                self._evidence_header.grid_remove()
                self._evidence_frame.grid_remove()
        except Exception:
            pass

    def _render_evidence_list(self) -> None:
        for btn in self._evidence_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._evidence_buttons = []

        total = len(self._evidence_rows)
        shown = self._evidence_rows[-_EVIDENCE_DISPLAY_LIMIT:]
        suffix = "SIMULATED SAMPLE" if self._evidence_is_sample else "CORRELATED"
        header = f"EVIDENCE · {suffix} · {len(shown)} OF {total}"
        try:
            self._evidence_header.configure(text=header)
        except Exception:
            pass

        if not shown:
            lbl = ctk.CTkLabel(
                self._evidence_frame,
                text="No evidence yet. Run a scan, a scenario, or an integrity comparison.",
                font=ctk.CTkFont("Segoe UI", 11),
                text_color=EX_COLORS["muted"], anchor="w", justify="left",
                wraplength=300)
            lbl.grid(row=0, column=0, sticky="ew", padx=8, pady=6)
            self._evidence_buttons.append(lbl)
            return

        base = total - len(shown)
        for row_i, row in enumerate(shown):
            idx = base + row_i
            prov = str(row.get("provenance", "UNAVAILABLE")).upper()
            color = PROVENANCE_COLORS.get(prov, EX_COLORS["muted"])
            time_text = str(row.get("timestamp_text") or "TIME UNAVAILABLE")
            short_time = time_text[11:] if len(time_text) >= 19 else time_text
            title = str(row.get("title", "Evidence"))
            if len(title) > 42:
                title = title[:39] + "…"
            selected = idx == self._selected_evidence
            btn = ctk.CTkButton(
                self._evidence_frame,
                text=f"{short_time}  {prov[:9]:<9}  {title}",
                font=ctk.CTkFont("Consolas", 10),
                anchor="w", height=24, corner_radius=4,
                fg_color="#243552" if selected else "transparent",
                hover_color="#2a5a8a",
                text_color=color,
                command=lambda i=idx: self._show_evidence_detail(i))
            btn.grid(row=row_i, column=0, sticky="ew", padx=4, pady=1)
            self._evidence_buttons.append(btn)

    def _show_evidence_detail(self, index: int) -> None:
        if not (0 <= index < len(self._evidence_rows)):
            return
        row = self._evidence_rows[index]
        self._selected_evidence = index
        limitations = row.get("limitations") or []
        evidence = row.get("evidence") or []
        parts = [
            f"{row.get('timestamp_text') or 'TIME UNAVAILABLE'} · "
            f"{row.get('provenance_label') or row.get('provenance')}",
            str(row.get("title", "")),
        ]
        if row.get("detail"):
            parts.append(str(row["detail"]))
        parts.append(f"Source: {row.get('source') or 'not recorded'}")
        if evidence:
            parts.append("Evidence: " + "; ".join(str(e) for e in evidence[:3]))
        if limitations:
            parts.append("Limits: " + " ".join(str(l) for l in limitations[:2]))
        try:
            self._detail_label.configure(text="\n".join(parts))
        except Exception:
            pass
        self._render_evidence_list()

    # --- App state polling ---------------------------------------------------

    def _poll_app_state(self) -> None:
        if self._is_destroyed:
            return
        try:
            self._refresh_canvas_state()
        except Exception:
            pass
        self._safe_after(2000, self._poll_app_state)

    def _refresh_canvas_state(self) -> None:
        win = self.master
        pages = getattr(win, "_pages", {})
        status = "IDLE"
        prob = 0.0
        files = 0
        procs = 0
        provenance = "UNAVAILABLE"
        scan_id = ""

        dashboard = pages.get("dashboard") if pages else None
        if dashboard is not None:
            try:
                status = str(getattr(dashboard, "_threat_level", "NOT_SCANNED")).upper()
                prob = float(getattr(dashboard, "_risk_score", 0.0))
                sr = (getattr(dashboard, "_last_scan_result", None)
                      or getattr(dashboard, "_last_host_scan_result", None))
                if sr is not None:
                    files = int(getattr(sr, "files_inspected", 0))
                    procs = int(getattr(sr, "processes_analyzed", 0))
                    scan_id = str(getattr(sr, "scan_id", "") or "")
                    origin = str(getattr(sr, "scan_origin", "") or "")
                    simulated = bool(getattr(sr, "is_simulation", False)) or \
                        origin.upper() == "CONTROLLED_SIMULATION"
                    if simulated:
                        provenance = "SIMULATED"
                    elif status in _UNSAFE:
                        provenance = ("ERROR" if status in ("ERROR", "ANALYSIS_ERROR")
                                      else "UNAVAILABLE")
                    elif getattr(sr, "ml_executed", False):
                        provenance = "MEASURED"
                    else:
                        provenance = "UNAVAILABLE"
                self._last_scan_result = sr
            except Exception:
                pass

        if status in _UNSAFE:
            prob = 0.0

        corr, sample = self._collect_evidence(pages)
        self._evidence_is_sample = sample
        self._evidence_rows = corr.to_dicts()
        self._canvas.set_evidence_items(self._evidence_rows[-8:])

        self._canvas.set_scan_context(status, prob, provenance, scan_id)
        self._canvas.set_scan_stats(files, procs)
        badge = f"STATUS: {status}"
        if prob > 0:
            badge += f"  ({prob * 100:.0f}%)"
        if provenance == "MEASURED":
            badge += "  · MEASURED"
        elif provenance == "SIMULATED":
            badge += "  · SIMULATED"
        try:
            self._status_badge.configure(text=badge,
                                         text_color=_status_color(status))
        except Exception:
            pass

        if _CHAPTERS[self._index]["id"] == SCENE_INVESTIGATION:
            self._render_evidence_list()

    def _collect_evidence(self, pages: dict):
        corr = EvidenceCorrelator()
        sr = self._last_scan_result
        if sr is not None:
            try:
                corr.add_scan_result(
                    sr, source=f"SentinelML scan {getattr(sr, 'scan_id', '') or 'result'}")
            except Exception:
                pass

        wt = pages.get("integrity_watchtower") if pages else None
        if wt is not None:
            diff = getattr(wt, "_last_diff", None)
            if diff is not None:
                try:
                    corr.add_integrity_diff(
                        diff,
                        getattr(wt, "_baseline_at", None),
                        getattr(wt, "_last_compare_at", None),
                        source=f"File Integrity Watchtower · {getattr(wt, '_folder', '') or 'folder'}")
                except Exception:
                    pass

        lab = pages.get("exhibition_lab") if pages else None
        if lab is not None:
            timeline = None
            try:
                last = getattr(lab, "_last_result", None)
                timeline = getattr(last, "timeline", None) if last is not None else None
                if timeline is None:
                    runner = getattr(lab, "_runner", None)
                    timeline = getattr(runner, "timeline", None)
            except Exception:
                timeline = None
            if timeline is not None and len(getattr(timeline, "events", [])):
                try:
                    corr.add_timeline(timeline)
                except Exception:
                    pass

        if len(corr) == 0:
            return demo_correlator(), True
        return corr, False

    # --- Lifecycle -----------------------------------------------------------

    def on_shown(self) -> None:
        try:
            self._canvas.resume()
            if self._playing:
                self._schedule_auto()
        except Exception:
            pass

    def _back_to_dashboard(self) -> None:
        self._cancel_auto()
        try:
            self._canvas.pause()
        except Exception:
            pass
        if callable(self._on_exit):
            try:
                self._on_exit()
            except Exception:
                pass
            return
        show = getattr(self.master, "_show_page", None)
        if callable(show):
            try:
                show("dashboard")
            except Exception:
                pass

    def destroy(self) -> None:
        self._is_destroyed = True
        self._cancel_auto()
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
