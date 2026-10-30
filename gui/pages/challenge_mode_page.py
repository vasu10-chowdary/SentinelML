"""
SentinelML V2 — Challenge Mode (Tk page)
========================================
Renders the deterministic, file-safe investigation exercise defined in
``exhibition.challenge_mode``. No worker threads are needed: every case is
static data and every interaction is instantaneous.

The page never touches user files, never executes anything, and always badges
the in-case model output as SIMULATED.
"""

from __future__ import annotations

import logging
from typing import Optional

import customtkinter as ctk

from gui.exhibition_theme import EX_COLORS
from exhibition.challenge_mode import (
    CASES,
    VERDICT_BENIGN,
    VERDICT_INCONCLUSIVE,
    VERDICT_INVESTIGATE,
    ChallengeSession,
    get_case,
)

log = logging.getLogger("sentinel.gui.challenge_mode")

_PROV_COLORS = {
    "MEASURED": EX_COLORS["safe"],
    "SIMULATED": EX_COLORS["simulated"],
    "HEURISTIC": EX_COLORS["warning"],
    "UNAVAILABLE": EX_COLORS["inconclusive"],
    "APPLICATION": EX_COLORS["cyan"],
}


class ChallengeModePage(ctk.CTkFrame):
    """Interactive investigation challenge page."""

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=EX_COLORS["bg"], **kwargs)
        self._config = config
        self._is_destroyed = False
        self._case_titles = [c.title for c in CASES]
        self._case_by_title = {c.title: c for c in CASES}
        self._case = CASES[0]
        self._session: Optional[ChallengeSession] = None
        self._build_ui()
        self._update_case_view()

    # ── lifecycle ────────────────────────────────────────────────────────
    def destroy(self) -> None:
        self._is_destroyed = True
        try:
            super().destroy()
        except Exception:
            pass

    # ── UI ───────────────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        header = ctk.CTkFrame(self, fg_color=EX_COLORS["header"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            header, text="🎯  SENTINELML V2  —  CHALLENGE MODE",
            font=ctk.CTkFont("Segoe UI", 18, weight="bold"),
            text_color=EX_COLORS["white"]).grid(row=0, column=0, padx=20, pady=12, sticky="w")
        ctk.CTkButton(
            header, text="← Back to Lab", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#103a60", hover_color="#185285", text_color=EX_COLORS["cyan"],
            height=32, command=self._back_to_lab).grid(row=0, column=2, padx=(16, 4), pady=10, sticky="e")

        ctk.CTkButton(
            header, text="← Dashboard", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#1a3a5c", hover_color="#245178", text_color=EX_COLORS["white"],
            height=32, command=self._back_to_dashboard).grid(row=0, column=3, padx=(4, 16), pady=10, sticky="e")

        banner = ctk.CTkFrame(self, fg_color="#0e2a5e", corner_radius=0)
        banner.grid(row=1, column=0, sticky="ew")
        ctk.CTkLabel(
            banner,
            text="ℹ Scripted training exercise. No malware is executed and no user files are read, "
                 "written, or deleted. The model result inside each case is SIMULATED. "
                 "Labelling everything ransomware is penalised.",
            font=ctk.CTkFont("Segoe UI", 12, weight="bold"), text_color=EX_COLORS["cyan"],
            anchor="w", wraplength=1100, justify="left").pack(fill="x", padx=16, pady=8)

        bar = ctk.CTkFrame(self, fg_color=EX_COLORS["card"], corner_radius=8,
                           border_width=1, border_color=EX_COLORS["card_border"])
        bar.grid(row=2, column=0, sticky="ew", padx=14, pady=(10, 6))
        bar.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(bar, text="Case:", font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                     text_color=EX_COLORS["muted"]).grid(row=0, column=0, padx=(12, 4), pady=8)
        self._case_menu = ctk.CTkOptionMenu(
            bar, values=self._case_titles, command=self._on_case_change,
            font=ctk.CTkFont("Segoe UI", 11), fg_color="#1a2e56", button_color="#1a4a7a",
            button_hover_color="#2060a0", text_color=EX_COLORS["white"], width=280)
        self._case_menu.set(self._case.title)
        self._case_menu.grid(row=0, column=1, padx=4, pady=8)

        self._start_btn = ctk.CTkButton(
            bar, text="▶ Start Challenge", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"], text_color="#000000",
            height=32, command=self._on_start)
        self._start_btn.grid(row=0, column=2, padx=8, pady=8)

        self._status_lbl = ctk.CTkLabel(
            bar, text="Select a case and press Start. Evidence is scripted.",
            font=ctk.CTkFont("Segoe UI", 11), text_color=EX_COLORS["muted"], anchor="w")
        self._status_lbl.grid(row=0, column=3, padx=12, pady=8, sticky="ew")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=3, column=0, sticky="nsew", padx=14, pady=(0, 10))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(1, weight=1)

        self._brief_lbl = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont("Segoe UI", 12), text_color=EX_COLORS["white"],
            anchor="w", justify="left", wraplength=980)
        self._brief_lbl.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        self._update_brief()

        # Left: evidence
        left = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                            border_width=1, border_color=EX_COLORS["card_border"])
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(left, text="EVIDENCE — select the events that matter",
                     font=ctk.CTkFont("Segoe UI", 13, weight="bold"), text_color=EX_COLORS["gold"]).grid(
            row=0, column=0, sticky="w", padx=10, pady=(8, 4))
        self._evidence_scroll = ctk.CTkScrollableFrame(left, fg_color=EX_COLORS["panel_dark"])
        self._evidence_scroll.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self._evidence_scroll.grid_columnconfigure(0, weight=1)

        self._detail_lbl = ctk.CTkLabel(
            left, text="Select an event to read its details. Explanations are revealed with the score.",
            font=ctk.CTkFont("Segoe UI", 10, slant="italic"), text_color=EX_COLORS["muted"],
            anchor="w", justify="left", wraplength=640)
        self._detail_lbl.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 8))

        # Right: model, verdict, actions, submit, result
        right = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                             border_width=1, border_color=EX_COLORS["card_border"])
        right.grid(row=1, column=1, sticky="nsew", padx=(6, 0))
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="SIMULATED MODEL RESULT",
                     font=ctk.CTkFont("Segoe UI", 13, weight="bold"),
                     text_color=EX_COLORS["simulated"]).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))
        self._model_lbl = ctk.CTkLabel(
            right, text="—", font=ctk.CTkFont("Segoe UI", 15, weight="bold"),
            text_color=EX_COLORS["white"], anchor="w", justify="left", wraplength=380)
        self._model_lbl.grid(row=1, column=0, sticky="ew", padx=12)
        ctk.CTkLabel(right, text="Not a detection of real files. Thresholds: WARNING ≥ 0.50 · CRITICAL ≥ 0.90",
                     font=ctk.CTkFont("Segoe UI", 10), text_color=EX_COLORS["muted"],
                     anchor="w").grid(row=2, column=0, sticky="w", padx=12, pady=(0, 6))

        ctk.CTkLabel(right, text="YOUR VERDICT",
                     font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                     text_color=EX_COLORS["cyan"]).grid(row=3, column=0, sticky="w", padx=12, pady=(2, 2))
        self._verdict_seg = ctk.CTkSegmentedButton(
            right, values=[VERDICT_INVESTIGATE, VERDICT_INCONCLUSIVE, VERDICT_BENIGN],
            font=ctk.CTkFont("Consolas", 10, weight="bold"),
            fg_color="#1a2e56", selected_color="#1a4a7a", selected_hover_color="#2060a0",
            unselected_color="#1a2e56", unselected_hover_color="#243552",
            text_color=EX_COLORS["white"], command=self._on_verdict)
        self._verdict_seg.grid(row=4, column=0, sticky="ew", padx=10, pady=(0, 4))

        ctk.CTkLabel(right, text="ACTIONS",
                     font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                     text_color=EX_COLORS["gold"]).grid(row=5, column=0, sticky="w", padx=12, pady=(4, 2))
        self._actions_scroll = ctk.CTkScrollableFrame(right, fg_color=EX_COLORS["panel_dark"], height=170)
        self._actions_scroll.grid(row=6, column=0, sticky="nsew", padx=8, pady=(0, 6))
        self._actions_scroll.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(6, weight=1)

        btns = ctk.CTkFrame(right, fg_color="transparent")
        btns.grid(row=7, column=0, sticky="ew", padx=10, pady=(0, 6))
        btns.grid_columnconfigure(0, weight=1)
        btns.grid_columnconfigure(1, weight=1)
        self._submit_btn = ctk.CTkButton(
            btns, text="✓ Submit & Score", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"], text_color="#000000",
            height=32, state="disabled", command=self._on_submit)
        self._submit_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self._restart_btn = ctk.CTkButton(
            btns, text="↻ Restart", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a", text_color=EX_COLORS["white"],
            height=32, state="disabled", command=self._on_restart)
        self._restart_btn.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        self._result_box = ctk.CTkTextbox(right, height=150, fg_color=EX_COLORS["panel_dark"],
                                          text_color=EX_COLORS["white"], font=ctk.CTkFont("Consolas", 10),
                                          wrap="word")
        self._result_box.grid(row=8, column=0, sticky="ew", padx=10, pady=(0, 10))
        self._result_box.insert("1.0", "Score and learning summary appear here after you submit.")
        self._result_box.configure(state="disabled")

    def _update_brief(self) -> None:
        self._brief_lbl.configure(text=self._case.brief)

    def _update_case_view(self) -> None:
        self._update_brief()
        self._model_lbl.configure(
            text=f"{self._case.model_label}" + (
                f"  ·  p = {self._case.model_probability:.3f}"
                if self._case.model_probability is not None else "  ·  no probability")
            + f"\n{self._case.model_note}",
            text_color=EX_COLORS["simulated"])
        for w in self._evidence_scroll.winfo_children():
            w.destroy()
        ctk.CTkLabel(self._evidence_scroll,
                     text="Press Start Challenge to load the evidence for this case.",
                     font=ctk.CTkFont("Segoe UI", 11, slant="italic"),
                     text_color=EX_COLORS["muted"]).pack(fill="x", padx=12, pady=16, anchor="w")
        for w in self._actions_scroll.winfo_children():
            w.destroy()
        ctk.CTkLabel(self._actions_scroll, text="Press Start Challenge to load response actions.",
                     font=ctk.CTkFont("Segoe UI", 11, slant="italic"),
                     text_color=EX_COLORS["muted"]).pack(fill="x", padx=12, pady=16, anchor="w")

    # ── controls ─────────────────────────────────────────────────────────
    def _on_case_change(self, title: str) -> None:
        case = self._case_by_title.get(title)
        if case is None:
            return
        self._case = case
        self._session = None
        self._update_case_view()
        self._submit_btn.configure(state="disabled")
        self._restart_btn.configure(state="disabled")
        self._status_lbl.configure(text="Case selected. Press Start Challenge.",
                                   text_color=EX_COLORS["muted"])

    def _on_start(self) -> None:
        self._session = ChallengeSession(self._case)
        self._session.start()
        self._verdict_seg.set("")
        self._submit_btn.configure(state="normal")
        self._restart_btn.configure(state="normal")
        self._status_lbl.configure(
            text=f"Running: {self._case.title}. Inspect, select evidence, compare hashes, then submit.",
            text_color=EX_COLORS["cyan"])
        self._render_evidence()
        self._render_actions()
        self._set_result_text("Score and learning summary appear here after you submit.")

    def _on_restart(self) -> None:
        if self._session is None:
            return
        self._session.restart()
        self._session.start()
        self._verdict_seg.set("")
        self._submit_btn.configure(state="normal")
        self._status_lbl.configure(text="Challenge restarted with the same scripted case.",
                                   text_color=EX_COLORS["cyan"])
        self._render_evidence()
        self._render_actions()
        self._set_result_text("Score and learning summary appear here after you submit.")

    def _on_event_toggle(self, event_id: str) -> None:
        if self._session is None or self._session.finished:
            return
        selected = self._session.toggle_event(event_id)
        card = self._session.case.evidence_by_id(event_id)
        if card is not None:
            self._session.inspect(event_id)
            self._detail_lbl.configure(
                text=f"{card.timestamp} · {card.provenance} · {card.title}\n{card.detail}",
                text_color=_PROV_COLORS.get(card.provenance, EX_COLORS["white"]))
        self._status_lbl.configure(
            text=f"{len(self._session.selected_events)} event(s) selected.",
            text_color=EX_COLORS["white"])
        self._render_evidence()

    def _on_compare(self, event_id: str) -> None:
        if self._session is None:
            return
        result = self._session.compare_hashes(event_id)
        if result is None:
            return
        self._detail_lbl.configure(
            text=(f"HASH COMPARISON · {event_id}\n"
                  f"old: {result['old_hash'][:24]}…\nnew: {result['new_hash'][:24]}…\n"
                  f"{result['interpretation']}"),
            text_color=EX_COLORS["cyan"])
        self._render_evidence()

    def _on_action_toggle(self, action_id: str) -> None:
        if self._session is None or self._session.finished:
            return
        self._session.choose_action(action_id)
        self._render_actions()

    def _on_verdict(self, verdict: str) -> None:
        if self._session is None or self._session.finished:
            return
        self._session.choose_verdict(verdict)

    def _on_submit(self) -> None:
        if self._session is None:
            return
        result = self._session.finish()
        if "error" in result:
            self._status_lbl.configure(text=result["error"], text_color=EX_COLORS["warning"])
            return
        self._submit_btn.configure(state="disabled")
        self._status_lbl.configure(
            text=f"Score: {result['score']} / {result['max_score']} · {result['grade']}",
            text_color=EX_COLORS["gold"])
        self._render_result(result)

    # ── rendering ────────────────────────────────────────────────────────
    def _render_evidence(self) -> None:
        for w in self._evidence_scroll.winfo_children():
            w.destroy()
        if self._session is None:
            return
        finished = self._session.finished
        for row in self._session.evidence_rows():
            frame = ctk.CTkFrame(self._evidence_scroll, fg_color=EX_COLORS["card"],
                                 corner_radius=6, border_width=1, border_color=EX_COLORS["card_border"])
            frame.pack(fill="x", padx=4, pady=3)
            frame.grid_columnconfigure(2, weight=1)
            select_text = "✓ SELECTED" if row["selected"] else "SELECT"
            color = EX_COLORS["gold"] if row["selected"] else "#1a4a7a"
            ctk.CTkButton(
                frame, text=select_text, width=92, height=26,
                font=ctk.CTkFont("Consolas", 9, weight="bold"),
                fg_color=color, hover_color="#2060a0",
                text_color="#000000" if row["selected"] else EX_COLORS["cyan"],
                state="disabled" if finished else "normal",
                command=lambda eid=row["event_id"]: self._on_event_toggle(eid)
            ).grid(row=0, column=0, padx=6, pady=6, rowspan=2, sticky="n")
            ctk.CTkLabel(frame, text=f"{row['timestamp']}  {row['provenance']}",
                         font=ctk.CTkFont("Consolas", 10, weight="bold"),
                         text_color=_PROV_COLORS.get(row["provenance"], EX_COLORS["muted"]),
                         anchor="w").grid(row=0, column=1, columnspan=2, sticky="w", padx=4, pady=(5, 0))
            ctk.CTkLabel(frame, text=row["title"], font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                         text_color=EX_COLORS["white"], anchor="w").grid(
                row=1, column=1, sticky="w", padx=4)
            ctk.CTkLabel(frame, text=row["detail"], font=ctk.CTkFont("Segoe UI", 10),
                         text_color=EX_COLORS["muted"], anchor="w", justify="left",
                         wraplength=430).grid(row=2, column=1, columnspan=2, sticky="w", padx=4, pady=(0, 4))
            if row["has_hash_pair"]:
                ctk.CTkButton(
                    frame, text="Compare hashes", width=110, height=24,
                    font=ctk.CTkFont("Consolas", 9),
                    fg_color="#1a4a7a", hover_color="#2060a0", text_color=EX_COLORS["cyan"],
                    command=lambda eid=row["event_id"]: self._on_compare(eid)
                ).grid(row=3, column=1, sticky="w", padx=4, pady=(0, 6))

    def _render_actions(self) -> None:
        for w in self._actions_scroll.winfo_children():
            w.destroy()
        if self._session is None:
            return
        finished = self._session.finished
        for row in self._session.action_rows():
            text = ("✓ " if row["selected"] else "○ ") + row["label"]
            color = EX_COLORS["gold"] if row["selected"] else EX_COLORS["muted"]
            ctk.CTkButton(
                self._actions_scroll, text=text, anchor="w", height=26,
                font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
                fg_color="#1a2e56" if not row["selected"] else "#1a4a7a",
                hover_color="#243552", text_color=color,
                state="disabled" if finished else "normal",
                command=lambda aid=row["action_id"]: self._on_action_toggle(aid)
            ).pack(fill="x", padx=4, pady=2)

    def _render_result(self, result: dict) -> None:
        b = result["breakdown"]
        lines = [
            f"SCORE: {result['score']} / {result['max_score']}  ({result['grade']})",
            f"  Evidence selection : {b['evidence']['points']:>2} / {b['evidence']['max']}",
            f"  Hash comparison    : {b['hash_comparison']['points']:>2} / {b['hash_comparison']['max']}",
            f"  Verdict            : {b['verdict']['points']:>2} / {b['verdict']['max']}"
            f"   (you: {result['verdict'] or '—'}, case: {result['expected_verdict']})",
            f"  Response actions   : {b['actions']['points']:>2} / {b['actions']['max']}",
            "",
            "LEARNING SUMMARY",
        ]
        for item in result["learning"]:
            lines.append(f"• {item}")
        self._set_result_text("\n".join(lines))

    def _set_result_text(self, text: str) -> None:
        self._result_box.configure(state="normal")
        self._result_box.delete("1.0", "end")
        self._result_box.insert("1.0", text)
        self._result_box.configure(state="disabled")

    # ── navigation ───────────────────────────────────────────────────────
    def _back_to_lab(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("exhibition_lab")

    def _back_to_dashboard(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("dashboard")
