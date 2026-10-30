"""
SentinelML V2 — Live Attack Replay Simulator (Tk page)
=====================================================
Step-by-step simulated ransomware-incident replay with Play / Pause / Resume /
Reset and playback-speed controls. Events stream into an investigation timeline
as they occur; selecting an event shows its detail and evidence.

Safety contract (enforced here and in exhibition.attack_replay):
  * SIMULATION ONLY — no ransomware runs, no real file is encrypted/modified/
    deleted, no real process is launched.
  * Every generated event is tagged SIMULATED and badged as such in the UI.
  * The replay never claims to prove real-world ransomware detection accuracy.

Threading: playback is driven by ``safe_after`` timers on the Tk main thread
(never ``time.sleep`` / tight loops), so the UI stays responsive. No worker
thread is needed because there is no I/O or model work — only timed UI updates.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

import customtkinter as ctk

from gui.exhibition_theme import (
    EX_COLORS,
    source_color,
    source_label,
    category_color,
)
from exhibition.attack_replay import (
    ReplayController,
    ReplayStep,
    SEVERITY_INFO,
    SEVERITY_WARNING,
    SEVERITY_CRITICAL,
    apply_replay_step_to_timeline,
    build_attack_replay_plan,
)
from exhibition.investigation_timeline import InvestigationEvent, InvestigationTimeline, SOURCE_SIMULATED

log = logging.getLogger("sentinel.gui.attack_replay")


def _severity_color(severity: str) -> str:
    return {
        SEVERITY_INFO: EX_COLORS["cyan"],
        SEVERITY_WARNING: EX_COLORS["warning"],
        SEVERITY_CRITICAL: EX_COLORS["critical"],
    }.get(severity, EX_COLORS["muted"])


class AttackReplayPage(ctk.CTkFrame):
    """Live Attack Replay Simulator page."""

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=EX_COLORS["bg"], **kwargs)
        self._config = config
        self._is_destroyed = False

        self._plan = build_attack_replay_plan()
        self._ctrl = ReplayController(self._plan)
        self._timeline = InvestigationTimeline()
        self._pending_step: Optional[str] = None
        self._pending_after_ids: set = set()
        self._event_rows: Dict[int, ctk.CTkFrame] = {}
        self._last_step: Optional[ReplayStep] = None

        self._build_ui()
        self._update_buttons()
        self._update_progress()

    # ── safe scheduling + destroy ───────────────────────────────────────
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

    def _cancel_pending_step(self) -> None:
        if self._pending_step is not None:
            try:
                self.after_cancel(self._pending_step)
            except Exception:
                pass
            self._pending_step = None

    def destroy(self) -> None:
        self._is_destroyed = True
        self._cancel_pending_step()
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
            header, text="⏯  SENTINELML V2  —  LIVE ATTACK REPLAY SIMULATOR",
            font=ctk.CTkFont("Segoe UI", 18, weight="bold"),
            text_color=EX_COLORS["white"]).grid(row=0, column=0, padx=20, pady=12, sticky="w")

        self._status_badge = ctk.CTkLabel(
            header, text="STATE: IDLE",
            font=ctk.CTkFont("Consolas", 12, weight="bold"),
            text_color=EX_COLORS["cyan"], fg_color="#1e3a6e", corner_radius=6, padx=12)
        self._status_badge.grid(row=0, column=1, padx=8, pady=12, sticky="w")

        back = ctk.CTkButton(
            header, text="← Back to Lab", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#103a60", hover_color="#185285", text_color=EX_COLORS["cyan"],
            height=32, command=self._back_to_lab)
        back.grid(row=0, column=2, padx=16, pady=10, sticky="e")

        # Disclaimer banner
        banner = ctk.CTkFrame(self, fg_color="#3d2800", corner_radius=0, border_width=0)
        banner.grid(row=1, column=0, sticky="ew")
        ctk.CTkLabel(
            banner,
            text="⚠ SIMULATED incident replay — no ransomware executes, no files are modified. "
                 "This does NOT prove real-world detection accuracy. All events are labelled SIMULATED.",
            font=ctk.CTkFont("Segoe UI", 12, weight="bold"), text_color=EX_COLORS["warning"],
            anchor="w").pack(fill="x", padx=16, pady=8)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=14, pady=10)
        body.grid_columnconfigure(0, weight=2)
        body.grid_columnconfigure(1, weight=3)
        body.grid_rowconfigure(1, weight=1)

        # Control bar
        ctrl = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                           border_width=1, border_color=EX_COLORS["card_border"])
        ctrl.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        ctrl.grid_columnconfigure(6, weight=1)

        self._play_btn = ctk.CTkButton(
            ctrl, text="▶ Play", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"], text_color="#000000",
            height=32, command=self._play)
        self._play_btn.grid(row=0, column=0, padx=10, pady=8)

        self._pause_btn = ctk.CTkButton(
            ctrl, text="⏸ Pause", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#3d5070", hover_color="#4a6090", text_color=EX_COLORS["white"],
            width=90, height=32, state="disabled", command=self._pause)
        self._pause_btn.grid(row=0, column=1, padx=6, pady=8)

        self._resume_btn = ctk.CTkButton(
            ctrl, text="⏵ Resume", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#103a60", hover_color="#185285", text_color=EX_COLORS["cyan"],
            width=100, height=32, state="disabled", command=self._resume)
        self._resume_btn.grid(row=0, column=2, padx=6, pady=8)

        self._reset_btn = ctk.CTkButton(
            ctrl, text="↻ Reset", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a", text_color=EX_COLORS["white"],
            width=90, height=32, command=self._reset)
        self._reset_btn.grid(row=0, column=3, padx=6, pady=8)

        ctk.CTkLabel(ctrl, text="Speed:", font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                     text_color=EX_COLORS["muted"]).grid(row=0, column=4, padx=(10, 4), pady=8)
        self._speed_seg = ctk.CTkSegmentedButton(
            ctrl, values=["0.5x", "1x", "2x", "4x"], command=self._on_speed,
            selected_color=EX_COLORS["gold"], selected_hover_color=EX_COLORS["gold_hover"],
            text_color=EX_COLORS["white"], fg_color=EX_COLORS["panel_dark"])
        self._speed_seg.set("1x")
        self._speed_seg.grid(row=0, column=5, padx=6, pady=8)

        self._progress_lbl = ctk.CTkLabel(
            ctrl, text="0 / 12 events", font=ctk.CTkFont("Consolas", 11, weight="bold"),
            text_color=EX_COLORS["white"])
        self._progress_lbl.grid(row=0, column=6, padx=12, pady=8, sticky="e")

        # Left: timeline
        left = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                           border_width=1, border_color=EX_COLORS["card_border"])
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="INVESTIGATION TIMELINE  (SIMULATED)",
                     font=ctk.CTkFont("Segoe UI", 13, weight="bold"),
                     text_color=EX_COLORS["gold"]).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))

        self._scroll = ctk.CTkScrollableFrame(left, fg_color=EX_COLORS["panel_dark"])
        self._scroll.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self._scroll.grid_columnconfigure(0, weight=1)
        self._empty_lbl = ctk.CTkLabel(
            self._scroll, text="Press ▶ Play to start the simulated incident replay.",
            font=ctk.CTkFont("Segoe UI", 11, slant="italic"), text_color=EX_COLORS["muted"])
        self._empty_lbl.pack(padx=12, pady=16, anchor="w")

        # Right: detail
        right = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                             border_width=1, border_color=EX_COLORS["card_border"])
        right.grid(row=1, column=1, sticky="nsew", padx=(6, 0))
        right.grid_rowconfigure(3, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="EVENT DETAIL & EVIDENCE",
                     font=ctk.CTkFont("Segoe UI", 13, weight="bold"),
                     text_color=EX_COLORS["cyan"]).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        self._detail_title = ctk.CTkLabel(
            right, text="Select an event to inspect its evidence.",
            font=ctk.CTkFont("Segoe UI", 14, weight="bold"), text_color=EX_COLORS["white"], anchor="w", wraplength=420)
        self._detail_title.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 2))

        self._detail_meta = ctk.CTkLabel(right, text="", font=ctk.CTkFont("Consolas", 10),
                                         text_color=EX_COLORS["muted"], anchor="w")
        self._detail_meta.grid(row=2, column=0, sticky="ew", padx=12)

        self._detail_scroll = ctk.CTkScrollableFrame(right, fg_color=EX_COLORS["panel_dark"])
        self._detail_scroll.grid(row=3, column=0, sticky="nsew", padx=8, pady=(4, 8))
        self._detail_scroll.grid_columnconfigure(0, weight=1)
        self._detail_body = ctk.CTkLabel(self._detail_scroll, text="", font=ctk.CTkFont("Segoe UI", 12), text_color=EX_COLORS["white"], anchor="w", justify="left", wraplength=420)
        self._detail_body.pack(fill="x", padx=6, pady=6, anchor="w")

    # ── controls ─────────────────────────────────────────────────────────
    def _play(self) -> None:
        if self._ctrl.state in ("idle", "done"):
            self._reset_timeline_view()
            self._ctrl.start()
        elif self._ctrl.state == "paused":
            self._ctrl.resume()
        if self._ctrl.state == "playing":
            self._schedule_next()
        self._update_buttons()
        self._status_badge.configure(text="STATE: PLAYING", text_color=EX_COLORS["cyan"])

    def _schedule_next(self) -> None:
        self._cancel_pending_step()
        if self._ctrl.is_done() or self._ctrl.state != "playing":
            return
        ms = self._ctrl.delay_before_next_ms()
        self._pending_step = self.safe_after(ms, self._apply_next)

    def _apply_next(self) -> None:
        if getattr(self, "_is_destroyed", False) or not self.winfo_exists():
            return
        if self._ctrl.state != "playing":
            return
        step = self._ctrl.advance()
        if step is None:
            self._on_done()
            return
        evt = apply_replay_step_to_timeline(step, self._timeline)
        self._last_step = step
        self._add_event_row(evt, step)
        self._update_progress()
        if self._ctrl.is_done():
            self._on_done()
        else:
            self._schedule_next()

    def _on_done(self) -> None:
        self._cancel_pending_step()
        self._status_badge.configure(text="STATE: COMPLETE (SIMULATED)", text_color=EX_COLORS["safe"])
        self._update_buttons()

    def _pause(self) -> None:
        if self._ctrl.state != "playing":
            return
        self._ctrl.pause()
        self._cancel_pending_step()
        self._status_badge.configure(text="STATE: PAUSED", text_color=EX_COLORS["warning"])
        self._update_buttons()

    def _resume(self) -> None:
        if self._ctrl.state != "paused":
            return
        self._ctrl.resume()
        self._status_badge.configure(text="STATE: PLAYING", text_color=EX_COLORS["cyan"])
        self._schedule_next()
        self._update_buttons()

    def _reset(self) -> None:
        self._cancel_pending_step()
        self._ctrl.reset()
        self._timeline.clear()
        self._reset_timeline_view()
        self._last_step = None
        self._update_progress()
        self._status_badge.configure(text="STATE: IDLE", text_color=EX_COLORS["cyan"])
        self._update_buttons()

    def _on_speed(self, value: str) -> None:
        try:
            mult = float(value.rstrip("x"))
        except ValueError:
            mult = 1.0
        self._ctrl.set_speed(mult)
        if self._ctrl.state == "playing":
            self._schedule_next()

    def _update_buttons(self) -> None:
        s = self._ctrl.state
        self._play_btn.configure(state="normal" if s in ("idle", "done") else "disabled")
        self._pause_btn.configure(state="normal" if s == "playing" else "disabled")
        self._resume_btn.configure(state="normal" if s == "paused" else "disabled")
        self._reset_btn.configure(state="normal")

    def _update_progress(self) -> None:
        done = self._ctrl.index
        total = self._ctrl.total_steps()
        self._progress_lbl.configure(text=f"{done} / {total} events")

    # ── timeline rows ────────────────────────────────────────────────────
    def _reset_timeline_view(self) -> None:
        for row in list(self._event_rows.values()):
            try:
                row.destroy()
            except Exception:
                pass
        self._event_rows.clear()
        self._detail_title.configure(text="Select an event to inspect its evidence.",
                                      text_color=EX_COLORS["white"])
        self._detail_meta.configure(text="")
        self._detail_body.configure(text="")
        if not self._scroll.winfo_children():
            self._empty_lbl = ctk.CTkLabel(
                self._scroll, text="Press ▶ Play to start the simulated incident replay.",
                font=ctk.CTkFont("Segoe UI", 11, slant="italic"), text_color=EX_COLORS["muted"])
            self._empty_lbl.pack(padx=12, pady=16, anchor="w")

    def _add_event_row(self, evt: InvestigationEvent, step: ReplayStep) -> None:
        if self._empty_lbl is not None and self._empty_lbl.winfo_exists():
            try:
                self._empty_lbl.destroy()
            except Exception:
                pass
            self._empty_lbl = None
        row = ctk.CTkFrame(self._scroll, fg_color=EX_COLORS["card"],
                           corner_radius=6, border_width=1, border_color=EX_COLORS["card_border"])
        row.pack(fill="x", padx=4, pady=2)
        row.grid_columnconfigure(2, weight=1)

        sev = ctk.CTkLabel(row, text=step.severity.upper()[:4],
                           font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=_severity_color(step.severity), fg_color="#1e3a6e",
                           corner_radius=4, width=52)
        sev.grid(row=0, column=0, padx=6, pady=4)

        sim = ctk.CTkLabel(row, text=source_label(evt.source),
                           font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=source_color(evt.source), width=110)
        sim.grid(row=0, column=1, padx=4, pady=4)

        ctk.CTkLabel(row, text=f"#{evt.seq} {evt.timestamp}  {evt.title}",
                     font=ctk.CTkFont("Segoe UI", 12), text_color=EX_COLORS["white"], anchor="w").grid(row=0, column=2, sticky="ew", padx=4, pady=4)

        seq = evt.seq
        row.bind("<Button-1>", lambda e, s=seq: self._on_select_event(s))
        for child in row.winfo_children():
            child.bind("<Button-1>", lambda e, s=seq: self._on_select_event(s))
        self._event_rows[seq] = row
        # auto-select the latest event
        self._on_select_event(seq)
        try:
            self._scroll._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass

    def _on_select_event(self, seq: int) -> None:
        for s, row in self._event_rows.items():
            row.configure(border_color=EX_COLORS["gold"] if s == seq else EX_COLORS["card_border"])
        evt = self._timeline.get(seq)
        if evt is None:
            return
        # find the matching step for severity colour
        sev_color = EX_COLORS["muted"]
        if self._last_step and seq <= self._timeline.snapshot_summary()["event_count"]:
            pass
        self._detail_title.configure(text=evt.title, text_color=EX_COLORS["white"])
        self._detail_meta.configure(
            text=f"#{evt.seq}  •  {evt.timestamp}  •  {evt.category.replace('_', ' ')}  •  Source: {source_label(evt.source)}",
            text_color=source_color(evt.source))
        body_lines = [evt.detail, ""]
        if evt.evidence:
            body_lines.append("EVIDENCE:")
            body_lines += [f"  • {e}" for e in evt.evidence]
        self._detail_body.configure(text="\n".join(body_lines), text_color=EX_COLORS["white"])

    # ── navigation ──────────────────────────────────────────────────────
    def _back_to_lab(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("exhibition_lab")
