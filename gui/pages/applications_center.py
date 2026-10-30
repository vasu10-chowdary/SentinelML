"""
SentinelML V2 — Real-World Applications Center (Tk page)
=========================================================
Interactive showcase of five industry use-cases demonstrating how
SentinelML's CURRENT capabilities map to real cybersecurity problems.

Honesty rules enforced:
  * Clearly distinguishes IMPLEMENTED features, SIMULATED demonstrations,
    and FUTURE possibilities via badges.
  * Healthcare displayed with an ILLUSTRATIVE USE CASE banner.
  * Live-demo buttons navigate to existing registered pages only.
  * No background threads needed (read-only data display).
"""

from __future__ import annotations

import logging
from typing import Optional

import customtkinter as ctk

from gui.exhibition_theme import EX_COLORS
from exhibition.applications_data import (
    ALL_USE_CASES,
    USE_CASE_BY_KEY,
    UseCase,
    validate_use_cases,
)

log = logging.getLogger("sentinel.gui.applications_center")

_SECTOR_COLORS = {
    "enterprise":     "#38d8f5",
    "education":      "#34d897",
    "forensics":      "#c9a8ff",
    "small_business": "#fbb03b",
    "healthcare":     "#ff6b6b",
}

_BADGE_IMPL = ("IMPLEMENTED", EX_COLORS["real"])
_BADGE_SIM  = ("SIMULATED",   EX_COLORS["simulated"])
_BADGE_ILLUS = ("ILLUSTRATIVE USE CASE", EX_COLORS["error"])
_BADGE_FUT  = ("FUTURE REQUIREMENT", EX_COLORS["inconclusive"])


class ApplicationsCenterPage(ctk.CTkFrame):
    """Real-World Applications Center page."""

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=EX_COLORS["bg"], **kwargs)
        self._config = config
        self._is_destroyed = False
        self._selected_key: Optional[str] = None

        errs = validate_use_cases()
        if errs:
            log.warning("applications_data validation errors: %s", errs)

        self._build_ui()
        if ALL_USE_CASES:
            self._select(ALL_USE_CASES[0].key)

    # ── UI ─────────────────────────────────────────────────────────────
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
            text="🏢  SENTINELML V2  —  REAL-WORLD APPLICATIONS CENTER",
            font=ctk.CTkFont("Segoe UI", 18, weight="bold"),
            text_color=EX_COLORS["white"],
        ).grid(row=0, column=0, padx=20, pady=12, sticky="w")

        ctk.CTkLabel(
            header,
            text="How SentinelML's current capabilities map to real cybersecurity problems",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=EX_COLORS["muted"],
        ).grid(row=1, column=0, padx=20, pady=(0, 8), sticky="w")

        ctk.CTkButton(
            header, text="🎯 Challenge Mode",
            font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#4a3a10", hover_color="#6a5416",
            text_color=EX_COLORS["gold"], height=32, width=155,
            command=self._open_challenge,
        ).grid(row=0, column=2, padx=(16, 4), pady=10, sticky="e")

        ctk.CTkButton(
            header, text="← Back to Lab",
            font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#103a60", hover_color="#185285",
            text_color=EX_COLORS["cyan"], height=32,
            command=self._back_to_lab,
        ).grid(row=0, column=3, padx=(4, 16), pady=10, sticky="e")

    def _build_body(self) -> None:
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=14, pady=10)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=3)
        body.grid_rowconfigure(0, weight=1)

        # Left: use-case selector
        left = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                            border_width=1, border_color=EX_COLORS["card_border"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="USE CASES",
                     font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                     text_color=EX_COLORS["gold"]
                     ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        scroll = ctk.CTkScrollableFrame(left, fg_color=EX_COLORS["panel_dark"])
        scroll.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        scroll.grid_columnconfigure(0, weight=1)

        self._selector_btns: dict = {}
        for uc in ALL_USE_CASES:
            color = _SECTOR_COLORS.get(uc.key, EX_COLORS["cyan"])
            card = ctk.CTkFrame(scroll, fg_color=EX_COLORS["card"],
                                corner_radius=6, border_width=2,
                                border_color=EX_COLORS["card_border"])
            card.pack(fill="x", padx=4, pady=4)
            card.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(card, text=uc.title,
                         font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                         text_color=EX_COLORS["white"], anchor="w",
                         ).pack(fill="x", padx=10, pady=(8, 1))

            row2 = ctk.CTkFrame(card, fg_color="transparent")
            row2.pack(fill="x", padx=10, pady=(0, 4))
            ctk.CTkLabel(row2, text=uc.sector,
                         font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=color,
                         ).pack(side="left")
            if uc.is_illustrative:
                ctk.CTkLabel(row2, text=" [ILLUSTRATIVE]",
                             font=ctk.CTkFont("Consolas", 9, weight="bold"),
                             text_color=EX_COLORS["error"],
                             ).pack(side="left")

            key = uc.key
            for widget in [card] + card.winfo_children():
                widget.bind("<Button-1>", lambda e, k=key: self._select(k))
            self._selector_btns[key] = card

        # Right: detail panel
        right = ctk.CTkFrame(body, fg_color=EX_COLORS["card"], corner_radius=8,
                             border_width=1, border_color=EX_COLORS["card_border"])
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        self._detail_header = ctk.CTkFrame(right, fg_color=EX_COLORS["panel_dark"],
                                           corner_radius=0)
        self._detail_header.grid(row=0, column=0, sticky="ew")
        self._detail_header.grid_columnconfigure(0, weight=1)

        self._detail_title = ctk.CTkLabel(
            self._detail_header, text="Select a use case",
            font=ctk.CTkFont("Segoe UI", 15, weight="bold"),
            text_color=EX_COLORS["white"], anchor="w")
        self._detail_title.grid(row=0, column=0, padx=14, pady=(10, 2), sticky="w")

        self._badge_row = ctk.CTkFrame(self._detail_header, fg_color="transparent")
        self._badge_row.grid(row=1, column=0, padx=14, pady=(0, 6), sticky="w")

        self._demo_btn = ctk.CTkButton(
            self._detail_header, text="▶  Open Live Demo",
            font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"],
            text_color="#000000", height=32, state="disabled",
            command=self._open_demo)
        self._demo_btn.grid(row=0, column=1, padx=14, pady=10, sticky="e")

        self._detail_scroll = ctk.CTkScrollableFrame(right, fg_color=EX_COLORS["panel_dark"])
        self._detail_scroll.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self._detail_scroll.grid_columnconfigure(0, weight=1)

        self._detail_placeholder = ctk.CTkLabel(
            self._detail_scroll, text="Click a use case on the left to explore it.",
            font=ctk.CTkFont("Segoe UI", 12, slant="italic"),
            text_color=EX_COLORS["muted"])
        self._detail_placeholder.pack(padx=16, pady=30, anchor="w")

    # ── Selection / rendering ──────────────────────────────────────────
    def _select(self, key: str) -> None:
        if self._is_destroyed:
            return
        self._selected_key = key
        for k, card in self._selector_btns.items():
            card.configure(border_color=EX_COLORS["gold"] if k == key
                           else EX_COLORS["card_border"])
        uc = USE_CASE_BY_KEY.get(key)
        if uc:
            self._render_detail(uc)

    def _render_detail(self, uc: UseCase) -> None:
        for w in list(self._detail_scroll.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass
        for w in list(self._badge_row.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass

        color = _SECTOR_COLORS.get(uc.key, EX_COLORS["cyan"])
        self._detail_title.configure(text=uc.title, text_color=color)

        for text, bc in [_BADGE_IMPL, _BADGE_SIM]:
            ctk.CTkLabel(self._badge_row, text=f" {text} ",
                         font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=bc, fg_color="#1e3a6e", corner_radius=4,
                         ).pack(side="left", padx=(0, 6))
        if uc.is_illustrative:
            ctk.CTkLabel(self._badge_row, text=f" {_BADGE_ILLUS[0]} ",
                         font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=_BADGE_ILLUS[1], fg_color="#4a1010", corner_radius=4,
                         ).pack(side="left", padx=(0, 6))

        self._demo_btn.configure(
            state="normal",
            text=f"▶  Open Demo: {uc.demo_page.replace('_', ' ').title()}")

        body = self._detail_scroll

        def section(title: str, tc: str = EX_COLORS["gold"]) -> None:
            ctk.CTkLabel(body, text=title,
                         font=ctk.CTkFont("Segoe UI", 13, weight="bold"), text_color=tc, anchor="w").pack(fill="x", padx=14, pady=(12, 2))

        def para(text: str, color: str = EX_COLORS["white"]) -> None:
            ctk.CTkLabel(body, text=text, font=ctk.CTkFont("Segoe UI", 11),
                         text_color=color, anchor="w", justify="left", wraplength=720,
                         ).pack(fill="x", padx=14, pady=(0, 4))

        def bullets(items: list, color: str = EX_COLORS["white"],
                    badge: Optional[tuple] = None) -> None:
            for item in items:
                row = ctk.CTkFrame(body, fg_color="transparent")
                row.pack(fill="x", padx=14, pady=1)
                if badge:
                    ctk.CTkLabel(row, text=f" {badge[0]} ",
                                 font=ctk.CTkFont("Consolas", 8, weight="bold"),
                                 text_color=badge[1], fg_color="#1e3a6e",
                                 corner_radius=3).pack(side="left", padx=(0, 6))
                ctk.CTkLabel(row, text=f"• {item}", font=ctk.CTkFont("Segoe UI", 11), text_color=color, anchor="w", justify="left", wraplength=680,
                             ).pack(side="left", fill="x")

        if uc.is_illustrative:
            warn = ctk.CTkFrame(body, fg_color="#4a1010", corner_radius=6, border_width=2, border_color=EX_COLORS["critical"])
            warn.pack(fill="x", padx=14, pady=(8, 0))
            ctk.CTkLabel(
                warn,
                text="⚠  ILLUSTRATIVE USE CASE ONLY — Not validated for clinical deployment. "
                     "Not HIPAA-certified. Must not be used as the sole security control in any "
                     "healthcare environment. See Limitations below.",
                font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                text_color=EX_COLORS["error"], anchor="w", justify="left", wraplength=720,
            ).pack(fill="x", padx=12, pady=10)

        section("THE PROBLEM", EX_COLORS["cyan"])
        para(uc.problem, EX_COLORS["muted"])

        section("CURRENT SENTINELML CAPABILITIES THAT HELP", EX_COLORS["gold"])
        bullets(uc.capabilities, EX_COLORS["white"], _BADGE_IMPL)

        section("RELEVANT TELEMETRY FEATURES", EX_COLORS["cyan"])
        ctk.CTkLabel(body, text="  ".join(f"[{f}]" for f in uc.telemetry_features),
                     font=ctk.CTkFont("Consolas", 9), text_color=EX_COLORS["muted"],
                     anchor="w", justify="left", wraplength=720,
                     ).pack(fill="x", padx=14, pady=(0, 4))

        section("EVIDENCE THE TOOL PRODUCES", EX_COLORS["gold"])
        bullets(uc.model_outputs, EX_COLORS["white"])
        ctk.CTkLabel(
            body,
            text=("Evidence items are observations, not proof of ransomware. "
                  "Co-occurrence in time does not establish causation, and a changed "
                  "file hash alone never indicates malware."),
            font=ctk.CTkFont("Segoe UI", 10, slant="italic"),
            text_color=EX_COLORS["muted"], anchor="w", justify="left",
            wraplength=720,
        ).pack(fill="x", padx=14, pady=(2, 4))

        section("SIMULATED VS MEASURED DATA", EX_COLORS["simulated"])
        bullets(uc.simulated_data, EX_COLORS["white"], _BADGE_SIM)

        section("LIVE DEMONSTRATION (using existing project tools)", EX_COLORS["gold"])
        demo_frame = ctk.CTkFrame(body, fg_color="#1e3a6e", corner_radius=6)
        demo_frame.pack(fill="x", padx=14, pady=(0, 4))
        ctk.CTkLabel(demo_frame, text=uc.demo_description,
                     font=ctk.CTkFont("Segoe UI", 11), text_color=EX_COLORS["white"],
                     anchor="w", justify="left", wraplength=720,
                     ).pack(fill="x", padx=12, pady=10)

        section("INVESTIGATION WORKFLOW", EX_COLORS["cyan"])
        for step in uc.investigation_steps:
            ctk.CTkLabel(body, text=step, font=ctk.CTkFont("Segoe UI", 11), text_color=EX_COLORS["white"], anchor="w",
                         justify="left", wraplength=720).pack(fill="x", padx=14, pady=1)

        section("RECOMMENDED NEXT STEPS", EX_COLORS["gold"])
        bullets(uc.next_steps, EX_COLORS["white"])

        section("CURRENT LIMITATIONS", EX_COLORS["warning"])
        bullets(uc.limitations, EX_COLORS["muted"])

        section("WHAT PRODUCTION DEPLOYMENT WOULD ADDITIONALLY REQUIRE",
                EX_COLORS["inconclusive"])
        bullets(uc.production_requirements, EX_COLORS["muted"], _BADGE_FUT)

    # ── Navigation ────────────────────────────────────────────────────
    def _open_demo(self) -> None:
        if not self._selected_key:
            return
        uc = USE_CASE_BY_KEY.get(self._selected_key)
        if uc is None:
            return
        show = getattr(self.master, "_show_page", None)
        if callable(show):
            show(uc.demo_page)

    def _open_challenge(self) -> None:
        show = getattr(self.master, "_show_page", None)
        if callable(show):
            show("challenge_mode")

    def _back_to_lab(self) -> None:
        show = getattr(self.master, "_show_page", None)
        if callable(show):
            show("exhibition_lab")

    def destroy(self) -> None:
        self._is_destroyed = True
        try:
            super().destroy()
        except Exception:
            pass
