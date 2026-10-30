"""
SentinelML V2 — File Integrity Watchtower (Tk page)
==================================================
Lets the user choose a dedicated test folder, establish a SHA-256 baseline, and
on request compare the current state to detect added / modified / deleted files,
showing old and new hashes, timestamps and change status.

Safety contract (enforced here and in exhibition.integrity_watchtower):
  * READ-ONLY — never creates, modifies or deletes files; only reads to hash.
  * SCOPE-LOCKED — only walks the selected folder; never inspects outside it.
  * CHANGE ≠ MALWARE — integrity changes are file-state observations only and
    do NOT confirm ransomware. A banner says so. Behavioral detection lives in
    the Exhibition Lab / ScanEngine.

Threading: SHA-256 hashing runs on a daemon worker thread; progress and results
are marshalled to the Tk main thread via the queue + dispatch + token +
safe_after pattern. No widget is touched off the main thread.
"""

from __future__ import annotations

import logging
import queue
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

import customtkinter as ctk

from gui.exhibition_theme import EX_COLORS
from exhibition.incident_report import build_integrity_report, write_report
from exhibition.integrity_watchtower import (
    IntegrityEntry,
    compute_integrity_diff,
    is_safe_watchtower_folder,
    scan_folder,
)

STATUS_PATH_MAX = 26


def display_folder(path, max_len: int = STATUS_PATH_MAX) -> str:
    """Shorten a folder path for the single-line status bar.

    The status bar is one line inside a fixed-height control row, so long
    paths must be shortened rather than wrapped (re-configuring a label from
    a <Configure> handler recurses through CustomTkinter's own
    update_idletasks chain). Full paths remain visible in the summary line,
    the folder picker and exported reports.
    """
    text = str(path)
    if len(text) <= max_len:
        return text
    tail = text[-(max_len - 1):]
    sep = max(tail.find("\\"), tail.find("/"))
    if 0 < sep < len(tail) - 1:
        tail = tail[sep + 1:]
    return "…" + tail

log = logging.getLogger("sentinel.gui.integrity_watchtower")


class IntegrityWatchtowerPage(ctk.CTkFrame):
    """File Integrity Watchtower page."""

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=EX_COLORS["bg"], **kwargs)
        self._config = config
        self._is_destroyed = False

        # Threading primitives
        self._ui_queue: queue.Queue = queue.Queue()
        self._pending_after_ids: set = set()
        self._active_token: Optional[str] = None
        self._cancel_requested = False
        self._busy = False

        self._folder: Optional[Path] = None
        self._baseline = None  # Dict[str, IntegrityEntry]
        self._baseline_at: Optional[str] = None
        self._last_compare_at: Optional[str] = None
        self._last_diff = None          # IntegrityDiff from the latest comparison
        self._skipped: list = []        # paths skipped during the latest scan
        self._all_changes: list = []    # IntegrityChange rows from the latest diff
        self._change_filter = "All"
        self._search_text = ""

        self._build_ui()
        self.safe_after(30, self._drain_ui_queue)

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
                    log.warning("Watchtower UI queue callback failed: %s", exc)
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
        self.grid_rowconfigure(3, weight=1)

        header = ctk.CTkFrame(self, fg_color=EX_COLORS["header"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            header, text="🔍  SENTINELML V2  —  FILE INTEGRITY WATCHTOWER",
            font=ctk.CTkFont("Segoe UI", 18, weight="bold"),
            text_color=EX_COLORS["white"]).grid(row=0, column=0, padx=20, pady=12, sticky="w")
        ctk.CTkButton(
            header, text="← Back to Lab", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#103a60", hover_color="#185285", text_color=EX_COLORS["cyan"],
            height=32, command=self._back_to_lab).grid(row=0, column=2, padx=16, pady=10, sticky="e")

        # Disclaimer banner
        banner = ctk.CTkFrame(self, fg_color="#0e2a5e", corner_radius=0, border_width=0)
        banner.grid(row=1, column=0, sticky="ew")
        ctk.CTkLabel(
            banner,
            text="ℹ File Integrity Watchtower monitors file changes only. A change does NOT confirm "
                 "ransomware. This tool is read-only and scope-locked to the selected folder. For "
                 "behavioral detection use the Exhibition Lab.",
            font=ctk.CTkFont("Segoe UI", 12, weight="bold"), text_color=EX_COLORS["cyan"],
            anchor="w", wraplength=1100, justify="left").pack(fill="x", padx=16, pady=8)

        # Control bar
        bar = ctk.CTkFrame(self, fg_color=EX_COLORS["card"], corner_radius=8,
                          border_width=1, border_color=EX_COLORS["card_border"])
        bar.grid(row=2, column=0, sticky="ew", padx=14, pady=(10, 6))
        bar.grid_columnconfigure(6, weight=1)

        self._folder_btn = ctk.CTkButton(
            bar, text="📁 Select Folder", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color=EX_COLORS["gold"], hover_color=EX_COLORS["gold_hover"], text_color="#000000",
            height=32, command=self._on_select_folder)
        self._folder_btn.grid(row=0, column=0, padx=10, pady=8)

        self._baseline_btn = ctk.CTkButton(
            bar, text=" Establish Baseline", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#103a60", hover_color="#185285", text_color=EX_COLORS["cyan"],
            height=32, state="disabled", command=self._on_establish_baseline)
        self._baseline_btn.grid(row=0, column=1, padx=6, pady=8)

        self._compare_btn = ctk.CTkButton(
            bar, text=" Compare Now", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#103a60", hover_color="#185285", text_color=EX_COLORS["cyan"],
            height=32, state="disabled", command=self._on_compare)
        self._compare_btn.grid(row=0, column=2, padx=6, pady=8)

        self._clear_btn = ctk.CTkButton(
            bar, text="✖ Clear Baseline", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#243552", hover_color="#2a5a8a", text_color=EX_COLORS["white"],
            height=32, state="disabled", command=self._on_clear)
        self._clear_btn.grid(row=0, column=3, padx=6, pady=8)

        self._cancel_btn = ctk.CTkButton(
            bar, text="✖ Cancel", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#3d5070", hover_color="#4a6090", text_color=EX_COLORS["white"],
            width=84, height=32, state="disabled", command=self._on_cancel)
        self._cancel_btn.grid(row=0, column=4, padx=6, pady=8)

        self._export_btn = ctk.CTkButton(
            bar, text="⤓ Export Report", font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
            fg_color="#1a4a7a", hover_color="#2060a0", text_color=EX_COLORS["cyan"],
            width=130, height=32, state="disabled", command=self._on_export)
        self._export_btn.grid(row=0, column=5, padx=6, pady=8)

        self._status_lbl = ctk.CTkLabel(
            bar, text="No folder selected.", font=ctk.CTkFont("Segoe UI", 12), text_color=EX_COLORS["muted"], anchor="w")
        self._status_lbl.grid(row=0, column=6, padx=12, pady=8, sticky="ew")

        # Results
        body = ctk.CTkFrame(self, fg_color=EX_COLORS["card"], corner_radius=8,
                           border_width=1, border_color=EX_COLORS["card_border"])
        body.grid(row=3, column=0, sticky="nsew", padx=14, pady=(0, 10))
        body.grid_rowconfigure(2, weight=1)
        body.grid_columnconfigure(0, weight=1)

        self._summary_lbl = ctk.CTkLabel(
            body, text="Baseline: none. Select a folder and establish a baseline, then Compare Now.",
            font=ctk.CTkFont("Segoe UI", 13, weight="bold"), text_color=EX_COLORS["gold"], anchor="w")
        self._summary_lbl.grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        filters = ctk.CTkFrame(body, fg_color="transparent")
        filters.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 4))
        filters.grid_columnconfigure(2, weight=1)

        self._filter_seg = ctk.CTkSegmentedButton(
            filters, values=["All", "Added", "Modified", "Deleted"],
            font=ctk.CTkFont("Consolas", 11, weight="bold"),
            fg_color="#1a2e56", selected_color="#1a4a7a",
            selected_hover_color="#2060a0", unselected_color="#1a2e56",
            unselected_hover_color="#243552", text_color=EX_COLORS["white"],
            command=self._on_filter_change)
        self._filter_seg.set("All")
        self._filter_seg.grid(row=0, column=0, padx=(2, 8), pady=2, sticky="w")

        ctk.CTkLabel(
            filters, text="Path filter:", font=ctk.CTkFont("Segoe UI", 11),
            text_color=EX_COLORS["muted"]).grid(row=0, column=1, padx=(4, 4), sticky="e")

        self._search_var = ctk.StringVar(value="")
        self._search_entry = ctk.CTkEntry(
            filters, textvariable=self._search_var,
            placeholder_text="Search file paths…",
            placeholder_text_color=EX_COLORS["muted"],
            font=ctk.CTkFont("Consolas", 11), height=28,
            fg_color="#0f1d38", border_color=EX_COLORS["card_border"],
            text_color=EX_COLORS["white"])
        self._search_entry.grid(row=0, column=2, sticky="ew", padx=4, pady=2)
        self._search_entry.bind("<KeyRelease>", self._on_search_change)

        self._results = ctk.CTkScrollableFrame(body, fg_color=EX_COLORS["panel_dark"])
        self._results.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._results.grid_columnconfigure(0, weight=1)
        self._results_placeholder = ctk.CTkLabel(
            self._results, text="No comparison yet.", font=ctk.CTkFont("Segoe UI", 11, slant="italic"),
            text_color=EX_COLORS["muted"])
        self._results_placeholder.pack(padx=12, pady=16, anchor="w")

    # ── controls ─────────────────────────────────────────────────────────
    def _on_select_folder(self) -> None:
        if self._busy:
            return
        try:
            from tkinter import filedialog, messagebox
        except Exception:
            return
        path = filedialog.askdirectory(title="Select a dedicated test folder for the Integrity Watchtower")
        if not path:
            return
        ok, reason = is_safe_watchtower_folder(path)
        if not ok:
            try:
                messagebox.showwarning("Folder advisory", f"{reason}\n\nPlease choose a dedicated test folder.")
            except Exception:
                pass
            return
        self._folder = Path(path)
        self._baseline = None
        self._baseline_at = None
        self._last_compare_at = None
        self._last_diff = None
        self._skipped = []
        self._all_changes = []
        self._reset_filters()
        self._status_lbl.configure(
            text=f"Folder: {display_folder(path)}   |   Baseline: none",
            text_color=EX_COLORS["white"])
        self._summary_lbl.configure(text="Baseline: none. Press 'Establish Baseline'.")
        self._clear_results()
        self._baseline_btn.configure(state="normal")
        self._compare_btn.configure(state="disabled")
        self._clear_btn.configure(state="disabled")
        self._export_btn.configure(state="disabled")

    def _on_establish_baseline(self) -> None:
        if self._busy or self._folder is None:
            return
        token = str(uuid.uuid4())
        self._active_token = token
        self._cancel_requested = False
        self._busy = True
        self._last_diff = None
        self._all_changes = []
        self._set_busy(True)
        self._status_lbl.configure(text="Establishing baseline (hashing files)…", text_color=EX_COLORS["cyan"])
        threading.Thread(target=self._scan_thread, args=(token, "baseline"),
                         daemon=True, name="WatchtowerScan").start()

    def _on_compare(self) -> None:
        if self._busy or self._folder is None or self._baseline is None:
            return
        token = str(uuid.uuid4())
        self._active_token = token
        self._cancel_requested = False
        self._busy = True
        self._set_busy(True)
        self._status_lbl.configure(text="Comparing current state to baseline (hashing files)…",
                                   text_color=EX_COLORS["cyan"])
        threading.Thread(target=self._scan_thread, args=(token, "compare"),
                         daemon=True, name="WatchtowerScan").start()

    def _on_clear(self) -> None:
        if self._busy:
            return
        self._baseline = None
        self._baseline_at = None
        self._last_compare_at = None
        self._last_diff = None
        self._skipped = []
        self._all_changes = []
        self._reset_filters()
        self._clear_results()
        self._summary_lbl.configure(text="Baseline cleared. Press 'Establish Baseline' to start again.")
        self._status_lbl.configure(
            text=f"Folder: {display_folder(self._folder)}   |   Baseline: none", text_color=EX_COLORS["white"])
        self._compare_btn.configure(state="disabled")
        self._clear_btn.configure(state="disabled")
        self._export_btn.configure(state="disabled")

    def _on_cancel(self) -> None:
        if not self._busy:
            return
        self._cancel_requested = True
        self._cancel_btn.configure(state="disabled", text="Cancelling…")
        self._status_lbl.configure(text="Cancellation requested — stopping at the next file…",
                                   text_color=EX_COLORS["warning"])

    def _set_busy(self, busy: bool) -> None:
        self._folder_btn.configure(state="disabled" if busy else "normal")
        self._baseline_btn.configure(state="disabled" if busy else ("normal" if self._folder else "disabled"))
        self._compare_btn.configure(state="disabled" if busy else ("normal" if self._baseline else "disabled"))
        self._clear_btn.configure(state="disabled" if busy else ("normal" if self._baseline else "disabled"))
        self._export_btn.configure(
            state="disabled" if busy else ("normal" if self._last_diff is not None else "disabled"))
        self._cancel_btn.configure(state="normal" if busy else "disabled", text="✖ Cancel")

    # ── worker ───────────────────────────────────────────────────────────
    def _scan_thread(self, token: str, mode: str) -> None:
        folder = self._folder
        skipped: list = []

        def progress(count: int) -> None:
            if self._cancel_requested or token != self._active_token:
                return
            self._dispatch_to_main(self._on_progress, count, token)

        def cancel_check() -> bool:
            return bool(self._cancel_requested or token != self._active_token)

        def on_skip(rel: str, reason: str) -> None:
            skipped.append(f"{reason}: {rel}")

        try:
            current = scan_folder(folder, on_progress=progress,
                                  cancel_check=cancel_check, on_skip=on_skip)
        except Exception as exc:
            if token == self._active_token:
                self._dispatch_to_main(self._on_scan_error, str(exc), mode, token)
            return
        if token != self._active_token:
            return
        cancelled = cancel_check()
        if mode == "baseline":
            self._dispatch_to_main(self._on_baseline_done, current, token,
                                   cancelled, skipped)
        else:
            self._dispatch_to_main(self._on_compare_done, current, token,
                                   cancelled, skipped)

    def _on_progress(self, count: int, token: str) -> None:
        if token != self._active_token or self._is_destroyed:
            return
        self._status_lbl.configure(text=f"Hashing… {count} files", text_color=EX_COLORS["cyan"])

    def _on_baseline_done(self, current, token: str, cancelled: bool = False,
                          skipped: Optional[list] = None) -> None:
        if self._is_destroyed or token != self._active_token:
            return
        self._busy = False
        self._set_busy(False)
        if cancelled:
            # A cancelled baseline is incomplete — never adopt it as the baseline.
            self._status_lbl.configure(
                text="Baseline cancelled — no baseline was saved.",
                text_color=EX_COLORS["warning"])
            self._summary_lbl.configure(
                text="Baseline cancelled. Press 'Establish Baseline' to try again.",
                text_color=EX_COLORS["warning"])
            return
        self._baseline = current
        self._baseline_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._skipped = list(skipped or [])
        n = len(current)
        skip_txt = f" · {len(self._skipped)} skipped" if self._skipped else ""
        stamp = self._baseline_at.split(" ")[-1] if self._baseline_at else "—"
        self._status_lbl.configure(
            text=f"Folder: {display_folder(self._folder)}   |   Baseline: {n} files · {stamp}{skip_txt}",
            text_color=EX_COLORS["safe"])
        self._summary_lbl.configure(
            text=(f"Baseline established at {self._baseline_at}: {n} files"
                  f"{skip_txt}. Press 'Compare Now' to detect changes."),
            text_color=EX_COLORS["safe"])
        self._compare_btn.configure(state="normal")
        self._clear_btn.configure(state="normal")

    def _on_compare_done(self, current, token: str, cancelled: bool = False,
                         skipped: Optional[list] = None) -> None:
        if self._is_destroyed or token != self._active_token:
            return
        self._busy = False
        self._set_busy(False)
        diff = compute_integrity_diff(self._baseline, current)
        diff.skipped = list(skipped or [])
        diff.partial = bool(cancelled)
        self._last_diff = diff
        self._last_compare_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._skipped = list(skipped or [])
        self._render_diff(diff, len(current))
        base_txt = self._baseline_at or "UNAVAILABLE"
        partial_txt = "  · PARTIAL (cancelled)" if cancelled else ""
        self._status_lbl.configure(
            text=f"Folder: {display_folder(self._folder)}   |   +{len(diff.added)} ~{len(diff.modified)} "
                 f"-{len(diff.deleted)} · {diff.unchanged_count} unchanged{partial_txt}",
            text_color=EX_COLORS["warning"] if cancelled else EX_COLORS["white"])
        self._summary_lbl.configure(
            text=(f"Baseline {base_txt} → compared {self._last_compare_at}: "
                  f"{len(diff.added)} added, {len(diff.modified)} modified, "
                  f"{len(diff.deleted)} deleted, {diff.unchanged_count} unchanged. "
                  f"File-state changes — NOT confirmed ransomware."
                  + (" COMPARISON WAS CANCELLED — rows may be missing." if cancelled else "")),
            text_color=EX_COLORS["warning"] if cancelled else EX_COLORS["gold"])
        self._export_btn.configure(state="normal")

    def _on_scan_error(self, message: str, mode: str, token: str) -> None:
        if self._is_destroyed or token != self._active_token:
            return
        self._busy = False
        self._set_busy(False)
        self._status_lbl.configure(text=f"Error ({mode}): {str(message)[:90]}", text_color=EX_COLORS["error"])

    # ── results rendering ────────────────────────────────────────────────
    def _clear_results(self) -> None:
        for w in list(self._results.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass
        self._results_placeholder = ctk.CTkLabel(
            self._results, text="No comparison yet.", font=ctk.CTkFont("Segoe UI", 11, slant="italic"),
            text_color=EX_COLORS["muted"])
        self._results_placeholder.pack(padx=12, pady=16, anchor="w")

    def _reset_filters(self) -> None:
        self._change_filter = "All"
        self._search_text = ""
        try:
            self._filter_seg.set("All")
        except Exception:
            pass
        try:
            self._search_var.set("")
        except Exception:
            pass

    def _on_filter_change(self, value) -> None:
        self._change_filter = str(value or "All")
        self._render_filtered()

    def _on_search_change(self, event=None) -> None:
        try:
            self._search_text = self._search_var.get().strip().lower()
        except Exception:
            self._search_text = ""
        self._render_filtered()

    def _visible_changes(self) -> list:
        changes = list(self._all_changes)
        if self._change_filter and self._change_filter != "All":
            want = self._change_filter.lower()
            changes = [c for c in changes if c.status == want]
        if self._search_text:
            changes = [c for c in changes if self._search_text in c.relpath.lower()]
        return changes

    def _render_diff(self, diff, current_count: int) -> None:
        self._all_changes = list(diff.added) + list(diff.modified) + list(diff.deleted)
        self._current_count = int(current_count)
        self._render_filtered()

    def _render_filtered(self) -> None:
        for w in list(self._results.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass
        if self._last_diff is None:
            ctk.CTkLabel(self._results, text="No comparison yet.",
                         font=ctk.CTkFont("Segoe UI", 11, slant="italic"),
                         text_color=EX_COLORS["muted"]).pack(fill="x", padx=12, pady=16, anchor="w")
            return
        if not self._all_changes:
            ctk.CTkLabel(self._results, text="No changes detected since the baseline.",
                         font=ctk.CTkFont("Segoe UI", 12, weight="bold"), text_color=EX_COLORS["safe"]).pack(
                fill="x", padx=12, pady=16, anchor="w")
            return

        visible = self._visible_changes()
        total = len(self._all_changes)
        skip_txt = f" · {len(self._skipped)} skipped" if self._skipped else ""
        status_line = (f"Showing {len(visible)} of {total} changes · filter: {self._change_filter.lower()}"
                       f"{' · search: “' + self._search_text + '”' if self._search_text else ''}{skip_txt}")
        ctk.CTkLabel(self._results, text=status_line, font=ctk.CTkFont("Consolas", 11, weight="bold"),
                     text_color=EX_COLORS["muted"], anchor="w").pack(fill="x", padx=8, pady=(6, 2))

        if not visible:
            ctk.CTkLabel(self._results, text="No changes match the current filter.",
                         font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                         text_color=EX_COLORS["warning"]).pack(fill="x", padx=12, pady=16, anchor="w")
            return

        status_color = {"added": EX_COLORS["safe"], "modified": EX_COLORS["warning"],
                         "deleted": EX_COLORS["error"], "unchanged": EX_COLORS["muted"]}
        # header row
        hdr = ctk.CTkFrame(self._results, fg_color="transparent")
        hdr.pack(fill="x", padx=6, pady=(2, 2))
        hdr.grid_columnconfigure(2, weight=1)
        ctk.CTkLabel(hdr, text="STATUS", font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=EX_COLORS["muted"], width=80).grid(row=0, column=0, padx=2)
        ctk.CTkLabel(hdr, text="PATH", font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=EX_COLORS["muted"]).grid(row=0, column=1, sticky="w", padx=2)
        ctk.CTkLabel(hdr, text="OLD HASH → NEW HASH", font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=EX_COLORS["muted"], width=260).grid(row=0, column=2, sticky="w", padx=2)
        ctk.CTkLabel(hdr, text="TIMESTAMPS", font=ctk.CTkFont("Consolas", 11, weight="bold"), text_color=EX_COLORS["muted"], width=200).grid(row=0, column=3, sticky="w", padx=2)
        for ch in visible:
            row = ctk.CTkFrame(self._results, fg_color=EX_COLORS["card"],
                               corner_radius=6, border_width=1, border_color=EX_COLORS["card_border"])
            row.pack(fill="x", padx=4, pady=2)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=ch.status.upper(), font=ctk.CTkFont("Consolas", 12, weight="bold"), text_color=status_color.get(ch.status, EX_COLORS["muted"]),
                         fg_color="#1e3a6e", corner_radius=4, width=72).grid(row=0, column=0, padx=4, pady=4)
            ctk.CTkLabel(row, text=ch.relpath, font=ctk.CTkFont("Consolas", 12), text_color=EX_COLORS["white"], anchor="w").grid(row=0, column=1, sticky="w", padx=4, pady=4)
            hashes = f"{(ch.old_hash[:12]+'…') if ch.old_hash else '—'} → {(ch.new_hash[:12]+'…') if ch.new_hash else '—'}"
            ctk.CTkLabel(row, text=hashes, font=ctk.CTkFont("Consolas", 11), text_color=EX_COLORS["muted"], anchor="w").grid(row=0, column=2, sticky="w", padx=4, pady=4)
            ts = f"{ch.old_ts or '—'} → {ch.new_ts or '—'}"
            ctk.CTkLabel(row, text=ts, font=ctk.CTkFont("Consolas", 11), text_color=EX_COLORS["muted"], anchor="w").grid(row=0, column=3, sticky="w", padx=4, pady=4)

    # ── report export ────────────────────────────────────────────────────
    def _on_export(self) -> None:
        if self._busy or self._last_diff is None or self._folder is None:
            return
        try:
            report = build_integrity_report(
                self._last_diff,
                self._folder,
                baseline_at=self._baseline_at,
                compared_at=self._last_compare_at,
                skipped=self._skipped,
                partial=bool(getattr(self._last_diff, "partial", False)),
            )
            paths = write_report(report)
            saved_name = Path(paths["md"]).name
            self._status_lbl.configure(
                text=f"Report saved: {saved_name}  (JSON alongside)", text_color=EX_COLORS["safe"])
            log.info("Integrity report exported: %s", paths)
        except Exception as exc:
            log.error("Integrity report export failed: %s", exc)
            self._status_lbl.configure(text=f"Report export failed: {exc}", text_color=EX_COLORS["error"])

    # ── navigation ───────────────────────────────────────────────────────
    def _back_to_lab(self) -> None:
        win = self.master
        show = getattr(win, "_show_page", None)
        if callable(show):
            show("exhibition_lab")
