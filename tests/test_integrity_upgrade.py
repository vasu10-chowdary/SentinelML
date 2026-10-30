"""File Integrity Watchtower upgrade tests (Phase 3).

Covers: skip reporting (unreadable / symlink / vanished), diff flags,
cancellation, report content, collision-safe export, filters and search.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.integrity_watchtower import (
    IntegrityChange,
    IntegrityDiff,
    IntegrityEntry,
    compute_integrity_diff,
    scan_folder,
)
from exhibition.incident_report import (
    MAX_ROWS_PER_SECTION,
    REPORT_NOTICE,
    build_integrity_report,
    render_integrity_markdown,
    unique_output_path,
    write_report,
)


def _entry(rel, digest, size=10, ts="2026-01-01 00:00:00"):
    return IntegrityEntry(relpath=rel, hash=digest, size=size, mtime=0.0, ts=ts)


def _sample_diff():
    diff = IntegrityDiff()
    diff.added.append(IntegrityChange(
        relpath="docs/new.txt", status="added", old_hash="", new_hash="a" * 64,
        old_ts="", new_ts="2026-01-02 10:00:00", old_size=-1, new_size=3))
    diff.modified.append(IntegrityChange(
        relpath="docs/changed.txt", status="modified", old_hash="b" * 64, new_hash="c" * 64,
        old_ts="2026-01-01 09:00:00", new_ts="2026-01-02 10:00:00", old_size=4, new_size=5))
    diff.deleted.append(IntegrityChange(
        relpath="old/gone.txt", status="deleted", old_hash="d" * 64, new_hash="",
        old_ts="2026-01-01 09:00:00", new_ts="", old_size=6, new_size=-1))
    diff.unchanged_count = 7
    diff.total = 10
    return diff


class TestScanFolderSkips(unittest.TestCase):

    def test_unreadable_file_reported_with_reason(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "readable.txt").write_text("ok", encoding="utf-8")
            Path(td, "locked.bin").write_bytes(b"x")
            skipped = []

            def fake_hash(path):
                if Path(path).name == "locked.bin":
                    return None
                return "f" * 64

            with patch("exhibition.integrity_watchtower.hash_file", side_effect=fake_hash):
                entries = scan_folder(td, on_skip=lambda rel, why: skipped.append((rel, why)))

            self.assertIn("readable.txt", entries)
            self.assertNotIn("locked.bin", entries)
            self.assertEqual(skipped, [("locked.bin", "unreadable")])

    def test_vanished_file_reported_with_reason(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "vanish.txt").write_text("x", encoding="utf-8")
            skipped = []
            real_stat = Path.stat

            def fake_stat(self, *args, **kwargs):
                if self.name == "vanish.txt":
                    raise OSError("gone")
                return real_stat(self, *args, **kwargs)

            with patch("exhibition.integrity_watchtower.Path.stat", fake_stat):
                scan_folder(td, on_skip=lambda rel, why: skipped.append((rel, why)))

            self.assertEqual(skipped, [("vanish.txt", "vanished")])

    def test_symlink_reported_with_reason(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as td:
            target = Path(td, "target.txt")
            target.write_text("x", encoding="utf-8")
            link = Path(td, "link.txt")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation requires privileges on this host")
            skipped = []
            entries = scan_folder(td, on_skip=lambda rel, why: skipped.append((rel, why)))
            self.assertIn("target.txt", entries)
            self.assertIn(("link.txt", "symlink"), skipped)

    def test_cancel_check_stops_early(self):
        with tempfile.TemporaryDirectory() as td:
            for i in range(6):
                Path(td, f"f{i}.txt").write_text(str(i), encoding="utf-8")
            calls = {"n": 0}

            def cancel():
                calls["n"] += 1
                return calls["n"] > 1

            entries = scan_folder(td, cancel_check=cancel)
            self.assertLess(len(entries), 6)


class TestIntegrityDiffAndReport(unittest.TestCase):

    def test_diff_detects_added_modified_deleted(self):
        base = {"a.txt": _entry("a.txt", "1" * 64),
                "b.txt": _entry("b.txt", "2" * 64),
                "c.txt": _entry("c.txt", "3" * 64)}
        cur = {"a.txt": _entry("a.txt", "1" * 64),
               "b.txt": _entry("b.txt", "9" * 64),
               "d.txt": _entry("d.txt", "4" * 64)}
        diff = compute_integrity_diff(base, cur)
        self.assertEqual([c.relpath for c in diff.added], ["d.txt"])
        self.assertEqual([c.relpath for c in diff.modified], ["b.txt"])
        self.assertEqual([c.relpath for c in diff.deleted], ["c.txt"])
        self.assertEqual(diff.unchanged_count, 1)
        self.assertEqual(diff.total, 4)
        self.assertFalse(diff.partial)
        self.assertFalse(diff.limited)

    def test_report_contains_timestamps_hashes_and_limitations(self):
        diff = _sample_diff()
        report = build_integrity_report(
            diff, r"C:\Users\vasur\Desktop\TestFolder",
            baseline_at="2026-01-01 09:00:00",
            compared_at="2026-01-02 10:00:00",
            skipped=["unreadable: locked.bin"],
            partial=True)
        self.assertEqual(report["report_type"], "FILE_INTEGRITY")
        self.assertEqual(report["baseline_at"], "2026-01-01 09:00:00")
        self.assertEqual(report["compared_at"], "2026-01-02 10:00:00")
        self.assertTrue(report["partial"])
        self.assertIn("[USER_PROFILE]", report["folder"])
        self.assertNotIn("vasur", report["folder"])
        self.assertEqual(report["summary"]["added"], 1)
        self.assertEqual(report["summary"]["modified"], 1)
        self.assertEqual(report["summary"]["deleted"], 1)
        self.assertEqual(report["added"][0]["new_hash"], "a" * 64)
        self.assertEqual(report["modified"][0]["old_hash"], "b" * 64)
        self.assertIsNone(report["deleted"][0]["new_hash"])
        self.assertEqual(report["notice"], REPORT_NOTICE)
        self.assertTrue(any("not prove malware" in n.lower() for n in [report["notice"]]))
        self.assertTrue(any("content changed" in lim for lim in report["limitations"]))

        md = render_integrity_markdown(report)
        self.assertIn("FILE INTEGRITY REPORT", md)
        self.assertIn("PARTIAL", md)
        self.assertIn("docs/changed.txt", md)
        self.assertIn("2026-01-01 09:00:00", md)
        self.assertIn("Limitations", md)
        self.assertIn("read-only", md)

    def test_report_truncation_flag(self):
        diff = IntegrityDiff()
        for i in range(MAX_ROWS_PER_SECTION + 1):
            diff.added.append(IntegrityChange(
                relpath=f"f{i}.txt", status="added", old_hash="", new_hash="a" * 64,
                old_ts="", new_ts="t", old_size=-1, new_size=1))
        report = build_integrity_report(diff, "/tmp/x")
        self.assertTrue(report["summary"]["rows_truncated"])
        self.assertEqual(len(report["added"]), MAX_ROWS_PER_SECTION)

    def test_write_report_does_not_overwrite(self):
        report = build_integrity_report(_sample_diff(), "/tmp/x",
                                        baseline_at="b", compared_at="c")
        with tempfile.TemporaryDirectory() as td:
            first = write_report(report, output_dir=Path(td), stem="integrity_fixed")
            second = write_report(report, output_dir=Path(td), stem="integrity_fixed")
            self.assertTrue(first["json"].exists())
            self.assertTrue(first["md"].exists())
            self.assertNotEqual(first["json"], second["json"])
            self.assertEqual(second["json"].name, "integrity_fixed_2.json")
            self.assertEqual(second["md"].name, "integrity_fixed_2.md")

    def test_unique_output_path_never_returns_existing(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "x.md").write_text("taken", encoding="utf-8")
            self.assertEqual(unique_output_path(d, "x", ".md").name, "x_2.md")


class TestWatchtowerPage(unittest.TestCase):
    _root = None

    @classmethod
    def setUpClass(cls):
        try:
            import customtkinter as ctk
            cls._root = ctk.CTk()
            cls._root.withdraw()
        except Exception as exc:
            cls._root = None
            cls._skip_reason = str(exc)

    @classmethod
    def tearDownClass(cls):
        if cls._root is not None:
            try:
                cls._root.destroy()
            except Exception:
                pass

    def _skip(self):
        if self._root is None:
            self.skipTest(getattr(self, "_skip_reason", "Tk unavailable"))

    def _make_page(self, folder=None):
        from gui.pages.integrity_watchtower_page import IntegrityWatchtowerPage
        page = IntegrityWatchtowerPage(self._root, {})
        if folder is not None:
            page._folder = Path(folder)
        return page

    def _load_diff(self, page, diff=None):
        page._last_diff = diff or _sample_diff()
        page._baseline_at = "2026-01-01 09:00:00"
        page._last_compare_at = "2026-01-02 10:00:00"
        page._render_diff(page._last_diff, 10)

    def test_filter_selects_change_type(self):
        self._skip()
        page = self._make_page()
        try:
            self._load_diff(page)
            self.assertEqual(len(page._visible_changes()), 3)
            page._on_filter_change("Modified")
            self.assertEqual([c.status for c in page._visible_changes()], ["modified"])
            page._on_filter_change("Deleted")
            self.assertEqual([c.status for c in page._visible_changes()], ["deleted"])
            page._on_filter_change("All")
            self.assertEqual(len(page._visible_changes()), 3)
        finally:
            page.destroy()

    def test_search_filters_paths_case_insensitively(self):
        self._skip()
        page = self._make_page()
        try:
            self._load_diff(page)
            page._search_var.set("CHANGED")
            page._on_search_change()
            visible = page._visible_changes()
            self.assertEqual(len(visible), 1)
            self.assertIn("changed", visible[0].relpath)
            page._search_var.set("nothing-matches")
            page._on_search_change()
            self.assertEqual(page._visible_changes(), [])
        finally:
            page.destroy()

    def test_reset_filters_restores_all_rows(self):
        self._skip()
        page = self._make_page()
        try:
            self._load_diff(page)
            page._on_filter_change("Added")
            page._search_var.set("new")
            page._on_search_change()
            page._reset_filters()
            self.assertEqual(page._change_filter, "All")
            self.assertEqual(page._search_text, "")
            self.assertEqual(len(page._visible_changes()), 3)
        finally:
            page.destroy()

    def test_cancelled_baseline_is_discarded(self):
        self._skip()
        page = self._make_page()
        try:
            page._active_token = "tok"
            page._busy = True
            page._on_baseline_done({"a.txt": _entry("a.txt", "1" * 64)}, "tok", True, [])
            self.assertIsNone(page._baseline)
            self.assertIsNone(page._baseline_at)
            self.assertIn("cancelled", page._status_lbl.cget("text").lower())
        finally:
            page.destroy()

    def test_status_bar_shortens_long_folder_path(self):
        self._skip()
        long_folder = Path(tempfile.gettempdir()) / ("sentinel_audit_" + "x" * 40)
        page = self._make_page(folder=long_folder)
        try:
            page._active_token = "tok"
            page._busy = True
            page._on_baseline_done({"a.txt": _entry("a.txt", "1" * 64)}, "tok", False, [])
            text = page._status_lbl.cget("text")
            self.assertNotIn(str(long_folder), text)
            self.assertIn("…", text)
            self.assertIn(long_folder.name[-24:], text)
            self.assertLess(len(text), 130, text)
        finally:
            page.destroy()

    def test_status_bar_stays_single_line_and_compact(self):
        self._skip()
        long_folder = Path(tempfile.gettempdir()) / ("sentinel_audit_" + "x" * 40)
        page = self._make_page(folder=long_folder)
        try:
            # The status bar must never reconfigure wraplength: doing so from a
            # <Configure> handler recurses through CTk's update_idletasks chain.
            self.assertEqual(int(page._status_lbl.cget("wraplength") or 0), 0)

            page._active_token = "tok"
            page._busy = True
            page._on_baseline_done({"a.txt": _entry("a.txt", "1" * 64)}, "tok", False, [])
            baseline_text = page._status_lbl.cget("text")
            self.assertNotIn(str(long_folder), baseline_text)
            self.assertIn("…", baseline_text)
            self.assertIn(long_folder.name[-24:], baseline_text)
            self.assertNotIn("\n", baseline_text)
            self.assertLessEqual(len(baseline_text), 90, baseline_text)

            page._busy = True
            page._on_compare_done(
                {"a.txt": _entry("a.txt", "2" * 64), "b.txt": _entry("b.txt", "3" * 64)},
                "tok", False, [])
            compare_text = page._status_lbl.cget("text")
            self.assertIn("+1", compare_text)
            self.assertIn("~1", compare_text)
            self.assertNotIn("\n", compare_text)
            self.assertLessEqual(len(compare_text), 90, compare_text)
        finally:
            page.destroy()

    def test_compare_records_timestamps_and_enables_export(self):
        self._skip()
        page = self._make_page(folder=tempfile.gettempdir())
        try:
            page._active_token = "tok"
            page._baseline = {"a.txt": _entry("a.txt", "1" * 64)}
            page._baseline_at = "2026-01-01 09:00:00"
            page._busy = True
            page._on_compare_done({"a.txt": _entry("a.txt", "2" * 64)}, "tok", False, ["unreadable: x"])
            self.assertIsNotNone(page._last_diff)
            self.assertTrue(page._baseline_at)
            self.assertTrue(page._last_compare_at)
            self.assertEqual(page._skipped, ["unreadable: x"])
            self.assertEqual(str(page._export_btn.cget("state")), "normal")
            self.assertIn("NOT confirmed ransomware", page._summary_lbl.cget("text"))
        finally:
            page.destroy()

    def test_export_writes_report(self):
        self._skip()
        with tempfile.TemporaryDirectory() as td:
            page = self._make_page(folder=td)
            try:
                self._load_diff(page)
                saved = {"md": Path(td) / "r.md", "json": Path(td) / "r.json"}
                with patch("gui.pages.integrity_watchtower_page.write_report",
                           return_value=saved) as wr:
                    page._on_export()
                    self.assertTrue(wr.called)
                self.assertIn("Report saved", page._status_lbl.cget("text"))
            finally:
                page.destroy()

    def test_export_failure_is_reported_not_raised(self):
        self._skip()
        with tempfile.TemporaryDirectory() as td:
            page = self._make_page(folder=td)
            try:
                self._load_diff(page)
                with patch("gui.pages.integrity_watchtower_page.write_report",
                           side_effect=OSError("disk full")):
                    page._on_export()
                self.assertIn("failed", page._status_lbl.cget("text").lower())
            finally:
                page.destroy()

    def test_destroy_marks_page_dead(self):
        self._skip()
        page = self._make_page()
        page.destroy()
        self.assertTrue(page._is_destroyed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
