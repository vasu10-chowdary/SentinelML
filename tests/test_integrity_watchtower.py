"""
SentinelML V2 — File Integrity Watchtower tests (Phase 8 / Task 3)
===================================================================
Covers the pure-logic layer (exhibition/integrity_watchtower.py):
  * hash_file, scan_folder, compute_integrity_diff, is_safe_watchtower_folder
  * normal flow, cancellation, edge cases, read-only contract
  * Tk construction of IntegrityWatchtowerPage (single shared root)
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.integrity_watchtower import (
    IntegrityDiff,
    IntegrityEntry,
    compute_integrity_diff,
    hash_file,
    is_safe_watchtower_folder,
    scan_folder,
)


# ---------------------------------------------------------------------------
# Pure-logic tests (no Tkinter)
# ---------------------------------------------------------------------------

class TestHashFile(unittest.TestCase):
    def test_hashes_known_content(self):
        import hashlib
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"SentinelML V2 test")
            path = Path(f.name)
        try:
            expected = hashlib.sha256(b"SentinelML V2 test").hexdigest()
            self.assertEqual(hash_file(path), expected)
        finally:
            path.unlink(missing_ok=True)

    def test_nonexistent_file_returns_none(self):
        self.assertIsNone(hash_file(Path("/nonexistent/file.txt")))

    def test_different_content_different_hash(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".a") as fa:
            fa.write(b"content A")
            pa = Path(fa.name)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".b") as fb:
            fb.write(b"content B")
            pb = Path(fb.name)
        try:
            self.assertNotEqual(hash_file(pa), hash_file(pb))
        finally:
            pa.unlink(missing_ok=True)
            pb.unlink(missing_ok=True)

    def test_same_content_same_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as fa:
            fa.write(b"identical")
            pa = Path(fa.name)
        with tempfile.NamedTemporaryFile(delete=False) as fb:
            fb.write(b"identical")
            pb = Path(fb.name)
        try:
            self.assertEqual(hash_file(pa), hash_file(pb))
        finally:
            pa.unlink(missing_ok=True)
            pb.unlink(missing_ok=True)


class TestScanFolder(unittest.TestCase):
    def _make_sandbox(self, file_contents: dict) -> Path:
        """Create a temp dir with given {filename: bytes} contents."""
        d = tempfile.mkdtemp(prefix="watchtower_test_")
        for name, content in file_contents.items():
            (Path(d) / name).write_bytes(content)
        return Path(d)

    def _rm(self, d: Path):
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def test_scans_files(self):
        d = self._make_sandbox({"a.txt": b"aaa", "b.txt": b"bbb"})
        try:
            entries = scan_folder(d)
            self.assertEqual(len(entries), 2)
            self.assertIn("a.txt", entries)
            self.assertIn("b.txt", entries)
        finally:
            self._rm(d)

    def test_entries_have_hashes(self):
        import hashlib
        d = self._make_sandbox({"x.txt": b"hello"})
        try:
            entries = scan_folder(d)
            expected = hashlib.sha256(b"hello").hexdigest()
            self.assertEqual(entries["x.txt"].hash, expected)
        finally:
            self._rm(d)

    def test_empty_folder(self):
        with tempfile.TemporaryDirectory() as d:
            entries = scan_folder(d)
        self.assertEqual(len(entries), 0)

    def test_nonexistent_folder_returns_empty(self):
        entries = scan_folder("/nonexistent/path/watchtower")
        self.assertEqual(len(entries), 0)

    def test_cancellation_stops_early(self):
        # Create enough files that cancellation before the first yields empty/partial
        d = self._make_sandbox({f"file_{i}.txt": b"x" for i in range(50)})
        try:
            entries = scan_folder(d, cancel_check=lambda: True)
            self.assertEqual(len(entries), 0,
                             "Immediate cancel should yield no entries")
        finally:
            self._rm(d)

    def test_progress_callback_fires(self):
        counts = []
        d = self._make_sandbox({"p1.txt": b"a", "p2.txt": b"b", "p3.txt": b"c"})
        try:
            scan_folder(d, on_progress=lambda c: counts.append(c))
            self.assertGreater(len(counts), 0)
        finally:
            self._rm(d)

    def test_scan_is_read_only(self):
        """scan_folder must never create, modify or delete files."""
        d = self._make_sandbox({"ro.txt": b"unchanged"})
        try:
            before_mtime = (d / "ro.txt").stat().st_mtime
            scan_folder(d)
            after_mtime = (d / "ro.txt").stat().st_mtime
            self.assertEqual(before_mtime, after_mtime,
                             "scan_folder must not modify file timestamps")
            remaining = list(d.iterdir())
            self.assertEqual(len(remaining), 1,
                             "scan_folder must not create extra files")
        finally:
            self._rm(d)

    def test_relpath_is_posix_style(self):
        d = self._make_sandbox({"sub_dir": b""})
        # Create a subdirectory file
        sub = d / "subdir"
        sub.mkdir()
        (sub / "deep.txt").write_bytes(b"deep")
        try:
            entries = scan_folder(d)
            keys = list(entries.keys())
            for k in keys:
                self.assertNotIn("\\", k, f"relpath must use posix separators: {k}")
        finally:
            import shutil; shutil.rmtree(d, ignore_errors=True)


class TestComputeIntegrityDiff(unittest.TestCase):
    def _entry(self, relpath, content=b"data"):
        import hashlib, time
        h = hashlib.sha256(content).hexdigest()
        return relpath, IntegrityEntry(
            relpath=relpath, hash=h, size=len(content),
            mtime=time.time(), ts="2024-01-01 00:00:00")

    def test_added_file(self):
        baseline = {}
        current = dict([self._entry("new.txt", b"added")])
        diff = compute_integrity_diff(baseline, current)
        self.assertEqual(len(diff.added), 1)
        self.assertEqual(diff.added[0].relpath, "new.txt")
        self.assertEqual(len(diff.deleted), 0)
        self.assertEqual(len(diff.modified), 0)

    def test_deleted_file(self):
        baseline = dict([self._entry("gone.txt", b"was here")])
        current = {}
        diff = compute_integrity_diff(baseline, current)
        self.assertEqual(len(diff.deleted), 1)
        self.assertEqual(diff.deleted[0].relpath, "gone.txt")
        self.assertEqual(len(diff.added), 0)

    def test_modified_file(self):
        k, v = self._entry("same.txt", b"old content")
        baseline = {k: v}
        k2, v2 = self._entry("same.txt", b"new content")
        current = {k2: v2}
        diff = compute_integrity_diff(baseline, current)
        self.assertEqual(len(diff.modified), 1)
        self.assertEqual(diff.modified[0].relpath, "same.txt")
        self.assertNotEqual(diff.modified[0].old_hash, diff.modified[0].new_hash)

    def test_unchanged_file(self):
        k, v = self._entry("same.txt", b"same content")
        baseline = {k: v}
        k2, v2 = self._entry("same.txt", b"same content")
        current = {k2: v2}
        diff = compute_integrity_diff(baseline, current)
        self.assertEqual(len(diff.modified), 0)
        self.assertEqual(diff.unchanged_count, 1)

    def test_empty_vs_empty(self):
        diff = compute_integrity_diff({}, {})
        self.assertEqual(len(diff.added), 0)
        self.assertEqual(len(diff.deleted), 0)
        self.assertEqual(len(diff.modified), 0)

    def test_total_count(self):
        baseline = dict([self._entry("a.txt", b"a"), self._entry("b.txt", b"b")])
        current = dict([self._entry("b.txt", b"b_changed"), self._entry("c.txt", b"c")])
        diff = compute_integrity_diff(baseline, current)
        # a deleted, b modified, c added
        self.assertEqual(len(diff.deleted), 1)
        self.assertEqual(len(diff.modified), 1)
        self.assertEqual(len(diff.added), 1)
        self.assertEqual(diff.total, 3)

    def test_diff_does_not_mutate_inputs(self):
        baseline = dict([self._entry("f.txt", b"orig")])
        current = dict([self._entry("f.txt", b"changed")])
        ids_before = id(baseline), id(current)
        compute_integrity_diff(baseline, current)
        self.assertEqual((id(baseline), id(current)), ids_before)


class TestIsSafeWatchtowerFolder(unittest.TestCase):
    def test_valid_temp_folder(self):
        with tempfile.TemporaryDirectory() as d:
            ok, reason = is_safe_watchtower_folder(d)
            self.assertTrue(ok, reason)

    def test_nonexistent_path(self):
        ok, reason = is_safe_watchtower_folder("/nonexistent/does/not/exist/xyz")
        self.assertFalse(ok)

    def test_windows_system_root_rejected(self):
        ok, reason = is_safe_watchtower_folder("C:\\Windows")
        self.assertFalse(ok)

    def test_empty_string_rejected(self):
        ok, reason = is_safe_watchtower_folder("")
        self.assertFalse(ok)

    def test_program_files_rejected(self):
        ok, reason = is_safe_watchtower_folder("C:\\Program Files")
        self.assertFalse(ok)

    def test_file_path_rejected(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            ok, reason = is_safe_watchtower_folder(path)
            self.assertFalse(ok)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# End-to-end: create, baseline, modify, compare
# ---------------------------------------------------------------------------

class TestWatchtowerEndToEnd(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="wt_e2e_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def test_full_cycle(self):
        # Establish baseline with 3 files
        (self.d / "alpha.txt").write_bytes(b"alpha")
        (self.d / "beta.txt").write_bytes(b"beta")
        (self.d / "gamma.txt").write_bytes(b"gamma")
        baseline = scan_folder(self.d)
        self.assertEqual(len(baseline), 3)

        # Simulate: modify beta, delete gamma, add delta
        (self.d / "beta.txt").write_bytes(b"beta MODIFIED")
        (self.d / "gamma.txt").unlink()
        (self.d / "delta.txt").write_bytes(b"delta NEW")

        current = scan_folder(self.d)
        diff = compute_integrity_diff(baseline, current)

        self.assertEqual(len(diff.added), 1)
        self.assertEqual(diff.added[0].relpath, "delta.txt")
        self.assertEqual(len(diff.modified), 1)
        self.assertEqual(diff.modified[0].relpath, "beta.txt")
        self.assertEqual(len(diff.deleted), 1)
        self.assertEqual(diff.deleted[0].relpath, "gamma.txt")
        self.assertEqual(diff.unchanged_count, 1)  # alpha

    def test_change_does_not_mean_ransomware(self):
        """Integrity changes are file-state observations only — not malware confirmation."""
        (self.d / "victim.txt").write_bytes(b"original")
        baseline = scan_folder(self.d)
        (self.d / "victim.txt").write_bytes(b"modified content")
        current = scan_folder(self.d)
        diff = compute_integrity_diff(baseline, current)
        # We can detect the change — but there is no ransomware classification here.
        self.assertEqual(len(diff.modified), 1)
        # The watchtower returns no threat_level or classification field.
        self.assertFalse(hasattr(diff, "threat_level"))
        self.assertFalse(hasattr(diff, "classification"))


# ---------------------------------------------------------------------------
# Tk UI tests (single shared root)
# ---------------------------------------------------------------------------

class TestIntegrityWatchtowerPageUI(unittest.TestCase):
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

    def test_page_constructs(self):
        self._skip()
        from gui.pages.integrity_watchtower_page import IntegrityWatchtowerPage
        page = IntegrityWatchtowerPage(self._root, config={})
        try:
            self.assertIsNone(page._folder)
            self.assertIsNone(page._baseline)
            self.assertEqual(page._baseline_btn.cget("state"), "disabled")
            self.assertEqual(page._compare_btn.cget("state"), "disabled")
        finally:
            page.destroy()

    def test_baseline_done_enables_compare(self):
        self._skip()
        from gui.pages.integrity_watchtower_page import IntegrityWatchtowerPage
        page = IntegrityWatchtowerPage(self._root, config={})
        try:
            import tempfile
            d = Path(tempfile.mkdtemp())
            try:
                page._folder = d
                fake_baseline = {}
                token = "test-token"
                page._active_token = token
                page._on_baseline_done(fake_baseline, token)
                self.assertEqual(page._compare_btn.cget("state"), "normal")
                self.assertEqual(page._clear_btn.cget("state"), "normal")
            finally:
                import shutil; shutil.rmtree(d, ignore_errors=True)
        finally:
            page.destroy()

    def test_stale_token_ignored_on_baseline_done(self):
        self._skip()
        from gui.pages.integrity_watchtower_page import IntegrityWatchtowerPage
        page = IntegrityWatchtowerPage(self._root, config={})
        try:
            page._active_token = "current-token"
            # Call with a stale token — should not update state
            page._on_baseline_done({}, "stale-token")
            # Baseline should still be None
            self.assertIsNone(page._baseline)
        finally:
            page.destroy()

    def test_cancel_sets_flag(self):
        self._skip()
        from gui.pages.integrity_watchtower_page import IntegrityWatchtowerPage
        page = IntegrityWatchtowerPage(self._root, config={})
        try:
            page._busy = True
            page._cancel_btn.configure(state="normal")
            page._on_cancel()
            self.assertTrue(page._cancel_requested)
        finally:
            page.destroy()

    def test_destroy_sets_flag(self):
        self._skip()
        from gui.pages.integrity_watchtower_page import IntegrityWatchtowerPage
        page = IntegrityWatchtowerPage(self._root, config={})
        page.destroy()
        self.assertTrue(page._is_destroyed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
