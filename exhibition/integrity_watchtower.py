"""
SentinelML V2 — File Integrity Watchtower (pure logic, no Tkinter)
=================================================================
SHA-256 baseline + on-demand comparison for a single, user-chosen test folder.

Design / safety contract:
  * READ-ONLY. This module never creates, modifies, or deletes files. It only
    opens files for reading to compute SHA-256 hashes.
  * SCOPE-LOCKED. It only walks the selected folder (``os.walk`` with
    ``followlinks=False``) and never inspects anything outside it.
  * CHANGE != MALWARE. Integrity changes are file-state observations only; they
    do NOT confirm ransomware. The UI must say so. Behavioral detection lives in
    the Exhibition Lab / ScanEngine.
  * UNAVAILABLE, not zero. Files that cannot be read (permission denied, locked)
    are skipped and reported, never hashed as empty.

Pure data + functions so the core is unit-testable headless. The Tk page
(gui/pages/integrity_watchtower_page.py) runs hashing on a daemon worker thread
and marshals results back via the queue+dispatch pattern.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

CancelCheck = Optional[Callable[[], bool]]
ProgressFn = Optional[Callable[[int], None]]
SkipFn = Optional[Callable[[str, str], None]]

CHUNK_SIZE = 1024 * 1024  # 1 MiB read chunks
MAX_FILES = 20000         # guard rail so a huge folder cannot exhaust the host


@dataclass
class IntegrityEntry:
    relpath: str          # posix-style path relative to the watched folder
    hash: str             # SHA-256 hex digest, or "" if unreadable
    size: int
    mtime: float
    ts: str               # human-readable capture timestamp


@dataclass
class IntegrityChange:
    relpath: str
    status: str           # added | modified | deleted | unchanged
    old_hash: str
    new_hash: str
    old_ts: str
    new_ts: str
    old_size: int
    new_size: int


@dataclass
class IntegrityDiff:
    added: List[IntegrityChange] = field(default_factory=list)
    modified: List[IntegrityChange] = field(default_factory=list)
    deleted: List[IntegrityChange] = field(default_factory=list)
    unchanged_count: int = 0
    skipped: List[str] = field(default_factory=list)
    total: int = 0
    limited: bool = False      # MAX_FILES guard rail was hit
    partial: bool = False      # comparison was cancelled before completion


def _now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hash_file(path: Path) -> Optional[str]:
    """Return the SHA-256 hex digest of a file, or None if it cannot be read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def scan_folder(folder, on_progress: ProgressFn = None,
                cancel_check: CancelCheck = None,
                on_skip: SkipFn = None) -> Dict[str, IntegrityEntry]:
    """Walk ``folder`` (read-only, no symlink following) and return a baseline map.

    Keys are posix-style relative paths. Unreadable files are skipped and
    reported through ``on_skip(relpath, reason)``. Honours a cancel check to
    stop early. Bounded by MAX_FILES as a guard rail.
    """
    root = Path(folder)
    entries: Dict[str, IntegrityEntry] = {}
    if not root.exists() or not root.is_dir():
        return entries

    def report_skip(rel: str, reason: str) -> None:
        if on_skip is not None:
            try:
                on_skip(rel, reason)
            except Exception:
                pass

    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if cancel_check is not None and cancel_check():
            break
        # Do not descend into symlinked directories (followlinks=False already
        # prevents this; this belt-and-braces guard keeps scope inside the folder).
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for fname in filenames:
            if cancel_check is not None and cancel_check():
                break
            if count >= MAX_FILES:
                break
            full = Path(dirpath) / fname
            try:
                rel = full.relative_to(root).as_posix()
            except Exception:
                continue
            try:
                if os.path.islink(str(full)):
                    report_skip(rel, "symlink")
                    continue
                if full.is_dir():
                    continue
            except Exception:
                report_skip(rel, "vanished")
                continue
            try:
                st = full.stat()
            except Exception:
                report_skip(rel, "vanished")
                continue
            digest = hash_file(full)
            if digest is None:
                report_skip(rel, "unreadable")
                continue
            entries[rel] = IntegrityEntry(
                relpath=rel, hash=digest, size=int(st.st_size),
                mtime=float(st.st_mtime), ts=_now_ts(),
            )
            count += 1
            if on_progress is not None:
                try:
                    on_progress(count)
                except Exception:
                    pass
    return entries


def compute_integrity_diff(baseline: Dict[str, IntegrityEntry],
                            current: Dict[str, IntegrityEntry]) -> IntegrityDiff:
    """Compare two scans and return added / modified / deleted / unchanged."""
    diff = IntegrityDiff()
    base_keys = set(baseline.keys())
    cur_keys = set(current.keys())
    for rel in sorted(cur_keys - base_keys):
        cur = current[rel]
        diff.added.append(IntegrityChange(
            relpath=rel, status="added",
            old_hash="", new_hash=cur.hash, old_ts="", new_ts=cur.ts,
            old_size=-1, new_size=cur.size))
    for rel in sorted(base_keys - cur_keys):
        old = baseline[rel]
        diff.deleted.append(IntegrityChange(
            relpath=rel, status="deleted",
            old_hash=old.hash, new_hash="", old_ts=old.ts, new_ts="",
            old_size=old.size, new_size=-1))
    for rel in sorted(base_keys & cur_keys):
        old = baseline[rel]
        cur = current[rel]
        if old.hash != cur.hash:
            diff.modified.append(IntegrityChange(
                relpath=rel, status="modified",
                old_hash=old.hash, new_hash=cur.hash,
                old_ts=old.ts, new_ts=cur.ts,
                old_size=old.size, new_size=cur.size))
        else:
            diff.unchanged_count += 1
    diff.total = len(diff.added) + len(diff.modified) + len(diff.deleted) + diff.unchanged_count
    return diff


# Known-dangerous roots the watchtower should refuse / warn on.
_WIN_SYS = ("c:\\windows", "c:\\program files", "c:\\program files (x86)")
_UNIX_SYS = ("/", "/etc", "/usr", "/bin", "/sbin", "/var", "/sys", "/proc", "/dev", "/boot")


def is_safe_watchtower_folder(path) -> Tuple[bool, str]:
    """Soft advisory: is ``path`` a sensible dedicated test folder?

    Returns (ok, reason). Never raises. The page warns but still lets the user
    proceed (it is the user's choice); this just discourages system roots.
    """
    # Reject empty / whitespace-only input before resolving
    try:
        raw = str(path).strip()
    except Exception:
        return False, "Invalid path."
    if not raw or raw in (".", ""):
        return False, "No folder selected."
    try:
        p = Path(path).expanduser().resolve()
    except Exception:
        return False, "Invalid path."
    s = str(p).lower()
    if not p.exists():
        return False, "Folder does not exist."
    if not p.is_dir():
        return False, "Path is not a folder."
    # Drive root on Windows (e.g. C:\)
    if len(p.parts) <= 1 or (os.name == "nt" and len(p.parts) == 2 and p.parts[1] == "\\"):
        return False, "Drive root is too broad — choose a dedicated test folder."
    for bad in _WIN_SYS + _UNIX_SYS:
        if s == bad or s.startswith(bad + os.sep) or s.startswith(bad.rstrip(os.sep) + "/"):
            return False, "System directory — choose a dedicated test folder."
    return True, "OK"
