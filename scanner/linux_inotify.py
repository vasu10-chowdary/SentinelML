"""Minimal ctypes inotify wrapper and event accounting for LBS-1.

No third-party dependency. Importing this module on non-Linux platforms is side-effect free;
constructing a watcher raises InotifyUnavailable.
"""

from __future__ import annotations

import ctypes
import errno
import os
import posixpath
import select
import stat
import struct
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Optional, Sequence

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000

EVENT_MASK = (
    IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)

DEFAULT_WATCH_MASK = EVENT_MASK | IN_Q_OVERFLOW
MAX_WATCHES_DEFAULT = 20_000

DEFAULT_PRUNE = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv", "build", "dist", ".cache"}
)

_HEADER = struct.Struct("iIII")

RANSOM_EXTENSIONS = frozenset(
    {
        ".locked",
        ".encrypted",
        ".crypto",
        ".crypt",
        ".enc",
        ".ransom",
        ".wcry",
        ".wncry",
        ".locky",
        ".zepto",
        ".cerber",
        ".ryk",
        ".ryuk",
        ".conti",
        ".lockbit",
        ".babuk",
        ".hive",
        ".blackcat",
        ".alphv",
        ".clop",
        ".darkside",
        ".maze",
        ".phobos",
        ".dharma",
        ".stop",
    }
)

# Deliberately narrow: generic README.md must not match.
RANSOM_NOTE_TOKENS = (
    "how_to_decrypt",
    "decrypt_instruction",
    "decrypt_your_files",
    "restore_your_files",
    "recover_your_files",
    "readme_for_decrypt",
    "ransom_note",
    "unlock_your_files",
)
RANSOM_NOTE_GENERIC = frozenset(
    {"readme.txt", "readme.html", "decrypt.txt", "decrypt.html", "restore.txt"}
)

LIST_VERSION = "lbs1-lists-1.0.0"


class InotifyError(RuntimeError):
    """Base error for inotify setup or use."""


class InotifyUnavailable(InotifyError):
    """Raised when the platform or libc cannot provide inotify."""


class WatchBudgetExceeded(InotifyError):
    """Raised when the configured watch budget is exhausted."""


@dataclass(frozen=True)
class RawEvent:
    wd: int
    mask: int
    cookie: int
    name: str

    @property
    def is_dir(self) -> bool:
        return bool(self.mask & IN_ISDIR)


def parse_events(buffer: bytes) -> list[RawEvent]:
    """Parse one or more raw inotify_event records from *buffer*."""
    events: list[RawEvent] = []
    offset = 0
    size = len(buffer)
    while offset + _HEADER.size <= size:
        wd, mask, cookie, length = _HEADER.unpack_from(buffer, offset)
        name_start = offset + _HEADER.size
        name_end = name_start + length
        if name_end > size:
            raise ValueError("truncated inotify event buffer")
        raw_name = buffer[name_start:name_end].split(b"\x00", 1)[0]
        events.append(
            RawEvent(
                wd=wd,
                mask=mask,
                cookie=cookie,
                name=raw_name.decode("utf-8", errors="surrogateescape"),
            )
        )
        offset = name_end
    if offset != size:
        raise ValueError("trailing bytes in inotify event buffer")
    return events


def _load_libc() -> ctypes.CDLL:
    if not sys.platform.startswith("linux"):
        raise InotifyUnavailable(f"inotify is unavailable on {sys.platform!r}")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError as exc:  # pragma: no cover - defensive
        raise InotifyUnavailable(f"libc unavailable: {exc}") from exc
    for symbol in ("inotify_init1", "inotify_add_watch", "inotify_rm_watch"):
        if not hasattr(libc, symbol):
            raise InotifyUnavailable(f"libc lacks {symbol}")
    return libc


@dataclass
class TreeWatchResult:
    watches: int = 0
    directories: int = 0
    shortfall: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return self.watches > 0 and self.shortfall == 0 and not self.errors


class InotifyWatcher:
    """Recursive inotify watcher with an explicit watch budget."""

    def __init__(self, max_watches: int = MAX_WATCHES_DEFAULT, libc: Optional[ctypes.CDLL] = None):
        if max_watches <= 0:
            raise ValueError("max_watches must be positive")
        self.max_watches = max_watches
        self._libc = libc if libc is not None else _load_libc()
        flags = os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        self._fd = self._libc.inotify_init1(flags)
        if self._fd < 0:
            err = ctypes.get_errno()
            raise InotifyUnavailable(f"inotify_init1 failed: {os.strerror(err)}")
        self._paths_by_wd: dict[int, str] = {}
        self._closed = False
        self.overflowed = False
        self.shortfall = 0

    @property
    def fd(self) -> int:
        return self._fd

    @property
    def watch_count(self) -> int:
        return len(self._paths_by_wd)

    def path_for_wd(self, wd: int) -> Optional[str]:
        return self._paths_by_wd.get(wd)

    def add_watch(self, path: str, mask: int = DEFAULT_WATCH_MASK) -> int:
        if self._closed:
            raise InotifyError("watcher is closed")
        if self.watch_count >= self.max_watches:
            raise WatchBudgetExceeded(f"watch budget {self.max_watches} exhausted")
        wd = self._libc.inotify_add_watch(self._fd, os.fsencode(path), ctypes.c_uint32(mask))
        if wd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), path)
        self._paths_by_wd[wd] = path
        return wd

    def add_tree(
        self,
        root: str,
        mask: int = DEFAULT_WATCH_MASK,
        prune: Iterable[str] = DEFAULT_PRUNE,
    ) -> TreeWatchResult:
        prune_names = set(prune)
        result = TreeWatchResult()
        for directory, dirnames, _filenames in os.walk(root, followlinks=False):
            dirnames[:] = [name for name in dirnames if name not in prune_names]
            if self.watch_count >= self.max_watches:
                result.shortfall += 1 + len(dirnames)
                continue
            try:
                self.add_watch(directory, mask)
            except WatchBudgetExceeded:
                result.shortfall += 1 + len(dirnames)
            except OSError as exc:
                result.errors.append(f"{directory}:{exc.errno}:{exc.strerror}")
            else:
                result.watches += 1
                result.directories += 1
        self.shortfall += result.shortfall
        return result

    def remove_watch(self, wd: int) -> None:
        self._libc.inotify_rm_watch(self._fd, wd)
        self._paths_by_wd.pop(wd, None)

    def read_available(self, chunk_size: int = 64 * 1024) -> list[RawEvent]:
        if self._closed:
            raise InotifyError("watcher is closed")
        try:
            data = os.read(self._fd, chunk_size)
        except BlockingIOError:
            return []
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return []
            raise InotifyError(f"inotify read failed: {exc}") from exc
        if not data:
            return []
        events = parse_events(data)
        for event in events:
            if event.mask & IN_Q_OVERFLOW:
                self.overflowed = True
            if event.mask & IN_IGNORED:
                self._paths_by_wd.pop(event.wd, None)
        return events

    def poll(self, timeout: float = 0.0) -> list[RawEvent]:
        if self._closed:
            raise InotifyError("watcher is closed")
        try:
            ready, _, _ = select.select([self._fd], [], [], timeout)
        except OSError as exc:  # pragma: no cover - defensive
            raise InotifyError(f"inotify select failed: {exc}") from exc
        if not ready:
            return []
        return self.read_available()

    def resolve(self, event: RawEvent) -> Optional[str]:
        base = self._paths_by_wd.get(event.wd)
        if base is None:
            return None
        if not event.name:
            return base
        return posixpath.join(base, event.name)

    def close(self) -> None:
        if not self._closed:
            os.close(self._fd)
            self._closed = True
            self._paths_by_wd.clear()

    def __enter__(self) -> "InotifyWatcher":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _matches_ransom_extension(path: str) -> bool:
    return posixpath.splitext(posixpath.basename(path))[1].lower() in RANSOM_EXTENSIONS


def _matches_ransom_note(path: str) -> bool:
    name = posixpath.basename(path).lower()
    if name in RANSOM_NOTE_GENERIC:
        return True
    return any(token in name for token in RANSOM_NOTE_TOKENS)


@dataclass
class FileEventSummary:
    close_write_events: int = 0
    modify_only_events: int = 0
    close_write_paths: set[str] = field(default_factory=set)
    modify_paths: set[str] = field(default_factory=set)
    created_paths: set[str] = field(default_factory=set)
    renamed_paths: set[str] = field(default_factory=set)
    deleted_paths: set[str] = field(default_factory=set)
    rename_events: int = 0
    delete_events: int = 0
    dirs_touched: set[str] = field(default_factory=set)
    ransom_extension_match_count: int = 0
    ransom_note_match_count: int = 0
    setuid_event_count: int = 0
    overflow: bool = False
    unpaired_moves: int = 0

    @property
    def write_events(self) -> int:
        # IN_MODIFY is counted once per file and only when no CLOSE_WRITE occurred.
        return self.close_write_events + len(self.modify_paths - self.close_write_paths)

    @property
    def modified_paths(self) -> set[str]:
        return self.close_write_paths | self.modify_paths

    @property
    def event_touched_paths(self) -> set[str]:
        return self.modified_paths | self.created_paths | self.renamed_paths


class WindowAccumulator:
    """Turns raw inotify events into the counts required by LBS-1 features 0-5, 9, 10, 18."""

    def __init__(self) -> None:
        self.summary = FileEventSummary()
        self._pending_moves: dict[int, str] = {}
        self._mode_paths: set[str] = set()
        self._modify_seen: set[str] = set()

    def _touch_dir(self, path: str) -> None:
        parent = posixpath.dirname(path)
        if parent:
            self.summary.dirs_touched.add(parent)

    def _record_resulting_name(self, path: str) -> None:
        if _matches_ransom_extension(path):
            self.summary.ransom_extension_match_count += 1
        if _matches_ransom_note(path):
            self.summary.ransom_note_match_count += 1

    def consume(self, events: Iterable[tuple[RawEvent, Optional[str]]]) -> None:
        for event, path in events:
            if event.mask & IN_Q_OVERFLOW:
                self.summary.overflow = True
                continue
            if event.mask & IN_IGNORED or path is None:
                continue
            if event.mask & IN_CLOSE_WRITE:
                self.summary.close_write_events += 1
                self.summary.close_write_paths.add(path)
                self._mode_paths.add(path)
                self._touch_dir(path)
            if event.mask & IN_MODIFY:
                if path not in self._modify_seen:
                    self._modify_seen.add(path)
                    self.summary.modify_paths.add(path)
                self._touch_dir(path)
            if event.mask & IN_CREATE:
                if not event.is_dir:
                    self.summary.created_paths.add(path)
                    self._record_resulting_name(path)
                    self._mode_paths.add(path)
                self._touch_dir(path)
            if event.mask & IN_ATTRIB:
                self._mode_paths.add(path)
                self._touch_dir(path)
            if event.mask & IN_MOVED_FROM:
                self._pending_moves[event.cookie] = path
                self._touch_dir(path)
            if event.mask & IN_MOVED_TO:
                origin = self._pending_moves.pop(event.cookie, None)
                if origin is not None:
                    self.summary.rename_events += 1
                    self.summary.renamed_paths.add(path)
                    self._record_resulting_name(path)
                    self._mode_paths.add(path)
                elif not event.is_dir:
                    # Moved in from outside the watched tree: a create, not a rename.
                    self.summary.created_paths.add(path)
                    self._record_resulting_name(path)
                self._touch_dir(path)
            if event.mask & IN_MOVE_SELF:
                self.summary.rename_events += 1
                self.summary.renamed_paths.add(path)
            if event.mask & IN_DELETE:
                self.summary.delete_events += 1
                self.summary.deleted_paths.add(path)
                self._touch_dir(path)
            if event.mask & IN_DELETE_SELF:
                self.summary.delete_events += 1
                self.summary.deleted_paths.add(path)

    def finalize(
        self,
        mode_lookup: Optional[Callable[[str], Optional[int]]] = None,
        xattr_lookup: Optional[Callable[[str], bool]] = None,
    ) -> FileEventSummary:
        unpaired = [path for path in self._pending_moves.values()]
        self.summary.unpaired_moves = len(unpaired)
        self.summary.delete_events += len(unpaired)
        self.summary.deleted_paths.update(unpaired)
        self._pending_moves.clear()

        if mode_lookup is not None or xattr_lookup is not None:
            count = 0
            for path in self._mode_paths:
                matched = False
                if mode_lookup is not None:
                    try:
                        mode = mode_lookup(path)
                    except OSError:
                        mode = None
                    if mode is not None and (stat.S_ISUID & mode or stat.S_ISGID & mode):
                        matched = True
                if not matched and xattr_lookup is not None:
                    try:
                        matched = bool(xattr_lookup(path))
                    except OSError:
                        matched = False
                if matched:
                    count += 1
            self.summary.setuid_event_count = count
        return self.summary


def summarize_events(
    events: Iterable[tuple[RawEvent, Optional[str]]],
    mode_lookup: Optional[Callable[[str], Optional[int]]] = None,
    xattr_lookup: Optional[Callable[[str], bool]] = None,
) -> FileEventSummary:
    accumulator = WindowAccumulator()
    accumulator.consume(events)
    return accumulator.finalize(mode_lookup=mode_lookup, xattr_lookup=xattr_lookup)
