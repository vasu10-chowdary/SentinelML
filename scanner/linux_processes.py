"""Process dynamics for LBS-1 features 11-17 and network feature 19.

Reads /proc directly (world-readable fields) so that the logic is testable with fixtures.
Kernel threads are excluded from created-process counts. Nothing but counts leaves this module.
"""

from __future__ import annotations

import ipaddress
import os
import posixpath
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional, Sequence

SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "fish"})
TERMINALS = frozenset(
    {
        "xterm",
        "uxterm",
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "terminator",
        "alacritty",
        "kitty",
        "wezterm",
        "tmux",
        "screen",
        "guake",
        "tilix",
    }
)
SHORT_LIVED_SECONDS = 1.0
MIN_SNAPSHOTS = 3
RESOLUTION_THRESHOLD = 0.90
DEFAULT_TEMP_ROOTS = ("/tmp", "/var/tmp", "/dev/shm")

STATUS_OK = "OK"
STATUS_DEGRADED = "DEGRADED"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int
    comm: str
    state: str
    start_ticks: int
    exe: Optional[str] = None
    argv: tuple[str, ...] = ()
    uid_real: Optional[int] = None
    uid_eff: Optional[int] = None
    uid_saved: Optional[int] = None
    cap_eff: Optional[int] = None
    status_readable: bool = True
    exe_readable: bool = True

    @property
    def is_kernel_thread(self) -> bool:
        return self.pid == 2 or self.comm.startswith("[")

    @property
    def argv0(self) -> str:
        if self.argv:
            return self.argv[0]
        return self.comm

    @property
    def resolved(self) -> bool:
        return bool(self.argv) or self.exe is not None

    @property
    def is_privileged(self) -> bool:
        if self.is_kernel_thread:
            return False
        uids = (self.uid_real, self.uid_eff, self.uid_saved)
        if any(uid == 0 for uid in uids if uid is not None):
            return True
        return bool(self.cap_eff)


@dataclass
class ProcessWindowResult:
    created_count: int = 0
    exited_count: int = 0
    short_lived_count: int = 0
    short_lived_ratio: Optional[float] = None
    destructive_count: int = 0
    destructive_rules: tuple[str, ...] = ()
    shell_spawn_count: int = 0
    temp_exec_count: int = 0
    privileged_count: int = 0
    resolution_rate: Optional[float] = None
    status_readable_rate: Optional[float] = None
    samples: int = 0
    g4_status: str = STATUS_DEGRADED
    g5_status: str = STATUS_NOT_APPLICABLE
    g6_status: str = STATUS_NOT_APPLICABLE
    notes: list[str] = field(default_factory=list)


def _parse_stat(text: str) -> tuple[str, int, int, str]:
    left = text.find("(")
    right = text.rfind(")")
    if left < 0 or right < 0 or right <= left:
        raise ValueError("malformed /proc stat")
    comm = text[left + 1 : right]
    rest = text[right + 2 :].split()
    if len(rest) < 20:
        raise ValueError("short /proc stat")
    state = rest[0]
    ppid = int(rest[1])
    start_ticks = int(rest[19])
    return comm, ppid, start_ticks, state


def _parse_status(text: str) -> tuple[Optional[int], Optional[int], Optional[int], Optional[int]]:
    real = eff = saved = cap = None
    for line in text.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 4:
                real, eff, saved = int(parts[1]), int(parts[2]), int(parts[3])
        elif line.startswith("CapEff:"):
            try:
                cap = int(line.split()[1], 16)
            except (IndexError, ValueError):
                cap = None
    return real, eff, saved, cap


def read_process(pid: int, proc_root: str = "/proc") -> Optional[ProcessInfo]:
    base = os.path.join(proc_root, str(pid))
    try:
        with open(os.path.join(base, "stat"), "r", encoding="utf-8", errors="replace") as handle:
            comm, ppid, start_ticks, state = _parse_stat(handle.read())
    except (OSError, ValueError):
        return None

    status_readable = True
    uid_real = uid_eff = uid_saved = cap_eff = None
    try:
        with open(os.path.join(base, "status"), "r", encoding="utf-8", errors="replace") as handle:
            uid_real, uid_eff, uid_saved, cap_eff = _parse_status(handle.read())
    except OSError:
        status_readable = False

    argv: tuple[str, ...] = ()
    try:
        with open(os.path.join(base, "cmdline"), "rb") as handle:
            raw = handle.read()
        argv = tuple(part.decode("utf-8", errors="surrogateescape") for part in raw.split(b"\x00") if part)
    except OSError:
        argv = ()

    exe: Optional[str] = None
    exe_readable = True
    try:
        exe = os.readlink(os.path.join(base, "exe"))
    except OSError:
        exe_readable = False

    return ProcessInfo(
        pid=pid,
        ppid=ppid,
        comm=comm,
        state=state,
        start_ticks=start_ticks,
        exe=exe,
        argv=argv,
        uid_real=uid_real,
        uid_eff=uid_eff,
        uid_saved=uid_saved,
        cap_eff=cap_eff,
        status_readable=status_readable,
        exe_readable=exe_readable,
    )


def take_snapshot(proc_root: str = "/proc", pids: Optional[Iterable[int]] = None) -> dict[int, ProcessInfo]:
    if pids is None:
        try:
            pids = [int(name) for name in os.listdir(proc_root) if name.isdigit()]
        except OSError:
            return {}
    snapshot: dict[int, ProcessInfo] = {}
    for pid in pids:
        info = read_process(pid, proc_root)
        if info is not None:
            snapshot[pid] = info
    return snapshot


class ProcessSnapshotSession:
    """Repeated /proc snapshots with full re-reads only where details can matter.

    `analyze_process_windows` consumes fresh details for processes created inside the
    window (identities, argv, exe, credentials, resolution/status rates) and consults
    persisted processes only as parents of those created processes. Snapshot cost is
    dominated by the per-pid status/cmdline/exe reads, so pids present in the first
    snapshot are cached and reused, while pids first seen later are re-read in full on
    every snapshot. Parents of created pids are refreshed on the snapshot where the
    child is visible, preserving parent shell/terminal classification.
    """

    def __init__(self, proc_root: str = "/proc") -> None:
        self._proc_root = proc_root
        self._first_pids: Optional[set[int]] = None
        self._cache: dict[int, ProcessInfo] = {}
        self._present_last: set[int] = set()

    def _list_pids(self) -> list[int]:
        try:
            return [int(name) for name in os.listdir(self._proc_root) if name.isdigit()]
        except OSError:
            return []

    def full_snapshot(self) -> dict[int, ProcessInfo]:
        snapshot = take_snapshot(self._proc_root)
        if self._first_pids is None:
            self._first_pids = set(snapshot)
        self._cache = dict(snapshot)
        self._present_last = set(snapshot)
        return snapshot

    def snapshot(self) -> dict[int, ProcessInfo]:
        pids = self._list_pids()
        if self._first_pids is None:
            return self.full_snapshot()

        attempted: set[int] = set()
        failed: set[int] = set()
        refreshed: dict[int, ProcessInfo] = {}
        for pid in pids:
            # Pids absent from the first snapshot are created-process candidates, and a
            # pid that vanished and reappeared may have been reused: both need full reads.
            if pid not in self._first_pids or pid not in self._present_last:
                attempted.add(pid)
                info = read_process(pid, self._proc_root)
                if info is not None:
                    refreshed[pid] = info
                else:
                    failed.add(pid)

        for pid in list(refreshed):
            parent = refreshed[pid].ppid
            if parent in pids and parent not in attempted:
                attempted.add(parent)
                info = read_process(parent, self._proc_root)
                if info is not None:
                    refreshed[parent] = info
                else:
                    failed.add(parent)

        snapshot: dict[int, ProcessInfo] = {}
        for pid in pids:
            if pid in failed:
                # A failed read must drop the pid from this snapshot, matching
                # take_snapshot(), so the analyzer still counts the exit.
                continue
            info = refreshed.get(pid)
            if info is None:
                info = self._cache.get(pid)
            if info is not None:
                snapshot[pid] = info
        self._cache = dict(snapshot)
        self._present_last = set(snapshot)
        return snapshot


def _basename(token: str) -> str:
    return posixpath.basename(token).lower()


def _rm_flags(args: Sequence[str]) -> tuple[bool, bool]:
    recursive = False
    force = False
    for arg in args:
        if arg == "--":
            break
        if arg == "--recursive":
            recursive = True
        elif arg == "--force":
            force = True
        elif arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            flags = arg[1:]
            recursive = recursive or "r" in flags or "R" in flags
            force = force or "f" in flags
    return recursive, force


def match_destructive(argv: Sequence[str]) -> Optional[str]:
    """Return the matched rule id, or None. argv is matched in memory and never stored."""
    if not argv:
        return None
    name = _basename(argv[0])
    args = list(argv[1:])
    if name.startswith("mkfs"):
        return "mkfs"
    if name == "shred":
        return "shred"
    if name in {"wipe", "srm"}:
        return "wipe"
    if name == "cryptsetup":
        return "cryptsetup"
    if name in {"wipefs", "fdisk", "parted", "sgdisk"}:
        return name
    if name == "truncate":
        return "truncate"
    if name == "dd" and any(arg.startswith("of=/dev/") for arg in args):
        return "dd"
    if name == "rm":
        recursive, force = _rm_flags(args)
        if recursive and force:
            return "rm"
    return None


def _is_temp_path(path: Optional[str], uid: Optional[int], extra_roots: Sequence[str]) -> bool:
    if not path or not path.startswith("/"):
        return False
    roots = list(DEFAULT_TEMP_ROOTS) + list(extra_roots)
    if uid is not None:
        roots.append(f"/run/user/{uid}")
    for root in roots:
        root = root.rstrip("/")
        if path == root or path.startswith(root + "/"):
            return True
    return False


def is_temp_exec(info: ProcessInfo, extra_roots: Sequence[str] = ()) -> bool:
    candidate = info.exe
    if not candidate and info.argv and info.argv[0].startswith("/"):
        candidate = info.argv[0]
    return _is_temp_path(candidate, info.uid_real, extra_roots)


def _is_shell(info: Optional[ProcessInfo]) -> bool:
    if info is None:
        return False
    return _basename(info.argv0) in SHELLS or info.comm.lower() in SHELLS


def _is_terminal(info: Optional[ProcessInfo]) -> bool:
    if info is None:
        return False
    return _basename(info.argv0) in TERMINALS or info.comm.lower() in TERMINALS


def analyze_process_windows(
    snapshots: Sequence[Mapping[int, ProcessInfo]],
    window_seconds: float,
    extra_temp_roots: Sequence[str] = (),
) -> ProcessWindowResult:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    result = ProcessWindowResult(samples=len(snapshots))
    if not snapshots:
        result.notes.append("no snapshots")
        return result

    first = snapshots[0]
    last = snapshots[-1]
    latest: dict[int, ProcessInfo] = {}
    for snapshot in snapshots:
        latest.update(snapshot)
    seen = set(latest)
    created = sorted(pid for pid in seen if pid not in first and not latest[pid].is_kernel_thread)
    exited = {pid for pid in seen if pid not in last}

    result.created_count = len(created)
    result.exited_count = len(exited)
    short_lived = [pid for pid in created if pid in exited]
    result.short_lived_count = len(short_lived)
    if created:
        result.short_lived_ratio = len(short_lived) / len(created)

    rules: list[str] = []
    for pid in created:
        info = latest[pid]
        rule = match_destructive(info.argv)
        if rule:
            result.destructive_count += 1
            rules.append(rule)
        if is_temp_exec(info, extra_temp_roots):
            result.temp_exec_count += 1
        if info.is_privileged:
            result.privileged_count += 1
        parent = latest.get(info.ppid)
        if _is_shell(info) and not _is_shell(parent) and not _is_terminal(parent):
            result.shell_spawn_count += 1
    result.destructive_rules = tuple(sorted(set(rules)))

    if created:
        resolved = sum(1 for pid in created if latest[pid].resolved)
        status_ok = sum(1 for pid in created if latest[pid].status_readable)
        result.resolution_rate = resolved / len(created)
        result.status_readable_rate = status_ok / len(created)
        result.g5_status = STATUS_OK if result.resolution_rate >= RESOLUTION_THRESHOLD else STATUS_DEGRADED
        result.g6_status = STATUS_OK if result.status_readable_rate >= RESOLUTION_THRESHOLD else STATUS_DEGRADED
        if result.g5_status != STATUS_OK:
            result.notes.append("command resolution below 90%")
        if result.g6_status != STATUS_OK:
            result.notes.append("status readability below 90%")
    else:
        result.g5_status = STATUS_NOT_APPLICABLE
        result.g6_status = STATUS_NOT_APPLICABLE

    if len(snapshots) < MIN_SNAPSHOTS:
        result.g4_status = STATUS_DEGRADED
        result.notes.append(f"only {len(snapshots)} snapshots")
    else:
        # Zero created processes is no activity, not a G4 failure.
        result.g4_status = STATUS_OK
    return result


@dataclass
class NetworkResult:
    status: str
    external_ips: set[str] = field(default_factory=set)
    connection_count: int = 0
    error: Optional[str] = None

    @property
    def unique_external_ip_count(self) -> int:
        return len(self.external_ips)


def count_external_ips(connections: Iterable[object]) -> NetworkResult:
    ips: set[str] = set()
    count = 0
    for conn in connections:
        status = getattr(conn, "status", None)
        if isinstance(conn, Mapping):
            status = conn.get("status")
            raddr = conn.get("raddr")
        else:
            raddr = getattr(conn, "raddr", None)
        if status != "ESTABLISHED" or not raddr:
            continue
        ip = raddr[0] if isinstance(raddr, (tuple, list)) else getattr(raddr, "ip", None)
        if not ip:
            continue
        count += 1
        try:
            if ipaddress.ip_address(ip).is_global:
                ips.add(ip)
        except ValueError:
            continue
    return NetworkResult(status=STATUS_OK, external_ips=ips, connection_count=count)


def collect_network() -> NetworkResult:
    try:
        import psutil
    except ImportError as exc:  # pragma: no cover - psutil is a project dependency
        return NetworkResult(STATUS_UNAVAILABLE, error=f"psutil unavailable: {exc}")
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError) as exc:
        return NetworkResult(STATUS_DEGRADED, error=exc.__class__.__name__)
    return count_external_ips(connections)
