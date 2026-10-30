"""
SentinelML V2 — Platform Capability Layer
==========================================
Explicit, per-OS capability probes for telemetry sources used by the Live SOC.

Every source is reported with exactly one of four statuses:

    AVAILABLE            Probe succeeded and real values can be read.
    UNAVAILABLE          The platform does not expose this source at all.
    PERMISSION_REQUIRED  The source exists but the process lacks the rights.
    ERROR                The probe raised or timed out; the value is unknown.

A source is never reported AVAILABLE without a successful probe, and a failed
probe never yields a zero value that could be mistaken for real data.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Tuple

STATUS_AVAILABLE = "available"
STATUS_UNAVAILABLE = "unavailable"
STATUS_PERMISSION_REQUIRED = "permission_required"
STATUS_ERROR = "error"

VALID_STATUSES = frozenset({
    STATUS_AVAILABLE,
    STATUS_UNAVAILABLE,
    STATUS_PERMISSION_REQUIRED,
    STATUS_ERROR,
})

ProbeResult = Tuple[str, str]

CAPABILITY_DEFS: Tuple[Tuple[str, str, str], ...] = (
    ("process_enumeration", "Process enumeration", "psutil.process_iter"),
    ("process_memory", "Process memory metrics", "psutil.Process.memory_info"),
    ("system_cpu_memory", "System CPU & memory", "psutil.cpu_percent / virtual_memory"),
    ("network_connections", "Network connections", "psutil.net_connections"),
    ("file_metadata", "File metadata scope", "os.scandir (read-only)"),
    ("file_hash", "File hashing", "hashlib.sha256 (on demand)"),
    ("process_handles", "Process handle counts", "psutil.Process.num_handles"),
    ("registry", "Registry telemetry", "winreg (HKCU)"),
    ("event_log", "OS event channel", "wevtutil / journalctl"),
    ("security_services", "Security service status", "psutil service table"),
)

_CAPABILITY_INDEX: Dict[str, Tuple[str, str]] = {
    key: (label, source) for key, label, source in CAPABILITY_DEFS
}


@dataclass(frozen=True)
class Capability:
    """Result of probing one telemetry source."""

    key: str
    label: str
    status: str
    detail: str = ""
    source: str = ""

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(f"Invalid capability status: {self.status!r}")

    @property
    def available(self) -> bool:
        return self.status == STATUS_AVAILABLE

    def to_dict(self) -> Dict[str, str]:
        return {
            "key": self.key,
            "label": self.label,
            "status": self.status,
            "detail": self.detail,
            "source": self.source,
        }


# ── Low-level helpers ─────────────────────────────────────────────────────

def _psutil_module():
    import psutil
    return psutil


def _run_command(cmd, timeout: float = 5.0) -> subprocess.CompletedProcess:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        creationflags=flags,
    )


def _first_line(text: Optional[str], fallback: str = "") -> str:
    if not text:
        return fallback
    for line in str(text).splitlines():
        line = line.strip()
        if line:
            return line[:180]
    return fallback


def is_elevated() -> bool:
    """Best-effort, non-raising elevation check for display purposes only."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def describe_platform() -> Dict[str, str]:
    """Human-readable platform facts shown in the SOC header."""
    try:
        system = platform.system() or sys.platform
    except Exception:
        system = sys.platform
    info = {
        "system": system,
        "release": "",
        "machine": platform.machine() or "",
        "python": platform.python_version(),
        "elevated": "yes" if is_elevated() else "no",
    }
    try:
        info["release"] = platform.release() or ""
    except Exception:
        pass
    try:
        if system == "Linux":
            with open("/etc/os-release", "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("PRETTY_NAME="):
                        info["release"] = line.split("=", 1)[1].strip().strip('"')
                        break
    except Exception:
        pass
    return info


# ── Shared probes (all supported platforms) ───────────────────────────────

def probe_process_enumeration() -> ProbeResult:
    try:
        psutil = _psutil_module()
    except Exception as exc:
        return STATUS_UNAVAILABLE, f"psutil unavailable: {exc}"
    try:
        it = psutil.process_iter(["pid"])
        next(it, None)
        return STATUS_AVAILABLE, "Process table readable"
    except psutil.AccessDenied:
        return STATUS_PERMISSION_REQUIRED, "Process table denied by OS policy"
    except Exception as exc:
        return STATUS_ERROR, str(exc)


def probe_process_memory() -> ProbeResult:
    try:
        psutil = _psutil_module()
    except Exception as exc:
        return STATUS_UNAVAILABLE, f"psutil unavailable: {exc}"
    try:
        info = psutil.Process(os.getpid()).memory_info()
        if int(getattr(info, "rss", 0)) <= 0:
            return STATUS_ERROR, "Process memory info returned no RSS"
        return STATUS_AVAILABLE, f"Own RSS {int(info.rss) // (1024 * 1024)} MiB"
    except psutil.AccessDenied:
        return STATUS_PERMISSION_REQUIRED, "Process memory denied by OS policy"
    except Exception as exc:
        return STATUS_ERROR, str(exc)


def probe_system_cpu_memory() -> ProbeResult:
    try:
        psutil = _psutil_module()
    except Exception as exc:
        return STATUS_UNAVAILABLE, f"psutil unavailable: {exc}"
    try:
        vm = psutil.virtual_memory()
        if int(getattr(vm, "total", 0)) <= 0:
            return STATUS_ERROR, "System memory total reported as zero"
        return STATUS_AVAILABLE, f"{int(vm.total) // (1024 ** 3)} GiB total"
    except Exception as exc:
        return STATUS_ERROR, str(exc)


def probe_network_connections() -> ProbeResult:
    try:
        psutil = _psutil_module()
    except Exception as exc:
        return STATUS_UNAVAILABLE, f"psutil unavailable: {exc}"
    try:
        conns = psutil.net_connections(kind="inet")
        return STATUS_AVAILABLE, f"{len(conns)} inet connections visible"
    except psutil.AccessDenied:
        return STATUS_PERMISSION_REQUIRED, "Connection table requires elevation on this OS"
    except Exception as exc:
        return STATUS_ERROR, str(exc)


def probe_file_metadata() -> ProbeResult:
    try:
        from utils.platform_utils import get_monitored_directories
        dirs = [d for d in get_monitored_directories() if d.exists()]
    except Exception as exc:
        return STATUS_ERROR, f"Scope resolution failed: {exc}"
    if not dirs:
        return STATUS_UNAVAILABLE, "No monitored directories exist"
    readable = []
    denied = 0
    for d in dirs:
        try:
            with os.scandir(d) as it:
                next(it, None)
            readable.append(d.name)
        except PermissionError:
            denied += 1
        except Exception:
            denied += 1
    if readable:
        names = ", ".join(readable[:3]) + ("…" if len(readable) > 3 else "")
        return STATUS_AVAILABLE, f"{len(readable)} scope dir(s): {names}"
    if denied:
        return STATUS_PERMISSION_REQUIRED, "Monitored directories deny read access"
    return STATUS_UNAVAILABLE, "No readable monitored directories"


def probe_file_hash() -> ProbeResult:
    try:
        with open(__file__, "rb") as fh:
            if not fh.read(1024):
                return STATUS_ERROR, "Probe file read returned no bytes"
        return STATUS_AVAILABLE, "Local file reads verified"
    except PermissionError:
        return STATUS_PERMISSION_REQUIRED, "Local file reads denied"
    except Exception as exc:
        return STATUS_ERROR, str(exc)


def probe_process_handles() -> ProbeResult:
    if sys.platform != "win32":
        return STATUS_UNAVAILABLE, "Handle tables are not exposed on this platform"
    try:
        psutil = _psutil_module()
        proc = psutil.Process()
        if not hasattr(proc, "num_handles"):
            return STATUS_UNAVAILABLE, "psutil build lacks handle counts"
        return STATUS_AVAILABLE, f"{int(proc.num_handles())} handles (self)"
    except Exception as exc:
        return STATUS_ERROR, str(exc)


def probe_registry() -> ProbeResult:
    if sys.platform != "win32":
        return STATUS_UNAVAILABLE, "Windows registry is not present on this platform"
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software") as key:
            winreg.QueryInfoKey(key)
        return STATUS_AVAILABLE, "HKCU readable"
    except PermissionError:
        return STATUS_PERMISSION_REQUIRED, "Registry read denied"
    except Exception as exc:
        return STATUS_ERROR, str(exc)


def probe_event_log() -> ProbeResult:
    """Report whether an OS event channel list can be read.

    The probe only lists channel names; it never reads event contents.
    """
    if sys.platform == "win32":
        exe = shutil.which("wevtutil")
        if not exe:
            return STATUS_UNAVAILABLE, "Event channel CLI not found"
        try:
            res = _run_command([exe, "el"], timeout=5.0)
        except subprocess.TimeoutExpired:
            return STATUS_ERROR, "Event channel list timed out"
        except Exception as exc:
            return STATUS_ERROR, str(exc)
        if res.returncode == 0:
            return STATUS_AVAILABLE, "Event channel list readable"
        return STATUS_ERROR, _first_line(res.stderr, "Channel list query failed")
    if sys.platform.startswith("linux"):
        exe = shutil.which("journalctl")
        if not exe:
            return STATUS_UNAVAILABLE, "journalctl not found (non-systemd host)"
        try:
            res = _run_command(
                [exe, "-n", "1", "--no-pager", "-q", "-o", "cat"], timeout=5.0
            )
        except subprocess.TimeoutExpired:
            return STATUS_ERROR, "journalctl timed out"
        except Exception as exc:
            return STATUS_ERROR, str(exc)
        if res.returncode == 0:
            return STATUS_AVAILABLE, "systemd journal readable"
        err = ((res.stderr or "") + (res.stdout or "")).lower()
        if "not been booted with systemd" in err or "no journal files" in err or "failed to connect to bus" in err:
            return STATUS_UNAVAILABLE, "systemd journal is not running on this host"
        if "permission" in err:
            return STATUS_PERMISSION_REQUIRED, "Journal read requires additional rights"
        return STATUS_ERROR, _first_line(res.stderr, "journalctl query failed")
    return STATUS_UNAVAILABLE, "No supported OS event channel interface"


def probe_security_services() -> ProbeResult:
    """Probe the OS service/security-module table via psutil."""
    if sys.platform == "win32":
        try:
            psutil = _psutil_module()
            if not hasattr(psutil, "win_service_iter"):
                return STATUS_UNAVAILABLE, "psutil build lacks service enumeration"
            count = sum(1 for _ in psutil.win_service_iter())
            return STATUS_AVAILABLE, f"{count} services enumerable"
        except Exception as exc:
            if exc.__class__.__name__ == "AccessDenied":
                return STATUS_PERMISSION_REQUIRED, "Service table denied by OS policy"
            return STATUS_ERROR, str(exc)
    if sys.platform.startswith("linux"):
        lsm = Path("/sys/kernel/security/lsm")
        try:
            if lsm.exists():
                names = lsm.read_text(encoding="utf-8").strip()
                return STATUS_AVAILABLE, f"LSM: {names or 'unknown'}"
        except PermissionError:
            return STATUS_PERMISSION_REQUIRED, "LSM status requires privileges"
        except Exception as exc:
            return STATUS_ERROR, str(exc)
        aa = shutil.which("aa-status")
        if aa:
            try:
                res = _run_command([aa, "--enabled"], timeout=3.0)
                if res.returncode == 0:
                    return STATUS_AVAILABLE, "AppArmor status readable"
            except subprocess.TimeoutExpired:
                return STATUS_ERROR, "aa-status timed out"
            except Exception as exc:
                return STATUS_ERROR, str(exc)
        return STATUS_UNAVAILABLE, "No AppArmor/SELinux status interface exposed"
    return STATUS_UNAVAILABLE, "No supported security service interface"


SHARED_PROBES: Dict[str, Callable[[], ProbeResult]] = {
    "process_enumeration": probe_process_enumeration,
    "process_memory": probe_process_memory,
    "system_cpu_memory": probe_system_cpu_memory,
    "network_connections": probe_network_connections,
    "file_metadata": probe_file_metadata,
    "file_hash": probe_file_hash,
    "process_handles": probe_process_handles,
    "registry": probe_registry,
    "event_log": probe_event_log,
    "security_services": probe_security_services,
}


# ── Public interface ──────────────────────────────────────────────────────

class PlatformCapabilities:
    """Probes and caches capability status for one host.

    ``probe_all`` is safe to call from a worker thread; ``get`` and
    ``snapshot`` are cheap reads for the UI. A probe always re-runs so a
    permission change or a transient failure is reflected honestly.
    """

    def __init__(
        self,
        platform_name: str,
        probes: Mapping[str, Callable[[], ProbeResult]],
    ) -> None:
        self.platform_name = platform_name
        self._probes: Dict[str, Callable[[], ProbeResult]] = dict(probes)
        self._cache: Dict[str, Capability] = {}
        self._lock = threading.Lock()
        self._last_probe_wall: Optional[float] = None

    def probe(self, key: str) -> Capability:
        label, source = _CAPABILITY_INDEX.get(key, (key, ""))
        probe = self._probes.get(key)
        if probe is None:
            cap = Capability(key, label, STATUS_UNAVAILABLE, "No probe registered", source)
        else:
            try:
                status, detail = probe()
                if status not in VALID_STATUSES:
                    status, detail = STATUS_ERROR, f"Invalid probe result: {status}"
                cap = Capability(key, label, status, str(detail or "")[:200], source)
            except Exception as exc:
                cap = Capability(key, label, STATUS_ERROR, str(exc)[:200], source)
        with self._lock:
            self._cache[key] = cap
        return cap

    def probe_all(self) -> Dict[str, Capability]:
        for key, _label, _src in CAPABILITY_DEFS:
            self.probe(key)
        with self._lock:
            self._last_probe_wall = time.time()
            return dict(self._cache)

    def get(self, key: str) -> Capability:
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        label, source = _CAPABILITY_INDEX.get(key, (key, ""))
        return Capability(key, label, STATUS_UNAVAILABLE, "Not probed yet", source)

    def snapshot(self) -> Dict[str, Dict[str, str]]:
        with self._lock:
            return {key: cap.to_dict() for key, cap in self._cache.items()}

    def available_keys(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(k for k, c in self._cache.items() if c.available)

    @property
    def last_probe_wall(self) -> Optional[float]:
        return self._last_probe_wall


def build_platform_capabilities(system_name: Optional[str] = None) -> PlatformCapabilities:
    """Build the capability probe set for the current (or supplied) OS."""
    system = system_name if system_name is not None else platform.system()
    name = (system or "Unknown").strip()
    # Every supported platform shares the same interface and probe set; each
    # probe decides whether the source is exposed on this OS.
    return PlatformCapabilities(name, SHARED_PROBES)


_singleton: Optional[PlatformCapabilities] = None
_singleton_lock = threading.Lock()


def get_platform_capabilities() -> PlatformCapabilities:
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = build_platform_capabilities()
        return _singleton
