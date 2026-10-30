import sys
"""
SentinelML V2 - Live Scanner
Extracts 19 behavioral features from the running system using psutil.

CRITICAL: Feature ordering MUST match training data / scaler feature names.

Features (19 total, in exact order):
 [0]  total_processes
 [1]  suspicious_process_count
 [2]  avg_entropy
 [3]  max_entropy
 [4]  high_entropy_region_count
 [5]  malfind_injection_count
 [6]  crypto_dll_count
 [7]  cmd_vssadmin_count
 [8]  network_connection_count
 [9]  unique_external_ips
[10]  file_handle_count
[11]  registry_handle_count
[12]  orphan_process_count
[13]  powershell_process_count
[14]  unsigned_module_count
[15]  suspicious_mutex_count
[16]  abnormal_privilege_count
[17]  suspicious_thread_count
[18]  defender_tampering_count
"""
import ipaddress, logging, math, os, time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import numpy as np
import psutil
from utils.logging_config import get_scanner_logger

log = get_scanner_logger()

FEATURE_NAMES = [
    "total_processes","suspicious_process_count","avg_entropy","max_entropy",
    "high_entropy_region_count","malfind_injection_count","crypto_dll_count",
    "cmd_vssadmin_count","network_connection_count","unique_external_ips",
    "file_handle_count","registry_handle_count","orphan_process_count",
    "powershell_process_count","unsigned_module_count","suspicious_mutex_count",
    "abnormal_privilege_count","suspicious_thread_count","defender_tampering_count",
]


def get_platform_feature_availability() -> dict:
    """
    Return the feature availability status map for the current platform.
    Categories:
    - GENUINE_MEASURED: Directly queried from OS telemetry (psutil, Toolhelp32, filesystem)
    - HEURISTIC_PROXY: Approximate proxy heuristic derived from unprivileged telemetry
    - SUBSTITUTED: Platform-specific equivalent used (e.g. .so on Linux, .dylib on macOS)
    - UNAVAILABLE_PLATFORM: Feature relies on OS subsystem unavailable on this platform (evaluates to 0.0)
    - RESTRICTED_PERMISSION: Requires elevated root/admin permissions
    """
    if sys.platform == "win32":
        return {
            "total_processes": "GENUINE_MEASURED",
            "suspicious_process_count": "GENUINE_MEASURED",
            "avg_entropy": "GENUINE_MEASURED",
            "max_entropy": "GENUINE_MEASURED",
            "high_entropy_region_count": "GENUINE_MEASURED",
            "malfind_injection_count": "HEURISTIC_PROXY",
            "crypto_dll_count": "GENUINE_MEASURED",
            "cmd_vssadmin_count": "GENUINE_MEASURED",
            "network_connection_count": "GENUINE_MEASURED",
            "unique_external_ips": "GENUINE_MEASURED",
            "file_handle_count": "GENUINE_MEASURED",
            "registry_handle_count": "HEURISTIC_PROXY",
            "orphan_process_count": "GENUINE_MEASURED",
            "powershell_process_count": "GENUINE_MEASURED",
            "unsigned_module_count": "HEURISTIC_PROXY",
            "suspicious_mutex_count": "HEURISTIC_PROXY",
            "abnormal_privilege_count": "HEURISTIC_PROXY",
            "suspicious_thread_count": "HEURISTIC_PROXY",
            "defender_tampering_count": "GENUINE_MEASURED",
        }
    elif sys.platform.startswith("linux"):
        return {
            "total_processes": "GENUINE_MEASURED",
            "suspicious_process_count": "GENUINE_MEASURED",
            "avg_entropy": "GENUINE_MEASURED",
            "max_entropy": "GENUINE_MEASURED",
            "high_entropy_region_count": "GENUINE_MEASURED",
            "malfind_injection_count": "HEURISTIC_PROXY",
            "crypto_dll_count": "SUBSTITUTED",
            "cmd_vssadmin_count": "SUBSTITUTED",
            "network_connection_count": "GENUINE_MEASURED",
            "unique_external_ips": "GENUINE_MEASURED",
            "file_handle_count": "UNAVAILABLE_PLATFORM",
            "registry_handle_count": "UNAVAILABLE_PLATFORM",
            "orphan_process_count": "GENUINE_MEASURED",
            "powershell_process_count": "GENUINE_MEASURED",
            "unsigned_module_count": "HEURISTIC_PROXY",
            "suspicious_mutex_count": "HEURISTIC_PROXY",
            "abnormal_privilege_count": "UNAVAILABLE_PLATFORM",
            "suspicious_thread_count": "HEURISTIC_PROXY",
            "defender_tampering_count": "UNAVAILABLE_PLATFORM",
        }
    else:  # darwin / macos
        return {
            "total_processes": "GENUINE_MEASURED",
            "suspicious_process_count": "GENUINE_MEASURED",
            "avg_entropy": "GENUINE_MEASURED",
            "max_entropy": "GENUINE_MEASURED",
            "high_entropy_region_count": "GENUINE_MEASURED",
            "malfind_injection_count": "HEURISTIC_PROXY",
            "crypto_dll_count": "SUBSTITUTED",
            "cmd_vssadmin_count": "SUBSTITUTED",
            "network_connection_count": "RESTRICTED_PERMISSION",
            "unique_external_ips": "RESTRICTED_PERMISSION",
            "file_handle_count": "UNAVAILABLE_PLATFORM",
            "registry_handle_count": "UNAVAILABLE_PLATFORM",
            "orphan_process_count": "GENUINE_MEASURED",
            "powershell_process_count": "GENUINE_MEASURED",
            "unsigned_module_count": "HEURISTIC_PROXY",
            "suspicious_mutex_count": "HEURISTIC_PROXY",
            "abnormal_privilege_count": "UNAVAILABLE_PLATFORM",
            "suspicious_thread_count": "HEURISTIC_PROXY",
            "defender_tampering_count": "UNAVAILABLE_PLATFORM",
        }

SUSPICIOUS_PROC_NAMES = {
    "vssadmin.exe","wmic.exe","bcdedit.exe","wbadmin.exe","cipher.exe",
    "sdelete.exe","icacls.exe","attrib.exe","net.exe","net1.exe",
    "taskkill.exe","wevtutil.exe","reg.exe","regsvr32.exe","mshta.exe",
    "wscript.exe","cscript.exe","certutil.exe","bitsadmin.exe","rundll32.exe",
    "powershell_ise.exe","msiexec.exe","expand.exe",
}
CRYPTO_DLLS = {
    "bcrypt.dll","cryptsp.dll","crypt32.dll","advapi32.dll",
    "ncrypt.dll","rsaenh.dll","dpapi.dll",
}
VSSADMIN_PROCS = {"cmd.exe","vssadmin.exe","bcdedit.exe","wbadmin.exe"}
HIGH_ENTROPY_BENIGN_EXTENSIONS = {
    ".zip",".rar",".7z",".gz",".bz2",".xz",".lz4",".zst",".tar",
    ".jpg",".jpeg",".png",".gif",".bmp",".webp",".heic",
    ".mp4",".mkv",".avi",".mov",".wmv",".flv",".mp3",
    ".exe",".dll",".pyd",".so",".whl",".jar",".apk",".ipa",
    ".pdf",".docx",".xlsx",".pptx",
}
ENTROPY_SCAN_DIRS = [
    Path.home() / "Documents",
    Path.home() / "Desktop",
    Path.home() / "Downloads",
]
ENTROPY_SAMPLE_LIMIT = 200
ENTROPY_HIGH_THRESHOLD = 7.0
DEFENDER_SERVICES = {"WinDefend","SecurityHealthService","wscsvc"}

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return True

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy



SYSTEM_PROTECTED_PROCS = {
    "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
    "memory compression", "secure system"
}

class FastProcessProxy:
    """Lightweight proxy for process info allowing lazy memory_maps on demand."""
    __slots__ = ("info", "pid", "_ps")
    def __init__(self, info_dict: dict):
        self.info = info_dict
        self.pid = info_dict.get("pid", 0)
        self._ps = None

    def memory_maps(self):
        if self._ps is None:
            self._ps = psutil.Process(self.pid)
        return self._ps.memory_maps()


# ── Native Fast Win32 Module Inspection ──────────────────────────────────────
if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes

    _kernel32 = ctypes.windll.kernel32
    _kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    _kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

    class _MODULEENTRY32(ctypes.Structure):
        _fields_ = [
            ('dwSize', ctypes.wintypes.DWORD),
            ('th32ModuleID', ctypes.wintypes.DWORD),
            ('th32ProcessID', ctypes.wintypes.DWORD),
            ('GlblcntUsage', ctypes.wintypes.DWORD),
            ('ProccntUsage', ctypes.wintypes.DWORD),
            ('modBaseAddr', ctypes.POINTER(ctypes.c_byte)),
            ('modBaseSize', ctypes.wintypes.DWORD),
            ('hModule', ctypes.wintypes.HMODULE),
            ('szModule', ctypes.c_char * 256),
            ('szExePath', ctypes.c_char * 260)
        ]

    _kernel32.Module32First.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(_MODULEENTRY32)]
    _kernel32.Module32First.restype = ctypes.wintypes.BOOL
    _kernel32.Module32Next.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(_MODULEENTRY32)]
    _kernel32.Module32Next.restype = ctypes.wintypes.BOOL

    _INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value

    def _fast_has_crypto_dll_win32(pid: int) -> Optional[bool]:
        # Fast native module table check via Toolhelp32 (<0.001s, no memory query)
        if pid <= 4:
            return False
        # TH32CS_SNAPMODULE (0x8) | TH32CS_SNAPMODULE32 (0x10)
        hSnap = _kernel32.CreateToolhelp32Snapshot(0x00000008 | 0x00000010, pid)
        if not hSnap or hSnap == _INVALID_HANDLE_VALUE:
            return None
        entry = _MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(_MODULEENTRY32)
        has_crypto = False
        try:
            if _kernel32.Module32First(hSnap, ctypes.byref(entry)):
                mod_name = entry.szModule.decode('ansi', errors='ignore').lower()
                if mod_name in CRYPTO_DLLS:
                    has_crypto = True
                else:
                    while _kernel32.Module32Next(hSnap, ctypes.byref(entry)):
                        mod_name = entry.szModule.decode('ansi', errors='ignore').lower()
                        if mod_name in CRYPTO_DLLS:
                            has_crypto = True
                            break
        except Exception:
            pass
        finally:
            _kernel32.CloseHandle(hSnap)
        return has_crypto
else:
    def _fast_has_crypto_dll_win32(pid: int) -> Optional[bool]:
        return None

def _get_fast_process_snapshot():
    """High-speed process snapshot: uses Win32 Toolhelp32 on Windows for instant ppid/threads."""
    if sys.platform == "win32":
        try:
            import ctypes, ctypes.wintypes
            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ('dwSize', ctypes.wintypes.DWORD),
                    ('cntUsage', ctypes.wintypes.DWORD),
                    ('th32ProcessID', ctypes.wintypes.DWORD),
                    ('th32DefaultHeapID', ctypes.c_size_t),
                    ('th32ModuleID', ctypes.wintypes.DWORD),
                    ('cntThreads', ctypes.wintypes.DWORD),
                    ('th32ParentProcessID', ctypes.wintypes.DWORD),
                    ('pcPriClassBase', ctypes.c_long),
                    ('dwFlags', ctypes.wintypes.DWORD),
                    ('szExeFile', ctypes.c_char * 260)
                ]
            snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            success = ctypes.windll.kernel32.Process32First(snap, ctypes.byref(entry))
            procs_dict = {}
            while success:
                procs_dict[entry.th32ProcessID] = {
                    'pid': entry.th32ProcessID,
                    'ppid': entry.th32ParentProcessID,
                    'num_threads': entry.cntThreads,
                    'name': entry.szExeFile.decode('ansi', errors='ignore'),
                    'exe': '',
                    'num_handles': 0
                }
                success = ctypes.windll.kernel32.Process32Next(snap, ctypes.byref(entry))
            ctypes.windll.kernel32.CloseHandle(snap)

            # High-speed native Win32 pass for exe path and handle count (completes in ~8ms vs 700ms in psutil)
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            buf = ctypes.create_unicode_buffer(1024)
            size = ctypes.wintypes.DWORD(1024)
            handle_cnt = ctypes.wintypes.DWORD(0)

            try:
                import psutil._pswindows as psw
                proc_exe_fn = psw.cext.proc_exe
            except Exception:
                proc_exe_fn = None

            for idx, (pid, info) in enumerate(procs_dict.items()):
                if idx % 50 == 0:
                    time.sleep(0.001)
                if pid > 4 and proc_exe_fn:
                    try:
                        info['exe'] = proc_exe_fn(pid)
                    except Exception:
                        pass
                h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if h:
                    if not info.get('exe'):
                        size.value = 1024
                        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                            info['exe'] = buf.value
                    if kernel32.GetProcessHandleCount(h, ctypes.byref(handle_cnt)):
                        info['num_handles'] = handle_cnt.value
                    kernel32.CloseHandle(h)

            return [FastProcessProxy(d) for d in procs_dict.values()]
        except Exception as e:
            log.warning("Fast Win32 process snapshot fallback to psutil: %s", e)

    # Cross-platform fallback
    attrs = ["pid", "name", "exe", "ppid", "num_threads", "num_handles"] if sys.platform == "win32" else ["pid", "name", "exe", "ppid", "num_threads"]
    raw_procs = list(psutil.process_iter(attrs))
    if sys.platform != "win32":
        filtered = []
        for p in raw_procs:
            try:
                pid = p.info.get("pid", 0)
                ppid = p.info.get("ppid", 0)
                name = p.info.get("name") or ""
                if pid <= 2 or ppid == 2 or (name.startswith("[") and name.endswith("]")):
                    continue
                filtered.append(p)
            except Exception:
                pass
        return filtered
    return raw_procs


class LiveScanner:
    """Extracts the 19 behavioral features the ML model was trained on."""

    def __init__(self):
        self._scan_start_time: float = 0.0
        self._scan_duration: float = 0.0
        self._processes_scanned: int = 0
        self._errors_encountered: int = 0
        self._feature_values: Dict[str, float] = {}
        self._cancel_requested: bool = False

    def cancel(self) -> None:
        self._cancel_requested = True

    def scan_system(
        self,
        target_directories: Optional[List[Path]] = None,
        progress_callback: Optional[object] = None,
        cancel_checker: Optional[object] = None
    ) -> Optional[np.ndarray]:
        log.info("Starting live behavioral scan...")
        self._cancel_requested = False
        self._scan_start_time = time.time()
        self._processes_scanned = 0
        self._errors_encountered = 0
        self._feature_values = {}
        try:
            if progress_callback:
                progress_callback("Enumerating active host processes...")

            try:
                procs = _get_fast_process_snapshot()
                self._processes_scanned = len(procs)
                log.info("Process snapshot: %d processes", len(procs))
            except Exception as e:
                log.error("Failed to enumerate processes: %s", e, exc_info=True)
                self._errors_encountered += 1
                procs = []

            if self._cancel_requested or (cancel_checker and cancel_checker()):
                log.info("Scan cancelled during process enumeration")
                return None

            alive_pids = set()
            for p in procs:
                try:
                    alive_pids.add(p.info["pid"])
                except Exception:
                    pass

            features = []
            features.append(float(len(procs)))                              # [0]
            features.append(self._count_suspicious_procs(procs))           # [1]

            if progress_callback:
                progress_callback("Analyzing filesystem behavioral entropy...")
            avg_e, max_e, high_e = self._scan_file_entropy(
                target_directories=target_directories,
                progress_callback=progress_callback,
                cancel_checker=cancel_checker
            )
            features.append(avg_e)                                          # [2]
            features.append(max_e)                                          # [3]
            features.append(high_e)                                         # [4]

            if self._cancel_requested or (cancel_checker and cancel_checker()):
                log.info("Scan cancelled after entropy analysis")
                return None

            features.append(self._count_hollow_procs(procs))               # [5]

            if progress_callback:
                progress_callback("Inspecting process cryptographic modules...")
            features.append(self._count_crypto_dll_procs(
                procs,
                progress_callback=progress_callback,
                cancel_checker=cancel_checker
            ))                                                              # [6]

            if self._cancel_requested or (cancel_checker and cancel_checker()):
                log.info("Scan cancelled after crypto module inspection")
                return None

            features.append(self._count_vssadmin_procs(procs))             # [7]
            conn_count, ext_ips = self._scan_network()
            features.append(conn_count)                                     # [8]
            features.append(ext_ips)                                        # [9]
            features.append(self._total_file_handles(procs))               # [10]
            features.append(self._registry_handle_heuristic(procs))        # [11]
            features.append(self._count_orphan_procs(procs, alive_pids))   # [12]
            features.append(self._count_powershell_procs(procs))           # [13]
            features.append(self._count_suspicious_path_procs(procs))      # [14]
            features.append(self._count_high_thread_procs(procs, 50))      # [15]
            features.append(self._count_abnormal_handle_procs(procs))      # [16]
            features.append(self._count_high_thread_procs(procs, 100))     # [17]
            features.append(self._check_defender_tampering())               # [18]

            if len(features) != 19:
                log.error("BUG: Feature count mismatch! Expected 19, got %d", len(features))
                return None

            self._feature_values = dict(zip(FEATURE_NAMES, features))
            log.info("Features extracted:")
            for name, val in self._feature_values.items():
                log.info("  %-35s = %.2f", name, val)

            self._scan_duration = time.time() - self._scan_start_time
            log.info("Live scan complete. Duration: %.2fs, Processes: %d, Errors: %d",
                     self._scan_duration, self._processes_scanned, self._errors_encountered)
            return np.array([features], dtype=np.float64)

        except Exception as e:
            log.error("Live scan failed: %s", e, exc_info=True)
            return None

    def get_scan_stats(self) -> Dict[str, object]:
        return {
            "duration": self._scan_duration,
            "processes_scanned": self._processes_scanned,
            "errors": self._errors_encountered,
            "feature_values": dict(self._feature_values),
        }

    def get_feature_availability(self) -> dict:
        return get_platform_feature_availability()

    def get_feature_names(self) -> List[str]:
        return list(FEATURE_NAMES)

    def _count_suspicious_procs(self, procs: list) -> float:
        count = 0
        from utils.platform_adapter import get_platform_adapter
        adapter = get_platform_adapter()
        for p in procs:
            try:
                name = (p.info.get("name") or "").lower()
                if adapter.is_suspicious_process_name(name):
                    count += 1
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _scan_file_entropy(
        self,
        target_directories: Optional[List[Path]] = None,
        progress_callback: Optional[object] = None,
        cancel_checker: Optional[object] = None
    ) -> Tuple[float, float, float]:
        entropies = []
        high_count = 0
        files_sampled = 0
        if target_directories:
            scan_dirs = [Path(d) for d in target_directories if Path(d).exists()]
        else:
            from utils.platform_utils import PlatformInfo
            scan_dirs = PlatformInfo().get_monitored_directories()
        
        for scan_dir in scan_dirs:
            if not scan_dir.exists() or self._cancel_requested or (cancel_checker and cancel_checker()):
                continue
            try:
                for root, dirs, files in os.walk(scan_dir):
                    if files_sampled >= ENTROPY_SAMPLE_LIMIT or self._cancel_requested or (cancel_checker and cancel_checker()):
                        break
                    # Prune common build and virtualenv noise dirs to prevent disk thrashing
                    dirs[:] = [
                        d for d in dirs
                        if d.lower() not in {
                            '.git', 'node_modules', '__pycache__', '.pytest_cache',
                            '.venv', 'venv', 'env', 'build_env', 'build', 'dist',
                            '.idea', '.vscode'
                        } and not d.startswith('.freebuff')
                    ]
                    for _ent_idx, fname in enumerate(files):
                        if files_sampled >= ENTROPY_SAMPLE_LIMIT or self._cancel_requested or (cancel_checker and cancel_checker()):
                            break
                        # Cooperative GIL yield every 20 files
                        if _ent_idx % 20 == 0:
                            time.sleep(0)
                        fpath = Path(root) / fname
                        if fpath.suffix.lower() in HIGH_ENTROPY_BENIGN_EXTENSIONS:
                            continue
                        try:
                            # Skip cloud/reparse placeholder files on Windows to prevent network recall
                            if sys.platform == "win32":
                                try:
                                    st = fpath.stat()
                                    attrs = getattr(st, "st_file_attributes", 0)
                                    if attrs & 0x00401000:
                                        continue
                                except Exception:
                                    pass

                            with open(fpath, "rb") as f:
                                data = f.read(4096)
                            if len(data) < 64:
                                continue
                            ent = _shannon_entropy(data)
                            entropies.append(ent)
                            if ent > ENTROPY_HIGH_THRESHOLD:
                                high_count += 1
                            files_sampled += 1
                        except (PermissionError, OSError, IOError):
                            pass
                        except Exception as e:
                            log.debug("Entropy error on %s: %s", fpath, e)
            except Exception as e:
                log.warning("Entropy scan failed for %s: %s", scan_dir, e)
                self._errors_encountered += 1
        if not entropies:
            log.warning("No files sampled for entropy analysis")
            return 0.0, 0.0, 0.0
        avg_e = sum(entropies) / len(entropies)
        max_e = max(entropies)
        log.info("Entropy: %d files, avg=%.2f, max=%.2f, high=%d",
                 len(entropies), avg_e, max_e, high_count)
        return avg_e, max_e, float(high_count)

    def _count_hollow_procs(self, procs: list) -> float:
        count = 0
        for p in procs:
            try:
                exe = p.info.get("exe")
                if exe is None or exe == "":
                    name = (p.info.get("name") or "").lower()
                    pid = p.info.get("pid", 0)
                    ppid = p.info.get("ppid", 0)
                    if name in {"system","idle","registry","smss.exe","memory compression"}:
                        continue
                    if pid <= 2 or ppid in {0, 1, 2, 4} or (name.startswith("[") and name.endswith("]")) or (name.startswith("(") and name.endswith(")")):
                        continue
                    if sys.platform != "win32":
                        if name in {"init", "init-watcher", "systemd", "dbus-daemon", "sshd", "cron", "rsyslogd"}:
                            continue
                    count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _count_crypto_dll_procs(
        self,
        procs: list,
        progress_callback: Optional[object] = None,
        cancel_checker: Optional[object] = None
    ) -> float:
        count = 0
        total_p = len(procs)
        for idx, p in enumerate(procs):
            if self._cancel_requested or (cancel_checker and cancel_checker()):
                break
            # Cooperative GIL yield every 15 processes to keep main-thread event loop responsive
            if idx % 15 == 0:
                time.sleep(0.001)
            if progress_callback and (idx % 25 == 0 or idx == total_p - 1):
                progress_callback(f"Inspecting cryptographic modules ({idx+1}/{total_p})...")
            try:
                pid = p.info.get("pid", 0)
                name = (p.info.get("name") or "").lower()
                # Skip kernel, system, and protected OS processes
                if pid <= 4 or name in SYSTEM_PROTECTED_PROCS:
                    continue

                # 1. Fast Win32 Toolhelp32 module table check (<0.001s, no memory query)
                res = _fast_has_crypto_dll_win32(pid)
                if res is not None:
                    if res:
                        count += 1
                    continue

                # 2. Cross-platform / fallback to memory_maps (skipped on win32 if native snapshot failed due to access denial)
                if sys.platform != "win32":
                    maps = p.memory_maps()
                    from utils.platform_adapter import get_platform_adapter
                    adapter = get_platform_adapter()
                    for m in maps:
                        path_lower = m.path.lower() if hasattr(m, "path") else ""
                        if adapter.is_crypto_module(path_lower):
                            count += 1
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _count_vssadmin_procs(self, procs: list) -> float:
        count = 0
        for p in procs:
            try:
                name = (p.info.get("name") or "").lower()
                if name in VSSADMIN_PROCS:
                    count += 1
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _scan_network(self) -> Tuple[float, float]:
        try:
            conns = psutil.net_connections(kind="inet")
            total = len(conns)
            external_ips = set()
            for conn in conns:
                if conn.raddr and conn.raddr.ip:
                    if not _is_private_ip(conn.raddr.ip):
                        external_ips.add(conn.raddr.ip)
            log.info("Network: %d connections, %d external IPs", total, len(external_ips))
            return float(total), float(len(external_ips))
        except Exception as e:
            log.warning("Network scan failed: %s", e)
            self._errors_encountered += 1
            return 0.0, 0.0

    def _total_file_handles(self, procs: list) -> float:
        total = 0
        for p in procs:
            try:
                total += (p.info.get("num_handles") or 0) if sys.platform == "win32" else 0
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                self._errors_encountered += 1
        return float(total)

    def _registry_handle_heuristic(self, procs: list) -> float:
        system_procs = {"system","lsass.exe","svchost.exe","explorer.exe",
                        "csrss.exe","wininit.exe","services.exe","winlogon.exe"}
        count = 0
        for p in procs:
            try:
                name = (p.info.get("name") or "").lower()
                if name in system_procs:
                    continue
                handles = (p.info.get("num_handles") or 0) if sys.platform == "win32" else 0
                if handles > 500:
                    count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _count_orphan_procs(self, procs: list, alive_pids: set) -> float:
        count = 0
        for p in procs:
            try:
                ppid = p.info.get("ppid", 0)
                if ppid and ppid not in {0, 1, 2, 4} and ppid not in alive_pids:
                    name = (p.info.get("name") or "").lower()
                    if name not in {"system","registry","idle"}:
                        count += 1
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _count_powershell_procs(self, procs: list) -> float:
        count = 0
        for p in procs:
            try:
                name = (p.info.get("name") or "").lower()
                if name in {"powershell.exe","pwsh.exe"}:
                    count += 1
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _count_suspicious_path_procs(self, procs: list) -> float:
        frags = ["\\temp\\","\\tmp\\","\\appdata\\local\\temp\\",
                 "\\downloads\\","\\users\\public\\","\\programdata\\",
                 "/tmp/", "/var/tmp/", "/dev/shm/", "/downloads/"]
        count = 0
        for p in procs:
            try:
                exe = (p.info.get("exe") or "").lower()
                if exe and any(f in exe for f in frags):
                    count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _count_high_thread_procs(self, procs: list, threshold: int) -> float:
        count = 0
        for p in procs:
            try:
                threads = p.info.get("num_threads", 0) or 0
                if threads > threshold:
                    count += 1
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _count_abnormal_handle_procs(self, procs: list) -> float:
        system_procs = {"system","lsass.exe","svchost.exe"}
        count = 0
        for p in procs:
            try:
                name = (p.info.get("name") or "").lower()
                if name in system_procs:
                    continue
                handles = (p.info.get("num_handles") or 0) if sys.platform == "win32" else 0
                if handles > 2000:
                    count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _check_defender_tampering(self) -> float:
        from utils.platform_adapter import get_platform_adapter
        return get_platform_adapter().check_security_service_tampering()
