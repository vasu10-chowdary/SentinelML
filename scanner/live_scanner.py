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


class LiveScanner:
    """Extracts the 19 behavioral features the ML model was trained on."""

    def __init__(self):
        self._scan_start_time: float = 0.0
        self._scan_duration: float = 0.0
        self._processes_scanned: int = 0
        self._errors_encountered: int = 0
        self._feature_values: Dict[str, float] = {}

    def scan_system(self) -> Optional[np.ndarray]:
        """Perform live system scan. Returns (1,19) array or None on failure."""
        log.info("Starting live behavioral scan...")
        self._scan_start_time = time.time()
        self._processes_scanned = 0
        self._errors_encountered = 0
        self._feature_values = {}
        try:
            try:
                procs = list(psutil.process_iter(
                    ["pid","name","exe","ppid","num_threads","num_handles","status"] if sys.platform == "win32" else ["pid","name","exe","ppid","num_threads","status"]
                ))
                self._processes_scanned = len(procs)
                log.info("Process snapshot: %d processes", len(procs))
            except Exception as e:
                log.error("Failed to enumerate processes: %s", e, exc_info=True)
                self._errors_encountered += 1
                procs = []

            alive_pids = set()
            for p in procs:
                try:
                    alive_pids.add(p.info["pid"])
                except Exception:
                    pass

            features = []
            features.append(float(len(procs)))                              # [0]
            features.append(self._count_suspicious_procs(procs))           # [1]
            avg_e, max_e, high_e = self._scan_file_entropy()
            features.append(avg_e)                                          # [2]
            features.append(max_e)                                          # [3]
            features.append(high_e)                                         # [4]
            features.append(self._count_hollow_procs(procs))               # [5]
            features.append(self._count_crypto_dll_procs(procs))           # [6]
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

    def get_feature_names(self) -> List[str]:
        return list(FEATURE_NAMES)

    def _count_suspicious_procs(self, procs: list) -> float:
        count = 0
        for p in procs:
            try:
                name = (p.info.get("name") or "").lower()
                if name in SUSPICIOUS_PROC_NAMES:
                    count += 1
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _scan_file_entropy(self) -> Tuple[float, float, float]:
        entropies = []
        high_count = 0
        files_sampled = 0
        from utils.platform_utils import PlatformInfo
        scan_dirs = PlatformInfo().get_monitored_directories()
        
        for scan_dir in scan_dirs:
            if not scan_dir.exists():
                continue
            try:
                for root, _dirs, files in os.walk(scan_dir):
                    if files_sampled >= ENTROPY_SAMPLE_LIMIT:
                        break
                    for fname in files:
                        if files_sampled >= ENTROPY_SAMPLE_LIMIT:
                            break
                        fpath = Path(root) / fname
                        if fpath.suffix.lower() in HIGH_ENTROPY_BENIGN_EXTENSIONS:
                            continue
                        try:
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
                    if name not in {"system","idle","registry","smss.exe","memory compression"}:
                        count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _count_crypto_dll_procs(self, procs: list) -> float:
        count = 0
        for p in procs:
            try:
                maps = p.memory_maps()
                for m in maps:
                    path_lower = m.path.lower() if hasattr(m, "path") else ""
                    fname = Path(path_lower).name
                    if fname in CRYPTO_DLLS:
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
                if (p.info.get("num_handles") or 0) if sys.platform == "win32" else 0 > 500:
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
                if ppid and ppid not in {0, 4} and ppid not in alive_pids:
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
                if (p.info.get("num_handles") or 0) if sys.platform == "win32" else 0 > 2000:
                    count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                self._errors_encountered += 1
        return float(count)

    def _check_defender_tampering(self) -> float:
        import sys
        if sys.platform != 'win32':
            return 0.0
            
        count = 0
        try:
            for service_name in DEFENDER_SERVICES:
                try:
                    svc = psutil.win_service_get(service_name)
                    status = svc.status()
                    if status not in ("running", "start_pending"):
                        log.warning("Security service '%s' NOT running: %s", service_name, status)
                        count += 1
                except psutil.NoSuchProcess:
                    log.warning("Security service '%s' not found", service_name)
                    count += 1
                except Exception:
                    pass
        except Exception as e:
            log.debug("Defender check unavailable: %s", e)
        return float(count)
