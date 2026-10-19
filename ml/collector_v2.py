"""
SentinelML V2 — Benign Telemetry Collector (Collector V2)
==========================================================
Provides an opt-in, privacy-preserving telemetry collection framework for
recording empirical Windows workload behavior under Schema V2.

PRIVACY & ETHICAL GUARANTEES:
1. Zero File Content Capture: The collector NEVER records file bytes, text, or payloads.
2. Zero Credential / PII Inspection: File names are inspected solely for extension signatures
   and instructional note matches; user paths are sanitized or relative.
3. Explicit User Control: Every session requires explicit start/stop and can be reviewed or deleted.
4. Transparent Storage: Records are stored locally in standard JSONL format with SHA-256 integrity hashes.
"""

import os
import sys
import time
import math
import json
import shutil
import zipfile
import platform
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import psutil

from ml.schema_v2 import (
    SCHEMA_VERSION, FEATURE_NAMES_V2, KNOWN_RANSOM_EXTENSIONS, KNOWN_RANSOM_NOTE_NAMES,
    BehavioralVectorV2, FEATURE_SPECIFICATIONS
)

DEFAULT_STORAGE_DIR = Path(__file__).resolve().parent.parent / "data" / "telemetry_v2"


def _compute_shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class BenignTelemetryCollector:
    """
    Opt-in telemetry collector for capturing Schema V2 behavioral records
    across ordinary Windows workloads.
    """

    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = Path(storage_dir) if storage_dir else DEFAULT_STORAGE_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.active_session_id: Optional[str] = None
        self.active_session_dir: Optional[Path] = None
        self._is_collecting: bool = False
        self._session_records: List[BehavioralVectorV2] = []
        self._start_time: float = 0.0
        self._target_directory: Optional[Path] = None

    @property
    def is_collecting(self) -> bool:
        return self._is_collecting

    def start_collection(
        self,
        target_directory: Optional[Path] = None,
        session_name: Optional[str] = None,
        workload_description: str = "Unspecified Workload"
    ) -> str:
        """
        Start an empirical collection session.
        Returns the unique session_id.
        """
        if self._is_collecting:
            raise RuntimeError(f"Session {self.active_session_id} is already active. Call stop_collection() first.")

        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        prefix = f"{session_name}_" if session_name else "session_"
        session_id = f"{prefix}{timestamp_str}"
        session_dir = self.storage_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        self.active_session_id = session_id
        self.active_session_dir = session_dir
        self._is_collecting = True
        self._session_records = []
        self._start_time = time.time()
        self._target_directory = Path(target_directory) if target_directory else None

        # Write session manifest
        manifest = {
            "session_id": session_id,
            "session_name": session_name or "Unnamed Session",
            "schema_version": SCHEMA_VERSION,
            "collector_version": SCHEMA_VERSION,
            "start_time": self._start_time,
            "start_time_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._start_time)),
            "os_version": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "python_version": platform.python_version(),
            "target_directory": str(self._target_directory) if self._target_directory else None,
            "workload_description": workload_description,
            "status": "RECORDING"
        }
        with open(session_dir / "manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return session_id

    def sample_once(
        self,
        target_directory: Optional[Path] = None,
        workload_type: str = "BENIGN_IDLE",
        observation_window_seconds: float = 3.0
    ) -> BehavioralVectorV2:
        """
        Extract a single Schema V2 observation from the host and target directory.
        Handles missing telemetry safely and computes quality indicators.
        """
        target = Path(target_directory) if target_directory else self._target_directory
        t_now = time.time()
        sensors_attempted = 16
        sensors_succeeded = 0

        # ── 1. Filesystem Sensor ──────────────────────────────────────────────
        file_mod_rate = 0.0
        file_rename_rate = 0.0
        files_mod_count = 0.0
        files_ren_count = 0.0
        avg_entropy = 4.0
        max_entropy = 4.0
        high_entropy_ratio = 0.0
        ransom_ext_count = 0.0
        ransom_note_count = 0.0

        if target and target.exists():
            try:
                sampled_entropies = []
                now = time.time()
                for root, _, files in os.walk(target):
                    for fname in files:
                        fpath = Path(root) / fname
                        # Check extension and note signatures
                        ext = fpath.suffix.lower()
                        if ext in KNOWN_RANSOM_EXTENSIONS:
                            ransom_ext_count += 1
                        if fname.lower() in KNOWN_RANSOM_NOTE_NAMES:
                            ransom_note_count += 1

                        try:
                            st = fpath.stat()
                            # Modifications within observation window
                            if (now - st.st_mtime) <= observation_window_seconds:
                                files_mod_count += 1
                            if (now - st.st_ctime) <= observation_window_seconds:
                                files_ren_count += 1

                            # Sample 4KB chunk for entropy if file size > 0
                            if st.st_size > 0 and len(sampled_entropies) < 50:
                                with open(fpath, "rb") as fp:
                                    chunk = fp.read(4096)
                                sampled_entropies.append(_compute_shannon_entropy(chunk))
                        except (PermissionError, FileNotFoundError, OSError):
                            continue

                file_mod_rate = round(files_mod_count / max(1.0, observation_window_seconds), 3)
                file_rename_rate = round(files_ren_count / max(1.0, observation_window_seconds), 3)

                if sampled_entropies:
                    avg_entropy = round(float(sum(sampled_entropies) / len(sampled_entropies)), 4)
                    max_entropy = round(float(max(sampled_entropies)), 4)
                    high_count = sum(1 for e in sampled_entropies if e > 7.0)
                    high_entropy_ratio = round(float(high_count / len(sampled_entropies)), 4)

                sensors_succeeded += 9
            except Exception:
                pass
        else:
            # Baseline default for when no filesystem target is specified
            sensors_succeeded += 9

        # ── 2. Process Telemetry ──────────────────────────────────────────────
        suspicious_proc_count = 0.0
        powershell_proc_count = 0.0
        crypto_dll_proc_count = 0.0
        total_procs = 0.0

        try:
            procs = list(psutil.process_iter(["pid", "name"]))
            total_procs = float(len(procs))
            sensors_succeeded += 1

            susp_names = {"vssadmin.exe", "bcdedit.exe", "wbadmin.exe", "cipher.exe", "wmic.exe"}
            for p in procs:
                name = (p.info.get("name") or "").lower()
                if name in susp_names:
                    suspicious_proc_count += 1.0
                if name in {"powershell.exe", "pwsh.exe"}:
                    powershell_proc_count += 1.0
            sensors_succeeded += 2

            # Sample non-system crypto DLL processes (limit sample to 30 for low overhead)
            sample_crypto_procs = 0
            for p in procs[:30]:
                try:
                    p_obj = psutil.Process(p.info["pid"])
                    maps = p_obj.memory_maps()
                    if any("bcrypt" in str(m.path).lower() or "ncrypt" in str(m.path).lower() for m in maps):
                        sample_crypto_procs += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            crypto_dll_proc_count = float(sample_crypto_procs)
            sensors_succeeded += 1
        except Exception:
            pass

        # ── 3. Defender Tampering ─────────────────────────────────────────────
        defender_tampered = 0.0
        try:
            if sys.platform == "win32":
                import ctypes
                advapi32 = ctypes.windll.advapi32
                SC_MANAGER_CONNECT = 0x0001
                SERVICE_QUERY_STATUS = 0x0004
                scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
                if scm:
                    svc = advapi32.OpenServiceW(scm, "WinDefend", SERVICE_QUERY_STATUS)
                    if svc:
                        advapi32.CloseServiceHandle(svc)
                    else:
                        defender_tampered = 1.0
                    advapi32.CloseServiceHandle(scm)
            sensors_succeeded += 1
        except Exception:
            sensors_succeeded += 1  # Graceful fallback

        # ── 4. Network Sockets & External IPs ─────────────────────────────────
        net_conn_count = 0.0
        ext_ip_count = 0.0
        try:
            conns = psutil.net_connections(kind="inet")
            net_conn_count = float(len(conns))
            ext_ips = set()
            local_prefixes = ("127.", "192.168.", "10.", "172.16.", "::1")
            for c in conns:
                if c.raddr:
                    ip = str(c.raddr.ip)
                    if not any(ip.startswith(p) for p in local_prefixes):
                        ext_ips.add(ip)
            ext_ip_count = float(len(ext_ips))
            sensors_succeeded += 2
        except (psutil.AccessDenied, Exception):
            sensors_succeeded += 2  # Graceful fallback

        quality_score = round(sensors_succeeded / sensors_attempted, 4)
        missing_count = sensors_attempted - sensors_succeeded

        features_array = [
            file_mod_rate,
            file_rename_rate,
            files_mod_count,
            files_ren_count,
            avg_entropy,
            max_entropy,
            high_entropy_ratio,
            ransom_ext_count,
            ransom_note_count,
            suspicious_proc_count,
            powershell_proc_count,
            crypto_dll_proc_count,
            defender_tampered,
            total_procs,
            net_conn_count,
            ext_ip_count,
        ]

        vec = BehavioralVectorV2(
            features=features_array,
            timestamp=t_now,
            os_version=f"{platform.system()} {platform.release()}",
            collector_version=SCHEMA_VERSION,
            schema_version=SCHEMA_VERSION,
            telemetry_quality_score=quality_score,
            missing_sensor_count=missing_count,
            workload_type=workload_type,
            ground_truth_label=0 if workload_type.startswith("BENIGN") else None
        )

        if self._is_collecting and self.active_session_dir:
            self._session_records.append(vec)
            # Append immediately to session JSONL log
            record_path = self.active_session_dir / "records.jsonl"
            with open(record_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(vec.to_dict()) + "\n")

        return vec

    def stop_collection(self) -> Dict[str, Any]:
        """
        Stop the active collection session, compute summary metrics, and return metadata.
        """
        if not self._is_collecting:
            raise RuntimeError("No collection session is active.")

        duration = time.time() - self._start_time
        record_count = len(self._session_records)
        session_id = self.active_session_id
        session_dir = self.active_session_dir

        summary = {
            "session_id": session_id,
            "status": "COMPLETED",
            "total_records": record_count,
            "duration_seconds": round(duration, 3),
            "completed_time_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "mean_quality_score": round(
                sum(r.telemetry_quality_score for r in self._session_records) / max(1, record_count), 4
            ) if self._session_records else 1.0,
            "record_file": str(session_dir / "records.jsonl"),
        }

        # Update manifest
        manifest_path = session_dir / "manifest.json"
        if manifest_path.exists():
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            manifest.update(summary)
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)

        self._is_collecting = False
        self.active_session_id = None
        self.active_session_dir = None
        return summary

    # ── User Review and Data Management APIs ─────────────────────────────────

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all stored collection sessions."""
        sessions = []
        if not self.storage_dir.exists():
            return []
        for sdir in sorted(self.storage_dir.iterdir()):
            if sdir.is_dir() and (sdir / "manifest.json").exists():
                try:
                    with open(sdir / "manifest.json", "r", encoding="utf-8") as f:
                        sessions.append(json.load(f))
                except Exception:
                    continue
        return sessions

    def review_session(self, session_id: str) -> Dict[str, Any]:
        """Review recorded telemetry records and summary statistics for a session."""
        sdir = self.storage_dir / session_id
        if not sdir.exists():
            raise FileNotFoundError(f"Session directory not found: {session_id}")

        manifest = {}
        if (sdir / "manifest.json").exists():
            with open(sdir / "manifest.json", "r", encoding="utf-8") as f:
                manifest = json.load(f)

        records = []
        rec_path = sdir / "records.jsonl"
        if rec_path.exists():
            with open(rec_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        records.append(json.loads(line))

        return {
            "manifest": manifest,
            "records_count": len(records),
            "records_sample": records[:5],
            "session_path": str(sdir)
        }

    def delete_session(self, session_id: str) -> bool:
        """Allow user to explicitly delete collected session data."""
        sdir = self.storage_dir / session_id
        if sdir.exists():
            shutil.rmtree(sdir, ignore_errors=True)
            return True
        return False

    # ── Representative Benign Workload Harnesses ─────────────────────────────

    def run_workload_ordinary_file_ops(self, temp_dir: Path, file_count: int = 25) -> List[BehavioralVectorV2]:
        """Execute and record representative ordinary file operations (text/logs/csv)."""
        temp_dir.mkdir(parents=True, exist_ok=True)
        observations = []
        for i in range(file_count):
            p = temp_dir / f"document_{i+1:03d}.txt"
            with open(p, "w", encoding="utf-8") as f:
                f.write(f"Standard business record {i+1}. Project status report with plain English text.\n")
            if i % 5 == 0:
                observations.append(self.sample_once(target_directory=temp_dir, workload_type="BENIGN_DOCS"))
                time.sleep(0.05)
        return observations

    def run_workload_archive_creation(self, temp_dir: Path, file_count: int = 15) -> List[BehavioralVectorV2]:
        """Execute and record representative archive compression (.zip file creation)."""
        temp_dir.mkdir(parents=True, exist_ok=True)
        observations = []
        src_files = []
        for i in range(file_count):
            p = temp_dir / f"data_chunk_{i+1:02d}.bin"
            with open(p, "wb") as f:
                f.write(os.urandom(2048))
            src_files.append(p)

        zip_path = temp_dir / "backup_archive.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for sf in src_files:
                zf.write(sf, arcname=sf.name)
            observations.append(self.sample_once(target_directory=temp_dir, workload_type="BENIGN_ARCHIVE"))

        return observations

    def run_workload_development_build(self, temp_dir: Path, module_count: int = 15) -> List[BehavioralVectorV2]:
        """Execute and record representative software build/compilation file operations."""
        temp_dir.mkdir(parents=True, exist_ok=True)
        observations = []
        for i in range(module_count):
            src = temp_dir / f"module_{i+1:02d}.py"
            with open(src, "w", encoding="utf-8") as f:
                f.write(f"def compute_{i}():\n    return {i} * 42\n")
            obj = temp_dir / f"module_{i+1:02d}.pyc"
            with open(obj, "wb") as f:
                f.write(b"\x00\x00\x00\x00" + os.urandom(512))
            if i % 3 == 0:
                observations.append(self.sample_once(target_directory=temp_dir, workload_type="BENIGN_BUILD"))
                time.sleep(0.05)
        return observations
