"""
SentinelML V2 — Controlled Ransomware-Behavior Simulator
=========================================================
Harmless, isolated simulation designed exclusively for educational
demonstrations and exhibition testing.

STRICT SAFETY CONSTRAINTS:
1. Operates exclusively inside an isolated, dedicated sandbox directory.
2. NEVER touches user directories (Desktop, Documents, Downloads), system files,
   startup locations, network shares, or external drives.
3. Every target path is strictly validated against path traversal (../) and symlink escapes.
4. Generates only synthetic test data (dummy text, pseudorandom byte streams).
5. Does NOT execute real malware, malicious binaries, or ransomware scripts.
6. Does NOT manipulate or force the ML model's prediction. The model evaluates
   what it genuinely observes.
7. Prominent cancellation support and safe, automated sandbox cleanup.
"""

import os
import time
import math
import shutil
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field

log = logging.getLogger("sentinel.exhibition.simulator")


class SecurityError(Exception):
    """Raised when an operation attempts to violate sandbox security boundaries."""
    pass


@dataclass
class SimulationEvent:
    """Represents a single timestamped event during simulation."""
    timestamp: str
    phase: str
    action: str
    target_path: str
    details: str
    entropy: float = 0.0


@dataclass
class SimulationResult:
    """Summary of a completed or stopped simulation run."""
    run_id: str
    start_time: str
    end_time: str
    duration_seconds: float
    total_files_created: int
    total_files_modified: int
    total_files_renamed: int
    events: List[SimulationEvent] = field(default_factory=list)
    stopped_early: bool = False
    sandbox_root: str = ""
    avg_entropy_before: float = 0.0
    avg_entropy_after: float = 0.0
    error_message: str = ""


class SandboxSimulator:
    """
    Controlled, safe ransomware behavioral simulator operating strictly
    within a verified sandbox directory.
    """

    def __init__(self, sandbox_root: Optional[Path] = None):
        if sandbox_root is None:
            # Default to an isolated folder in the project root
            base_dir = Path(__file__).resolve().parent.parent
            self._sandbox_root = base_dir / "temp_sandbox"
        else:
            self._sandbox_root = sandbox_root.resolve()

        self._stop_requested = threading.Event()
        self._is_running = False
        self._events: List[SimulationEvent] = []
        self._lock = threading.Lock()

    @property
    def sandbox_root(self) -> Path:
        return self._sandbox_root

    @property
    def is_running(self) -> bool:
        return self._is_running

    def validate_path_safety(self, path: Path) -> Path:
        """
        Strictly verify that path resolves within the sandbox root.
        Prevents directory traversal attacks and symlink escapes.
        """
        resolved_sandbox = self._sandbox_root.resolve()
        resolved_path = path.resolve()

        try:
            # Python 3.9+ is_relative_to
            is_inside = resolved_path.is_relative_to(resolved_sandbox)
        except AttributeError:
            try:
                resolved_path.relative_to(resolved_sandbox)
                is_inside = True
            except ValueError:
                is_inside = False

        if not is_inside:
            raise SecurityError(
                f"SECURITY VIOLATION: Path '{path}' resolves outside sandbox '{resolved_sandbox}'!"
            )
        return resolved_path

    def stop(self) -> None:
        """Request immediate cessation of simulation."""
        log.info("Stop requested for SandboxSimulator")
        self._stop_requested.set()

    def reset_sandbox(self) -> int:
        """
        Safely purge all synthetic files from the sandbox root.
        Returns count of removed items.
        """
        count = 0
        with self._lock:
            resolved_sandbox = self._sandbox_root.resolve()
            if not resolved_sandbox.exists():
                return 0

            # Double check to ensure we are never deleting outside our dedicated folder
            if resolved_sandbox == Path.home().resolve() or resolved_sandbox == Path("C:\\").resolve():
                raise SecurityError("REFUSING TO CLEANUP: Target is a root or home directory!")

            log.info("Cleaning up sandbox directory: %s", resolved_sandbox)
            for item in list(resolved_sandbox.iterdir()):
                self.validate_path_safety(item)
                if item.is_file() or item.is_symlink():
                    item.unlink()
                    count += 1
                elif item.is_dir():
                    shutil.rmtree(item)
                    count += 1

            self._events.clear()
            log.info("Sandbox reset completed. %d items removed.", count)
            return count

    def get_events(self) -> List[SimulationEvent]:
        """Return a copy of all recorded simulation events."""
        with self._lock:
            return list(self._events)

    def _record_event(self, phase: str, action: str, target: Path, details: str, entropy: float = 0.0):
        evt = SimulationEvent(
            timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
            phase=phase,
            action=action,
            target_path=str(target.name),
            details=details,
            entropy=round(entropy, 3)
        )
        with self._lock:
            self._events.append(evt)
        log.debug("[%s] %s: %s (%s)", phase, action, target.name, details)

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """Compute Shannon entropy in bits per byte for given byte array."""
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

    def run_simulation(
        self,
        num_files: int = 30,
        delay_between_ops: float = 0.05,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> SimulationResult:
        """
        Execute controlled ransomware behavior simulation:
        1. Initialize sandbox
        2. Create synthetic documents (low entropy text)
        3. Simulate burst high-entropy file modifications (simulated encryption)
        4. Simulate rapid file renames with .locked_sim extension
        5. Create harmless educational recovery notice (READ_ME_RECOVERY_SIM.txt)
        """
        with self._lock:
            if self._is_running:
                raise RuntimeError("Simulation is already running!")
            self._is_running = True
            self._stop_requested.clear()
            self._events.clear()

        run_id = datetime.now().strftime("SIM_%Y%m%d_%H%M%S")
        start_ts = datetime.now().isoformat()
        t0 = time.time()

        created_files: List[Path] = []
        files_created = 0
        files_modified = 0
        files_renamed = 0
        entropies_before: List[float] = []
        entropies_after: List[float] = []
        stopped_early = False
        error_msg = ""

        try:
            # Phase 0: Ensure sandbox exists
            self._sandbox_root.mkdir(parents=True, exist_ok=True)
            self._record_event("SETUP", "INIT_SANDBOX", self._sandbox_root, "Created safe demonstration sandbox")

            # Phase 1: Populate synthetic benign documents
            if progress_callback:
                progress_callback("Generating synthetic test documents...", 0, num_files)

            extensions = [".txt", ".dat", ".docx_sim", ".csv_sim", ".log"]
            for i in range(num_files):
                if self._stop_requested.is_set():
                    stopped_early = True
                    break

                ext = extensions[i % len(extensions)]
                filename = f"synthetic_document_{i+1:03d}{ext}"
                target = self.validate_path_safety(self._sandbox_root / filename)

                # Low-entropy human-readable text
                content = (
                    f"--- SENTINELML SYNTHETIC BENIGN DOCUMENT #{i+1} ---\n"
                    f"Generated for educational demonstration at {datetime.now()}.\n"
                    f"Content: Standard plain text ASCII record simulating normal document storage.\n"
                    f"Record ID: {1000 + i} | Category: Exhibition Test Data | Department: QA\n"
                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt.\n"
                ).encode("utf-8")

                ent = self.calculate_shannon_entropy(content)
                entropies_before.append(ent)

                with open(target, "wb") as f:
                    f.write(content)

                created_files.append(target)
                files_created += 1
                self._record_event("GENERATE", "CREATE_FILE", target, f"Low-entropy plaintext ({len(content)} bytes)", ent)

                if progress_callback:
                    progress_callback(f"Created file {i+1}/{num_files}", i + 1, num_files)
                time.sleep(delay_between_ops * 0.5)

            # Phase 2: Simulated Burst Encryption (High-Entropy Content Replacement)
            if not stopped_early:
                if progress_callback:
                    progress_callback("Simulating burst high-entropy file modification...", 0, len(created_files))

                for i, target in enumerate(created_files):
                    if self._stop_requested.is_set():
                        stopped_early = True
                        break

                    self.validate_path_safety(target)
                    # Generate pseudorandom bytes (mimicking high-entropy ciphertext, entropy ~7.95)
                    random_payload = os.urandom(2048)
                    ent = self.calculate_shannon_entropy(random_payload)
                    entropies_after.append(ent)

                    with open(target, "wb") as f:
                        f.write(random_payload)

                    files_modified += 1
                    self._record_event(
                        "ENCRYPT_SIM",
                        "BURST_MODIFY",
                        target,
                        f"Overwritten with high-entropy bytes (entropy: {ent:.2f})",
                        ent
                    )

                    if progress_callback:
                        progress_callback(f"Modified file {i+1}/{len(created_files)}", i + 1, len(created_files))
                    time.sleep(delay_between_ops)

            # Phase 3: Simulated Ransomware File Renaming (.locked_sim)
            renamed_files: List[Path] = []
            if not stopped_early:
                if progress_callback:
                    progress_callback("Simulating bulk extension renaming...", 0, len(created_files))

                for i, target in enumerate(created_files):
                    if self._stop_requested.is_set():
                        stopped_early = True
                        break

                    self.validate_path_safety(target)
                    new_target = self.validate_path_safety(target.with_suffix(target.suffix + ".locked_sim"))
                    target.rename(new_target)
                    renamed_files.append(new_target)
                    files_renamed += 1

                    self._record_event(
                        "RENAME_SIM",
                        "APPEND_EXTENSION",
                        new_target,
                        f"Renamed {target.name} -> {new_target.name}"
                    )

                    if progress_callback:
                        progress_callback(f"Renamed file {i+1}/{len(created_files)}", i + 1, len(created_files))
                    time.sleep(delay_between_ops * 0.5)

            # Phase 4: Create harmless educational note
            if not stopped_early:
                note_path = self.validate_path_safety(self._sandbox_root / "READ_ME_RECOVERY_SIM.txt")
                note_content = (
                    "========================================================================\n"
                    "         SENTINELML V2 — CONTROLLED SIMULATION DEMONSTRATION NOTICE      \n"
                    "========================================================================\n"
                    "THIS IS A HARMLESS EDUCATIONAL TEST PERFORMED WITHIN A DISPOSABLE SANDBOX.\n"
                    "NO REAL MALWARE WAS EXECUTED. NO PERSONAL USER FILES WERE MODIFIED.\n\n"
                    f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"Simulation Run: {run_id}\n"
                    f"Files Modified: {files_modified}\n"
                    f"Files Renamed: {files_renamed}\n"
                    "This test demonstrates high-volume file modification, high-entropy\n"
                    "generation, and rapid renaming patterns commonly observed in ransomware.\n"
                    "========================================================================\n"
                ).encode("utf-8")

                with open(note_path, "wb") as f:
                    f.write(note_content)

                self._record_event("NOTICE", "WRITE_RANSOM_NOTE", note_path, "Created harmless educational notice")

        except Exception as e:
            log.error("Simulation failed with exception: %s", e, exc_info=True)
            error_msg = str(e)
        finally:
            with self._lock:
                self._is_running = False

        duration = time.time() - t0
        avg_before = sum(entropies_before) / max(1, len(entropies_before))
        avg_after = sum(entropies_after) / max(1, len(entropies_after))

        res = SimulationResult(
            run_id=run_id,
            start_time=start_ts,
            end_time=datetime.now().isoformat(),
            duration_seconds=round(duration, 3),
            total_files_created=files_created,
            total_files_modified=files_modified,
            total_files_renamed=files_renamed,
            events=self.get_events(),
            stopped_early=stopped_early,
            sandbox_root=str(self._sandbox_root),
            avg_entropy_before=round(avg_before, 3),
            avg_entropy_after=round(avg_after, 3),
            error_message=error_msg
        )
        log.info(
            "Simulation '%s' finished in %.2fs (stopped_early=%s, created=%d, mod=%d, ren=%d)",
            run_id, duration, stopped_early, files_created, files_modified, files_renamed
        )
        return res
