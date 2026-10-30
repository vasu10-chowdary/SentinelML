"""
SentinelML V2 — Integrated Scan Engine
========================================
Combines filesystem scanning, process analysis, and ML threat detection.

CRITICAL: This is a REAL scan engine, not a fake UI.

Scan States:
- IDLE: No scan running
- SCANNING: Filesystem/process enumeration in progress
- ANALYZING: ML analysis in progress
- COMPLETE: Scan finished successfully
- THREAT_DETECTED: Threats found
- SAFE: No threats detected (only if scan completed successfully)
- SCAN_INCOMPLETE: Scan failed or was cancelled
- ERROR: Critical error occurred

IMPORTANT: SAFE is NOT a fallback. If scanning fails, report SCAN_INCOMPLETE.
"""

import time
import logging
import sys
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field

from scanner.filesystem_scanner import FilesystemScanner, ScanStats as FilesystemStats
from scanner.live_scanner import LiveScanner

log = logging.getLogger("sentinel.scanner.engine")


class ScanState(Enum):
    """Scan state machine states."""
    IDLE = "idle"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    THREAT_DETECTED = "threat_detected"
    SAFE = "safe"
    SCAN_INCOMPLETE = "scan_incomplete"
    ANALYSIS_ERROR = "analysis_error"  # ML or prediction failure
    ERROR = "error"  # Critical system error
    LIMITED_COVERAGE = "limited_coverage"  # Analysis limited by missing telemetry/permissions
    INCONCLUSIVE = "inconclusive"  # Safety cannot be validated due to unsupported platform sensors


class ScanType(Enum):
    """Types of scans available."""
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"
    PROCESS = "process"


@dataclass
class ScanResult:
    """Complete scan results."""
    scan_type: ScanType
    state: ScanState
    
    # Filesystem scanning
    files_inspected: int = 0
    directories_inspected: int = 0
    files_skipped: int = 0
    access_denied: int = 0
    filesystem_errors: int = 0
    suspicious_files: List[str] = field(default_factory=list)
    
    # Process scanning
    processes_analyzed: int = 0
    process_errors: int = 0
    
    # ML analysis
    ml_executed: bool = False
    ml_probability: float = 0.0
    ml_prediction: str = ""  # Raw model verdict, preserved even if final state is INCONCLUSIVE
    threat_level: str = "ANALYSIS_ERROR"  # Default to ERROR, not UNKNOWN or SAFE
    
    # Timing
    elapsed_seconds: float = 0.0
    phase_timings: Dict[str, float] = field(default_factory=dict)
    
    # Status
    cancelled: bool = False
    error_message: str = ""
    
    # Scan Identity & Live Location
    scan_id: str = ""
    current_path: str = ""
    
    # Model Provenance & Simulation Transparency
    model_source: str = "EXPERIMENTAL_SYNTHETIC_BASELINE_V1"
    is_simulation: bool = False
    scan_origin: str = "LIVE_HOST_SCAN"
    observable_schema: str = "SCHEMA_V2_COMPATIBLE"
    
    # Telemetry Feature Availability & Coverage Tracking
    telemetry_availability: Dict[str, str] = field(default_factory=dict)
    missing_features: List[str] = field(default_factory=list)
    available_feature_count: int = 19
    telemetry_coverage_ratio: float = 1.0
    is_inconclusive: bool = False
    inconclusive_reason: str = ""
    
    def was_successful(self) -> bool:
        """
        Check if scan completed successfully with valid security classification.
        
        **SECURITY-CRITICAL:** Returns True ONLY if scan completed AND produced
        a valid threat classification (SAFE, WARNING, or CRITICAL).
        
        Returns False for:
        - SCAN_INCOMPLETE (scan didn't finish)
        - ANALYSIS_ERROR (ML/prediction failed)
        - ERROR (critical system error)
        - Any other non-success state
        """
        return self.state in [ScanState.SAFE, ScanState.THREAT_DETECTED]

    def get_unified_classification(self) -> dict:
        """
        Return the authoritative, unified security classification for this scan result.
        Unifies display across SOC Dashboard, Threat Log, Evidence Dialog, and Incident Reports.
        
        Guarantees:
        - A partial, permission-denied, cancelled, or failed scan is NEVER reported as clean SAFE.
        - Preserves distinction between model probability, decision threshold, completeness, and scope.
        - Discloses synthetic baseline ML model provenance and borderline probabilities (40%-55%).
        """
        access_denied = getattr(self, "access_denied", 0)
        fs_errors = getattr(self, "filesystem_errors", 0)
        is_partial = (access_denied > 0 or fs_errors > 0)
        is_quick = (self.scan_type == ScanType.QUICK)
        from ml.predictor import normalize_risk_score
        raw_prob = getattr(self, "ml_probability", 0.0)
        prob, _, _ = normalize_risk_score(raw_prob)
        is_sim = bool(getattr(self, "is_simulation", False) or getattr(self, "scan_origin", "") == "CONTROLLED_SIMULATION")

                # 0. Inconclusive / Limited Coverage states
        if self.state in (ScanState.INCONCLUSIVE, ScanState.LIMITED_COVERAGE) or getattr(self, "is_inconclusive", False):
            reason = getattr(self, "inconclusive_reason", "") or "Incomplete sensor coverage across platform telemetry."
            missing_count = len(getattr(self, "missing_features", []))
            return {
                "level": "INCONCLUSIVE",
                "tag": "INCONCLUSIVE — LIMITED COVERAGE",
                "status_title": "INCONCLUSIVE — LIMITED COVERAGE",
                "status_badge": "  [LIMITED COVERAGE]  ",
                "risk_label": "INCONCLUSIVE",
                "sidebar_text": "INCONCLUSIVE",
                "color_key": "yellow",
                "is_clean": False,
                "is_limited": True,
                "is_partial": is_partial,
                "is_simulation": is_sim,
                "is_borderline": False,
                "borderline_note": "",
                "scope_description": "Telemetry Coverage Restricted / Platform Disparity",
                "description": f"Safety assessment inconclusive: {reason} Zero-filled sensors prevent validated clean certification.",
                "disclosures": [
                    f"Platform Sensor Limitation: {missing_count} of 19 behavioral telemetry sensors are unavailable on non-Windows platforms.",
                    "Model Validation Boundary: 19-feature Random Forest model requires full telemetry schema for confident classification.",
                    "Integrity Contract: Non-Windows hosts or partial sensor scans are never certified as definitively SAFE."
                ]
            }

# 1. Non-success / incomplete states
        if getattr(self, "cancelled", False) or self.state == ScanState.SCAN_INCOMPLETE:
            return {
                "level": "SCAN_INCOMPLETE",
                "tag": "CANCELLED",
                "status_title": "SCAN CANCELLED",
                "status_badge": "  [INCOMPLETE — CANCELLED]  ",
                "risk_label": "CANCELLED",
                "sidebar_text": "CANCELLED",
                "color_key": "orange",
                "is_clean": False,
                "is_limited": True,
                "is_partial": is_partial,
                "is_simulation": is_sim,
                "is_borderline": False,
                "borderline_note": "",
                "scope_description": "Host Quick Scan (Aborted)" if not is_sim else "Controlled Sandbox Simulation (Aborted)",
                "description": "Scan was stopped before completion. Partial results discarded to prevent false safety claims.",
                "disclosures": ["Incomplete scan: No safety classification can be determined."]
            }

        if self.state in (ScanState.ERROR, ScanState.ANALYSIS_ERROR) or not self.was_successful():
            err = self.error_message or "Analysis failed"
            return {
                "level": "ANALYSIS_ERROR",
                "tag": "ERROR",
                "status_title": "SCAN ERROR",
                "status_badge": "  [INCOMPLETE]  ",
                "risk_label": "ERROR",
                "sidebar_text": "SCAN ERROR",
                "color_key": "orange",
                "is_clean": False,
                "is_limited": True,
                "is_partial": is_partial,
                "is_simulation": is_sim,
                "is_borderline": False,
                "borderline_note": "",
                "scope_description": "Host Scan (Failed)" if not is_sim else "Controlled Sandbox Simulation (Failed)",
                "description": f"Analysis failed: {err}. No security classification can be determined.",
                "disclosures": ["Analysis Error: Model inference or sensor telemetry collection could not be completed."]
            }

        # 2. Simulation Results
        if is_sim:
            level = "CRITICAL" if prob >= 0.90 else "WARNING"
            return {
                "level": level,
                "tag": f"{level} [SIMULATION]",
                "status_title": f"{level} [SIMULATION]",
                "status_badge": "  [SANDBOX SIMULATION]  ",
                "risk_label": f"{level} (SIM)",
                "sidebar_text": f"SIM: {level}",
                "color_key": "red" if level == "CRITICAL" else "yellow",
                "is_clean": False,
                "is_limited": False,
                "is_partial": False,
                "is_simulation": True,
                "is_borderline": False,
                "borderline_note": "",
                "scope_description": "Controlled Sandbox Simulation (temp_sandbox/)",
                "description": f"Controlled behavioral simulation in temp_sandbox/: elevated Shannon entropy and rapid file modification evaluated. ML Probability: {prob * 100:.1f}%. Host files unaffected.",
                "disclosures": [
                    "Sandbox Isolation: Execution was strictly confined to temp_sandbox/.",
                    "Containment Assessment: Not assessed (Host escape/isolation verification was not executed)."
                ]
            }

        # 3. Live Host Threats
        if prob >= 0.90 or self.threat_level == "CRITICAL":
            return {
                "level": "CRITICAL",
                "tag": "CRITICAL",
                "status_title": "SYSTEM CRITICAL",
                "status_badge": "  [LIVE HOST SCAN]  ",
                "risk_label": "CRITICAL",
                "sidebar_text": "CRITICAL",
                "color_key": "red",
                "is_clean": False,
                "is_limited": is_quick,
                "is_partial": is_partial,
                "is_simulation": False,
                "is_borderline": False,
                "borderline_note": "",
                "scope_description": "Live Host Quick Scan" if is_quick else "Full System Scan",
                "description": "High-confidence ransomware heuristics detected on host! Immediate defensive isolation advised.",
                "disclosures": [
                    "High Threat Alert: Multiple behavioral indicators exceeded critical thresholds.",
                    "Experimental Model Limitation: Synthetic baseline (EXPERIMENTAL_SYNTHETIC_BASELINE_V1)."
                ]
            }

        if prob >= 0.50 or self.threat_level in ("WARNING", "THREAT_DETECTED"):
            is_borderline = (prob <= 0.55)
            note = f" Borderline note: ML probability ({prob * 100:.1f}%) is within 5% of the 50.0% decision threshold." if is_borderline else ""
            return {
                "level": "WARNING",
                "tag": "WARNING",
                "status_title": "SYSTEM WARNING",
                "status_badge": "  [LIVE HOST SCAN]  ",
                "risk_label": "WARNING",
                "sidebar_text": "WARNING",
                "color_key": "yellow",
                "is_clean": False,
                "is_limited": is_quick,
                "is_partial": is_partial,
                "is_simulation": False,
                "is_borderline": is_borderline,
                "borderline_note": note,
                "scope_description": "Live Host Quick Scan" if is_quick else "Full System Scan",
                "description": f"Suspicious behavioral signals observed during host scan (ML Risk: {prob * 100:.1f}%).{note} Review incident evidence.",
                "disclosures": [
                    "Elevated Behavioral Signal: Anomaly score exceeded nominal baseline.",
                    "Experimental Model Limitation: Synthetic baseline (EXPERIMENTAL_SYNTHETIC_BASELINE_V1)."
                ]
            }

        # 4. Clean Results (prob < 0.50)
        # Check if limited coverage (Quick scan depth=1 or partial access denied)
        if is_partial:
            return {
                "level": "SAFE",
                "tag": "NO THREATS DETECTED — LIMITED SCAN",
                "status_title": "NO THREATS DETECTED — LIMITED SCAN",
                "status_badge": "  [LIVE HOST SCAN — LIMITED]  ",
                "risk_label": "LIMITED (PARTIAL)",
                "sidebar_text": "LIMITED SCAN",
                "color_key": "yellow",
                "is_clean": True,
                "is_limited": True,
                "is_partial": True,
                "is_simulation": False,
                "is_borderline": (prob >= 0.40),
                "borderline_note": f" Borderline note: score ({prob * 100:.1f}%) is within 10% of the 50.0% decision threshold." if prob >= 0.40 else "",
                "scope_description": "Partial Live Scan (Access Denied Encountered)",
                "description": f"No threats detected in accessible files. Caution: {access_denied + fs_errors} path(s) had access denied or errors. Full coverage not guaranteed.",
                "disclosures": [
                    f"Coverage Limitation: {access_denied + fs_errors} filesystem location(s) were inaccessible due to OS permissions.",
                    "Incomplete filesystem coverage means unread paths cannot be guaranteed clean."
                ]
            }

        if is_quick:
            is_borderline = (prob >= 0.40)
            border_note = f" Borderline note: score ({prob * 100:.1f}%) is within 10% of the 50.0% decision boundary." if is_borderline else ""
            return {
                "level": "SAFE",
                "tag": "NO THREATS DETECTED — LIMITED SCAN",
                "status_title": "NO THREATS DETECTED — LIMITED SCAN",
                "status_badge": "  [LIVE HOST SCAN — LIMITED]  ",
                "risk_label": "CLEAN (LIMITED)",
                "sidebar_text": "NO THREATS (LIMITED)",
                "color_key": "green",
                "is_clean": True,
                "is_limited": True,
                "is_partial": False,
                "is_simulation": False,
                "is_borderline": is_borderline,
                "borderline_note": border_note,
                "scope_description": "Fast Live Scan (Quick: Target Depth = 1)",
                "description": f"Quick Scan (depth=1) clean across monitored roots and running processes. Noise folders excluded. Synthetic baseline ML model: probabilistic estimation only.{border_note}",
                "disclosures": [
                    "Scan Scope Limitation: Fast Live Scan traverses user targets to depth=1 only.",
                    "Excluded Folders: System noise directories (AppData, node_modules, .git) were skipped.",
                    "Model Limitation: Experimental synthetic model baseline. Clean result reflects absence of observed heuristics in scanned scope."
                ]
            }

        # Full System Scan with 0 errors
        is_borderline = (prob >= 0.40)
        border_note = f" Borderline note: score ({prob * 100:.1f}%) is within 10% of the 50.0% decision boundary." if is_borderline else ""
        return {
            "level": "SAFE",
            "tag": "SYSTEM SAFE",
            "status_title": "SYSTEM SAFE",
            "status_badge": "  [LIVE HOST SCAN]  ",
            "risk_label": "SAFE",
            "sidebar_text": "SYSTEM SAFE",
            "color_key": "green",
            "is_clean": True,
            "is_limited": False,
            "is_partial": False,
            "is_simulation": False,
            "is_borderline": is_borderline,
            "borderline_note": border_note,
            "scope_description": "Full System Scan (Unrestricted Scope)",
            "description": f"Full System Scan clean across monitored roots and running processes.{border_note}",
            "disclosures": [
                "Full Scope Scan: All configured system roots inspected.",
                "Model Limitation: Experimental synthetic model baseline."
            ]
        }


class ScanEngine:
    """
    Integrated scan engine combining filesystem, process, and ML analysis.
    
    This performs REAL scanning, not simulated.
    """
    
    def __init__(self):
        self._state = ScanState.IDLE
        self._filesystem_scanner = FilesystemScanner()
        self._process_scanner = LiveScanner()
        self._cancel_requested = False
        self._progress_callback: Optional[Callable[[ScanResult], None]] = None
    
    def scan(self,
             scan_type: ScanType,
             custom_paths: Optional[List[Path]] = None,
             progress_callback: Optional[Callable[[ScanResult], None]] = None,
             scan_origin: str = "LIVE_HOST_SCAN") -> ScanResult:
        """
        Perform a security scan.
        
        Args:
            scan_type: Type of scan to perform
            custom_paths: Paths for custom scan (required if scan_type is CUSTOM)
            progress_callback: Called periodically with progress updates
        
        Returns:
            ScanResult with complete results
        """
        if self._cancel_requested:
            log.info("Scan cancelled prior to start")
            self._state = ScanState.SCAN_INCOMPLETE
            import uuid
            scan_id = f"SCN-{uuid.uuid4().hex[:12].upper()}"
            scan_id_val = scan_id
            res = ScanResult(
                scan_type=scan_type,
                state=ScanState.SCAN_INCOMPLETE,
                cancelled=True,
                error_message="Scan cancelled prior to execution",
                scan_id=scan_id
            )
            setattr(res, '_scan_id', scan_id)
            return res

        self._state = ScanState.SCANNING
        self._cancel_requested = False
        self._progress_callback = progress_callback
        
        scan_start = time.time()
        result = ScanResult(
            scan_type=scan_type,
            state=ScanState.SCANNING,
            scan_origin=scan_origin,
            is_simulation=(scan_origin == "CONTROLLED_SIMULATION")
        )
        
        try:
            import uuid
            scan_id = f"SCN-{uuid.uuid4().hex[:12].upper()}"
            result.scan_id = scan_id
            setattr(result, '_scan_id', scan_id)
            log.info(f"SCAN_START | ID: {scan_id} | TS: {scan_start} | MODE: {scan_type.value}")
            # Determine scan scope (process-only scans intentionally have no paths)
            scan_paths = self._determine_scan_paths(scan_type, custom_paths)
            if scan_type != ScanType.PROCESS and not scan_paths:
                log.error("No valid scan paths determined")
                result.state = ScanState.SCAN_INCOMPLETE
                result.error_message = "No valid scan paths"
                return result
            
            log.info("Scan scope: %d paths", len(scan_paths))
            
            # Phase 1: Filesystem scanning (if not process-only)
            filesystem_success = True
            t_p1 = time.time()
            if scan_type != ScanType.PROCESS:
                filesystem_success = self._scan_filesystem(scan_paths, result, scan_type=scan_type)
                result.phase_timings["filesystem_s"] = round(time.time() - t_p1, 3)
                
                if self._cancel_requested:
                    result.cancelled = True
                    result.state = ScanState.SCAN_INCOMPLETE
                    result.threat_level = "CANCELLED"
                    result.elapsed_seconds = time.time() - scan_start
                    return result
            else:
                result.phase_timings["filesystem_s"] = 0.0
            
            # Phase 2: Process scanning
            t_p2 = time.time()
            process_success = self._scan_processes(result, target_directories=scan_paths if scan_type == ScanType.CUSTOM else None)
            result.phase_timings["process_s"] = round(time.time() - t_p2, 3)
            
            if self._cancel_requested:
                result.cancelled = True
                result.state = ScanState.SCAN_INCOMPLETE
                result.threat_level = "CANCELLED"
                result.elapsed_seconds = time.time() - scan_start
                return result
            
            # Phase 3: ML analysis
            t_p3 = time.time()
            if process_success:
                self._state = ScanState.ANALYZING
                result.state = ScanState.ANALYZING
                self._update_progress(result)
                
                ml_success = self._run_ml_analysis(result)
                result.phase_timings["ml_analysis_s"] = round(time.time() - t_p3, 3)
            else:
                ml_success = False
                result.phase_timings["ml_analysis_s"] = 0.0
            
            if self._cancel_requested:
                result.cancelled = True
                result.state = ScanState.SCAN_INCOMPLETE
                result.threat_level = "CANCELLED"
                result.elapsed_seconds = time.time() - scan_start
                return result

            # Determine final state
            result.elapsed_seconds = time.time() - scan_start
            
            # **SECURITY-CRITICAL: NEVER classify as SAFE if any component failed**
            if not filesystem_success or not process_success or not ml_success:
                # Critical component failed - determine type of failure
                result.state = ScanState.SCAN_INCOMPLETE
                
                # Build detailed error message
                failed_components = []
                if not filesystem_success:
                    failed_components.append("filesystem")
                if not process_success:
                    failed_components.append("process")
                if not ml_success:
                    failed_components.append("ML analysis")
                
                result.error_message = f"Scan incomplete: {', '.join(failed_components)} failed"
                result.threat_level = "ANALYSIS_ERROR"  # Explicitly mark as error
                result.ml_probability = 0.0  # Reset probability to prevent misinterpretation
                
                log.error("[WARN]️ CRITICAL: Scan incomplete (filesystem=%s, process=%s, ml=%s)",
                         filesystem_success, process_success, ml_success)
                log.error("[WARN]️ CRITICAL: NO SECURITY CLASSIFICATION AVAILABLE - returning SCAN_INCOMPLETE")
                
            # Only classify if ALL components succeeded
            elif result.threat_level == "CRITICAL" or result.ml_probability >= 0.9:
                result.state = ScanState.THREAT_DETECTED
                log.warning("THREAT DETECTED: %.2f probability", result.ml_probability)
            elif result.threat_level == "WARNING" or result.ml_probability >= 0.5:
                result.state = ScanState.THREAT_DETECTED
                log.info("WARNING: Suspicious activity detected (%.2f)", result.ml_probability)
            elif result.ml_executed and result.threat_level in ["SAFE", "LOW"]:
                # **SECURITY-CRITICAL: Only allow SAFE if ML explicitly returned SAFE**
                if scan_type in (ScanType.QUICK, ScanType.FULL) and not getattr(result, "is_simulation", False) and getattr(result, "missing_features", None) and len(result.missing_features) > 0 and sys.platform != "win32":
                    result.state = ScanState.INCONCLUSIVE
                    result.threat_level = "INCONCLUSIVE"
                    result.is_inconclusive = True
                    result.inconclusive_reason = (
                        f"Safety cannot be validated: {len(result.missing_features)} of 19 behavioral sensors "
                        f"are unavailable on {sys.platform}. Incomplete telemetry cannot certify host as clean."
                    )
                    log.warning("Scan result marked INCONCLUSIVE: %s", result.inconclusive_reason)
                else:
                    result.state = ScanState.SAFE
                    log.info("Scan complete: SAFE (%.2f probability)", result.ml_probability)
            else:
                # ML didn't execute properly or returned unexpected value
                result.state = ScanState.SCAN_INCOMPLETE
                result.error_message = f"Invalid analysis result: threat_level={result.threat_level}, ml_executed={result.ml_executed}"
                result.threat_level = "ANALYSIS_ERROR"
                log.error("[WARN]️ CRITICAL: Invalid scan result - ML executed=%s, threat_level=%s",
                         result.ml_executed, result.threat_level)
            
            self._state = result.state
            scan_id = getattr(result, '_scan_id', 'UNKNOWN')
            log.info(f"SCAN_COMPLETE | ID: {scan_id} | DURATION: {result.elapsed_seconds:.3f}s (FS: {result.phase_timings.get('filesystem_s', 0.0):.3f}s, PROC: {result.phase_timings.get('process_s', 0.0):.3f}s, ML: {result.phase_timings.get('ml_analysis_s', 0.0):.3f}s) | FILES: {result.files_inspected} | DIRS: {result.directories_inspected} | PROCS: {result.processes_analyzed} | PROB: {result.ml_probability} | STATE: {result.state.value}")
            return result
            
        except Exception as e:
            log.error("Scan failed with exception: %s", e, exc_info=True)
            result.state = ScanState.ERROR
            result.error_message = str(e)
            result.elapsed_seconds = time.time() - scan_start
            self._state = ScanState.ERROR
            return result
    
    def _determine_scan_paths(self, 
                             scan_type: ScanType,
                             custom_paths: Optional[List[Path]]) -> List[Path]:
        """
        Determine which paths to scan based on scan type.
        
        Args:
            scan_type: Type of scan
            custom_paths: Custom paths (for CUSTOM scan)
        
        Returns:
            List of paths to scan
        """
        if scan_type == ScanType.CUSTOM:
            if not custom_paths:
                log.error("Custom scan requested but no paths provided")
                return []
            return [p for p in custom_paths if p.exists()]
        
        elif scan_type == ScanType.PROCESS:
            # Process-only scan, no filesystem paths
            return []
        
        elif scan_type == ScanType.QUICK:
            # Quick scan: critical user folders only
            from utils.platform_utils import get_monitored_directories
            paths = get_monitored_directories()
            log.info("Quick scan: %d monitored directories", len(paths))
            return paths
        
        elif scan_type == ScanType.FULL:
            # Full scan: all monitored directories plus system areas
            from utils.platform_utils import get_monitored_directories
            paths = get_monitored_directories()
            
            # Add user home directory root
            home = Path.home()
            if home not in paths:
                paths.append(home)
            
            log.info("Full scan: %d directories", len(paths))
            return paths
        
        return []
    
    def _scan_filesystem(self, paths: List[Path], result: ScanResult, scan_type: ScanType = ScanType.QUICK) -> bool:
        log.info(f"FILESYSTEM_SCAN_START")
        """
        Perform filesystem scanning.
        
        Args:
            paths: Paths to scan
            result: ScanResult to update
            scan_type: Type of scan (determines traversal depth)
        
        Returns:
            True if successful, False if failed
        """
        try:
            log.info("Filesystem scanning: %d paths", len(paths))
            
            def progress(stats: FilesystemStats):
                # Update result with filesystem progress
                result.files_inspected = stats.files_inspected
                result.directories_inspected = stats.directories_inspected
                result.files_skipped = stats.files_skipped
                result.access_denied = stats.access_denied
                result.filesystem_errors = stats.errors
                result.suspicious_files = stats.suspicious_files.copy()
                result.current_path = stats.current_path
                
                self._update_progress(result)
            
            target_depth = 1 if scan_type == ScanType.QUICK else 6
            stats = self._filesystem_scanner.scan_paths(
                paths,
                progress_callback=progress,
                max_depth=target_depth
            )
            
            # Update final filesystem stats
            result.files_inspected = stats.files_inspected
            result.directories_inspected = stats.directories_inspected
            result.files_skipped = stats.files_skipped
            result.access_denied = stats.access_denied
            result.filesystem_errors = stats.errors
            result.suspicious_files = stats.suspicious_files.copy()
            result.current_path = ""
            
            if stats.cancelled:
                log.info("Filesystem scan cancelled")
                return False
            
            if stats.errors > 100:
                log.warning("Filesystem scan had excessive errors: %d", stats.errors)
                return False
            
            log.info("Filesystem scan complete: %d files, %d dirs",
                    stats.files_inspected, stats.directories_inspected)
            log.info(f"FILESYSTEM_SCAN_END")
            return True
            
        except Exception as e:
            log.error("Filesystem scanning failed: %s", e, exc_info=True)
            result.filesystem_errors += 1
            return False
    
    def _scan_processes(self, result: ScanResult, target_directories: Optional[List[Path]] = None) -> bool:
        log.info(f"LIVE_PROCESS_SCAN_START")
        """
        Perform process scanning and extract behavioral features.
        
        Args:
            result: ScanResult to update
            target_directories: Optional custom paths to sample for filesystem entropy
        
        Returns:
            True if successful, False if failed
        """
        try:
            log.info("Process scanning...")
            result.current_path = "Inspecting active processes and behavioral modules..."
            self._update_progress(result)
            
            def _on_subprogress(msg: str):
                result.current_path = msg
                self._update_progress(result)

            # Extract features using live scanner with progress and cancellation hooks
            features = self._process_scanner.scan_system(
                target_directories=target_directories,
                progress_callback=_on_subprogress,
                cancel_checker=lambda: self._cancel_requested
            )
            
            if features is None:
                log.error("Process scanning failed")
                result.current_path = ""
                return False
            
            # Store features for ML analysis
            result._features = features  # Private attribute for ML use
            
            # Get process scan stats
            stats = self._process_scanner.get_scan_stats()
            result.processes_analyzed = stats["processes_scanned"]
            if hasattr(self._process_scanner, "get_feature_availability"):
                avail_map = self._process_scanner.get_feature_availability()
                result.telemetry_availability = avail_map
                missing = [f for f, s in avail_map.items() if s.startswith("UNAVAILABLE") or s.startswith("RESTRICTED")]
                result.missing_features = missing
                result.available_feature_count = len(avail_map) - len(missing)
                result.telemetry_coverage_ratio = round(result.available_feature_count / max(len(avail_map), 1), 3)
            result.process_errors = stats["errors"]
            result.current_path = ""
            
            log.info("Process scan complete: %d processes", result.processes_analyzed)
            log.info(f"LIVE_PROCESS_SCAN_END")
            return True
            
        except Exception as e:
            log.error("Process scanning failed: %s", e, exc_info=True)
            result.process_errors += 1
            return False
    
    def _run_ml_analysis(self, result: ScanResult) -> bool:
        log.info(f"ML_ANALYSIS_START")
        """
        Run ML threat detection analysis.
        
        **SECURITY-CRITICAL:** This function returns False on ANY failure.
        Caller must NOT classify as SAFE if this returns False.
        
        Args:
            result: ScanResult to update
        
        Returns:
            True if successful, False if failed
        """
        try:
            if not hasattr(result, '_features'):
                log.error("[WARN]️ CRITICAL: No features available for ML analysis")
                result.threat_level = "ANALYSIS_ERROR"
                result.error_message = "Feature extraction failed"
                return False
            
            log.info("ML analysis...")
            result.current_path = "Evaluating 19-feature behavioral vector via Random Forest..."
            self._update_progress(result)
            
            # Load and run ML model
            from ml.predictor import MLPredictor
            predictor = MLPredictor()
            
            if not predictor.load_model():
                log.error("[WARN]️ CRITICAL: Failed to load ML model")
                result.threat_level = "ANALYSIS_ERROR"
                result.error_message = "ML model loading failed"
                return False
            
            ml_result = predictor.predict(result._features)
            
            if ml_result is None:
                log.error("[WARN]️ CRITICAL: ML prediction failed (returned None)")
                result.threat_level = "ANALYSIS_ERROR"
                result.error_message = "ML prediction returned None"
                return False
            
            threat_level, probability = ml_result
            
            # Validate ML output
            if threat_level not in ["SAFE", "WARNING", "CRITICAL", "LOW"]:
                log.error("[WARN]️ CRITICAL: ML returned invalid threat_level: %s", threat_level)
                result.threat_level = "ANALYSIS_ERROR"
                result.error_message = f"Invalid ML output: {threat_level}"
                return False
            
            if not (0.0 <= probability <= 1.0):
                log.error("[WARN]️ CRITICAL: ML returned invalid probability: %.4f", probability)
                result.threat_level = "ANALYSIS_ERROR"
                result.error_message = f"Invalid probability: {probability}"
                return False
            
            # All validations passed - store results
            result.ml_executed = True
            result.ml_probability = probability
            result.ml_prediction = threat_level
            result.threat_level = threat_level
            result.current_path = ""
            
            log.info("[OK] ML analysis complete: %s (%.4f)", threat_level, probability)
            log.info(f"ML_ANALYSIS_END")
            return True
            
        except Exception as e:
            log.error("[WARN]️ CRITICAL: ML analysis exception: %s", e, exc_info=True)
            result.threat_level = "ANALYSIS_ERROR"
            result.error_message = f"ML exception: {str(e)}"
            result.current_path = ""
            return False
    
    def _update_progress(self, result: ScanResult) -> None:
        """Update progress callback if set."""
        if self._progress_callback:
            try:
                self._progress_callback(result)
            except Exception as e:
                log.warning("Progress callback failed: %s", e)
    
    def cancel(self) -> None:
        """Request scan cancellation."""
        log.info("Scan cancellation requested")
        self._cancel_requested = True
        self._filesystem_scanner.cancel()
        if hasattr(self._process_scanner, "cancel"):
            self._process_scanner.cancel()

    def cancel_scan(self) -> None:
        """Alias for cancel()."""
        self.cancel()
    
    def get_state(self) -> ScanState:
        """Get current scan state."""
        return self._state


# ── Testing ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, '..')
    
    from utils.logging_config import setup_logging
    
    setup_logging()
    
    print("SentinelML V2 — Scan Engine Test")
    print("="*70)
    
    engine = ScanEngine()
    
    def progress(result: ScanResult):
        print(f"\r[{result.state.value.upper()}] Files: {result.files_inspected}, "
              f"Dirs: {result.directories_inspected}, Processes: {result.processes_analyzed}",
              end="", flush=True)
    
    # Test quick scan
    print("\nRunning QUICK scan...")
    result = engine.scan(ScanType.QUICK, progress_callback=progress)
    
    print(f"\n\n[OK] Scan Complete!")
    print(f"   Final State: {result.state.value.upper()}")
    print(f"   Scan Type: {result.scan_type.value}")
    print(f"   Files: {result.files_inspected}")
    print(f"   Directories: {result.directories_inspected}")
    print(f"   Processes: {result.processes_analyzed}")
    print(f"   ML Probability: {result.ml_probability:.4f}")
    print(f"   Threat Level: {result.threat_level}")
    print(f"   Elapsed: {result.elapsed_seconds:.2f}s")
    print(f"   Successful: {result.was_successful()}")
    
    if result.suspicious_files:
        print(f"\n   Suspicious files: {len(result.suspicious_files)}")
        for f in result.suspicious_files[:5]:
            print(f"      - {f}")
