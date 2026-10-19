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
    threat_level: str = "ANALYSIS_ERROR"  # Default to ERROR, not UNKNOWN or SAFE
    
    # Timing
    elapsed_seconds: float = 0.0
    
    # Status
    cancelled: bool = False
    error_message: str = ""
    
    # Model Provenance & Simulation Transparency
    model_source: str = "EXPERIMENTAL_SYNTHETIC_BASELINE_V1"
    is_simulation: bool = False
    observable_schema: str = "SCHEMA_V2_COMPATIBLE"
    
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
             progress_callback: Optional[Callable[[ScanResult], None]] = None) -> ScanResult:
        """
        Perform a security scan.
        
        Args:
            scan_type: Type of scan to perform
            custom_paths: Paths for custom scan (required if scan_type is CUSTOM)
            progress_callback: Called periodically with progress updates
        
        Returns:
            ScanResult with complete results
        """
        log.info("Starting %s scan", scan_type.value)
        
        self._state = ScanState.SCANNING
        self._cancel_requested = False
        self._progress_callback = progress_callback
        
        scan_start = time.time()
        result = ScanResult(scan_type=scan_type, state=ScanState.SCANNING)
        
        try:
            import uuid
            scan_id = str(uuid.uuid4())
            setattr(result, '_scan_id', scan_id)
            log.info(f"SCAN_START | ID: {scan_id} | TS: {scan_start} | MODE: {scan_type.value}")
            # Determine scan scope
            scan_paths = self._determine_scan_paths(scan_type, custom_paths)
            if not scan_paths:
                log.error("No valid scan paths determined")
                result.state = ScanState.SCAN_INCOMPLETE
                result.error_message = "No valid scan paths"
                return result
            
            log.info("Scan scope: %d paths", len(scan_paths))
            
            # Phase 1: Filesystem scanning (if not process-only)
            filesystem_success = True
            if scan_type != ScanType.PROCESS:
                filesystem_success = self._scan_filesystem(scan_paths, result)
                
                if self._cancel_requested:
                    result.cancelled = True
                    result.state = ScanState.SCAN_INCOMPLETE
                    result.elapsed_seconds = time.time() - scan_start
                    return result
            
            # Phase 2: Process scanning
            process_success = self._scan_processes(result, target_directories=scan_paths if scan_type == ScanType.CUSTOM else None)
            
            if self._cancel_requested:
                result.cancelled = True
                result.state = ScanState.SCAN_INCOMPLETE
                result.elapsed_seconds = time.time() - scan_start
                return result
            
            # Phase 3: ML analysis
            if process_success:
                self._state = ScanState.ANALYZING
                result.state = ScanState.ANALYZING
                self._update_progress(result)
                
                ml_success = self._run_ml_analysis(result)
            else:
                ml_success = False
            
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
            log.info(f"SCAN_COMPLETE | ID: {scan_id} | DURATION: {result.elapsed_seconds:.3f}s | FILES: {result.files_inspected} | DIRS: {result.directories_inspected} | PROCS: {result.processes_analyzed} | PROB: {result.ml_probability} | STATE: {result.state.value}")
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
    
    def _scan_filesystem(self, paths: List[Path], result: ScanResult) -> bool:
        log.info(f"FILESYSTEM_SCAN_START")
        """
        Perform filesystem scanning.
        
        Args:
            paths: Paths to scan
            result: ScanResult to update
        
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
                
                self._update_progress(result)
            
            stats = self._filesystem_scanner.scan_paths(
                paths,
                progress_callback=progress,
                max_depth=5  # Reasonable depth limit
            )
            
            # Update final filesystem stats
            result.files_inspected = stats.files_inspected
            result.directories_inspected = stats.directories_inspected
            result.files_skipped = stats.files_skipped
            result.access_denied = stats.access_denied
            result.filesystem_errors = stats.errors
            result.suspicious_files = stats.suspicious_files.copy()
            
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
            
            # Extract features using live scanner
            features = self._process_scanner.scan_system(target_directories=target_directories)
            
            if features is None:
                log.error("Process scanning failed")
                return False
            
            # Store features for ML analysis
            result._features = features  # Private attribute for ML use
            
            # Get process scan stats
            stats = self._process_scanner.get_scan_stats()
            result.processes_analyzed = stats["processes_scanned"]
            result.process_errors = stats["errors"]
            
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
            result.threat_level = threat_level
            
            log.info("[OK] ML analysis complete: %s (%.4f)", threat_level, probability)
            log.info(f"ML_ANALYSIS_END")
            return True
            
        except Exception as e:
            log.error("[WARN]️ CRITICAL: ML analysis exception: %s", e, exc_info=True)
            result.threat_level = "ANALYSIS_ERROR"
            result.error_message = f"ML exception: {str(e)}"
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
