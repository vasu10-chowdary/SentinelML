"""
SentinelML V2 — Filesystem Scanner
====================================
Real filesystem scanning with progress tracking and permission handling.

CRITICAL RULES:
- Actually enumerate files and directories
- Handle permissions safely (no crashes on AccessDenied)
- Track what was scanned and what was skipped
- Support cancellation
- Provide real-time progress
- Never fake scan results
"""

import os
import time
import logging
from pathlib import Path
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field

log = logging.getLogger("sentinel.scanner.filesystem")


@dataclass
class ScanStats:
    """Statistics from filesystem scan."""
    files_inspected: int = 0
    directories_inspected: int = 0
    files_skipped: int = 0
    access_denied: int = 0
    errors: int = 0
    total_size_bytes: int = 0
    suspicious_files: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    cancelled: bool = False
    current_path: str = ""


class FilesystemScanner:
    """
    Real filesystem scanner with progress tracking.
    
    Responsibilities:
    - Directory traversal
    - File enumeration
    - Permission handling
    - Progress tracking
    - Cancellation support
    """
    
    def __init__(self):
        self._cancel_requested = False
        self._stats = ScanStats()
        self._progress_callback: Optional[Callable[[ScanStats], None]] = None
        self._scan_start_time = 0.0
    
    def scan_paths(self, 
                   paths: List[Path],
                   progress_callback: Optional[Callable[[ScanStats], None]] = None,
                   max_depth: int = 10) -> ScanStats:
        """
        Scan specified paths for files and directories.
        
        Args:
            paths: List of paths to scan
            progress_callback: Called periodically with scan progress
            max_depth: Maximum directory depth (safety limit)
        
        Returns:
            ScanStats with results
        """
        log.info("Starting filesystem scan: %d paths", len(paths))
        
        self._cancel_requested = False
        self._stats = ScanStats()
        self._progress_callback = progress_callback
        self._scan_start_time = time.time()
        
        try:
            for path in paths:
                if self._cancel_requested:
                    log.info("Scan cancelled by user")
                    self._stats.cancelled = True
                    break
                
                if not path.exists():
                    log.warning("Path does not exist: %s", path)
                    self._stats.errors += 1
                    continue
                
                if path.is_file():
                    self._scan_file(path)
                elif path.is_dir():
                    self._scan_directory(path, current_depth=0, max_depth=max_depth)
            
            self._stats.elapsed_seconds = time.time() - self._scan_start_time
            
            log.info(
                "Filesystem scan complete. Files: %d, Dirs: %d, Skipped: %d, Access Denied: %d, Time: %.2fs",
                self._stats.files_inspected,
                self._stats.directories_inspected,
                self._stats.files_skipped,
                self._stats.access_denied,
                self._stats.elapsed_seconds
            )
            
            return self._stats
            
        except Exception as e:
            log.error("Filesystem scan failed: %s", e, exc_info=True)
            self._stats.errors += 1
            self._stats.elapsed_seconds = time.time() - self._scan_start_time
            return self._stats
    
    def _scan_directory(self, directory: Path, current_depth: int, max_depth: int) -> None:
        """
        Recursively scan a directory.
        
        Args:
            directory: Directory to scan
            current_depth: Current recursion depth
            max_depth: Maximum depth limit
        """
        if current_depth >= max_depth:
            log.debug("Max depth reached: %s", directory)
            return
        
        if self._cancel_requested:
            return
        
        try:
            self._stats.directories_inspected += 1
            self._stats.current_path = str(directory)
            
            # Update progress periodically
            if self._stats.directories_inspected % 100 == 0:
                self._update_progress()
            
            # List directory contents
            try:
                entries = list(directory.iterdir())
            except PermissionError:
                log.debug("Access denied: %s", directory)
                self._stats.access_denied += 1
                return
            except OSError as e:
                log.debug("OS error accessing %s: %s", directory, e)
                self._stats.errors += 1
                return
            
            # Process each entry
            for entry in entries:
                if self._cancel_requested:
                    return
                
                try:
                    if entry.is_file():
                        self._scan_file(entry)
                    elif entry.is_dir():
                        self._scan_directory(entry, current_depth + 1, max_depth)
                    else:
                        # Symlink, special file, etc.
                        self._stats.files_skipped += 1
                        
                except PermissionError:
                    self._stats.access_denied += 1
                except OSError:
                    self._stats.errors += 1
                    
        except Exception as e:
            log.warning("Error scanning directory %s: %s", directory, e)
            self._stats.errors += 1
    
    def _scan_file(self, file_path: Path) -> None:
        """
        Inspect a single file.
        
        Args:
            file_path: File to inspect
        """
        try:
            self._stats.files_inspected += 1
            self._stats.current_path = str(file_path)
            
            # Update progress periodically
            if self._stats.files_inspected % 1000 == 0:
                self._update_progress()
            
            # Get file stats (metadata only, don't read content)
            try:
                file_stat = file_path.stat()
                self._stats.total_size_bytes += file_stat.st_size
                
                # Check for suspicious indicators (basic heuristics)
                suspicious = self._check_file_suspicious(file_path, file_stat)
                if suspicious:
                    self._stats.suspicious_files.append(str(file_path))
                    
            except PermissionError:
                self._stats.access_denied += 1
            except OSError:
                self._stats.errors += 1
                
        except Exception as e:
            log.debug("Error inspecting file %s: %s", file_path, e)
            self._stats.errors += 1
    
    def _check_file_suspicious(self, file_path: Path, file_stat) -> bool:
        """
        Check if file exhibits suspicious characteristics.
        
        This is basic heuristic checking, NOT ML-based classification.
        
        Args:
            file_path: Path to file
            file_stat: File stat object
        
        Returns:
            True if file appears suspicious
        """
        try:
            # Check for suspicious extensions (common ransomware indicators)
            suspicious_extensions = [
                '.encrypted', '.locked', '.crypto', '.crypt',
                '.locky', '.cerber', '.zepto', '.osiris',
                '.exe', '.scr', '.vbs', '.bat', '.cmd', '.ps1'
            ]
            
            ext = file_path.suffix.lower()
            if ext in suspicious_extensions:
                # Only mark executables/scripts in user directories as suspicious
                if 'Users' in str(file_path) or 'Documents' in str(file_path):
                    return True
            
            # Check for recently modified files (within last hour)
            current_time = time.time()
            if current_time - file_stat.st_mtime < 3600:  # 1 hour
                # Check if filename suggests ransomware (READ_ME, DECRYPT, etc.)
                name_lower = file_path.name.lower()
                suspicious_keywords = [
                    'readme', 'decrypt', 'restore', 'recovery',
                    'locked', 'encrypted', 'ransom'
                ]
                if any(keyword in name_lower for keyword in suspicious_keywords):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _update_progress(self) -> None:
        """Update progress callback if set."""
        if self._progress_callback:
            try:
                self._stats.elapsed_seconds = time.time() - self._scan_start_time
                self._progress_callback(self._stats)
            except Exception as e:
                log.warning("Progress callback failed: %s", e)
    
    def cancel(self) -> None:
        """Request scan cancellation."""
        log.info("Cancellation requested")
        self._cancel_requested = True
    
    def is_scanning(self) -> bool:
        """Check if scan is currently running."""
        return self._scan_start_time > 0 and self._stats.elapsed_seconds == 0


# ── Testing ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from utils.logging_config import setup_logging
    
    setup_logging()
    
    print("SentinelML V2 — Filesystem Scanner Test")
    print("="*70)
    
    # Test on Documents folder
    scanner = FilesystemScanner()
    test_path = Path.home() / "Documents"
    
    if test_path.exists():
        print(f"\nScanning: {test_path}")
        
        def progress(stats: ScanStats):
            print(f"\rFiles: {stats.files_inspected}, Dirs: {stats.directories_inspected}", end="")
        
        stats = scanner.scan_paths([test_path], progress_callback=progress, max_depth=3)
        
        print(f"\n\n[OK] Scan Complete!")
        print(f"   Files inspected: {stats.files_inspected}")
        print(f"   Directories: {stats.directories_inspected}")
        print(f"   Skipped: {stats.files_skipped}")
        print(f"   Access denied: {stats.access_denied}")
        print(f"   Errors: {stats.errors}")
        print(f"   Total size: {stats.total_size_bytes / (1024**3):.2f} GB")
        print(f"   Suspicious files: {len(stats.suspicious_files)}")
        print(f"   Elapsed: {stats.elapsed_seconds:.2f}s")
        
        if stats.suspicious_files:
            print(f"\n   Suspicious files found:")
            for f in stats.suspicious_files[:10]:  # Show first 10
                print(f"      - {f}")
    else:
        print(f"\n✗ Test path not found: {test_path}")
