"""
SentinelML V2 — Background Guard
==================================
Monitors filesystem for ransomware-like behavior.

CRITICAL: Must NOT spawn duplicate guards. Single instance only.

Monitored Locations:
-------------------
- Documents
- Desktop  
- Downloads
- OneDrive (if present)

Detected Behaviors:
------------------
- Rapid file modifications
- Mass file renaming
- Suspicious extensions (.encrypted, .locked, etc.)
- High-frequency filesystem activity

Phase 8: Basic implementation with single-instance protection.
"""

import logging
import os
import threading
import time
from pathlib import Path
from typing import List, Optional

from utils.logging_config import get_guard_logger

log = get_guard_logger()


class SentinelGuard:
    """
    Background filesystem monitor.
    
    Single-instance design - only one guard should run per system.
    """
    
    def __init__(self):
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitored_paths: List[Path] = []
        self._stop_event = threading.Event()
        
        # Statistics
        self._files_monitored = 0
        self._events_detected = 0
        self._threats_found = 0
        self._paused = False
    
    def pause(self) -> None:
        """Temporarily pause filesystem scanning during active on-demand scans."""
        self._paused = True
        log.debug("SentinelGuard monitoring paused for on-demand scan")

    def resume(self) -> None:
        """Resume background filesystem monitoring."""
        self._paused = False
        log.debug("SentinelGuard monitoring resumed")

    def start(self) -> bool:
        """
        Start the background guard.
        
        Returns:
            True if started successfully, False if already running
        """
        if self._running:
            log.warning("Guard is already running")
            return False
        
        log.info("Starting SentinelML Background Guard...")
        
        # Determine paths to monitor
        self._monitored_paths = self._get_monitored_paths()
        
        if not self._monitored_paths:
            log.error("No valid paths to monitor")
            return False
        
        log.info("Monitoring %d locations:", len(self._monitored_paths))
        for path in self._monitored_paths:
            log.info("  - %s", path)
        
        # Start monitor thread
        self._stop_event.clear()
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="GuardMonitorThread"
        )
        self._monitor_thread.start()
        
        log.info("Background Guard started successfully")
        return True
    
    def stop(self) -> None:
        """Stop the background guard."""
        if not self._running:
            log.warning("Guard is not running")
            return
        
        log.info("Stopping Background Guard...")
        self._running = False
        self._stop_event.set()
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2.0)
            if self._monitor_thread.is_alive():
                log.warning("Monitor thread did not stop cleanly")
        
        log.info("Background Guard stopped")
    
    def is_running(self) -> bool:
        """Check if guard is currently running."""
        return self._running
    
    def get_stats(self) -> dict:
        """Get guard statistics."""
        return {
            "running": self._running,
            "files_monitored": self._files_monitored,
            "events_detected": self._events_detected,
            "threats_found": self._threats_found,
            "monitored_paths": len(self._monitored_paths),
        }
    
    # ── Internal Methods ──────────────────────────────────────────────────
    
    def _get_monitored_paths(self) -> List[Path]:
        """Determine which paths to monitor."""
        paths = []
        
        # Use platform-specific monitored directories
        from utils.platform_utils import get_monitored_directories
        
        paths = []
        try:
            # Get platform-appropriate directories
            monitored_dirs = get_monitored_directories()
            
            for path in monitored_dirs:
                if path.exists() and path.is_dir():
                    paths.append(path)
                    log.debug("Will monitor: %s", path)
                else:
                    log.debug("Skipping (not found): %s", path)
        
        except Exception as e:
            log.error("Failed to determine monitored paths: %s", e)
            # Fallback to home directory
            home = Path.home()
            if home.exists():
                paths.append(home)
    
        return paths
    
    def _monitor_loop(self) -> None:
        """
        Main monitoring loop (runs in background thread).
        
        Phase 8: Simple periodic check.
        Phase 9+: Can be enhanced with watchdog library for real-time events.
        """
        log.info("Monitor loop started")
        
        try:
            while not self._stop_event.is_set():
                if not getattr(self, "_paused", False):
                    self._check_filesystem()
                
                # Sleep 30 seconds between background disk passes
                self._stop_event.wait(30.0)
        
        except Exception as e:
            log.error("Monitor loop crashed: %s", e, exc_info=True)
        
        finally:
            log.info("Monitor loop exited")
    
    def _check_filesystem(self) -> None:
        """
        Perform periodic filesystem check.
        
        Phase 8: Basic implementation (file counting).
        Phase 9+: Implement actual behavior detection.
        """
        if getattr(self, "_paused", False):
            return

        try:
            total_files = 0
            
            for path in self._monitored_paths:
                if getattr(self, "_paused", False):
                    return
                if not path.exists():
                    log.warning("Monitored path no longer exists: %s", path)
                    continue
                import time; time.sleep(0.005)
                
                # Count files with shallow depth limit (depth <= 2) and skip noise directories
                try:
                    file_count = 0
                    for item in path.iterdir():
                        if getattr(self, "_paused", False):
                            return
                        if item.is_file():
                            file_count += 1
                        elif item.is_dir() and item.name.lower() not in {'.git', 'node_modules', '__pycache__', '.pytest_cache', '.venv', 'venv'}:
                            try:
                                for sub in item.iterdir():
                                    if getattr(self, "_paused", False):
                                        return
                                    if sub.is_file():
                                        file_count += 1
                            except (PermissionError, OSError):
                                pass
                    total_files += file_count
                except (PermissionError, OSError) as e:
                    log.debug("Cannot access %s: %s", path, e)
            
            self._files_monitored = total_files
            log.debug("Filesystem check: %d files monitored", total_files)
            
        except Exception as e:
            log.error("Filesystem check failed: %s", e)


# ── Single Instance Check (for future implementation) ────────────────────

_guard_instance: Optional[SentinelGuard] = None
_guard_lock = threading.Lock()


def get_guard_instance() -> SentinelGuard:
    """
    Get the singleton guard instance.
    
    Ensures only one guard runs in the application.
    """
    global _guard_instance
    
    with _guard_lock:
        if _guard_instance is None:
            _guard_instance = SentinelGuard()
        return _guard_instance


# ── Testing ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from utils.logging_config import setup_logging
    
    setup_logging()
    
    print("SentinelML V2 — Background Guard Test")
    print("="*70)
    
    guard = get_guard_instance()
    
    print("\n1. Starting guard...")
    if guard.start():
        print("✓ Guard started")
    else:
        print("✗ Guard failed to start")
        exit(1)
    
    print("\n2. Running for 15 seconds...")
    try:
        for i in range(15):
            time.sleep(1)
            if (i + 1) % 5 == 0:
                stats = guard.get_stats()
                print(f"   [{i+1}s] Files monitored: {stats['files_monitored']}")
    except KeyboardInterrupt:
        print("\n   Interrupted by user")
    
    print("\n3. Stopping guard...")
    guard.stop()
    
    final_stats = guard.get_stats()
    print("\n[OK] Test complete")
    print(f"   Final stats: {final_stats}")
