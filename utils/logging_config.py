"""
SentinelML V2 — Logging Configuration
=======================================
Centralized logging setup with subsystem loggers.

Features:
---------
- Rotating file handler (prevents log files from growing indefinitely)
- Console logging during development
- Timestamps with milliseconds
- Log levels per subsystem
- Full traceback on exceptions
- threading.excepthook for background threads
- User-writable log location

Subsystem Loggers:
------------------
- sentinel.gui       — GUI events and user interactions
- sentinel.scanner   — Live scanner operations
- sentinel.ml        — ML model loading and predictions
- sentinel.guard     — Background guard monitoring
- sentinel.alerts    — Alert generation and management
- sentinel.reports   — Incident report generation
- sentinel.config    — Configuration operations
"""

import logging
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

from utils.paths import get_logs_dir


# ── Global logger references ──────────────────────────────────────────────
_loggers_configured = False


def setup_logging(level=logging.DEBUG, console=True) -> None:
    """
    Configure application-wide logging.
    
    Args:
        level: Root logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        console: Whether to log to console (True for development)
    """
    global _loggers_configured
    
    if _loggers_configured:
        return  # Already configured
    
    # Get log directory
    log_dir = get_logs_dir()
    log_file = log_dir / "app.log"
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear any existing handlers (avoid duplicates)
    root_logger.handlers.clear()
    
    # ── File Handler (Rotating) ───────────────────────────────────────────
    # Max 10MB per file, keep 5 backups
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    # ── Console Handler (optional) ────────────────────────────────────────
    if console and sys.stdout is not None:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)  # Less verbose in console
        console_formatter = logging.Formatter(
            fmt='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    # ── Configure threading exception hook ─────────────────────────────────
    _install_thread_exception_hook()
    
    _loggers_configured = True
    
    # Log initialization
    log = logging.getLogger("sentinel.logging")
    log.info("Logging configured. Log file: %s", log_file)
    log.debug("Console logging: %s", console)


def _install_thread_exception_hook() -> None:
    """
    Install threading.excepthook to capture exceptions in background threads.
    
    Without this, exceptions in threads are printed to stderr but not logged.
    """
    def thread_exception_hook(args):
        log = logging.getLogger("sentinel.threading")
        log.critical(
            "Unhandled exception in thread: %s",
            args.thread.name,
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback)
        )
    
    threading.excepthook = thread_exception_hook


# ── Subsystem Logger Getters ──────────────────────────────────────────────

def get_gui_logger():
    """Get GUI subsystem logger."""
    return logging.getLogger("sentinel.gui")


def get_scanner_logger():
    """Get scanner subsystem logger."""
    return logging.getLogger("sentinel.scanner")


def get_ml_logger():
    """Get ML subsystem logger."""
    return logging.getLogger("sentinel.ml")


def get_guard_logger():
    """Get guard subsystem logger."""
    return logging.getLogger("sentinel.guard")


def get_alerts_logger():
    """Get alerts subsystem logger."""
    return logging.getLogger("sentinel.alerts")


def get_reports_logger():
    """Get reports subsystem logger."""
    return logging.getLogger("sentinel.reports")


def get_config_logger():
    """Get config subsystem logger."""
    return logging.getLogger("sentinel.config")


# ── Convenience function for tests ────────────────────────────────────────

def log_test_message() -> None:
    """Log a test message from each subsystem (for verification)."""
    get_gui_logger().info("GUI subsystem initialized")
    get_scanner_logger().info("Scanner subsystem initialized")
    get_ml_logger().info("ML subsystem initialized")
    get_guard_logger().info("Guard subsystem initialized")
    get_alerts_logger().info("Alerts subsystem initialized")
    get_reports_logger().info("Reports subsystem initialized")
    get_config_logger().info("Config subsystem initialized")


# ── Testing ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    setup_logging()
    log_test_message()
    
    # Test threading exception hook
    import time
    
    def failing_thread():
        time.sleep(0.1)
        raise RuntimeError("Test exception in thread")
    
    thread = threading.Thread(target=failing_thread, name="TestThread")
    thread.start()
    thread.join()
    
    print("\nCheck logs/app.log for logged exception")
