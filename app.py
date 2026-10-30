"""
SentinelML V2 — Application Entry Point
=========================================
Run with:  python app.py
           python -m sentinelml   (future)

This file is intentionally minimal. All logic lives in gui/ and the
support modules.  The only things here are:
  1. Logging setup (writes to logs/app.log and console)
  2. multiprocessing freeze_support() for PyInstaller compatibility
  3. Single-instance enforcement (cross-platform via platform adapter)
  4. Importing and running the main window
"""

import logging
import multiprocessing
import sys

from utils.logging_config import setup_logging
from utils.paths import get_user_data_root
from utils.platform_adapter import get_platform_adapter


# ── sys.excepthook: catch unhandled exceptions and write a crash file ─────────
def _install_crash_hook() -> None:
    import traceback

    crash_file = get_user_data_root() / "CRASH.log"

    def _hook(exc_type, exc_value, exc_tb):
        try:
            with open(crash_file, "w", encoding="utf-8") as f:
                f.write("SentinelML V2 — Unhandled Exception\n")
                f.write("=" * 60 + "\n")
                traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
        except Exception:
            pass

        logging.critical(
            "UNHANDLED EXCEPTION — details in %s", crash_file,
            exc_info=(exc_type, exc_value, exc_tb),
        )

        # Show native OS error dialog without reinitializing Tkinter
        try:
            get_platform_adapter().show_native_fatal_error(
                "SentinelML V2 — Fatal Error",
                str(exc_value),
                crash_file
            )
        except Exception:
            pass

    sys.excepthook = _hook


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    # Required for PyInstaller multiprocessing support on Windows
    multiprocessing.freeze_support()

    setup_logging(console=(sys.stdout is not None))
    _install_crash_hook()

    log = logging.getLogger("sentinel.main")
    log.info("=" * 60)
    log.info(
        "SentinelML V2 starting. frozen=%s  argv=%s",
        getattr(sys, "frozen", False),
        sys.argv,
    )

    # Enforce strictly ONE application instance across all platforms
    adapter = get_platform_adapter()
    instance_lock = adapter.acquire_single_instance_lock()
    if instance_lock is None:
        log.warning("Another instance of SentinelML V2 is already running. Bringing it forward and exiting cleanly.")
        adapter.bring_existing_instance_to_front("SentinelML V2 — Behavioral AI Ransomware Defense")
        sys.exit(0)

    # Import the window here (not at module level) so that logging is
    # configured before any module-level code in gui/ runs
    from gui.main_window import MainWindow

    try:
        # Check command-line flags
        skip_animation = "--no-animation" in sys.argv
        demo_mode = "--demo" in sys.argv

        # Enable demo mode if requested
        if demo_mode:
            log.info("Demo mode enabled (--demo flag)")
            import demo_data
            demo_data.enable_demo_mode()

        # ── EXACTLY ONE APPLICATION WINDOW & ONE TK ROOT ──
        log.info("Creating MainWindow (show_animation=%s)...", not skip_animation)
        app = MainWindow(show_animation=(not skip_animation))
        log.info("MainWindow created — entering mainloop.")

        # Start main event loop
        app.mainloop()
        log.info("Mainloop exited normally.")

    except Exception as exc:
        log.critical("Application crashed on startup: %s", exc, exc_info=True)
        raise  # Let the excepthook handle the dialog
    finally:
        adapter.release_single_instance_lock(instance_lock)


if __name__ == "__main__":
    main()
