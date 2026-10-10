"""
SentinelML V2 -€” Application Entry Point
=========================================
Run with:  python app.py
           python -m sentinelml   (future)

This file is intentionally minimal. All logic lives in gui/ and the
support modules.  The only things here are:
  1. Logging setup (writes to logs/app.log and console)
  2. multiprocessing freeze_support() for PyInstaller compatibility
  3. Importing and running the main window
"""

import logging
import multiprocessing
import sys

from utils.logging_config import setup_logging
from utils.paths import get_user_data_root


# -”€-”€ sys.excepthook: catch unhandled exceptions and write a crash file -”€-”€-”€-”€
def _install_crash_hook() -> None:
    import traceback
    
    crash_file = get_user_data_root() / "CRASH.log"

    def _hook(exc_type, exc_value, exc_tb):
        with open(crash_file, "w", encoding="utf-8") as f:
            f.write("SentinelML V2 -€” Unhandled Exception\n")
            f.write("=" * 60 + "\n")
            traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
        logging.critical(
            "UNHANDLED EXCEPTION -€” details in %s", crash_file,
            exc_info=(exc_type, exc_value, exc_tb),
        )
        # Show a native error dialog even in windowed mode
        try:
            import tkinter
            import tkinter.messagebox
            root = tkinter.Tk()
            root.withdraw()
            tkinter.messagebox.showerror(
                "SentinelML V2 -€” Fatal Error",
                f"The application crashed:\n\n{exc_value}\n\n"
                f"Full details saved to:\n{crash_file}",
            )
            root.destroy()
        except Exception:
            pass

    sys.excepthook = _hook


# -”€-”€ Main -”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€-”€
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
        
        # ------------------------------------------------------------------------------------------------------------------------------
        # CRITICAL FIX: ONE APPLICATION WINDOW ONLY
        # ------------------------------------------------------------------------------------------------------------------------------
        # Create main application window FIRST
        log.info("Creating MainWindow...")
        app = MainWindow()
        
        if skip_animation:
            # Skip animation -€” show dashboard directly
            log.info("Skipping startup animation (--no-animation flag)")
        else:
            # Show startup animation INSIDE the main window
            log.info("Launching with startup animation")
            
            try:
                # Import animation inside main window
                from gui.startup_animation import show_startup_animation_inline
                
                # Show animation on main window (duration: 4 seconds)
                show_startup_animation_inline(
                    app,
                    duration=4200
                )
                log.info("Startup animation displayed")
                
            except Exception as anim_error:
                # Animation failed -€” skip it, continue with dashboard
                log.warning("Startup animation failed (%s) -€” skipping", anim_error)
        
        # Start main event loop
        log.info("MainWindow created -€” entering mainloop.")
        app.mainloop()
        log.info("Mainloop exited normally.")
        
    except Exception as exc:
        log.critical("Application crashed on startup: %s", exc, exc_info=True)
        raise  # Let the excepthook handle the dialog


if __name__ == "__main__":
    main()

