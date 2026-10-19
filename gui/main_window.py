"""

SentinelML V2 - Main Window

=============================

The application's single top-level window.  Appears immediately on launch -

no splash screen, no hidden window tricks.



Layout:

  -”Œ-----------”¬------------------------------------”

  -”‚ Sidebar  -”‚  Content area (page frames)       -”‚

  -”‚  nav     -”‚                                   -”‚

  -””-----------”´------------------------------------”˜

"""



import logging
from ai.sentinel_ai import SentinelAI

import os

import customtkinter as ctk

from tkinter import font as tkfont



import config as cfg

from constants import (

    COLOURS as C,

    FONT_PREFERENCE,

    SIDEBAR_W,

    WINDOW_MIN_H,

    WINDOW_MIN_W,

    WINDOW_TITLE,

    APP_VERSION,

)

from gui.pages.dashboard import DashboardPage

from gui.pages.threats   import ThreatsPage

from gui.pages.ransomware import RansomwarePage

from gui.pages.settings  import SettingsPage



log = logging.getLogger(__name__)





# -- Font resolution -----------------------------------------------------

def _resolve_font() -> str:

    """Return the first available font from FONT_PREFERENCE, else 'TkDefaultFont'."""

    available = set(tkfont.families())

    for f in FONT_PREFERENCE:

        if f in available:

            log.debug("UI font resolved: %s", f)

            return f

    return "TkDefaultFont"





# --------------------------------------------------------------------------------------------------------------------------------------------------------

class MainWindow(ctk.CTk):

    """

    SentinelML V2 application window.



    Lifecycle:

        app = MainWindow()

        app.mainloop()          # blocks until user closes window

    """



    def __init__(self):

        super().__init__()



        # -- CustomTkinter global appearance ------------------------------

        ctk.set_appearance_mode("dark")

        ctk.set_default_color_theme("blue")



        # -- Load persisted config -----------------------------------------

        self._config = cfg.load()

        log.info("Config loaded. setup_done=%s", self._config.get("setup_done"))



        # -- Window basics -------------------------------------------------

        self.title(WINDOW_TITLE)

        self.minsize(WINDOW_MIN_W, WINDOW_MIN_H)

        self.configure(fg_color=C["bg"])



        # Set application icon
        try:
            import sys
            from pathlib import Path
            icon_path = Path(__file__).parent.parent / "sentinel_icon.ico"
            if getattr(sys, "frozen", False):
                icon_path = Path(sys._MEIPASS) / "sentinel_icon.ico"
            if icon_path.exists():
                self.iconbitmap(str(icon_path))
        except Exception as e:
            pass

        # Maximise on first open

        try:

            self.state("zoomed")

        except Exception:

            self.geometry("1280x800")



        # Protocol: let the user close normally

        self.protocol("WM_DELETE_WINDOW", self._on_close)



        # -- Resolve font AFTER the Tk window is created -------------------

        self._font = _resolve_font()



        # -- Build layout --------------------------------------------------

        self._pages: dict[str, ctk.CTkFrame] = {}

        self._nav_btns: dict[str, ctk.CTkButton] = {}

        self._current_page: str | None = None



        self._build_layout()

        self._build_sidebar()

        self._build_pages()



        # -- Show dashboard on startup -------------------------------------

        self._show_page("dashboard")



        # -- Start periodic tick -------------------------------------------

        self.ai_copilot = SentinelAI(self._config.get("ai", {}))
        self._uptime_s = 0

        self._tick()
        self.after(500, self._start_background_services)



        log.info("MainWindow ready. Entering mainloop.")



    # -- Layout skeleton ---------------------------------------------------

    def _build_layout(self) -> None:

        self.grid_rowconfigure(0, weight=1)

        self.grid_columnconfigure(1, weight=1)



    def _build_sidebar(self) -> None:

        sidebar = ctk.CTkFrame(

            self,

            width=SIDEBAR_W,

            corner_radius=0,

            fg_color=C["panel"],

        )

        sidebar.grid(row=0, column=0, sticky="nsew")

        sidebar.grid_propagate(False)

        sidebar.grid_rowconfigure(3, weight=1)  # push bottom section down



        # -- Brand ---------------------------------------------------------

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")

        brand.grid(row=0, column=0, sticky="ew", padx=18, pady=(30, 24))



        ctk.CTkLabel(

            brand,

            text="[ S ]",

            font=ctk.CTkFont(size=36),

            text_color=C["accent"],

        ).pack(side="left")



        name_col = ctk.CTkFrame(brand, fg_color="transparent")

        name_col.pack(side="left", padx=10)



        ctk.CTkLabel(

            name_col,

            text="SentinelML",

            font=ctk.CTkFont(self._font, 18, weight="bold"),

            text_color=C["white"],

        ).pack(anchor="w")



        self._status_dot = ctk.CTkLabel(

            name_col,

            text=" READY TO SCAN",

            font=ctk.CTkFont(self._font, 10, weight="bold"),

            text_color=C["muted"],  # Gray for IDLE state

        )

        self._status_dot.pack(anchor="w")



        # -- Separator -----------------------------------------------------

        sep = ctk.CTkFrame(sidebar, height=1, fg_color=C["border"])

        sep.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))



        # -- Navigation buttons --------------------------------------------

        nav_frame = ctk.CTkFrame(sidebar, fg_color="transparent")

        nav_frame.grid(row=2, column=0, sticky="ew")



        nav_items = [

            ("dashboard",     "Dashboard",    "[ * ]"),

            ("exhibition",    "Exhibition",   "[ EX ]"),

            ("threats",       "Threat Log",   "[ ! ]"),

            ("sentinel_ai",   "SentinelAI",   "[ AI ]"),

            ("ransomware",    "Ransomware",   "[ ? ]"),

            ("settings",      "Settings",     "[ = ]"),

        ]

        for uid, label, icon in nav_items:

            btn = ctk.CTkButton(

                nav_frame,

                text=f"  {label}",

                font=ctk.CTkFont(self._font, 13),

                anchor="w",

                fg_color="transparent",

                text_color=C["muted"],

                hover_color=C["card"],

                height=46,

                corner_radius=10,

                command=lambda u=uid: self._show_page(u),

            )

            btn.pack(fill="x", padx=10, pady=3)

            self._nav_btns[uid] = btn



        # -- Bottom info ---------------------------------------------------

        bottom = ctk.CTkFrame(sidebar, fg_color="transparent")

        bottom.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 20))



        ctk.CTkLabel(

            bottom,

            text=f"v{APP_VERSION}",

            font=ctk.CTkFont(size=10),

            text_color=C["muted"],

        ).pack(side="bottom", anchor="w")



        self._sidebar = sidebar



    def _build_pages(self) -> None:
        """Register page classes for lazy loading."""
        from gui.pages.sentinel_ai_page import SentinelAIPage
        from gui.pages.exhibition_page import ExhibitionPage
        self._page_classes = {
            "dashboard":     DashboardPage,
            "exhibition":    ExhibitionPage,
            "threats":       ThreatsPage,
            "sentinel_ai":   SentinelAIPage,
            "ransomware":    RansomwarePage,
            "settings":      SettingsPage,
        }

    # -- Navigation --------------------------------------------------------
    def _show_page(self, uid: str) -> None:
        if self._current_page == uid:
            return

        # Hide old page
        if self._current_page and self._current_page in self._pages:
            self._pages[self._current_page].grid_remove()

        # Lazy load new page if not instantiated
        if uid not in self._pages:
            log.info("Lazy loading page: %s", uid)
            cls = self._page_classes[uid]
            frame = cls(self, config=self._config)
            frame.grid(row=0, column=1, sticky="nsew")
            self._pages[uid] = frame

        # Reset all nav button colours
        for key, btn in self._nav_btns.items():
            btn.configure(
                fg_color=C["accent"] if key == uid else "transparent",
                text_color=C["white"] if key == uid else C["muted"],
            )

        # Show new page
        self._pages[uid].grid()
        self._current_page = uid
        log.debug("Switched to page: %s", uid)



    # -- Periodic tick (1-second heartbeat) --------------------------------

    def _tick(self) -> None:

        self._uptime_s += 1



        # Update dashboard uptime tile

        dashboard = self._pages.get("dashboard")

        if isinstance(dashboard, DashboardPage):

            dashboard.update_stats(uptime_s=self._uptime_s)
        # Update guard status
        try:
            from guard.sentinel_guard import get_guard_instance
            guard = get_guard_instance()
            is_active = guard.is_running()
            if isinstance(dashboard, DashboardPage):
                dashboard.update_guard_status(is_active)
        except Exception:
            pass



        self.after(1000, self._tick)

    

    # -- Sidebar status synchronization ------------------------------------

    def update_sidebar_status(self, status: str, color: str) -> None:

        """

        Update sidebar status dot to match dashboard state.

        CRITICAL: ONE APPLICATION, ONE SECURITY STATE.

        

        Args:

            status: Status text (e.g., "SYSTEM SAFE", "SCAN ERROR", "READY TO SCAN")

            color: Color key from constants.COLOURS

        """

        self._status_dot.configure(

            text=f" {status}",

            text_color=color

        )

        log.debug("Sidebar status updated: %s (%s)", status, color)



    # -- Clean shutdown ----------------------------------------------------

    def _on_close(self) -> None:

        log.info("User closed window. Shutting down.")

        cfg.save(self._config)

        self.destroy()



    def _start_background_services(self) -> None:
        """Start background services like Guard and ML preload."""
        import threading
        
        def _init_thread():
            try:
                import time
                import logging
                log = logging.getLogger(__name__)
                # Wait for 3D animation to finish before doing heavy imports that block the GIL
                log.info("Delaying background init to avoid freezing startup animation...")
                time.sleep(3.0)
                
                # 1. Start SentinelGuard
                from guard.sentinel_guard import get_guard_instance
                guard = get_guard_instance()
                if not guard.is_running():
                    guard.start()
                    log.info("Background Guard started successfully.")
                
                # 2. Initialize SentinelAI in background
                self.ai_copilot.initialize()
                
                # 3. Preload ML model so the first scan is fast
                from ml.predictor import MLPredictor
                predictor = MLPredictor()
                if not predictor.is_loaded():
                    predictor.load_model()
                    log.info("ML Model preloaded successfully.")
                    
            except Exception as e:
                log.error("Failed to start background services: %s", e)
                
        threading.Thread(target=_init_thread, daemon=True, name="BackgroundInit").start()

