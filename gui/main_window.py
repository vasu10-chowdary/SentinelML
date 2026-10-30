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
import tkinter as tk
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



    def __init__(self, show_animation: bool = False):

        super().__init__()
        self._is_destroyed = False
        self._pending_after_ids: set[str] = set()



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
                from utils.platform_adapter import get_platform_adapter
                get_platform_adapter().set_window_icon(self, icon_path)
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



        # -- Start periodic tick -------------------------------------------
        self.ai_copilot = SentinelAI(self._config.get("ai", {}))
        self._uptime_s = 0
        self._tick()
        self.safe_after(1200, self._start_background_services)

        # -- Startup view transition ---------------------------------------
        if show_animation:
            log.info("MainWindow: launching inline cinematic startup sequence")
            try:
                from gui.startup_animation import show_startup_animation_inline
                show_startup_animation_inline(
                    self,
                    duration=5000,
                    on_complete=self._on_startup_animation_done
                )
            except Exception as anim_err:
                log.warning("Startup animation failed (%s) — showing dashboard directly", anim_err)
                self._show_page("dashboard")
                self.safe_after(4000, self._prewarm_next_page, ["threats", "ransomware", "sentinel_ai", "settings"])
        else:
            self._show_page("dashboard")
            self.safe_after(4000, self._prewarm_next_page, ["threats", "ransomware", "sentinel_ai", "settings"])

        log.info("MainWindow ready. Entering mainloop.")

    def _on_startup_animation_done(self) -> None:
        """Called seamlessly when startup animation completes or is skipped."""
        if getattr(self, "_is_destroyed", False):
            return
        log.info("Startup animation finished — presenting dashboard in READY TO SCAN state.")
        self._show_page("dashboard")
        self.safe_after(3500, self._prewarm_next_page, ["threats", "ransomware", "sentinel_ai", "settings"])



    def safe_after(self, ms: int, fn, *args, **kwargs):
        """Schedule a callback and track its ID for safe cancellation upon window destruction."""
        if getattr(self, "_is_destroyed", False):
            return None
        aid = None
        def wrapper():
            if not getattr(self, "_is_destroyed", False):
                try:
                    p = getattr(self, "_pending_after_ids", None)
                    if p is not None and aid is not None:
                        p.discard(aid)
                    if hasattr(self, "winfo_exists") and self.winfo_exists():
                        fn(*args, **kwargs)
                except Exception:
                    pass
            else:
                p = getattr(self, "_pending_after_ids", None)
                if p is not None and aid is not None:
                    p.discard(aid)
        try:
            aid = self.after(ms, wrapper)
            p = getattr(self, "_pending_after_ids", None)
            if p is not None and aid is not None:
                p.add(aid)
            return aid
        except Exception:
            return None

    def destroy(self) -> None:
        """Cancel all pending timers and destroy child pages cleanly without Tkinter errors."""
        self._is_destroyed = True

        # 1. Cancel tracked pending after ids
        ids = list(getattr(self, "_pending_after_ids", set()))
        if hasattr(self, "_pending_after_ids"):
            self._pending_after_ids.clear()
        for aid in ids:
            try:
                self.after_cancel(aid)
            except Exception:
                pass

        # 2. Cancel all pending after scripts in Tcl (including CTk internal timers)
        try:
            if hasattr(self, "tk") and self.tk:
                for after_id in self.tk.eval("after info").split():
                    try:
                        self.after_cancel(after_id)
                    except Exception:
                        pass
        except Exception:
            pass

        # 3. Destroy instantiated pages
        for page in list(getattr(self, "_pages", {}).values()):
            try:
                page.destroy()
            except Exception:
                log.exception("Failed to destroy page during shutdown")
        if hasattr(self, "_pages"):
            self._pages.clear()

        try:
            super().destroy()
        except Exception:
            log.exception("Failed to destroy Tk root cleanly")

        # Guarantee the event loop ends even if a child widget teardown raised.
        try:
            if self.winfo_exists():
                self.tk.call("destroy", ".")
        except Exception:
            pass

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
        from gui.pages.exhibition_lab import ExhibitionLabPage
        from gui.pages.guided_tour import GuidedTourPage
        from gui.pages.attack_replay_page import AttackReplayPage
        from gui.pages.ai_observatory_page import AIObservatoryPage
        from gui.pages.integrity_watchtower_page import IntegrityWatchtowerPage
        from gui.pages.applications_center import ApplicationsCenterPage
        from gui.pages.command_center_page import CommandCenterPage
        from gui.pages.story_mode_page import StoryModePage
        from gui.pages.challenge_mode_page import ChallengeModePage
        self._page_classes = {
            "dashboard":           DashboardPage,
            "exhibition":          ExhibitionPage,
            "exhibition_lab":      ExhibitionLabPage,
            "guided_tour":         GuidedTourPage,
            "attack_replay":       AttackReplayPage,
            "ai_observatory":      AIObservatoryPage,
            "integrity_watchtower": IntegrityWatchtowerPage,
            "applications_center": ApplicationsCenterPage,
            "command_center":      CommandCenterPage,
            "story_mode":          StoryModePage,
            "challenge_mode":      ChallengeModePage,
            "threats":             ThreatsPage,
            "sentinel_ai":         SentinelAIPage,
            "ransomware":          RansomwarePage,
            "settings":            SettingsPage,
        }

    # -- Navigation --------------------------------------------------------
    def _show_page(self, uid: str) -> None:
        if self._current_page == uid and uid in self._pages:
            return

        old_uid = self._current_page
        old_frame = self._pages.get(old_uid) if old_uid else None

        # 1. Instantiate target page if not already cached, keeping previous page fully visible
        if uid not in self._pages:
            try:
                log.info("Instantiating page: %s", uid)
                cls = self._page_classes[uid]
                frame = cls(self, config=self._config)
                self._pages[uid] = frame
            except Exception as e:
                log.critical("Failed to construct page %s: %s", uid, e, exc_info=True)
                if old_frame:
                    old_frame.grid(row=0, column=1, sticky="nsew")
                    tk.Misc.lift(old_frame)
                else:
                    # Provide visual error frame so the window is never blank black
                    err_frame = ctk.CTkFrame(self, fg_color=C["bg"])
                    err_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
                    ctk.CTkLabel(
                        err_frame,
                        text=f"Failed to load {uid.capitalize()}",
                        font=ctk.CTkFont(size=20, weight="bold"),
                        text_color=C["danger"],
                    ).pack(anchor="w", pady=(20, 10))
                    ctk.CTkLabel(
                        err_frame,
                        text=f"Error details:\n{e}\n\nPlease inspect the error logs at logs/app.log.",
                        font=ctk.CTkFont(size=13),
                        text_color=C["text"],
                        justify="left",
                    ).pack(anchor="w", pady=10)
                    self._pages[uid] = err_frame
                try:
                    import tkinter.messagebox as mbox
                    mbox.showerror("Page Load Error", f"Failed to load {uid.capitalize()} view:\n\n{e}")
                except Exception:
                    pass
                return

        # 2. Display new page first, lifting it to prevent any blank visual gap
        target_frame = self._pages[uid]
        try:
            target_frame.grid(row=0, column=1, sticky="nsew")
            tk.Misc.lift(target_frame)
            if uid == "dashboard":
                log.info("Dashboard geometry/layout completed.")
        except Exception as e:
            log.error("Failed to grid page %s: %s", uid, e)
            if old_frame:
                old_frame.grid(row=0, column=1, sticky="nsew")
                tk.Misc.lift(old_frame)
            return

        # 3. Safely remove previous page now that target is confirmed gridded and visible
        if old_frame and old_frame != target_frame:
            old_frame.grid_remove()

        try:
            self.update_idletasks()
        except Exception:
            pass

        # 4. Synchronize sidebar button highlights
        for key, btn in self._nav_btns.items():
            btn.configure(
                fg_color=C["accent"] if key == uid else "transparent",
                text_color=C["white"] if key == uid else C["muted"],
            )

        self._current_page = uid
        try:
            hook = getattr(target_frame, "on_shown", None)
            if callable(hook):
                hook()
        except Exception as e:
            log.debug("on_shown hook failed for %s: %s", uid, e)
        log.debug("Switched to page: %s", uid)

    def _prewarm_next_page(self, queue: list) -> None:
        """Pre-warm pages during idle intervals so subsequent clicks have zero lag and zero blank screen."""
        if not queue:
            return
        next_uid = queue.pop(0)
        if next_uid not in self._pages:
            try:
                log.debug("Prewarming page: %s", next_uid)
                cls = self._page_classes[next_uid]
                frame = cls(self, config=self._config)
                self._pages[next_uid] = frame
            except Exception as e:
                log.warning("Prewarming page %s failed: %s", next_uid, e)
        if queue and not getattr(self, "_is_destroyed", False):
            self.safe_after(2000, self._prewarm_next_page, queue)



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



        self.safe_after(1000, self._tick)

    

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

        # Stop the SOC refresh thread before the Tk root disappears so the
        # worker never touches destroyed widgets.
        try:
            dashboard = None
            if isinstance(getattr(self, "_pages", None), dict):
                dashboard = self._pages.get("dashboard")
            if dashboard is not None and hasattr(dashboard, "stop_soc"):
                dashboard.stop_soc(wait=True)
        except Exception:
            log.exception("Failed to stop SOC monitoring on close")

        try:
            from guard.sentinel_guard import get_guard_instance
            get_guard_instance().stop()
        except Exception:
            pass

        cfg.save(self._config)

        try:
            self.destroy()
        finally:
            # A teardown error must never leave the Tk mainloop running with
            # no window: that leaves an invisible process holding the
            # single-instance lock.
            try:
                self.quit()
            except Exception:
                pass



    def _start_background_services(self) -> None:
        """Start background services like Guard and ML preload."""
        import threading
        
        def _init_thread():
            try:
                import time
                import logging
                log = logging.getLogger(__name__)
                log.info("Starting background services asynchronously...")
                
                # 1. Preload ML model eagerly so the first scan is instantaneous
                from ml.predictor import MLPredictor
                predictor = MLPredictor()
                if not predictor.is_loaded():
                    predictor.load_model()
                    log.info("ML Model preloaded successfully.")

                # 2. Start SentinelGuard
                from guard.sentinel_guard import get_guard_instance
                guard = get_guard_instance()
                if not guard.is_running():
                    guard.start()
                    log.info("Background Guard started successfully.")
                
                # 3. Initialize SentinelAI in background
                self.ai_copilot.initialize()
                    
            except Exception as e:
                log.error("Failed to start background services: %s", e)
                
        threading.Thread(target=_init_thread, daemon=True, name="BackgroundInit").start()

