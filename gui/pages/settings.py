"""
SentinelML V2 - Settings page
================================
User preferences: permissions toggles, startup behaviour, theme,
and an About section.  Phase 1: all toggles are wired to config.py.
"""

import customtkinter as ctk
import config as cfg
from constants import COLOURS as C


class SettingsPage(ctk.CTkFrame):
    """Settings / preferences page."""

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=C["bg"], **kwargs)
        self._config = config
        self._main_window = master
        self._build()

    # -- Build -------------------------------------------------------------
    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)

        # -- Header -------------------------------------------------------
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=32, pady=(28, 0))
        ctk.CTkLabel(
            hdr, text="Settings",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color=C["white"],
        ).pack(side="left")
        ctk.CTkLabel(
            hdr, text="Preferences & permissions",
            font=ctk.CTkFont(size=13),
            text_color=C["muted"],
        ).pack(side="left", padx=(14, 0), pady=(6, 0))

        # -- Scrollable content --------------------------------------------
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.grid(row=1, column=0, sticky="nsew", padx=32, pady=(20, 24))
        self.grid_rowconfigure(1, weight=1)
        scroll.grid_columnconfigure(0, weight=1)

        row_idx = [0]

        def section(title: str) -> None:
            ctk.CTkLabel(
                scroll,
                text=title.upper(),
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=C["muted"],
            ).grid(row=row_idx[0], column=0, sticky="w", pady=(18, 6))
            row_idx[0] += 1

        def toggle_row(label: str, sublabel: str, key: str) -> None:
            card = ctk.CTkFrame(
                scroll,
                fg_color=C["panel"],
                corner_radius=10,
                border_width=1,
                border_color=C["border"],
            )
            card.grid(row=row_idx[0], column=0, sticky="ew", pady=(0, 8))
            card.grid_columnconfigure(0, weight=1)
            row_idx[0] += 1

            txt_col = ctk.CTkFrame(card, fg_color="transparent")
            txt_col.grid(row=0, column=0, sticky="w", padx=18, pady=14)
            ctk.CTkLabel(
                txt_col, text=label,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=C["white"],
            ).pack(anchor="w")
            ctk.CTkLabel(
                txt_col, text=sublabel,
                font=ctk.CTkFont(size=11),
                text_color=C["muted"],
            ).pack(anchor="w")

            current_val = self._config.get("permissions", {}).get(key, False)
            var = ctk.BooleanVar(value=current_val)
            ctk.CTkSwitch(
                card, text="",
                variable=var,
                onvalue=True, offvalue=False,
                progress_color=C["accent"],
                button_color=C["white"],
                button_hover_color=C["accent"],
                command=lambda: self._toggle(key, var.get()),
            ).grid(row=0, column=1, padx=18)

        # -- Permissions section -------------------------------------------
        section("Scan Permissions")
        toggle_row(
            "Process Scanning",
            "Allow scanning of running processes (recommended)",
            "process_scan",
        )
        toggle_row(
            "Filesystem Watch",
            "Monitor file system changes for suspicious patterns",
            "file_watch",
        )
        toggle_row(
            "Registry Monitoring",
            "Watch registry for persistence and tampering indicators",
            "registry_watch",
        )

        # -- Live SOC Monitoring section ------------------------------------
        section("Live SOC Monitoring")

        soc_cfg = self._config.setdefault("soc", {})

        soc_card = ctk.CTkFrame(
            scroll,
            fg_color=C["panel"],
            corner_radius=10,
            border_width=1,
            border_color=C["border"],
        )
        soc_card.grid(row=row_idx[0], column=0, sticky="ew", pady=(0, 8))
        soc_card.grid_columnconfigure(0, weight=1)
        row_idx[0] += 1

        soc_txt = ctk.CTkFrame(soc_card, fg_color="transparent")
        soc_txt.grid(row=0, column=0, sticky="w", padx=18, pady=14)
        ctk.CTkLabel(
            soc_txt,
            text="Background SOC Refresh",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C["white"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            soc_txt,
            text=(
                "Collects real host telemetry on a fixed schedule: processes, CPU/memory, "
                "file metadata changes in the monitored directories, network and alerts. "
                "No full-disk scan and no file hashing in this loop."
            ),
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
            justify="left",
            wraplength=560,
        ).pack(anchor="w", pady=(2, 0))

        self._soc_auto_var = ctk.BooleanVar(value=bool(soc_cfg.get("auto_refresh", True)))
        ctk.CTkSwitch(
            soc_card,
            text="",
            variable=self._soc_auto_var,
            onvalue=True,
            offvalue=False,
            progress_color=C["accent"],
            button_color=C["white"],
            button_hover_color=C["accent"],
            command=self._on_soc_auto_toggle,
        ).grid(row=0, column=1, padx=18)

        interval_card = ctk.CTkFrame(
            scroll,
            fg_color=C["panel"],
            corner_radius=10,
            border_width=1,
            border_color=C["border"],
        )
        interval_card.grid(row=row_idx[0], column=0, sticky="ew", pady=(0, 8))
        interval_card.grid_columnconfigure(0, weight=1)
        row_idx[0] += 1

        int_txt = ctk.CTkFrame(interval_card, fg_color="transparent")
        int_txt.grid(row=0, column=0, sticky="w", padx=18, pady=14)
        ctk.CTkLabel(
            int_txt,
            text="Refresh Interval",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C["white"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            int_txt,
            text=(
                "Default 60 seconds. Slow collections delay the next pass instead of "
                "queuing extra runs; the next refresh time is shown on the dashboard."
            ),
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
            justify="left",
            wraplength=560,
        ).pack(anchor="w", pady=(2, 0))

        interval_choices = ["30 seconds", "60 seconds", "120 seconds", "300 seconds"]
        current_interval = int(soc_cfg.get("interval_seconds", 60) or 60)
        current_choice = next(
            (c for c in interval_choices if int(c.split()[0]) == current_interval),
            "60 seconds",
        )
        self._soc_interval_menu = ctk.CTkOptionMenu(
            interval_card,
            values=interval_choices,
            width=140,
            fg_color=C["card"],
            button_color=C["border"],
            button_hover_color=C["accent"],
            text_color=C["white"],
            command=self._on_soc_interval_change,
        )
        self._soc_interval_menu.set(current_choice)
        self._soc_interval_menu.grid(row=0, column=1, padx=18)

        # -- Demo Mode section ----------------------------------------------
        section("Demo Mode")

        # Check current demo mode state
        import demo_data
        demo_enabled = demo_data.is_demo_mode()

        demo_card = ctk.CTkFrame(
            scroll,
            fg_color=C["panel"],
            corner_radius=10,
            border_width=1,
            border_color=C["border"],
        )
        demo_card.grid(row=row_idx[0], column=0, sticky="ew", pady=(0, 8))
        demo_card.grid_columnconfigure(0, weight=1)
        row_idx[0] += 1

        txt_col = ctk.CTkFrame(demo_card, fg_color="transparent")
        txt_col.grid(row=0, column=0, sticky="w", padx=18, pady=14)
        ctk.CTkLabel(
            txt_col,
            text="Demo Mode" + (" - ACTIVE" if demo_enabled else ""),
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C["accent"] if demo_enabled else C["white"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            txt_col,
            text="Use simulated data for demonstrations (no real scanning)",
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
        ).pack(anchor="w")

        demo_var = ctk.BooleanVar(value=demo_enabled)

        demo_sw = ctk.CTkSwitch(
            demo_card,
            text="",
            variable=demo_var,
            onvalue=True, offvalue=False,
            progress_color=C["accent"],
            button_color=C["white"],
            button_hover_color=C["accent"],
            command=lambda: self._toggle_demo_mode(demo_var.get()),
        )
        demo_sw.grid(row=0, column=1, padx=18)

        # Warning label
        if demo_enabled:
            warning = ctk.CTkLabel(
                demo_card,
                text="\u26a0 Restart application to disable demo mode",
                font=ctk.CTkFont(size=10),
                text_color=C["yellow"],
            )
            warning.grid(row=1, column=0, columnspan=2, sticky="w", padx=18, pady=(0, 14))

        # -- SentinelAI Copilot section ------------------------------------
        section("SentinelAI Copilot")

        ai_card = ctk.CTkFrame(
            scroll, fg_color=C["panel"], corner_radius=10,
            border_width=1, border_color=C["border"]
        )
        ai_card.grid(row=row_idx[0], column=0, sticky="ew", pady=(0, 8))
        ai_card.grid_columnconfigure(0, weight=1)
        row_idx[0] += 1

        ai_cfg = self._config.setdefault("ai", {})

        # 1. Enable Toggle
        toggle_frame = ctk.CTkFrame(ai_card, fg_color="transparent")
        toggle_frame.pack(fill="x", padx=18, pady=(14, 4))
        ctk.CTkLabel(
            toggle_frame, text="Enable SentinelAI",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C["white"]
        ).pack(side="left")

        ai_var = ctk.BooleanVar(value=bool(ai_cfg.get("enabled", False)))

        def _on_ai_toggle():
            ai_cfg["enabled"] = ai_var.get()
            cfg.save(self._config)
            if hasattr(self._main_window, "ai_copilot"):
                self._main_window.ai_copilot.config = ai_cfg
                import threading
                threading.Thread(
                    target=self._main_window.ai_copilot.initialize,
                    daemon=True
                ).start()

        ctk.CTkSwitch(
            toggle_frame, text="", command=_on_ai_toggle,
            variable=ai_var, onvalue=True, offvalue=False,
            progress_color=C["accent"]
        ).pack(side="right")

        # 2. Connection Mode Selection
        mode_frame = ctk.CTkFrame(ai_card, fg_color="transparent")
        mode_frame.pack(fill="x", padx=18, pady=4)
        ctk.CTkLabel(
            mode_frame, text="Connection Mode",
            font=ctk.CTkFont(size=12), text_color=C["muted"]
        ).pack(side="left")

        mode_var = ctk.StringVar(value=ai_cfg.get("mode", "backend"))

        def _on_mode(choice):
            if choice == "SentinelML AI Cloud":
                ai_cfg["mode"] = "backend"
            elif choice == "Local Gemini (BYOK)":
                ai_cfg["mode"] = "local"
            else:
                ai_cfg["mode"] = "auto"
            cfg.save(self._config)

        display_val = "SentinelML AI Cloud" if ai_cfg.get("mode") == "backend" else ("Local Gemini (BYOK)" if ai_cfg.get("mode") == "local" else "Auto")
        ctk.CTkOptionMenu(
            mode_frame, variable=ctk.StringVar(value=display_val),
            values=["SentinelML AI Cloud", "Local Gemini (BYOK)", "Auto"],
            command=_on_mode, fg_color=C["card"]
        ).pack(side="right")

        # 3. Backend URL (Cloud)
        url_frame = ctk.CTkFrame(ai_card, fg_color="transparent")
        url_frame.pack(fill="x", padx=18, pady=4)
        ctk.CTkLabel(
            url_frame, text="Backend URL",
            font=ctk.CTkFont(size=12), text_color=C["muted"]
        ).pack(side="left")
        
        url_entry = ctk.CTkEntry(url_frame, width=260, placeholder_text="https://...")
        url_entry.pack(side="right")
        existing_url = ai_cfg.get("backend_url", "http://127.0.0.1:8000")
        url_entry.insert(0, existing_url)

        # 4. Advanced / Developer Mode (Local Gemini Key)
        adv_label = ctk.CTkLabel(
            ai_card, text="Advanced / Developer Mode (Local Gemini BYOK)",
            font=ctk.CTkFont(size=11, weight="bold"), text_color=C["muted"]
        )
        adv_label.pack(anchor="w", padx=18, pady=(12, 4))
        
        key_frame = ctk.CTkFrame(ai_card, fg_color="transparent")
        key_frame.pack(fill="x", padx=18, pady=4)
        ctk.CTkLabel(
            key_frame, text="Gemini API Key",
            font=ctk.CTkFont(size=12), text_color=C["muted"]
        ).pack(side="left")

        key_entry = ctk.CTkEntry(key_frame, width=260, show="•", placeholder_text="(Optional) Fallback Gemini API key")
        key_entry.pack(side="right")
        existing_key = ai_cfg.get("gemini_api_key", "")
        if existing_key:
            key_entry.insert(0, existing_key)

        # 5. Action Buttons Row
        btn_frame = ctk.CTkFrame(ai_card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=18, pady=(12, 4))

        status_lbl = ctk.CTkLabel(
            btn_frame,
            text="Status: UNKNOWN",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"]
        )
        status_lbl.pack(side="left")

        def _save_and_apply():
            ai_cfg["gemini_api_key"] = key_entry.get().strip()
            ai_cfg["backend_url"] = url_entry.get().strip()
            cfg.save(self._config)
            
        def _test_ai():
            _save_and_apply()
            status_lbl.configure(text="Status: TESTING…", text_color=C["orange"])
            self.update_idletasks()
            import threading
            def _run():
                if hasattr(self._main_window, "ai_copilot"):
                    self._main_window.ai_copilot.config = ai_cfg
                    self._main_window.ai_copilot.initialize()
                    status = self._main_window.ai_copilot.status
                    detail = getattr(self._main_window.ai_copilot, "status_detail", "")
                    
                    if status == "READY":
                        label = f"Status: CONNECTED  —  {detail}"
                        color = C["green"]
                    else:
                        label = f"Status: UNAVAILABLE  —  {detail}"
                        color = C["red"]
                    self.after(0, lambda: status_lbl.configure(text=label, text_color=color))

            threading.Thread(target=_run, daemon=True).start()

        def _save_key_btn():
            _save_and_apply()
            status_lbl.configure(text="Settings saved. Click TEST to verify connection.", text_color=C["accent"])

        def _clear_key():
            key_entry.delete(0, "end")
            ai_cfg["gemini_api_key"] = ""
            cfg.save(self._config)
            status_lbl.configure(text="Status: KEY CLEARED", text_color=C["muted"])

        key_entry.bind("<FocusOut>", lambda e: _save_and_apply())
        url_entry.bind("<FocusOut>", lambda e: _save_and_apply())

        ctk.CTkButton(
            btn_frame, text="SAVE", width=80,
            command=_save_key_btn, fg_color=C["accent"], hover_color=C["card"], text_color=C["bg"]
        ).pack(side="right", padx=(6, 0))

        ctk.CTkButton(
            btn_frame, text="TEST CONNECTION", width=130,
            command=_test_ai, fg_color=C["card"], hover_color=C["accent"], text_color=C["white"]
        ).pack(side="right", padx=(6, 0))

        ctk.CTkButton(
            btn_frame, text="CLEAR KEY", width=80,
            command=_clear_key, fg_color=C["panel"], hover_color=C["red"], text_color=C["muted"]
        ).pack(side="right")
        
        # Space below
        ctk.CTkFrame(ai_card, fg_color="transparent", height=10).pack()

        # -- Startup section -----------------------------------------------
        section("Startup")
        toggle_row(
            "Launch at Windows startup",
            "Adds SentinelML to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (no admin needed)",
            "autostart",
        )

        # -- About section -------------------------------------------------
        section("About")
        about_card = ctk.CTkFrame(
            scroll,
            fg_color=C["panel"],
            corner_radius=10,
            border_width=1,
            border_color=C["border"],
        )
        about_card.grid(row=row_idx[0], column=0, sticky="ew", pady=(0, 8))
        row_idx[0] += 1

        from constants import APP_VERSION
        ctk.CTkLabel(
            about_card,
            text=f"SentinelML  \u00b7  Version {APP_VERSION}\n"
                 "Memory-Forensics-Based Ransomware Detection\n"
                 "Python  \u00b7  CustomTkinter  \u00b7  scikit-learn",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
            justify="left",
        ).pack(anchor="w", padx=18, pady=18)

    # -- Live SOC monitoring ----------------------------------------------
    def _soc_dashboard(self):
        pages = getattr(self._main_window, "_pages", None)
        if isinstance(pages, dict):
            page = pages.get("dashboard")
            if page is not None and hasattr(page, "_soc_monitor"):
                return page
        return None

    def _on_soc_auto_toggle(self) -> None:
        enabled = bool(self._soc_auto_var.get())
        self._config.setdefault("soc", {})["auto_refresh"] = enabled
        cfg.save(self._config)
        page = self._soc_dashboard()
        if page is not None:
            if enabled:
                page._soc_start()
            else:
                page._soc_stop()

    def _on_soc_interval_change(self, choice: str) -> None:
        try:
            seconds = int(str(choice).split()[0])
        except Exception:
            return
        self._config.setdefault("soc", {})["interval_seconds"] = seconds
        cfg.save(self._config)
        page = self._soc_dashboard()
        if page is not None:
            page._soc_monitor.apply_config(self._config)
            try:
                page._render_soc_status()
            except Exception:
                pass

    # -- Persistence -------------------------------------------------------
    def _toggle(self, key: str, value: bool) -> None:
        self._config.setdefault("permissions", {})[key] = value
        cfg.save(self._config)

        if key == "autostart":
            self._handle_autostart(value)

    def _toggle_demo_mode(self, enable: bool) -> None:
        """Toggle demo mode."""
        import demo_data

        if enable:
            demo_data.enable_demo_mode()
            # Show info dialog
            try:
                import tkinter
                from tkinter import messagebox
                messagebox.showinfo(
                    "Demo Mode Enabled",
                    "Demo mode is now enabled.\n\n"
                    "The application will use simulated data for demonstrations.\n\n"
                    "Restart the application for changes to take full effect."
                )
            except Exception:
                pass
        else:
            # Cannot disable demo mode without restart
            try:
                import tkinter
                from tkinter import messagebox
                messagebox.showwarning(
                    "Restart Required",
                    "To disable demo mode, restart the application without the --demo flag."
                )
            except Exception:
                pass

    @staticmethod
    def _handle_autostart(enable: bool) -> None:
        """Add / remove SentinelML from startup (Windows Registry / Linux XDG)."""
        try:
            import sys, os
            
            # Resolve executable safely across platforms
            if getattr(sys, "frozen", False):
                exe = sys.executable
            else:
                from pathlib import Path
                # Get the root path (utils/paths approach)
                exe = str(Path(__file__).parent.parent.parent / "app.py")
                
            from utils.platform_adapter import get_platform_adapter
            get_platform_adapter().set_autostart(enable, exe)
        except Exception:
            pass  # Non-fatal
