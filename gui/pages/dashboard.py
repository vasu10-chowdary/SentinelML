"""
SentinelML V2 — Dashboard page
================================
Professional dashboard with:
- System status card
- Fast Live Scan button (Phase 7: connected to ML)
- Risk meter visualization
- Stat tiles (scans, threats, blocked, uptime)
- Guard status indicator
- Recent activity feed
"""

from gui.pages.scan_visualizer import ScanVisualizer
import threading
import customtkinter as ctk
from constants import COLOURS as C
from utils.logging_config import get_gui_logger

log = get_gui_logger()


class DashboardPage(ctk.CTkFrame):
    """Main dashboard displayed when the app opens."""

    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=C["bg"], **kwargs)
        self._config = config
        self._threat_level = "SAFE"  # SAFE, WARNING, CRITICAL
        self._guard_active = False   # Guard status
        self._risk_score = 0.0       # 0.0 to 1.0
        self._scanning = False       # Scan in progress
        self._scans_completed = 0    # Counter
        self._last_scan_result = None  # Set after first scan completes

        # ML components (lazy loaded)
        self._predictor = None
        self._scanner = None
        
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────
    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)  # Risk meter column
        self.grid_rowconfigure(3, weight=1)

        # ── Demo Mode Banner ─────────────────────────────────────────────
        import demo_data
        if demo_data.is_demo_mode():
            demo_banner = ctk.CTkFrame(
                self,
                fg_color="#ff6b00",  # Orange
                corner_radius=0,
                height=40
            )
            demo_banner.grid(row=0, column=0, columnspan=2, sticky="ew", padx=0, pady=0)
            
            ctk.CTkLabel(
                demo_banner,
                text="🎓 DEMO MODE - SIMULATED DATA FOR DEMONSTRATION PURPOSES 🎓",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#000000",
            ).pack(pady=10)
            
            header_row = 1
        else:
            header_row = 0

        # ── Page header ──────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=header_row, column=0, columnspan=2, sticky="ew", padx=32, pady=(28, 0))

        ctk.CTkLabel(
            header,
            text="Dashboard",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color=C["white"],
        ).pack(side="left")

        ctk.CTkLabel(
            header,
            text="Real-time threat detection and system monitoring",
            font=ctk.CTkFont(size=13),
            text_color=C["muted"],
        ).pack(side="left", padx=(14, 0), pady=(6, 0))
        
        # Guard status indicator in header
        self._guard_status_label = ctk.CTkLabel(
            header,
            text="⬤ Guard: Inactive",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["muted"],
        )
        self._guard_status_label.pack(side="right")

        # ── Status card ──────────────────────────────────────────────────
        status_card = ctk.CTkFrame(
            self,
            fg_color=C["panel"],
            corner_radius=14,
            border_width=1,
            border_color=C["border"],
        )
        status_card.grid(row=1, column=0, sticky="ew", padx=32, pady=(22, 0))
        status_card.grid_columnconfigure(1, weight=1)

        # Status indicator dot
        self._status_dot = ctk.CTkLabel(
            status_card,
            text="●",
            font=ctk.CTkFont(size=28),
            text_color=C["green"],
        )
        self._status_dot.grid(row=0, column=0, padx=(24, 12), pady=22, rowspan=2)

        self._status_title = ctk.CTkLabel(
            status_card,
            text="SYSTEM SAFE",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=C["green"],
            anchor="w",
        )
        self._status_title.grid(row=0, column=1, sticky="w", pady=(22, 2))

        self._status_desc = ctk.CTkLabel(
            status_card,
            text="No threats detected. Real-time protection active.",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
            anchor="w",
        )
        self._status_desc.grid(row=1, column=1, sticky="w", pady=(0, 22))

        self._scan_btn = ctk.CTkButton(
            status_card,
            text="⚡ Fast Live Scan",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=C["accent"],
            hover_color="#00b896",
            text_color="#0d1117",
            corner_radius=8,
            width=150,
            height=38,
            command=self._on_scan,
        )
        self._scan_btn.grid(row=0, column=2, rowspan=2, padx=(0, 24))

        # ── Risk Meter (right side) ──────────────────────────────────────
        self._build_risk_meter()

        # ── Stat tiles row ───────────────────────────────────────────────
        tiles_row = ctk.CTkFrame(self, fg_color="transparent")
        tiles_row.grid(row=2, column=0, columnspan=2, sticky="new", padx=32, pady=22)
        tiles_row.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="tile")

        self._tile_scans   = self._make_tile(tiles_row, "Scans Today",    "0",  C["accent2"],  0)
        self._tile_threats = self._make_tile(tiles_row, "Threats Found",  "0",  C["red"],      1)
        self._tile_blocked = self._make_tile(tiles_row, "Blocked",        "0",  C["green"],    2)
        self._tile_uptime  = self._make_tile(tiles_row, "Guard Uptime",   "0m", C["yellow"],   3)

        # ── Recent activity label ─────────────────────────────────────────
        ctk.CTkLabel(
            self,
            text="Recent Activity",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=C["white"],
            anchor="w",
        ).grid(row=3, column=0, columnspan=2, sticky="w", padx=32, pady=(4, 8))

        # ── Activity feed placeholder ─────────────────────────────────────
        feed = ctk.CTkFrame(
            self,
            fg_color=C["panel"],
            corner_radius=12,
            border_width=1,
            border_color=C["border"],
        )
        feed.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=32, pady=(0, 24))
        self.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(
            feed,
            text="No recent activity.\nRun a scan or wait for the background guard to report.",
            font=ctk.CTkFont(size=13),
            text_color=C["muted"],
            justify="center",
        ).place(relx=0.5, rely=0.5, anchor="center")
    
    def _build_risk_meter(self) -> None:
        """Build the risk meter visualization."""
        risk_frame = ctk.CTkFrame(
            self,
            fg_color=C["panel"],
            corner_radius=14,
            border_width=1,
            border_color=C["border"],
            width=200,
        )
        risk_frame.grid(row=1, column=1, sticky="ns", padx=(0, 32), pady=(22, 0))
        risk_frame.grid_propagate(False)
        
        ctk.CTkLabel(
            risk_frame,
            text="RISK METER",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=C["muted"],
        ).pack(pady=(16, 8))
        
        # Risk score display
        self._risk_score_label = ctk.CTkLabel(
            risk_frame,
            text="0%",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=C["green"],
        )
        self._risk_score_label.pack(pady=(4, 8))
        
        # Progress bar representing risk
        self._risk_progress = ctk.CTkProgressBar(
            risk_frame,
            width=160,
            height=12,
            corner_radius=6,
            progress_color=C["green"],
        )
        self._risk_progress.pack(pady=(0, 12))
        self._risk_progress.set(0.0)
        
        # Risk level labels
        self._risk_level_label = ctk.CTkLabel(
            risk_frame,
            text="SAFE",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C["green"],
        )
        self._risk_level_label.pack(pady=(4, 16))

    # ── Helpers ───────────────────────────────────────────────────────────
    @staticmethod
    def _make_tile(
        parent, label: str, value: str, accent: str, col: int
    ) -> ctk.CTkLabel:
        """Create a stat tile and return the value label (so it can be updated)."""
        card = ctk.CTkFrame(
            parent,
            fg_color=C["panel"],
            corner_radius=12,
            border_width=1,
            border_color=C["border"],
        )
        card.grid(row=0, column=col, padx=(0, 14) if col < 3 else 0, sticky="ew")

        ctk.CTkLabel(
            card,
            text=label,
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
        ).pack(anchor="w", padx=18, pady=(16, 2))

        val_lbl = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=accent,
        )
        val_lbl.pack(anchor="w", padx=18, pady=(0, 16))
        return val_lbl

    # ── Event handlers ────────────────────────────────────────────────────
    def _close_visualizer(self):
        if getattr(self, "visualizer", None):
            self.visualizer.place_forget()
            self.visualizer = None

    def _on_scan(self) -> None:
        """Triggered by Fast Live Scan button. Runs scanner + ML in background thread."""
        if self._scanning:
            log.warning("Scan already in progress")
            return
        
        log.info("User initiated Fast Live Scan")
        self._scanning = True
        self._scan_btn.configure(text="⚡ Scanning…", state="disabled")
        
        self.visualizer = ScanVisualizer(self, on_close=self._close_visualizer)
        self.visualizer.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        # Run scan in background thread to keep GUI responsive
        thread = threading.Thread(target=self._run_scan_thread, daemon=True, name="ScanThread")
        thread.start()
    
    def _run_scan_thread(self) -> None:
        """Background thread for scanning. DO NOT call GUI methods directly from here."""
        try:
            log.info("Scan thread started")
            
            # Check if demo mode is enabled
            import demo_data
            if demo_data.is_demo_mode():
                log.info("Demo mode: Using simulated scan data")
                import time
                
                # Simulate scanning delay
                time.sleep(2)
                
                # Get random demo scan result
                demo_result = demo_data.generate_random_demo_scan()
                
                threat_level = demo_result["threat_level"]
                probability = demo_result["probability"]
                
                log.info("Demo scan complete: %s (%.4f)", threat_level, probability)
                
                # Update GUI from main thread
                self.after(0, self._on_scan_complete, threat_level, probability, demo_result)
                return
            
            # REAL SCAN MODE - Use integrated scan engine
            log.info("Starting REAL scan using scan engine")
            
            from scanner.scan_engine import ScanEngine, ScanType
            
            # Create scan engine
            engine = ScanEngine()
            
            # Define progress callback to update GUI
            def progress_update(scan_result):
                # Update GUI from main thread with real progress
                self.after(0, self._update_scan_progress, scan_result)
            
            # Run QUICK scan (fast scan of monitored directories)
            log.info("Executing QUICK scan...")
            result = engine.scan(ScanType.QUICK, progress_callback=progress_update)
            
            log.info("Scan complete: state=%s, files=%d, dirs=%d, processes=%d, ml=%.4f",
                    result.state.value, result.files_inspected, result.directories_inspected,
                    result.processes_analyzed, result.ml_probability)
            
            # Check scan result
            if not result.was_successful():
                log.error("Scan failed or incomplete: state=%s, error=%s", 
                         result.state.value, result.error_message)
                self.after(0, self._on_scan_error, result.error_message or "Scan incomplete", result)
                return
            
            # Update GUI from main thread
            self.after(0, self._on_scan_complete, result.threat_level, result.ml_probability, result)
            
        except Exception as e:
            log.error("Scan thread failed: %s", e, exc_info=True)
            self.after(0, self._on_scan_error, str(e))
    
    def _update_scan_progress(self, scan_result) -> None:
        """Update GUI with real-time scan progress (called from main thread)."""
        try:
            if getattr(self, "visualizer", None):
                self.visualizer.update_progress(scan_result)
                
            # Update status description with progress
            state_name = scan_result.state.value.upper().replace("_", " ")
            progress_text = f"{state_name}: "
            
            if scan_result.files_inspected > 0:
                progress_text += f"{scan_result.files_inspected} files, "
            if scan_result.directories_inspected > 0:
                progress_text += f"{scan_result.directories_inspected} dirs, "
            if scan_result.processes_analyzed > 0:
                progress_text += f"{scan_result.processes_analyzed} processes"
            
            self._status_desc.configure(text=progress_text, text_color=C["muted"])
            
            if hasattr(self, 'core'):
                state_upper = scan_result.state.value.upper()
                if state_upper in ("SCANNING", "ANALYZING"):
                    self.core.update_data(scan_result)
                    self.core.set_state(state_upper)

            
        except Exception as e:
            log.warning("Failed to update progress: %s", e)
    
    def _on_scan_complete(self, threat_level: str, probability: float, scan_result=None) -> None:
        """Called from main thread when scan completes successfully."""
        self._scanning = False
        if getattr(self, "visualizer", None):
            self.visualizer.on_complete(threat_level, probability, scan_result)
        self._scans_completed += 1

        if scan_result:
            self._last_scan_result = scan_result
        
        # Update threat status
        self.update_threat_status(threat_level, probability)
        
        # Update scan counter
        self.update_stats(scans=self._scans_completed)
        
        # Log scan statistics if available
        if scan_result and hasattr(scan_result, 'files_inspected'):
            log.info("Scan stats: %d files, %d dirs, %d processes, %.2fs",
                    scan_result.files_inspected,
                    scan_result.directories_inspected,
                    scan_result.processes_analyzed,
                    scan_result.elapsed_seconds)
        
        # Generate alert if threat detected
        if threat_level != "SAFE":
            self._generate_scan_alert(threat_level, probability, scan_result)
        
        # Re-enable scan button
        self._scan_btn.configure(text="⚡ Fast Live Scan", state="normal")
        
        log.info("Scan results displayed to user")
    
    def _generate_scan_alert(self, threat_level: str, probability: float, scan_result=None) -> None:
        """Generate alert when threat is detected."""
        try:
            from alerts.alert_manager import get_alert_manager
            
            manager = get_alert_manager()
            
            severity_map = {
                "CRITICAL": "CRITICAL",
                "WARNING": "HIGH",
            }
            
            title_map = {
                "CRITICAL": "⚠ RANSOMWARE DETECTED",
                "WARNING": "Suspicious Activity Detected",
            }
            
            # Build detailed message with scan statistics
            if scan_result and hasattr(scan_result, 'files_inspected'):
                evidence = f"Scanned {scan_result.files_inspected} files, {scan_result.directories_inspected} directories, and {scan_result.processes_analyzed} processes. "
                if scan_result.suspicious_files:
                    evidence += f"Found {len(scan_result.suspicious_files)} suspicious files. "
                message = f"{title_map.get(threat_level)} with {probability*100:.1f}% confidence. {evidence}"
            else:
                message_map = {
                    "CRITICAL": f"Critical threat detected with {probability*100:.1f}% confidence. Immediate action required.",
                    "WARNING": f"Suspicious behavior detected with {probability*100:.1f}% confidence. Review recommended.",
                }
                message = message_map.get(threat_level, f"Threat level: {threat_level}")
            
            metadata = {
                "threat_level": threat_level,
                "probability": probability,
                "scan_id": self._scans_completed
            }
            
            # Add scan statistics to metadata
            if scan_result:
                metadata["files_scanned"] = getattr(scan_result, 'files_inspected', 0)
                metadata["dirs_scanned"] = getattr(scan_result, 'directories_inspected', 0)
                metadata["processes_scanned"] = getattr(scan_result, 'processes_analyzed', 0)
                metadata["elapsed_seconds"] = getattr(scan_result, 'elapsed_seconds', 0)
                if hasattr(scan_result, 'suspicious_files') and scan_result.suspicious_files:
                    metadata["suspicious_file_count"] = len(scan_result.suspicious_files)
            
            manager.add_alert(
                severity=severity_map.get(threat_level, "MEDIUM"),
                category="scanner",
                title=title_map.get(threat_level, "Threat Detected"),
                message=message,
                source="Fast Live Scan",
                metadata=metadata
            )
            
            log.info("Alert generated for threat level: %s", threat_level)
            
        except Exception as e:
            log.error("Failed to generate alert: %s", e)
    
    def _on_scan_error(self, error_msg: str, scan_result=None) -> None:
        """Called from main thread when scan fails - CRITICAL: NEVER show SAFE after error."""
        self._scanning = False
        if getattr(self, "visualizer", None):
            self.visualizer.on_complete("ERROR", 0.0, scan_result, error=error_msg)
        if scan_result:
            self._last_scan_result = scan_result
        self._scan_btn.configure(text="⚡ Fast Live Scan", state="normal")
        
        log.error("⚠️ CRITICAL: Scan failed: %s", error_msg)
        
        # **SECURITY-CRITICAL: Display SCAN ERROR state, NOT SAFE**
        # Update status card to SCAN ERROR (persistent, not temporary)
        self._status_dot.configure(text_color=C["orange"])
        self._status_title.configure(text="SCAN ERROR", text_color=C["orange"])
        self._status_desc.configure(
            text=f"⚠️ Analysis failed: {error_msg}. No security classification available.",
            text_color=C["red"]
        )
        
        # Update risk meter to show unknown state
        self._risk_score_label.configure(text="ERR", text_color=C["orange"])
        self._risk_progress.configure(progress_color=C["orange"])
        self._risk_progress.set(0.0)
        self._risk_level_label.configure(text="ERROR", text_color=C["orange"])
        
        # DO NOT reset to SAFE after timeout - error state must persist
        # User must run a successful scan to get security classification

    # ── Public API (called by main_window.py or scanner) ──────────────────
    def update_stats(
        self,
        scans: int = 0,
        threats: int = 0,
        blocked: int = 0,
        uptime_s: int = 0,
    ) -> None:
        """Update stat tiles."""
        minutes = uptime_s // 60
        self._tile_scans.configure(text=str(scans))
        self._tile_threats.configure(text=str(threats))
        self._tile_blocked.configure(text=str(blocked))
        self._tile_uptime.configure(text=f"{minutes}m")
    
    def update_threat_status(self, level: str, probability: float = 0.0) -> None:
        """
        Update threat status display.
        
        Args:
            level: "SAFE", "WARNING", or "CRITICAL"
            probability: Threat probability 0.0 to 1.0
        """
        self._threat_level = level
        self._risk_score = probability
        
        # Update status card
        color_map = {
            "SAFE": C["green"],
            "WARNING": C["yellow"],
            "CRITICAL": C["red"],
        }
        color = color_map.get(level, C["green"])
        
        self._status_dot.configure(text_color=color)
        self._status_title.configure(text=f"SYSTEM {level}", text_color=color)
        
        desc_map = {
            "SAFE": "No threats detected. Real-time protection active.",
            "WARNING": "Suspicious activity detected. Review threat log.",
            "CRITICAL": "⚠ RANSOMWARE DETECTED! Immediate action required.",
        }
        self._status_desc.configure(text=desc_map.get(level, "Unknown status"))
        
        # Update risk meter
        percent = int(probability * 100)
        self._risk_score_label.configure(text=f"{percent}%", text_color=color)
        self._risk_progress.configure(progress_color=color)
        self._risk_progress.set(probability)
        self._risk_level_label.configure(text=level, text_color=color)
    
    def update_guard_status(self, active: bool) -> None:
        """
        Update guard status indicator.
        
        Args:
            active: True if guard is running, False otherwise
        """
        self._guard_active = active
        if active:
            self._guard_status_label.configure(
                text="⬤ Guard: Active",
                text_color=C["green"]
            )
        else:
            self._guard_status_label.configure(
                text="⬤ Guard: Inactive",
                text_color=C["muted"]
            )


    def _generate_incident_report(self) -> None:
        import tkinter.messagebox
        include_ai = False
        if getattr(self._main_window, "ai_copilot", None):
            include_ai = tkinter.messagebox.askyesno("SentinelAI", "Include an AI-generated summary in this report? (This may take a few seconds)")

        if include_ai:
            if hasattr(self, "_ai_desc"):
                self._ai_desc.configure(text="Generating AI report summary...", text_color="#00d4ff")
            self.update_idletasks()
            import threading
            def _async_report():
                try:
                    ai_summary = self._main_window.ai_copilot.explain_scan(self._last_scan_result)
                    self.after(0, lambda: self._do_generate_report(ai_summary))
                except Exception as e:
                    self.after(0, lambda: self._do_generate_report(f"AI failed: {e}"))
            threading.Thread(target=_async_report, daemon=True).start()
        else:
            self._do_generate_report(None)

    def _do_generate_report(self, ai_summary: str = None) -> None:
        try:
            if ai_summary is not None and hasattr(self, "_ai_desc"):
                self._ai_desc.configure(text="AI summary complete.", text_color="#ffffff")
            import datetime
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"SentinelML_Incident_Report_{ts}.txt"
            
            import tkinter.filedialog
            import os
            
            report_path = tkinter.filedialog.asksaveasfilename(
                title="Save SentinelML Incident Report",
                initialfile=default_name,
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if not report_path:
                return
                
            import socket, platform
            hostname = socket.gethostname()
            os_info = platform.system() + " " + platform.release()
            
            report = f"SENTINELML V2 INCIDENT REPORT\n===============================\n"
            report += f"Timestamp: {datetime.datetime.now().isoformat()}\n"
            report += f"Hostname: {hostname}\nPlatform: {os_info}\n\n"

            if hasattr(self, "_last_scan_result") and self._last_scan_result is not None:
                sr = self._last_scan_result
                report += f"SCAN STATISTICS\n---------------\n"
                report += f"Scan State: {sr.state.value}\n"
                report += f"Files Inspected: {getattr(sr, 'files_inspected', 'N/A')}\n"
                report += f"Dirs Inspected: {getattr(sr, 'directories_inspected', 'N/A')}\n"
                report += f"Processes Analyzed: {getattr(sr, 'processes_analyzed', 'N/A')}\n"
                report += f"Duration: {getattr(sr, 'elapsed_seconds', 0.0):.2f} seconds\n\n"
                report += f"ANALYSIS RESULTS\n----------------\n"
                report += f"Threat Level: {getattr(sr, 'threat_level', 'ANALYSIS_ERROR')}\n"
                report += f"ML Executed: {getattr(sr, 'ml_executed', False)}\n"
                if getattr(sr, 'ml_executed', False):
                    report += f"ML Probability (malicious): {getattr(sr, 'ml_probability', 0.0):.4f}\n"
                if getattr(sr, 'error_message', None):
                    report += f"Errors: {sr.error_message}\n"
                if getattr(sr, 'suspicious_files', None):
                    report += f"Suspicious Files Found: {len(sr.suspicious_files)}\n"
                    for sf in sr.suspicious_files[:10]:
                        report += f"  - {sf}\n"
                features = getattr(sr, '_features', None)
                if features is not None and hasattr(features, 'shape') and features.shape == (1, 19):
                    f_list = features[0].tolist()
                    FEATURE_NAMES = [
                        "total_processes", "suspicious_process_count", "avg_entropy",
                        "max_entropy", "high_entropy_region_count", "malfind_injection_count",
                        "crypto_dll_count", "cmd_vssadmin_count", "network_connection_count",
                        "unique_external_ips", "file_handle_count", "registry_handle_count",
                        "orphan_process_count", "powershell_process_count",
                        "unsigned_module_count", "suspicious_mutex_count",
                        "abnormal_privilege_count", "suspicious_thread_count",
                        "defender_tampering_count"
                    ]
                    report += "\nML FEATURES (19)\n----------------\n"
                    for name, val in zip(FEATURE_NAMES, f_list):
                        report += f"  {name}: {val:.4f}\n"
            else:
                report += "No completed scan result available.\n"


            if ai_summary:
                report += f"\nSENTINELAI ANALYSIS\n-------------------\n{ai_summary}\n"
                
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report)
                
            import tkinter.messagebox
            if tkinter.messagebox.askyesno("Report Saved", f"Report saved successfully to:\n{report_path}\n\nWould you like to open it now?"):
                import webbrowser
                webbrowser.open(report_path)
                
        except Exception as e:
            logging.getLogger(__name__).error("Failed to generate report: %s", e)
