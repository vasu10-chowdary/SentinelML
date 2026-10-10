import customtkinter as ctk
import tkinter as tk
import time
import math
from constants import COLOURS as C
import logging

log = logging.getLogger("sentinel.gui.threats")

class GlassPanel(ctk.CTkFrame):
    def __init__(self, master, title, **kwargs):
        super().__init__(master, fg_color="#0a0f18", border_width=1, border_color="#1a2b4c", corner_radius=6, **kwargs)
        if title:
            self.title_lbl = ctk.CTkLabel(self, text=title, font=ctk.CTkFont(family="Consolas", size=13, weight="bold"), text_color="#00a8cc")
            self.title_lbl.pack(anchor="w", padx=10, pady=(5, 0))
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(fill="both", expand=True, padx=10, pady=5)

class ThreatsPage(ctk.CTkFrame):
    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color="#050810", **kwargs)
        self._config = config
        self._alert_manager = None  # Lazy loaded
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        
        ctk.CTkLabel(hdr, text="THREAT INVESTIGATION", font=ctk.CTkFont(family="Consolas", size=26, weight="bold"), text_color=C["white"]).pack(side="left")
        ctk.CTkLabel(hdr, text="SOC Incident Response & ML Telemetry", font=ctk.CTkFont(family="Consolas", size=13), text_color=C["muted"]).pack(side="left", padx=(14, 0), pady=(6, 0))

        # Main Scrollable Body
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        # Frame to hold dynamic content
        self.content_frame = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(1, weight=1)

        self.last_scan_id = None
        self.after(500, self._poll_scan_data)

    def _poll_scan_data(self):
        try:
            dashboard = None
            if hasattr(self.master, "_pages"):
                dashboard = self.master._pages.get("dashboard")
                
            if dashboard and hasattr(dashboard, "_last_scan_result"):
                scan_result = dashboard._last_scan_result
                if scan_result and getattr(scan_result, 'state', None):
                    s_val = scan_result.state.value.upper()
                    if s_val in ("SAFE", "WARNING", "THREAT_DETECTED", "SCAN_INCOMPLETE", "ANALYSIS_ERROR"):
                        if id(scan_result) != self.last_scan_id:
                            self.last_scan_id = id(scan_result)
                            self._build_report(scan_result)
            
            if self.last_scan_id is None:
                self._build_empty_state()
        except Exception as e:
            log.error(f"Error polling scan data: {e}")
            
        self.after(1000, self._poll_scan_data)

    def _build_empty_state(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        empty = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        empty.pack(expand=True, pady=100)
        
        ctk.CTkLabel(empty, text="NO THREAT EVENTS RECORDED", font=("Consolas", 18, "bold"), text_color="#00a8cc").pack()
        ctk.CTkLabel(empty, text="Completed scans and detected behavioral events will appear here.", font=("Consolas", 13), text_color=C["muted"]).pack(pady=10)

    def _build_report(self, scan_result):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        s_val = scan_result.state.value.upper()
        
        left_col = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        left_col.grid(row=0, column=0, sticky="nsew", padx=5)
        right_col = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        right_col.grid(row=0, column=1, sticky="nsew", padx=5)

        # -- LEFT COL: OVERVIEW & THREAT LEVEL --
        
        # Threat Level Indicator (SECTION 2)
        p_lvl = GlassPanel(left_col, "THREAT LEVEL")
        p_lvl.pack(fill="x", pady=5)
        
        if s_val == "SAFE":
            col, txt = C["green"], "SAFE"
            msg = "No significant malicious behavior was detected during the completed scan."
        elif s_val == "WARNING":
            col, txt = C["orange"], "WARNING"
            msg = "The observed behavior was classified as potentially malicious by the trained model."
        elif s_val == "THREAT_DETECTED":
            col, txt = C["red"], "THREAT DETECTED"
            msg = "The observed behavior was classified as potentially malicious by the trained model."
        elif s_val == "SCAN_INCOMPLETE":
            col, txt = C["muted"], "SCAN INCOMPLETE"
            msg = "Scan was interrupted or cancelled before completion. NO COMPLETE ANALYSIS = NO SAFE RESULT."
        elif s_val == "ANALYSIS_ERROR":
            col, txt = "#e3b341", "ANALYSIS ERROR"
            msg = "An error occurred during ML analysis or feature extraction."
        else:
            col, txt = C["muted"], "UNKNOWN"
            msg = "Status unknown."
            
        ctk.CTkLabel(p_lvl.content, text=f"[{txt}]", font=("Consolas", 24, "bold"), text_color=col).pack(pady=5)
        ctk.CTkLabel(p_lvl.content, text=msg, font=("Consolas", 11), text_color=C["white"], wraplength=400, justify="center").pack(pady=5)

        # Threat Overview (SECTION 1 & 5)
        p_over = GlassPanel(left_col, "INCIDENT DETAILS & OVERVIEW")
        p_over.pack(fill="x", pady=5)
        
        stats = [
            ("STATUS", txt),
            ("ML RISK", f"{getattr(scan_result, 'ml_probability', 0.0)*100:.1f}%"),
            ("PROCESSES INSPECTED", str(getattr(scan_result, 'processes_analyzed', 'N/A'))),
            ("FILES INSPECTED", str(getattr(scan_result, 'files_inspected', 'N/A'))),
            ("SCAN DURATION", f"{getattr(scan_result, 'elapsed_seconds', 0.0):.1f}s"),
            ("TIMESTAMP", time.strftime("%Y-%m-%d %H:%M:%S"))
        ]
        
        for k, v in stats:
            row = ctk.CTkFrame(p_over.content, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=k, font=("Consolas", 11, "bold"), text_color="#00d4ff", width=160, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=v, font=("Consolas", 11), text_color=C["white"], anchor="w").pack(side="left")

        # -- RIGHT COL: ML EVIDENCE & BEHAVIORAL INDICATORS --
        
        # Behavioral Indicators (SECTION 3)
        p_ind = GlassPanel(right_col, "BEHAVIORAL INDICATORS")
        p_ind.pack(fill="x", pady=5)
        
        features = getattr(scan_result, '_features', None)
        indicators = []
        if features is not None and len(features) > 0 and len(features[0]) == 19:
            f = features[0]
            if f[1] > 0: indicators.append(f"Suspicious Processes: {int(f[1])}")
            if f[4] > 0: indicators.append(f"High Entropy Files: {int(f[4])}")
            if f[5] > 0: indicators.append(f"Malfind Memory Injections: {int(f[5])}")
            if f[6] > 0: indicators.append(f"Crypto DLLs Loaded: {int(f[6])}")
            if f[7] > 0: indicators.append(f"VSSAdmin / Shadow Copy Activity: {int(f[7])}")
            if f[12] > 0: indicators.append(f"Orphan Processes: {int(f[12])}")
            if f[13] > 0: indicators.append(f"PowerShell Processes: {int(f[13])}")
            if f[14] > 0: indicators.append(f"Unsigned Modules: {int(f[14])}")
            if f[15] > 0: indicators.append(f"Suspicious Mutexes: {int(f[15])}")
            if f[16] > 0: indicators.append(f"Abnormal Privileges: {int(f[16])}")
            if f[17] > 0: indicators.append(f"Suspicious Threads: {int(f[17])}")
            if f[18] > 0: indicators.append(f"Defender Tampering: {int(f[18])}")
            
        if not indicators:
            ctk.CTkLabel(p_ind.content, text="No suspicious behavioral indicators triggered.", font=("Consolas", 11, "italic"), text_color=C["muted"]).pack(anchor="w")
        else:
            for ind in indicators:
                ctk.CTkLabel(p_ind.content, text=f"[!] {ind}", font=("Consolas", 11, "bold"), text_color="#ff8800").pack(anchor="w", pady=1)

        # ML Evidence (SECTION 4)
        p_ml = GlassPanel(right_col, "ML EVIDENCE PIPELINE")
        p_ml.pack(fill="x", pady=5)
        
        steps = [
            "19 FEATURES",
            "   |",
            "   v",
            "STANDARD SCALER",
            "   |",
            "   v",
            "RANDOM FOREST",
            "   |",
            "   v",
            f"MALICIOUS PROBABILITY: {getattr(scan_result, 'ml_probability', 0.0)*100:.1f}%  [MODEL OUTPUT]"
        ]
        
        for step in steps:
            colr = "#00d4ff" if "->" not in step and "|" not in step and "v" not in step else C["muted"]
            if "MALICIOUS" in step:
                colr = C["red"] if getattr(scan_result, 'ml_probability', 0.0) >= 0.50 else C["green"]
            ctk.CTkLabel(p_ml.content, text=step, font=("Consolas", 11, "bold"), text_color=colr).pack()

        # Canvas Visualization (SECTION 7)
        self.canvas_panel = GlassPanel(right_col, "INVESTIGATION VISUALIZATION")
        self.canvas_panel.pack(fill="x", pady=5)
        self.canvas = tk.Canvas(self.canvas_panel.content, bg="#050810", height=150, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda e: self.draw_investigation_canvas(col))

        
        self.draw_investigation_canvas(col)

    def draw_investigation_canvas(self, active_color):
        try:
            self.canvas.delete("all")
            self.canvas.update()
            w = self.canvas.winfo_width()
            h = self.canvas.winfo_height()
            if w < 50: w = 400
            
            nodes = ["BEHAVIOR", "INDICATORS", "FEATURES", "ML MODEL", "RISK ASSESSMENT"]
            node_w = 100
            spacing = (w - (len(nodes)*node_w)) / max(1, len(nodes))
            
            for i, name in enumerate(nodes):
                x = (spacing/2) + i * (node_w + spacing) + node_w/2
                y = h/2
                
                self.canvas.create_rectangle(x-node_w/2, y-15, x+node_w/2, y+15, fill="#0a0f18", outline=active_color)
                self.canvas.create_text(x, y, text=name, font=("Consolas", 8, "bold"), fill=active_color)
                
                if i < len(nodes)-1:
                    nx = (spacing/2) + (i+1) * (node_w + spacing) + node_w/2
                    self.canvas.create_line(x+node_w/2, y, nx-node_w/2, y, fill=active_color, dash=(2,2), arrow=tk.LAST)
        except Exception: pass
