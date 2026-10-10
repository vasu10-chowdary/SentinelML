"""
SentinelML V2 — Cinematic 3D Scan Visualizer  (Stage 7 polish)
===============================================================
Layout (fixed):
  Row 0 – top status bar  (weight=0, fixed height)
  Row 1 – body frame      (weight=1, fills everything)
            Col 0 – Canvas panel  (weight=3, the HERO element)
            Col 1 – Info panel    (weight=2, plain CTkFrame – no ScrollableFrame)
                      grid rows inside:
                        0 – pipeline   (fixed)
                        1 – edu        (weight=1 → expands)
                        2 – stats      (fixed)
                        3 – learn card (fixed)

Fixes applied vs Stage 5/6:
  • Dead space: row 0 weight=0 (bar), row 1 weight=1 (body)
  • Hero canvas: radius = min(w, h) / 2.6  (bigger shield)
  • Duplicate header: removed CTkScrollableFrame, plain CTkFrame + grid
  • Center-text safe zone: nodes hard-clamped to min_node_r = sr * 0.55
  • Responsive: all geometry derived from live canvas dimensions
"""

import customtkinter as ctk
import tkinter as tk
import math
import time
import webbrowser
from constants import COLOURS as C

# ── Feature catalogue (19 real ML features, 6 groups) ─────────────────────
_FEATURE_GROUPS = [
    ("PROCESS",    "#3fb950", ["total_processes", "suspicious_process_count",
                               "orphan_process_count", "powershell_process_count",
                               "suspicious_thread_count"]),
    ("MEMORY",     "#0ea5e9", ["malfind_injection_count", "unsigned_module_count",
                               "suspicious_mutex_count"]),
    ("CRYPTO",     "#d29922", ["avg_entropy", "max_entropy",
                               "high_entropy_region_count", "crypto_dll_count"]),
    ("NETWORK",    "#00d4aa", ["network_connection_count", "unique_external_ips"]),
    ("FILESYSTEM", "#8b949e", ["file_handle_count", "registry_handle_count",
                               "cmd_vssadmin_count"]),
    ("PRIVILEGE",  "#f85149", ["abnormal_privilege_count",
                               "defender_tampering_count"]),
]

# ── Pipeline stages ────────────────────────────────────────────────────────
_STAGES = [
    ("RAW_TELEMETRY",       "Raw Telemetry"),
    ("PROCESS_ANALYSIS",    "Process Analysis"),
    ("FILESYSTEM_ANALYSIS", "Filesystem Analysis"),
    ("FEATURE_EXTRACTION",  "19 Behavioral Features"),
    ("STANDARD_SCALER",     "Standard Scaler"),
    ("RANDOM_FOREST",       "Random Forest"),
    ("SECURITY_DECISION",   "Security Decision"),
]

_STAGE_EDU = {
    "RAW_TELEMETRY":
        "Collecting raw system telemetry from the operating system, "
        "running processes, and the filesystem.",
    "PROCESS_ANALYSIS":
        "Examining running processes for behavioral indicators — "
        "injection patterns, unsigned modules, orphan processes, and "
        "suspicious PowerShell activity.",
    "FILESYSTEM_ANALYSIS":
        "Inspecting accessible files, measuring entropy distributions, "
        "and identifying filesystem access patterns associated with "
        "anomalous or ransomware-like behavior.",
    "FEATURE_EXTRACTION":
        "Aggregating observed behavioral signals into 19 numerical "
        "features that represent the system's threat profile.",
    "STANDARD_SCALER":
        "Applying the trained StandardScaler to normalize the 19 "
        "feature values to the same scale used during model training.",
    "RANDOM_FOREST":
        "The trained Random Forest is evaluating the normalized "
        "feature vector and estimating a malicious-behavior probability.",
    "SECURITY_DECISION":
        "Applying the verified ScanState rules to the completed ML "
        "output to produce the final security classification.",
}

_LEARN_CARDS = [
    ("WHY PROCESS ANALYSIS?",
     "Malware commonly leaves behavioral indicators in running processes — "
     "injection patterns, unsigned modules, and abnormal thread activity."),
    ("WHY ENTROPY MEASUREMENT?",
     "High file entropy can be associated with encrypted or compressed "
     "content. Entropy alone does not prove ransomware, but it is one "
     "useful behavioral signal."),
    ("WHY 19 FEATURES?",
     "SentinelML combines multiple behavioral indicators rather than "
     "relying on any single signal. A combination is harder to evade."),
    ("WHY RANDOM FOREST?",
     "The Random Forest classifier aggregates many decision trees to "
     "produce a robust probability estimate from the behavioral profile."),
    ("WHY STANDARDSCALER?",
     "Feature values have different units and ranges. Normalizing them "
     "ensures no single feature dominates the model's decision."),
]


class ScanVisualizer(ctk.CTkFrame):
    """Cinematic 3D scan overlay — shown during and after a live scan."""

    # ── Init ──────────────────────────────────────────────────────────────

    def __init__(self, master, on_close=None, **kwargs):
        super().__init__(master, fg_color=C["bg"], **kwargs)
        self.on_close = on_close

        # Row 0 = top bar (fixed), Row 1 = body (expands)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._build_topbar()
        self._build_body()

        # ── Animation state ────────────────────────────────────────────────
        self.running     = True
        self.angle       = 0.0
        self.t0          = time.time()
        self.stage       = "RAW_TELEMETRY"
        self.scan_state_str = "SCANNING"
        self._learn_idx  = 0
        self._last_learn_t = time.time()
        self._last_stage_t = time.time()
        self._particles  = self._make_particles()

        self._update_learn_card()
        self.set_stage("RAW_TELEMETRY")
        self._animate()

    # ── Layout builders ───────────────────────────────────────────────────

    def _build_topbar(self):
        bar = ctk.CTkFrame(self, fg_color=C["panel"], height=40, corner_radius=0)
        bar.grid(row=0, column=0, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            bar,
            text="SENTINELML  —  LIVE ANALYSIS",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["accent"],
        ).grid(row=0, column=0, padx=18, pady=11, sticky="w")

        self._bar_stage = ctk.CTkLabel(
            bar,
            text="INITIALIZING",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["muted"],
        )
        self._bar_stage.grid(row=0, column=2, padx=18, sticky="e")

    def _build_body(self):
        """Two-column body: canvas (hero) left, info panel right."""
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=18, pady=(10, 14))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=3)   # canvas: 3 parts
        body.grid_columnconfigure(1, weight=2)   # info:   2 parts

        # ── Canvas panel (hero) ────────────────────────────────────────────
        cp = ctk.CTkFrame(body, fg_color=C["panel"], corner_radius=12)
        cp.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        cp.grid_rowconfigure(0, weight=1)
        cp.grid_columnconfigure(0, weight=1)

        self.canvas = tk.Canvas(cp, bg="#0d1117", highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

        # ── Info panel (plain CTkFrame, NO scrollable = no duplicate headers) ─
        info = ctk.CTkFrame(body, fg_color="transparent")
        info.grid(row=0, column=1, sticky="nsew")
        info.grid_rowconfigure(0, weight=0)   # pipeline – fixed
        info.grid_rowconfigure(1, weight=1)   # edu – expands
        info.grid_rowconfigure(2, weight=0)   # stats – fixed
        info.grid_rowconfigure(3, weight=0)   # learn – fixed
        info.grid_columnconfigure(0, weight=1)

        self._build_pipeline(info)
        self._build_edu(info)
        self._build_stats(info)
        self._build_learn(info)

        self._info_panel = info   # stash for result transition

    def _build_pipeline(self, parent):
        f = ctk.CTkFrame(parent, fg_color=C["panel"], corner_radius=10)
        f.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self._pipe_frame = f

        ctk.CTkLabel(
            f, text="ANALYSIS PIPELINE",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=C["muted"],
        ).pack(anchor="w", padx=14, pady=(12, 6))

        self._stage_labels = {}
        for key, text in _STAGES:
            row_f = ctk.CTkFrame(f, fg_color="transparent")
            row_f.pack(fill="x", padx=10, pady=1)

            dot = ctk.CTkLabel(
                row_f, text="·",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color=C["muted"], width=16,
            )
            dot.pack(side="left")

            lbl = ctk.CTkLabel(
                row_f, text=text,
                font=ctk.CTkFont(size=11),
                text_color=C["muted"], anchor="w",
            )
            lbl.pack(side="left", fill="x", expand=True, pady=2)
            self._stage_labels[key] = (dot, lbl)

        ctk.CTkFrame(f, fg_color="transparent", height=8).pack()

    def _build_edu(self, parent):
        f = ctk.CTkFrame(parent, fg_color=C["panel"], corner_radius=10)
        f.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        self._edu_frame = f

        ctk.CTkLabel(
            f, text="WHAT IS SENTINELML DOING?",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=C["accent"],
        ).pack(anchor="w", padx=14, pady=(12, 4))

        self._edu_desc = ctk.CTkLabel(
            f, text="Initializing...",
            font=ctk.CTkFont(size=12),
            text_color=C["white"],
            wraplength=300, justify="left",
        )
        self._edu_desc.pack(anchor="nw", padx=14, pady=(0, 12), fill="both", expand=True)

    def _build_stats(self, parent):
        f = ctk.CTkFrame(parent, fg_color=C["panel"], corner_radius=10)
        f.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        self._stats_frame = f

        # Exactly ONE header label
        ctk.CTkLabel(
            f, text="LIVE TELEMETRY",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=C["muted"],
        ).pack(anchor="w", padx=14, pady=(10, 4))

        self._stat_vars = {}
        for label, default in [
            ("Processes inspected",    "Collecting..."),
            ("Files inspected",        "Collecting..."),
            ("Suspicious indicators",  "Collecting..."),
            ("Features extracted",     "Pending"),
            ("Elapsed",                "0.0 s"),
        ]:
            row_f = ctk.CTkFrame(f, fg_color="transparent")
            row_f.pack(fill="x", padx=14, pady=1)
            ctk.CTkLabel(
                row_f, text=label,
                font=ctk.CTkFont(size=11),
                text_color=C["muted"],
            ).pack(side="left")
            var = ctk.StringVar(value=default)
            ctk.CTkLabel(
                row_f, textvariable=var,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=C["white"],
            ).pack(side="right")
            self._stat_vars[label] = var

        ctk.CTkFrame(f, fg_color="transparent", height=6).pack()

    def _build_learn(self, parent):
        f = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=10)
        f.grid(row=3, column=0, sticky="ew")
        self._learn_frame = f

        self._learn_title = ctk.CTkLabel(
            f, text="",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=C["orange"],
        )
        self._learn_title.pack(anchor="w", padx=14, pady=(10, 2))

        self._learn_desc = ctk.CTkLabel(
            f, text="",
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
            wraplength=300, justify="left",
        )
        self._learn_desc.pack(anchor="w", padx=14, pady=(0, 10), fill="x")

    # ── Particles ─────────────────────────────────────────────────────────

    @staticmethod
    def _make_particles():
        import random
        rng = random.Random(42)
        return [
            (rng.uniform(0, 2 * math.pi),
             rng.uniform(0.6, 1.7),
             rng.uniform(0.5, 2.2))
            for _ in range(20)
        ]

    # ── Public API ────────────────────────────────────────────────────────

    def set_stage(self, stage: str):
        self.stage = stage
        self._bar_stage.configure(text=stage.replace("_", " "))

        passed = True
        for key, (dot, lbl) in self._stage_labels.items():
            if key == stage:
                dot.configure(text="●", text_color=C["accent"])
                lbl.configure(text_color=C["white"],
                              font=ctk.CTkFont(size=11, weight="bold"))
                passed = False
            elif passed:
                dot.configure(text="✓", text_color=C["green"])
                lbl.configure(text_color=C["green"],
                              font=ctk.CTkFont(size=11))
            else:
                dot.configure(text="·", text_color=C["muted"])
                lbl.configure(text_color=C["muted"],
                              font=ctk.CTkFont(size=11))

        if stage in _STAGE_EDU:
            self._edu_desc.configure(text=_STAGE_EDU[stage])

    def update_progress(self, scan_result):
        if not self.running:
            return

        elapsed = time.time() - self.t0
        self._stat_vars["Elapsed"].set(f"{elapsed:.1f} s")

        procs = getattr(scan_result, "processes_analyzed", 0)
        files = getattr(scan_result, "files_inspected", 0)
        if procs > 0:
            self._stat_vars["Processes inspected"].set(f"{procs:,}")
        if files > 0:
            self._stat_vars["Files inspected"].set(f"{files:,}")

        susp = len(getattr(scan_result, "suspicious_files", None) or [])
        if susp > 0:
            self._stat_vars["Suspicious indicators"].set(str(susp))
        elif procs > 0:
            self._stat_vars["Suspicious indicators"].set("0")

        state_val = scan_result.state.value.upper()
        self.scan_state_str = state_val

        if state_val == "SCANNING":
            if files > 0:
                self.set_stage("FILESYSTEM_ANALYSIS")
            elif procs > 0:
                self.set_stage("PROCESS_ANALYSIS")

        elif state_val == "ANALYZING":
            if self.stage in ("FILESYSTEM_ANALYSIS", "PROCESS_ANALYSIS",
                              "RAW_TELEMETRY"):
                self.set_stage("FEATURE_EXTRACTION")
                self._stat_vars["Features extracted"].set("Extracting...")
                self._last_stage_t = time.time()

    def on_complete(self, threat_level: str, probability: float,
                    scan_result, error: str = None):
        self.set_stage("SECURITY_DECISION")
        self._stat_vars["Features extracted"].set("19  (complete)")
        elapsed = time.time() - self.t0
        self._stat_vars["Elapsed"].set(f"{elapsed:.1f} s")

        if scan_result is not None:
            self.scan_state_str = scan_result.state.value.upper()
            procs = getattr(scan_result, "processes_analyzed", 0)
            files = getattr(scan_result, "files_inspected", 0)
            if procs > 0:
                self._stat_vars["Processes inspected"].set(f"{procs:,}")
            if files > 0:
                self._stat_vars["Files inspected"].set(f"{files:,}")
            susp = len(getattr(scan_result, "suspicious_files", None) or [])
            self._stat_vars["Suspicious indicators"].set(str(susp))

        # Hide scanning info panels
        self._pipe_frame.grid_remove()
        self._edu_frame.grid_remove()
        self._stats_frame.grid_remove()
        self._learn_frame.grid_remove()

        self._build_result_panel(threat_level, probability, scan_result, error)

    def close(self):
        self.running = False
        if self.on_close:
            self.on_close()
        self.destroy()

    # ── Result panel ──────────────────────────────────────────────────────

    def _build_result_panel(self, threat_level, probability, scan_result, error):
        f = ctk.CTkFrame(
            self._info_panel, fg_color=C["panel"], corner_radius=10,
        )
        f.grid(row=0, column=0, rowspan=4, sticky="nsew")
        f.grid_columnconfigure(0, weight=1)

        # ── State Checks ───────────────────────────────────────────────────
        is_error = error or not scan_result or scan_result.state.name in ("ERROR", "SCAN_INCOMPLETE", "ANALYSIS_ERROR")
        
        if is_error:
            err_msg = error or getattr(scan_result, "error_message", "A definitive security decision could not be completed.")
            state_text = scan_result.state.name.replace("_", " ") if scan_result else "SCAN INCOMPLETE"
            self._bar_stage.configure(text=state_text, text_color=C["orange"])
            self.scan_state_str = state_text

            ctk.CTkLabel(f, text="SECURITY STATUS", font=ctk.CTkFont(size=9, weight="bold"), text_color=C["muted"]).pack(pady=(20, 2))
            ctk.CTkLabel(f, text=state_text, font=ctk.CTkFont(size=22, weight="bold"), text_color=C["orange"]).pack(pady=(0, 16))
            
            ctk.CTkLabel(f, text=err_msg, font=ctk.CTkFont(size=12), text_color=C["white"], wraplength=300, justify="left").pack(padx=16, pady=(0, 20))
            
            btn_f = ctk.CTkFrame(f, fg_color="transparent")
            btn_f.pack(fill="x", side="bottom", padx=16, pady=16)
            ctk.CTkButton(btn_f, text="Close  —  Return to Dashboard", command=self.close, fg_color=C["card"], hover_color=C["border"], text_color=C["white"], border_width=1, border_color=C["border"]).pack(fill="x")
            return

        is_threat = threat_level in ("THREAT DETECTED", "CRITICAL")
        is_warning = threat_level == "WARNING"
        is_safe = not (is_threat or is_warning)

        if is_threat:
            label_text, label_color, bar_text = "THREAT DETECTED", C["red"], "THREAT DETECTED"
            action_title = "IMMEDIATE ACTION"
        elif is_warning:
            label_text, label_color, bar_text = "WARNING", C["yellow"], "WARNING"
            action_title = "WHAT TO DO NOW"
        else:
            label_text, label_color, bar_text = "SAFE", C["green"], "SAFE"
            action_title = "SECURITY RECOMMENDATIONS"

        self._bar_stage.configure(text=bar_text, text_color=label_color)
        self.scan_state_str = bar_text

        # ── 1. SECURITY STATUS ──────────────────────────────────────────────
        ctk.CTkLabel(f, text="SECURITY STATUS", font=ctk.CTkFont(size=9, weight="bold"), text_color=C["muted"]).pack(pady=(20, 2))
        ctk.CTkLabel(f, text=label_text, font=ctk.CTkFont(size=22, weight="bold"), text_color=label_color).pack()

        if is_safe:
            msg = "No significant malicious behavior was detected during this completed scan."
        elif is_threat:
            msg = "High-confidence malicious behavior detected."
        else:
            msg = "Behavioral indicators require attention."

        ctk.CTkLabel(f, text=msg, font=ctk.CTkFont(size=11), text_color=C["white"], wraplength=300).pack(pady=(4, 16))

        # ── 2. ML Probability & Stats ────────────────────────────────────────
        stats_frame = ctk.CTkFrame(f, fg_color="transparent")
        stats_frame.pack(fill="x", padx=16, pady=(0, 10))

        if getattr(scan_result, "ml_executed", False):
            prob = getattr(scan_result, "ml_probability", 0.0)
            r = ctk.CTkFrame(stats_frame, fg_color="transparent")
            r.pack(fill="x", pady=1)
            ctk.CTkLabel(r, text="ML confidence:", font=ctk.CTkFont(size=11), text_color=C["muted"]).pack(side="left")
            ctk.CTkLabel(r, text=f"{prob*100:.1f}%", font=ctk.CTkFont(size=11, weight="bold"), text_color=label_color).pack(side="right")
        
        for lbl, val in [
            ("Processes inspected", f"{getattr(scan_result, 'processes_analyzed', 0):,}"),
            ("Files inspected", f"{getattr(scan_result, 'files_inspected', 0):,}"),
            ("Duration", f"{getattr(scan_result, 'elapsed_seconds', 0.0):.1f}s")
        ]:
            r = ctk.CTkFrame(stats_frame, fg_color="transparent")
            r.pack(fill="x", pady=1)
            ctk.CTkLabel(r, text=lbl, font=ctk.CTkFont(size=11), text_color=C["muted"]).pack(side="left")
            ctk.CTkLabel(r, text=val, font=ctk.CTkFont(size=11, weight="bold"), text_color=C["white"]).pack(side="right")

        # ── 3. WHY THIS RESULT? (Features) ──────────────────────────────────
        if not is_safe:
            features_array = getattr(scan_result, '_features', None)
            if features_array is not None and hasattr(features_array, 'shape') and features_array.shape == (1, 19):
                ctk.CTkFrame(f, fg_color=C["border"], height=1).pack(fill="x", padx=16, pady=8)
                ctk.CTkLabel(f, text="WHY THIS RESULT?", font=ctk.CTkFont(size=9, weight="bold"), text_color=C["muted"]).pack(anchor="w", padx=16, pady=(0, 4))
                
                f_list = features_array[0].tolist()
                names = [
                    "total_processes", "suspicious_process_count", "avg_entropy",
                    "max_entropy", "high_entropy_region_count", "malfind_injection_count",
                    "crypto_dll_count", "cmd_vssadmin_count", "network_connection_count",
                    "unique_external_ips", "file_handle_count", "registry_handle_count",
                    "orphan_process_count", "powershell_process_count",
                    "unsigned_module_count", "suspicious_mutex_count",
                    "abnormal_privilege_count", "suspicious_thread_count",
                    "defender_tampering_count"
                ]
                
                human_names = {
                    "malfind_injection_count": "Memory Injections",
                    "crypto_dll_count": "Crypto DLLs Loaded",
                    "cmd_vssadmin_count": "VSSAdmin Activity",
                    "powershell_process_count": "PowerShell Activity",
                    "suspicious_process_count": "Suspicious Processes",
                    "unsigned_module_count": "Unsigned Modules",
                    "suspicious_mutex_count": "Suspicious Mutexes",
                    "abnormal_privilege_count": "Abnormal Privileges",
                    "suspicious_thread_count": "Suspicious Threads",
                    "defender_tampering_count": "Defender Tampering"
                }
                
                indicators = []
                for n, v in zip(names, f_list):
                    if v > 0 and n in human_names:
                        indicators.append((human_names[n], int(v) if v.is_integer() else v))
                
                if indicators:
                    feat_f = ctk.CTkFrame(f, fg_color="transparent")
                    feat_f.pack(fill="x", padx=16)
                    for name, val in indicators[:4]:  # Show top 4
                        row_f = ctk.CTkFrame(feat_f, fg_color="transparent")
                        row_f.pack(fill="x", pady=1)
                        ctk.CTkLabel(row_f, text=name, font=ctk.CTkFont(size=11), text_color=C["white"]).pack(side="left")
                        ctk.CTkLabel(row_f, text=str(val), font=ctk.CTkFont(size=11, weight="bold"), text_color=label_color).pack(side="right")
                else:
                    ctk.CTkLabel(f, text="Behavioral anomalies detected across aggregated signals.", font=ctk.CTkFont(size=11, slant="italic"), text_color=C["muted"], anchor="w").pack(padx=16)

        # ── 4. WHAT TO DO NOW ───────────────────────────────────────────────
        ctk.CTkFrame(f, fg_color=C["border"], height=1).pack(fill="x", padx=16, pady=8)
        ctk.CTkLabel(f, text=action_title, font=ctk.CTkFont(size=9, weight="bold"), text_color=C["muted"]).pack(anchor="w", padx=16)

        if is_safe:
            items = ["Maintain regular, tested backups of important data.", "Continue running periodic SentinelML scans."]
        elif is_warning:
            items = [
                "Review the detected behavioral indicators.",
                "Avoid opening suspicious files or applications.",
                "Disconnect from the network if suspicious activity is still occurring.",
                "Run another targeted/full scan if required.",
                "Preserve the incident report for investigation."
            ]
        else:
            items = [
                "Disconnect the affected system from the network.",
                "Do not open or execute suspicious files.",
                "Preserve evidence before deleting files.",
                "Review suspicious processes and behavioral indicators.",
                "Generate/save the incident report.",
                "Escalate the incident if required."
            ]

        for i, item in enumerate(items, 1):
            ctk.CTkLabel(f, text=f"{i}. {item}" if not is_safe else f"• {item}", font=ctk.CTkFont(size=11), text_color=C["white"] if not is_safe else C["muted"], justify="left", wraplength=290, anchor="w").pack(anchor="w", padx=16, pady=1)

        # ── 5. ACTIONS & CYBERCRIME SUPPORT ─────────────────────────────────
        btn_f = ctk.CTkFrame(f, fg_color="transparent")
        btn_f.pack(fill="x", side="bottom", padx=16, pady=16)

        if not is_safe:
            # Cybercrime Section
            cc_f = ctk.CTkFrame(btn_f, fg_color=C["bg"], corner_radius=6, border_width=1, border_color=C["border"])
            cc_f.pack(fill="x", pady=(0, 12))
            ctk.CTkLabel(cc_f, text="CYBERCRIME SUPPORT", font=ctk.CTkFont(size=9, weight="bold"), text_color=C["muted"]).pack(pady=(8, 0))
            ctk.CTkLabel(cc_f, text="1930", font=ctk.CTkFont(size=18, weight="bold"), text_color=label_color).pack()
            ctk.CTkLabel(cc_f, text="National Cyber Crime Reporting Portal", font=ctk.CTkFont(size=10), text_color=C["white"]).pack(pady=(0, 4))
            ctk.CTkButton(cc_f, text="OPEN OFFICIAL PORTAL", command=lambda: webbrowser.open("https://www.cybercrime.gov.in/"), fg_color=C["card"], hover_color=C["border"], text_color=C["white"], height=24, font=ctk.CTkFont(size=10, weight="bold")).pack(fill="x", padx=12, pady=(4, 10))

            # Action Buttons
            db = self.master
            if hasattr(db, "_generate_incident_report"):
                ctk.CTkButton(btn_f, text="SAVE INCIDENT REPORT", command=db._generate_incident_report, fg_color=C["accent"], hover_color="#00b896", text_color="#0d1117", font=ctk.CTkFont(size=11, weight="bold")).pack(fill="x", pady=3)
        
        btn_text = "CLOSE" if not is_safe else "VIEW SCAN DETAILS"
        ctk.CTkButton(btn_f, text=btn_text, command=self.close, fg_color=C["card"], hover_color=C["border"], text_color=C["white"], border_width=1, border_color=C["border"], font=ctk.CTkFont(size=11)).pack(fill="x", pady=(4, 0))

    # ── Learn card ────────────────────────────────────────────────────────

    def _update_learn_card(self):
        t, d = _LEARN_CARDS[self._learn_idx]
        self._learn_title.configure(text=t)
        self._learn_desc.configure(text=d)
        self._learn_idx = (self._learn_idx + 1) % len(_LEARN_CARDS)

    # ── Canvas rendering ──────────────────────────────────────────────────

    def _render_frame(self, cx: float, cy: float, r: float, angle: float):
        """One animation frame.  r = shield base radius (before sr scale)."""
        cv   = self.canvas
        gw   = cv.winfo_width()
        gh   = cv.winfo_height()
        sr   = r * 0.72          # shield half-size
        tilt = 0.40              # vertical compression → 3-D perspective

        cv.delete("all")

        # ── Fine perspective grid ──────────────────────────────────────────
        gc = "#192232"
        step = max(int(r * 0.30), 28)
        for x in range(0, gw, step):
            cv.create_line(x, 0, x, gh, fill=gc)
        for y in range(0, gh, step):
            cv.create_line(0, y, gw, y, fill=gc)
        # Stronger centre axes
        cv.create_line(cx, 0, cx, gh, fill="#1e2d40", width=1)
        cv.create_line(0, cy, gw, cy, fill="#1e2d40", width=1)

        # ── Radial lines from centre (subtle depth) ────────────────────────
        for i in range(12):
            ra = i * (math.pi / 6) + angle * 0.05
            rx = cx + (r + 95) * math.cos(ra)
            ry = cy + (r + 95) * math.sin(ra) * tilt
            cv.create_line(cx, cy, rx, ry, fill="#131f2e", width=1)

        # ── Orbital rings ─────────────────────────────────────────────────
        ring_specs = [
            (r + 85,  0.25,  C["muted"],   (3, 9), 1),
            (r + 50, -0.55,  C["accent2"], (4, 5), 1),
            (r + 18,  1.00,  C["accent"],  None,   2),
        ]
        for rad, speed, color, dash, width in ring_specs:
            a = angle * speed
            pts = []
            for i in range(72):
                th = i * (2 * math.pi / 72) + a
                pts.extend([cx + rad * math.cos(th),
                             cy + rad * math.sin(th) * tilt])
            kw = dict(outline=color, fill="", width=width, smooth=True)
            if dash:
                kw["dash"] = dash
            cv.create_polygon(pts, **kw)

        # ── Scan beam ─────────────────────────────────────────────────────
        ba   = angle * 1.7
        bx   = cx + (r + 85) * math.cos(ba)
        by   = cy + (r + 85) * math.sin(ba) * tilt
        cv.create_line(cx, cy, bx, by, fill=C["accent2"], width=2)
        cv.create_oval(bx - 4, by - 4, bx + 4, by + 4,
                       fill=C["accent2"], outline="")

        # ── Shield (outer polygon) ────────────────────────────────────────
        def shield_pts(scale=1.0):
            s = sr * scale
            return [
                cx,           cy - s,
                cx + s*0.75,  cy - s*0.30,
                cx + s*0.65,  cy + s*0.55,
                cx,           cy + s,
                cx - s*0.65,  cy + s*0.55,
                cx - s*0.75,  cy - s*0.30,
            ]

        cv.create_polygon(shield_pts(1.00),
                          outline=C["accent"], fill="#0a1520", width=2)
        cv.create_polygon(shield_pts(0.78),
                          outline=C["accent2"], fill="", width=1, dash=(6, 4))

        # ── Centre status text ────────────────────────────────────────────
        fs = max(10, int(sr * 0.17))
        cv.create_text(cx, cy, text=self.scan_state_str,
                       fill=C["white"],
                       font=("Segoe UI", fs, "bold"))

        # Safe radius: text spans roughly ±(fs * 5) horizontal pixels
        text_safe_r = fs * 5.5

        # ── Telemetry particles (raw/process/filesystem stages) ────────────
        if self.stage in ("RAW_TELEMETRY", "PROCESS_ANALYSIS",
                          "FILESYSTEM_ANALYSIS"):
            for i, (ao, dist, speed) in enumerate(self._particles):
                pa = angle * speed + ao
                pr = (r + 22) + dist * (r * 0.55)
                px = cx + pr * math.cos(pa)
                py = cy + pr * math.sin(pa) * tilt
                if 0 < px < gw and 0 < py < gh:
                    sz = 2 if i % 3 else 3
                    col = C["accent2"] if i % 2 else C["muted"]
                    cv.create_oval(px-sz, py-sz, px+sz, py+sz,
                                   fill=col, outline="")

        # ── Feature nodes (ML stages) ─────────────────────────────────────
        if self.stage in ("FEATURE_EXTRACTION", "STANDARD_SCALER",
                          "RANDOM_FOREST"):

            # Target orbit radius per stage
            target_r = {
                "FEATURE_EXTRACTION": r * 0.68,
                "STANDARD_SCALER":    r * 0.50,
                "RANDOM_FOREST":      r * 0.34,
            }[self.stage]

            # Breathing pulse
            node_r = target_r * (1.0 + 0.035 * math.sin(angle * 4))

            # ── Hard minimum: never enter the text safe zone ───────────────
            # Minimum orbit that keeps all nodes outside the text bounding box:
            # The farthest point at orbit node_r is exactly node_r from centre.
            # We need node_r > text_safe_r to avoid overlap on the sides.
            # Use a slightly larger margin (sr * 0.48) for visual comfort.
            min_safe = max(text_safe_r, sr * 0.48)
            node_r = max(node_r, min_safe)

            idx   = 0
            total = sum(len(g[2]) for g in _FEATURE_GROUPS)
            for group_name, group_color, features in _FEATURE_GROUPS:
                for feat in features:
                    pa = idx * (2 * math.pi / total) + angle * 0.40
                    px = cx + node_r * math.cos(pa)
                    py = cy + node_r * math.sin(pa) * tilt

                    if 0 < px < gw and 0 < py < gh:
                        cv.create_oval(px-5, py-5, px+5, py+5,
                                       fill=group_color, outline="")
                        if feat == features[0]:
                            lx = cx + (node_r + 18) * math.cos(pa)
                            ly = cy + (node_r + 18) * math.sin(pa) * tilt
                            if 0 < lx < gw and 0 < ly < gh:
                                cv.create_text(lx, ly, text=group_name,
                                               fill=group_color,
                                               font=("Segoe UI", 8))
                    idx += 1

    # ── Animation loop ────────────────────────────────────────────────────

    def _animate(self):
        if not self.running:
            return

        self.angle += 0.038

        # Learn card rotation
        if time.time() - self._last_learn_t > 7.5:
            self._update_learn_card()
            self._last_learn_t = time.time()

        # ML sub-stage progression while ANALYZING
        if self.scan_state_str == "ANALYZING":
            dt = time.time() - self._last_stage_t
            if self.stage == "FEATURE_EXTRACTION" and dt > 0.9:
                self._stat_vars["Features extracted"].set("19  (normalizing)")
                self.set_stage("STANDARD_SCALER")
                self._last_stage_t = time.time()
            elif self.stage == "STANDARD_SCALER" and dt > 0.9:
                self.set_stage("RANDOM_FOREST")
                self._last_stage_t = time.time()

        # Render canvas
        try:
            w = self.canvas.winfo_width()
            h = self.canvas.winfo_height()
            if w > 30 and h > 30:
                # Dynamic radius: use whichever dimension limits the rings most
                # rings extend to r+85, so max r = min(w,h)/2 - 95
                max_r = min(w / 2, h / 2) - 96
                r = max(60.0, min(max_r, min(w, h) / 2.6))
                self._render_frame(w / 2, h / 2, r, self.angle)
        except Exception:
            pass

        self.after(33, self._animate)   # ~30 FPS
