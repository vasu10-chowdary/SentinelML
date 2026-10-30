import customtkinter as ctk
import tkinter as tk
import time
import math
from constants import COLOURS as C

class GlassPanel(ctk.CTkFrame):
    def __init__(self, master, title, **kwargs):
        super().__init__(master, fg_color='#0a0f18', border_width=1, border_color='#1a2b4c', corner_radius=8, **kwargs)
        if title:
            self.title_lbl = ctk.CTkLabel(
                self, text=title,
                font=ctk.CTkFont(family='Consolas', size=12, weight='bold'),
                text_color='#00d4ff',
                anchor='w'
            )
            self.title_lbl.pack(anchor='w', padx=14, pady=(10, 4), fill='x')
        self.content = ctk.CTkFrame(self, fg_color='transparent')
        self.content.pack(fill='both', expand=True, padx=12, pady=(0, 10))

class RansomwarePage(ctk.CTkFrame):
    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color='#050810', **kwargs)
        self._wrap_labels = []

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ── Header ─────────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color='transparent')
        header.grid(row=0, column=0, sticky='ew', padx=28, pady=(20, 10))

        ctk.CTkLabel(
            header, text='RANSOMWARE DEFENSE ARCHITECTURE',
            font=ctk.CTkFont(family='Consolas', size=22, weight='bold'),
            text_color=C['white']
        ).pack(anchor='w')

        ctk.CTkLabel(
            header, text='Educational overview of behavioral ransomware detection, telemetry analysis, and model bounds.',
            font=ctk.CTkFont(size=12),
            text_color=C['muted']
        ).pack(anchor='w', pady=(2, 0))

        # ── Two-Column Scrollable Frame ────────────────────────────────────
        self.scroll = ctk.CTkScrollableFrame(self, fg_color='transparent')
        self.scroll.grid(row=1, column=0, sticky='nsew', padx=18, pady=(0, 16))
        self.scroll.grid_columnconfigure(0, weight=1)
        self.scroll.grid_columnconfigure(1, weight=1)

        left_col = ctk.CTkFrame(self.scroll, fg_color='transparent')
        left_col.grid(row=0, column=0, sticky='nsew', padx=(0, 8))

        # Panel 1: What is Ransomware?
        p1 = GlassPanel(left_col, 'WHAT IS RANSOMWARE?')
        p1.pack(fill='x', pady=(0, 10))
        text1 = (
            "Ransomware is malicious software that encrypts, alters, or locks access to user files, "
            "demanding payment for decryption keys. Contemporary ransomware combines rapid multi-threaded "
            "file modification with defense evasion, shadow copy deletion, process injection, and abnormal privileges."
        )
        lbl1 = ctk.CTkLabel(p1.content, text=text1, wraplength=420, justify='left', font=ctk.CTkFont(size=12), text_color=C['white'], anchor='w')
        lbl1.pack(anchor='w', pady=(4, 8), fill='x', padx=(4, 4))
        self._wrap_labels.append(lbl1)

        flow_box = ctk.CTkFrame(p1.content, fg_color='#0d1527', corner_radius=6, border_width=1, border_color='#1a2c4e')
        flow_box.pack(fill='x', pady=6, padx=2)
        flow_steps = [
            ("1. INITIAL ACCESS", "Phishing, dropped payload, or vulnerable service"),
            ("2. BEHAVIORAL CHANGES", "Suspicious processes, crypto DLLs loaded, network calls"),
            ("3. FILE / SYSTEM IMPACT", "Rapid Shannon entropy elevation & file renaming"),
            ("4. DETECTION DECISION", "SentinelML 100-Tree Random Forest classification")
        ]
        for step_title, step_sub in flow_steps:
            row_f = ctk.CTkFrame(flow_box, fg_color='transparent')
            row_f.pack(fill='x', padx=10, pady=3)
            ctk.CTkLabel(row_f, text=f"• {step_title}:", font=ctk.CTkFont(family='Consolas', size=11, weight='bold'), text_color='#00ff88').pack(anchor='w')
            s_lbl = ctk.CTkLabel(row_f, text=f"   {step_sub}", font=ctk.CTkFont(size=11), text_color=C['muted'], wraplength=380, justify='left', anchor='w')
            s_lbl.pack(anchor='w', fill='x')
            self._wrap_labels.append(s_lbl)

        # Panel 2: Why Behavioral Detection?
        p6 = GlassPanel(left_col, 'WHY BEHAVIORAL DETECTION?')
        p6.pack(fill='x', pady=(0, 10))
        text6 = (
            "Traditional signature scanners rely entirely on previously observed file hashes and byte sequences. "
            "Polymorphic and zero-day ransomware trivializes static signatures by recompiling with novel hashes.\n\n"
            "Behavioral detection analyzes operational indicators: mass file modification rates, elevated Shannon entropy, "
            "vssadmin shadow copy tampering, and suspicious process hierarchies. SentinelML evaluates these "
            "empirical signals with a calibrated machine-learning classifier."
        )
        lbl6 = ctk.CTkLabel(p6.content, text=text6, wraplength=420, justify='left', font=ctk.CTkFont(size=12), text_color=C['white'], anchor='w')
        lbl6.pack(anchor='w', pady=4, fill='x', padx=(4, 4))
        self._wrap_labels.append(lbl6)

        # Panel 3: How the ML Pipeline Works
        p4 = GlassPanel(left_col, 'HOW THE ML PIPELINE WORKS')
        p4.pack(fill='x', pady=(0, 10))

        pipe_steps = [
            ("RAW TELEMETRY", "User-space file traversal and process polling (psutil & OS APIs)."),
            ("19 BEHAVIORAL FEATURES", "Numerical feature extraction (entropy, handles, thread counts, crypto DLLs)."),
            ("STANDARD SCALER", "Z-score normalization matching baseline training distribution."),
            ("RANDOM FOREST INFERENCE", "100-estimator decision tree ensemble voting on malicious probability."),
            ("PROBABILISTIC CLASSIFICATION", "SAFE (<0.50), WARNING (0.50–0.89), or CRITICAL (≥0.90)."),
            ("DEFENSIVE INCIDENT LOG", "Audit history recording, event alerting, and transparent report export.")
        ]

        for i, (name, desc) in enumerate(pipe_steps, 1):
            box = ctk.CTkFrame(p4.content, fg_color='#0c1322', corner_radius=6, border_width=1, border_color='#1a2744')
            box.pack(fill='x', pady=3, padx=2)

            badge_f = ctk.CTkFrame(box, fg_color='transparent')
            badge_f.pack(fill='x', padx=10, pady=(6, 2))

            ctk.CTkLabel(
                badge_f,
                text=f"STEP {i}: {name}",
                font=ctk.CTkFont(family='Consolas', size=11, weight='bold'),
                text_color='#00d4ff',
                anchor='w'
            ).pack(side='left')

            d_lbl = ctk.CTkLabel(
                box,
                text=desc,
                font=ctk.CTkFont(size=11),
                text_color=C['white'],
                wraplength=400,
                justify='left',
                anchor='w'
            )
            d_lbl.pack(fill='x', padx=10, pady=(0, 6))
            self._wrap_labels.append(d_lbl)

        # ── Right Column ──────────────────────────────────────────────────
        right_col = ctk.CTkFrame(self.scroll, fg_color='transparent')
        right_col.grid(row=0, column=1, sticky='nsew', padx=(8, 0))

        # Panel 4: 19 Behavioral Features
        p3 = GlassPanel(right_col, 'WHAT SENTINELML LOOKS FOR (19 FEATURES)')
        p3.pack(fill='x', pady=(0, 10))

        feat_list = [
            '1. total_processes', '2. suspicious_process_count', '3. avg_entropy', '4. max_entropy',
            '5. high_entropy_region', '6. malfind_injection', '7. crypto_dll_count', '8. cmd_vssadmin',
            '9. network_connections', '10. unique_external_ips', '11. file_handle_count', '12. registry_handles',
            '13. orphan_processes', '14. powershell_instances', '15. unsigned_modules', '16. suspicious_mutexes',
            '17. abnormal_privileges', '18. suspicious_threads', '19. defender_tampering'
        ]

        f_frame = ctk.CTkFrame(p3.content, fg_color='transparent')
        f_frame.pack(fill='x', pady=4)
        f_frame.grid_columnconfigure((0, 1), weight=1)

        col0 = ctk.CTkFrame(f_frame, fg_color='#0c1322', corner_radius=4)
        col0.grid(row=0, column=0, sticky='nsew', padx=3, pady=2)
        col1 = ctk.CTkFrame(f_frame, fg_color='#0c1322', corner_radius=4)
        col1.grid(row=0, column=1, sticky='nsew', padx=3, pady=2)

        for i, feat in enumerate(feat_list):
            target_col = col0 if i < 10 else col1
            ctk.CTkLabel(
                target_col, text=f"• {feat}",
                font=ctk.CTkFont(family='Consolas', size=10),
                text_color='#ffcc00',
                anchor='w'
            ).pack(fill='x', padx=8, pady=2)

        # Panel 5: Probability & Decision Thresholds
        p5 = GlassPanel(right_col, 'PROBABILITY & DECISION THRESHOLDS')
        p5.pack(fill='x', pady=(0, 10))

        thresh_box = ctk.CTkFrame(p5.content, fg_color='#0c1322', corner_radius=6, border_width=1, border_color='#1a2744')
        thresh_box.pack(fill='x', pady=4, padx=2)
        thresh_lbl = ctk.CTkLabel(
            thresh_box,
            text="  < 0.50  :  SAFE  (Normal behavioral baseline)\n"
                 "0.50–0.89 :  WARNING  (Elevated entropy or process indicators)\n"
                 "  \u2265 0.90  :  CRITICAL  (High-confidence ransomware signature)",
            font=ctk.CTkFont(family='Consolas', size=11, weight='bold'),
            text_color=C['white'],
            justify='left',
            anchor='w'
        )
        thresh_lbl.pack(fill='x', padx=10, pady=8)
        self._wrap_labels.append(thresh_lbl)
        text5 = (
            "Honest Disclosure: SAFE indicates no significant anomalous behaviors were detected "
            "during the completed scan scope. It does not provide an absolute guarantee against "
            "dormant, kernel-level, or unobserved zero-day threats.\n\n"
            "FAIL-SAFE INVARIANT: An incomplete, interrupted, or permission-denied scan NEVER yields a SAFE verdict."
        )
        lbl5 = ctk.CTkLabel(p5.content, text=text5, wraplength=420, justify='left', font=ctk.CTkFont(size=11), text_color=C['muted'], anchor='w')
        lbl5.pack(anchor='w', pady=(4, 0), fill='x', padx=(4, 4))
        self._wrap_labels.append(lbl5)

        # Panel 6: Educational Warning
        p7 = GlassPanel(right_col, 'SCIENTIFIC & OPERATIONAL LIMITATIONS')
        p7.pack(fill='x', pady=(0, 10))
        text7 = (
            "SentinelML is an empirical research and behavioral cybersecurity analysis platform. "
            "The baseline model is calibrated on synthetic distributions (EXPERIMENTAL_SYNTHETIC_BASELINE_V1) "
            "and user-space heuristics. Full deep driver inspection requires kernel-level minifilters."
        )
        lbl7 = ctk.CTkLabel(p7.content, text=text7, wraplength=420, justify='left', font=ctk.CTkFont(size=11, slant='italic'), text_color='#ff9900', anchor='w')
        lbl7.pack(anchor='w', pady=4, fill='x', padx=(4, 4))
        self._wrap_labels.append(lbl7)

        # Panel 7: Attack Flow Animation Canvas
        self.canvas_panel = GlassPanel(right_col, 'ATTACK FLOW VISUALIZATION')
        self.canvas_panel.pack(fill='x', pady=(0, 10))
        self.canvas = tk.Canvas(self.canvas_panel.content, bg='#050810', height=240, highlightthickness=0)
        self.canvas.pack(fill='both', expand=True, pady=4)

        self.start_time = time.time()
        self.running = True
        self.after(30, self._animate)

        # Dynamic responsive text wrapping on resize
        self.scroll.bind("<Configure>", self._on_resize)

    def _on_resize(self, event=None):
        def _do_reflow():
            try:
                scroll_w = self.scroll.winfo_width()
                if scroll_w < 100:
                    try:
                        scroll_w = max(self.winfo_width(), self.master.winfo_width(), 1200)
                    except Exception:
                        scroll_w = 1200
                col_w = max(260, (scroll_w - 50) // 2)
                card_text_w = max(220, col_w - 40)
                if card_text_w == getattr(self, "_last_wrap_w", None):
                    return
                self._last_wrap_w = card_text_w
                for lbl in getattr(self, "_wrap_labels", []):
                    try:
                        lbl.configure(wraplength=card_text_w)
                    except Exception:
                        pass
            except Exception:
                pass

        if event is None:
            _do_reflow()
            return

        # Debounce configure reflow to avoid cascading Tk geometry recalcs
        if hasattr(self, '_resize_timer') and self._resize_timer:
            try:
                self.after_cancel(self._resize_timer)
            except Exception:
                pass
        self._resize_timer = self.after(70, _do_reflow)

    def _animate(self):
        if not getattr(self, 'running', False):
            return
        # Pause animation while page is hidden to save CPU/GPU cycles
        if not self.winfo_ismapped():
            self._anim_timer = self.after(250, self._animate)
            return
        try:
            self.canvas.delete('all')
            w = self.canvas.winfo_width()
            h = self.canvas.winfo_height()
            if w > 50:
                elapsed = (time.time() - self.start_time) % 10.0
                cx, cy = w / 2, h / 2

                stages = [
                    ('INITIAL ACCESS', '#00d4ff'),
                    ('EXECUTION', '#00d4ff'),
                    ('PROCESS ACTIVITY', '#ff8800'),
                    ('PRIVILEGE / SYSTEM ABUSE', '#ff8800'),
                    ('DEFENSE EVASION', '#ff8800'),
                    ('FILE / CRYPTOGRAPHIC ACTIVITY', '#ff2a2a'),
                    ('NETWORK ACTIVITY', '#ff2a2a'),
                    ('POTENTIAL IMPACT', '#ff2a2a')
                ]

                num = len(stages)
                box_w = min(130, (w - 30) / 2)
                for i, (name, col) in enumerate(stages):
                    y = 20 + i * (h - 40) / max(1, num - 1)
                    active = i == int(elapsed / (10.0 / num))
                    bg = col if active else '#0a0f18'
                    fg = '#000000' if active else col

                    self.canvas.create_rectangle(cx - box_w, y - 10, cx + box_w, y + 10, fill=bg, outline=col)
                    self.canvas.create_text(cx, y, text=name, font=('Consolas', 9, 'bold'), fill=fg)

                    if i < num - 1:
                        ny = 20 + (i + 1) * (h - 40) / max(1, num - 1)
                        self.canvas.create_line(cx, y + 10, cx, ny - 10, fill=col, dash=(2, 2))
        except Exception:
            pass

        if getattr(self, "running", False) and self.winfo_exists():
            self._anim_timer = self.after(50, self._animate)

    def destroy(self):
        self.running = False
        if hasattr(self, "_resize_timer") and self._resize_timer:
            try:
                self.after_cancel(self._resize_timer)
            except Exception:
                pass
            self._resize_timer = None
        if hasattr(self, "_anim_timer") and self._anim_timer:
            try:
                self.after_cancel(self._anim_timer)
            except Exception:
                pass
            self._anim_timer = None
        super().destroy()
