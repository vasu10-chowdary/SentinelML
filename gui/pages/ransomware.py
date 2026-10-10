import customtkinter as ctk
import tkinter as tk
import time
import math
from constants import COLOURS as C

class GlassPanel(ctk.CTkFrame):
    def __init__(self, master, title, **kwargs):
        super().__init__(master, fg_color='#0a0f18', border_width=1, border_color='#1a2b4c', corner_radius=6, **kwargs)
        if title:
            self.title_lbl = ctk.CTkLabel(self, text=title, font=ctk.CTkFont(family='Consolas', size=13, weight='bold'), text_color='#00a8cc')
            self.title_lbl.pack(anchor='w', padx=10, pady=(5, 0))
        self.content = ctk.CTkFrame(self, fg_color='transparent')
        self.content.pack(fill='both', expand=True, padx=10, pady=5)

class RansomwarePage(ctk.CTkFrame):
    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color='#050810', **kwargs)
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        header = ctk.CTkFrame(self, fg_color='transparent')
        header.grid(row=0, column=0, sticky='ew', padx=20, pady=(20, 10))
        
        ctk.CTkLabel(header, text='RANSOMWARE', font=ctk.CTkFont(family='Consolas', size=26, weight='bold'), text_color=C['white']).pack(anchor='w')
        ctk.CTkLabel(header, text='Understanding the threat SentinelML is designed to detect.', font=ctk.CTkFont(family='Consolas', size=13), text_color=C['muted']).pack(anchor='w')
        
        self.scroll = ctk.CTkScrollableFrame(self, fg_color='transparent')
        self.scroll.grid(row=1, column=0, sticky='nsew', padx=10, pady=10)
        self.scroll.grid_columnconfigure(0, weight=1)
        self.scroll.grid_columnconfigure(1, weight=1)
        
        left_col = ctk.CTkFrame(self.scroll, fg_color='transparent')
        left_col.grid(row=0, column=0, sticky='nsew', padx=5)
        
        p1 = GlassPanel(left_col, 'WHAT IS RANSOMWARE?')
        p1.pack(fill='x', pady=5)
        text1 = 'Ransomware is malware that can encrypt or otherwise make a victim''s files inaccessible and demands payment from the victim. Modern ransomware attacks can also involve data theft, system disruption, privilege abuse, security-tool tampering, and other malicious behavior.'
        ctk.CTkLabel(p1.content, text=text1, wraplength=450, justify='left', font=('Consolas', 12), text_color=C['white']).pack(anchor='w', pady=5)
        
        flow1 = '[ Normal Files ] -> [ Malicious Execution ] -> [ Behavioral Changes ] -> [ File/System Impact ] -> [ Potential Ransomware Activity ]'
        ctk.CTkLabel(p1.content, text=flow1.replace(' -> ', chr(10)+'      |'+chr(10)+'      v'+chr(10)), justify='center', font=('Consolas', 11), text_color='#00ff88').pack(pady=10)

        p6 = GlassPanel(left_col, 'WHY BEHAVIORAL DETECTION?')
        p6.pack(fill='x', pady=5)
        text6 = (
            'Traditional signature-based approaches depend heavily on known indicators.' + chr(10) + chr(10) +
            'Behavioral analysis instead examines what a process/system is actually doing.' + chr(10) + chr(10) +
            'SentinelML combines behavioral telemetry with machine learning to estimate whether the observed behavior resembles malicious activity.'
        )
        ctk.CTkLabel(p6.content, text=text6, wraplength=450, justify='left', font=('Consolas', 12), text_color=C['white']).pack(anchor='w', pady=5)
        
        p4 = GlassPanel(left_col, 'HOW THE ML PIPELINE WORKS')
        p4.pack(fill='x', pady=5)
        
        pipe_steps = [
            ('REAL SYSTEM TELEMETRY', 'Data collected from the application''s behavioral scanners.'),
            ('19 BEHAVIORAL FEATURES', 'Numerical behavioral indicators extracted from the telemetry.'),
            ('STANDARD SCALER', 'Normalizes the feature values using the trained scaler.'),
            ('RANDOM FOREST', 'The trained machine-learning classifier evaluates the feature vector.'),
            ('MALICIOUS PROBABILITY', 'The model produces the malicious-class probability.'),
            ('CLASSIFICATION', 'The application maps the probability to its existing ScanState/classification thresholds.')
        ]
        
        for name, desc in pipe_steps:
            f = ctk.CTkFrame(p4.content, fg_color='transparent')
            f.pack(fill='x', pady=2)
            ctk.CTkLabel(f, text=f'[{name}]', font=('Consolas', 11, 'bold'), text_color='#00d4ff', width=180, anchor='e').pack(side='left', padx=5)
            ctk.CTkLabel(f, text=desc, font=('Consolas', 11), text_color=C['white'], wraplength=250, justify='left').pack(side='left')

        right_col = ctk.CTkFrame(self.scroll, fg_color='transparent')
        right_col.grid(row=0, column=1, sticky='nsew', padx=5)
        
        p3 = GlassPanel(right_col, 'WHAT SENTINELML LOOKS FOR (19 FEATURES)')
        p3.pack(fill='x', pady=5)
        
        feat_list = [
            '1. total_processes', '2. suspicious_process_count', '3. avg_entropy', '4. max_entropy', 
            '5. high_entropy', '6. malfind', '7. crypto_dll', '8. vssadmin', '9. network_conn', 
            '10. ext_ips', '11. file_handle', '12. reg_handle', '13. orphan_proc', '14. powershell_proc', 
            '15. unsigned_mod', '16. susp_mutex', '17. ab_privs', '18. susp_thread', '19. defender_tampering'
        ]
        
        f_frame = ctk.CTkFrame(p3.content, fg_color='transparent')
        f_frame.pack(fill='x')
        c1 = ctk.CTkFrame(f_frame, fg_color='transparent')
        c1.pack(side='left', fill='both', expand=True)
        c2 = ctk.CTkFrame(f_frame, fg_color='transparent')
        c2.pack(side='left', fill='both', expand=True)
        
        for i, feat in enumerate(feat_list):
            parent = c1 if i < 10 else c2
            ctk.CTkLabel(parent, text=feat, font=('Consolas', 11), text_color='#ffcc00').pack(anchor='w')
            
        p5 = GlassPanel(right_col, 'PROBABILITY & CLASSIFICATION')
        p5.pack(fill='x', pady=5)
        ctk.CTkLabel(p5.content, text='< 0.50 : SAFE' + chr(10) + '0.50 - 0.89 : WARNING' + chr(10) + '>= 0.90 : THREAT DETECTED', font=('Consolas', 12, 'bold'), text_color=C['white'], justify='left').pack(anchor='w', pady=5)
        ctk.CTkLabel(p5.content, text='SAFE means no significant malicious behavior was detected during the completed scan. It does not guarantee that a system is completely free of malware.' + chr(10) + chr(10) + 'NO COMPLETE ANALYSIS = NO SAFE RESULT', font=('Consolas', 11), text_color=C['muted'], wraplength=450, justify='left').pack(anchor='w')

        p7 = GlassPanel(right_col, 'EDUCATIONAL WARNING')
        p7.pack(fill='x', pady=5)
        ctk.CTkLabel(p7.content, text='SentinelML is a college/project security demonstration and behavioral analysis tool. Detection results are probabilistic and should not be interpreted as a guarantee of system security.', font=('Consolas', 11, 'italic'), text_color='#ff8800', wraplength=450, justify='left').pack(anchor='w')

        self.canvas_panel = GlassPanel(right_col, 'ATTACK FLOW VISUALIZATION')
        self.canvas_panel.pack(fill='x', pady=5)
        self.canvas = tk.Canvas(self.canvas_panel.content, bg='#050810', height=240, highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)
        
        self.start_time = time.time()
        self.running = True
        self.after(30, self._animate)
        
    def _animate(self):
        if not self.running: return
        try:
            self.canvas.delete('all')
            w = self.canvas.winfo_width()
            h = self.canvas.winfo_height()
            if w > 50:
                elapsed = (time.time() - self.start_time) % 10.0
                cx, cy = w/2, h/2
                
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
                for i, (name, col) in enumerate(stages):
                    y = 20 + i * (h-40)/max(1, num-1)
                    
                    active = i == int(elapsed / (10.0 / num))
                    bg = col if active else '#0a0f18'
                    fg = '#000' if active else col
                    
                    self.canvas.create_rectangle(cx-140, y-10, cx+140, y+10, fill=bg, outline=col)
                    self.canvas.create_text(cx, y, text=name, font=('Consolas', 9, 'bold'), fill=fg)
                    
                    if i < num - 1:
                        ny = 20 + (i+1) * (h-40)/max(1, num-1)
                        self.canvas.create_line(cx, y+10, cx, ny-10, fill=col, dash=(2,2))
        except Exception: pass
        self.after(50, self._animate)

    def destroy(self):
        self.running = False
        super().destroy()
