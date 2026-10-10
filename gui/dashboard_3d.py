import tkinter as tk
import math
import time
import random

class Dashboard3DCore(tk.Canvas):
    def __init__(self, master, width=400, height=350, **kwargs):
        kwargs["bg"] = "#050810"
        kwargs["highlightthickness"] = 0
        super().__init__(master, width=width, height=height, **kwargs)
        
        self.state = "IDLE"
        self.visual_substate = ""
        self.risk_score = 0.0
        self.start_time = time.time()
        self.state_time = time.time()
        self.scan_data = None
        
        # Geometry
        self.shield_points = []
        radius = 120
        for i in range(6):
            a = math.radians(60 * i + 30)
            self.shield_points.append({"x": math.cos(a)*radius, "y": math.sin(a)*radius, "z": 0})
            
        self.particles = []
        self.rings = []
        
        # Queued result if ML finishes faster than visual sequence
        self.queued_final_state = None
        self.queued_risk_score = 0.0
        
        self.running = True
        self.after(30, self._animate)

    def set_state(self, state, risk_score=0.0):
        # Prevent SAFE before COMPLETION
        if state == "SAFE" and self.state not in ("ANALYZING", "SAFE"):
            return
            
        # If we are in ANALYZING, enforce a minimum visual time before showing final
        if self.state == "ANALYZING" and state in ("SAFE", "WARNING", "THREAT DETECTED"):
            elapsed_analyzing = time.time() - self.state_time
            if elapsed_analyzing < 2.5:  # Give the visual pipeline time to play
                self.queued_final_state = state
                self.queued_risk_score = risk_score
                return
                
        self.state = state
        self.risk_score = risk_score
        self.state_time = time.time()
        
        if state in ("SCANNING", "INITIALIZING", "PROCESS_ANALYSIS", "FILE_ANALYSIS"):
            self.rings.append({"radius": 20, "life": 1.0, "color": "#00d4ff"})
            
        if state == "ANALYZING":
            # Spawn 19 feature particles
            for i in range(19):
                a = math.radians((360 / 19) * i)
                self.particles.append({
                    "x": math.cos(a)*200, "y": math.sin(a)*200,
                    "vx": -math.cos(a)*5, "vy": -math.sin(a)*5,
                    "life": 1.5, "color": "#ffcc00", "type": "feature"
                })
        elif state == "THREAT DETECTED":
            for _ in range(25):
                a = random.uniform(0, math.pi*2)
                s = random.uniform(3, 9)
                self.particles.append({
                    "x": 0, "y": 0,
                    "vx": math.cos(a)*s, "vy": math.sin(a)*s,
                    "life": 1.5, "color": "#ff2a2a", "type": "explosion"
                })

    def update_data(self, scan_result):
        self.scan_data = scan_result
        if self.state in ("IDLE", "SAFE", "WARNING", "THREAT DETECTED", "ANALYSIS_ERROR", "SCAN_INCOMPLETE"):
            return
            
        # Deduce fine-grained stages from scan_result properties safely
        if getattr(scan_result, 'state', None):
            s_val = scan_result.state.value if hasattr(scan_result.state, 'value') else str(scan_result.state)
            if s_val == "scanning":
                # Check metrics to guess sub-stage
                f_ins = getattr(scan_result, 'files_inspected', 0)
                p_ana = getattr(scan_result, 'processes_analyzed', 0)
                
                if f_ins > 0 and p_ana == 0:
                    self.visual_substate = "FILE / ENTROPY ANALYSIS"
                elif p_ana > 0:
                    self.visual_substate = "PROCESS ANALYSIS"
                else:
                    self.visual_substate = "COLLECTING TELEMETRY"
                    
            elif s_val == "analyzing":
                pass # Handled by self.state = "ANALYZING"

    def destroy(self):
        self.running = False
        super().destroy()

    def _animate(self):
        if not self.running: return
        try:
            self.delete("all")
            w = self.winfo_width() or 400
            h = self.winfo_height() or 350
            cx, cy = w/2, h/2
            
            now = time.time()
            elapsed = now - self.start_time
            state_elapsed = now - self.state_time
            
            # Handle queued final state
            if self.state == "ANALYZING" and self.queued_final_state and state_elapsed >= 2.5:
                self.set_state(self.queued_final_state, self.queued_risk_score)
                self.queued_final_state = None
            
            color = "#00d4ff"
            outline_width = 2
            rot_y = elapsed * 0.4
            rot_x = math.sin(elapsed * 0.3) * 0.15
            
            label_text = self.state
            sub_label = "CORE ONLINE"
            
            if self.state == "IDLE":
                pass
            elif self.state in ("SCANNING", "INITIALIZING"):
                color = "#00ffcc"
                outline_width = 3
                rot_y = elapsed * 2.5
                rot_x = math.sin(elapsed) * 0.2
                label_text = self.visual_substate if self.visual_substate else "SENTINELML ANALYSIS INITIALIZING"
                
                # Radar sweep
                sweep_angle = (elapsed * 3) % (math.pi * 2)
                self.create_line(cx, cy, cx + math.cos(sweep_angle) * 160, cy + math.sin(sweep_angle) * 160, fill="#006488", dash=(2, 4))
                r = 150 + math.sin(elapsed*4)*5
                self.create_oval(cx-r, cy-r, cx+r, cy+r, outline="#004466", dash=(4, 8))
                
                # Incoming telemetry streams
                if random.random() < 0.3:
                    a = random.uniform(0, math.pi*2)
                    self.particles.append({"x": math.cos(a)*200, "y": math.sin(a)*200, "vx": -math.cos(a)*8, "vy": -math.sin(a)*8, "life": 1.0, "color": "#00ffcc", "type": "stream"})
                    
                if self.scan_data:
                    sub_label = f"Files: {getattr(self.scan_data, 'files_inspected', 0)} | Procs: {getattr(self.scan_data, 'processes_analyzed', 0)}"
                
            elif self.state == "ANALYZING":
                color = "#ffcc00"
                outline_width = 3
                rot_y = elapsed * 4.0
                rot_x = 0
                
                # ML Pipeline Sequence
                if state_elapsed < 0.8:
                    label_text = "FEATURE EXTRACTION"
                    sub_label = "Extracting 19 Behavioral Features..."
                elif state_elapsed < 1.6:
                    label_text = "STANDARD SCALING"
                    sub_label = "Normalizing Vectors..."
                else:
                    label_text = "RANDOM FOREST ANALYSIS"
                    sub_label = "Evaluating Probability..."
                
                r = 140 - (state_elapsed*50)%40
                self.create_oval(cx-r, cy-r, cx+r, cy+r, outline="#aa8800", dash=(2, 4))
                
            elif self.state == "SAFE":
                color = "#00ff88"
                label_text = "ANALYSIS COMPLETE"
                sub_label = "RESULT: SAFE"
                rot_x = 0
            elif self.state == "WARNING":
                color = "#ff8800"
                outline_width = 3 + math.sin(elapsed*10)*2
                rot_y = elapsed * 3.5
                label_text = "ANALYSIS COMPLETE"
                sub_label = f"RESULT: WARNING ({self.risk_score*100:.1f}%)"
                pr = 140 + (elapsed * 50) % 60
                alpha = max(0, 1.0 - (pr-140)/60)
                if alpha > 0.1:
                    self.create_oval(cx-pr, cy-pr, cx+pr, cy+pr, outline=color, width=int(2*alpha))
            elif self.state == "THREAT DETECTED":
                color = "#ff2a2a"
                outline_width = 4 + math.sin(elapsed*15)*2
                rot_y = elapsed * 5.0
                rot_x = math.sin(elapsed*20) * 0.3
                label_text = "ANALYSIS COMPLETE"
                sub_label = f"THREAT DETECTED ({self.risk_score*100:.1f}%)"
                pr = 140 + (elapsed * 60) % 80
                alpha = max(0, 1.0 - (pr-140)/80)
                if alpha > 0.1:
                    self.create_oval(cx-pr, cy-pr, cx+pr, cy+pr, outline=color, width=int(3*alpha))
            elif self.state == "SCAN_INCOMPLETE":
                color = "#8b949e"
                label_text = "SCAN INCOMPLETE"
                sub_label = getattr(self.scan_data, "error_message", "Cancelled by user") if self.scan_data else "Cancelled"
                rot_y = elapsed * 0.1
            elif self.state == "ANALYSIS_ERROR":
                color = "#e3b341"
                label_text = "ANALYSIS ERROR"
                sub_label = getattr(self.scan_data, "error_message", "Failed to analyze telemetry") if self.scan_data else "Error"
                rot_y = elapsed * 0.1
                
            # Draw Shield Core Projection
            proj = []
            for p in self.shield_points:
                c_y, s_y = math.cos(rot_y), math.sin(rot_y)
                rx, rz = p["x"]*c_y - p["z"]*s_y, p["x"]*s_y + p["z"]*c_y
                ry = p["y"]
                c_x, s_x = math.cos(rot_x), math.sin(rot_x)
                ry, rz = ry*c_x - rz*s_x, ry*s_x + rz*c_x
                z = rz - 400
                f = 400 / z if z < -1 else 1
                proj.extend([cx + rx*f, cy + ry*f])
                
            if len(proj) == 12:
                self.create_polygon(proj, fill="", outline=color, width=int(outline_width))
                for scale in [0.7, 0.4]:
                    inner = []
                    for i in range(0, len(proj), 2):
                        inner.extend([cx + (proj[i]-cx)*scale, cy + (proj[i+1]-cy)*scale])
                    self.create_polygon(inner, fill="", outline=color, width=1, dash=(2, 4))
                for i in range(0, len(proj), 2):
                    self.create_line(cx, cy, proj[i], proj[i+1], fill=color, dash=(1, 5))
                    
            # Draw rings
            new_rings = []
            for ring in self.rings:
                r = ring["radius"]
                ring["radius"] += 4
                ring["life"] -= 0.05
                if ring["life"] > 0:
                    self.create_oval(cx-r, cy-r, cx+r, cy+r, outline=ring["color"], width=int(ring["life"]*3))
                    new_rings.append(ring)
            self.rings = new_rings
            
            # Draw particles
            new_particles = []
            for p in self.particles:
                p["x"] += p["vx"]
                p["y"] += p["vy"]
                p["life"] -= 0.05
                if p["life"] > 0:
                    px, py = cx + p["x"], cy + p["y"]
                    if p["type"] == "feature":
                        self.create_text(px, py, text="1", font=("Consolas", 8), fill=p["color"])
                    else:
                        self.create_oval(px-2, py-2, px+2, py+2, fill=p["color"], outline="")
                    new_particles.append(p)
            self.particles = new_particles

            # Text
            self.create_text(cx, cy - 12, text=label_text, font=("Consolas", 14, "bold"), fill=color)
            self.create_text(cx, cy + 12, text=sub_label, font=("Consolas", 10), fill=color)
                
            # Crosshairs
            self.create_line(cx-180, cy, cx-160, cy, fill="#006488")
            self.create_line(cx+160, cy, cx+180, cy, fill="#006488")
            self.create_line(cx, cy-180, cx, cy-160, fill="#006488")
            self.create_line(cx, cy+160, cx, cy+180, fill="#006488")

        except Exception: pass
        self.after(40, self._animate)
