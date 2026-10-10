import tkinter as tk
import time
import math
import random

class Vec3:
    def __init__(self, x, y, z):
        self.x = x
        self.y = y
        self.z = z

class Particle:
    def __init__(self, x, y, z, vx, vy, vz, life, color, ptype, size):
        self.x, self.y, self.z = x, y, z
        self.vx, self.vy, self.vz = vx, vy, vz
        self.life = life
        self.color = color
        self.type = ptype
        self.size = size

def rotate_y(p, angle):
    c, s = math.cos(angle), math.sin(angle)
    return Vec3(p.x * c - p.z * s, p.y, p.x * s + p.z * c)

def rotate_x(p, angle):
    c, s = math.cos(angle), math.sin(angle)
    return Vec3(p.x, p.y * c - p.z * s, p.y * s + p.z * c)

def project(p, cx, cy, fov, viewer_z):
    z = p.z - viewer_z
    if z < 1: z = 1
    factor = fov / z
    return cx + p.x * factor, cy + p.y * factor, factor

def ease_out_cubic(x):
    return 1 - pow(1 - x, 3)

def show_startup_animation_inline(main_window: tk.Tk, duration: int = 4200) -> None:
    try:
        # Hide children safely
        hidden_children = []
        for child in main_window.winfo_children():
            try:
                if child.winfo_manager() == "grid":
                    info = child.grid_info()
                    hidden_children.append((child, info))
                    child.grid_remove()
            except Exception:
                pass
                
        # Full-window borderless canvas
        canvas = tk.Canvas(main_window, bg="#050810", highlightthickness=0)
        canvas.grid(row=0, column=0, rowspan=10, columnspan=10, sticky="nsew")
        
        start_time = time.time()
        particles = []
        
        # Shield geometry
        shield_points = []
        radius = 120
        for i in range(6):
            a = math.radians(60 * i + 30)
            shield_points.append(Vec3(math.cos(a)*radius, math.sin(a)*radius, 0))
        
        # Background Grid
        grid_lines = []
        for i in range(-6, 7):
            grid_lines.append((Vec3(i*150, 300, -500), Vec3(i*150, 300, 2000)))
            grid_lines.append((Vec3(-1000, 300, i*150 + 500), Vec3(1000, 300, i*150 + 500)))

        def add_threat_particles():
            for _ in range(8):
                x = random.uniform(-400, 400)
                y = random.uniform(-300, 100)
                z = random.uniform(800, 1400)
                vz = random.uniform(-25, -10)
                particles.append(Particle(x, y, z, 0, 0, vz, 1.0, "#ff2a2a", "line", random.uniform(2, 5)))

        def add_shield_impact_particles():
            for _ in range(80):
                angle = random.uniform(0, math.pi*2)
                speed = random.uniform(10, 30)
                vx = math.cos(angle) * speed
                vy = math.sin(angle) * speed
                vz = random.uniform(-10, 20)
                color = random.choice(["#00d4ff", "#00ff88", "#ffffff", "#1a3a4a"])
                particles.append(Particle(0, 0, 0, vx, vy, vz, 1.0, color, "dot", random.uniform(2,6)))

        def animate_frame():
            now = time.time()
            elapsed_ms = (now - start_time) * 1000
            progress = min(elapsed_ms / duration, 1.0)
            
            if progress >= 1.0:
                canvas.destroy()
                for child, info in hidden_children:
                    try: child.grid(**info)
                    except Exception: pass
                try: main_window.focus_set()
                except Exception: pass
                return

            canvas.delete("all")
            width = canvas.winfo_width() or 1280
            height = canvas.winfo_height() or 800
            cx, cy = width / 2, height / 2

            # Very slow camera movement
            cam_z = -400 + (progress * 150)
            
            # Scene timings
            # Scene 1: 0.0-0.8s (progress < 0.19)
            # Scene 2: 0.8-1.6s (0.19 to 0.38)
            # Scene 3: 1.6-2.5s (0.38 to 0.59)
            # Scene 4: 2.5-3.3s (0.59 to 0.78)
            # Scene 5: 3.3-4.0s (0.78 to 0.95)
            # Scene 6: >4.0s (0.95+)
            
            # 1. Background Grid (Cyber Environment)
            grid_speed = elapsed_ms * 0.3
            for p1, p2 in grid_lines:
                shifted_p1 = Vec3(p1.x, p1.y, ((p1.z - grid_speed) % 2500) - 500)
                shifted_p2 = Vec3(p2.x, p2.y, ((p2.z - grid_speed) % 2500) - 500)
                px1, py1, f1 = project(shifted_p1, cx, cy, 400, cam_z)
                px2, py2, f2 = project(shifted_p2, cx, cy, 400, cam_z)
                if f1 > 0 and f2 > 0:
                    canvas.create_line(px1, py1, px2, py2, fill="#0c1626", width=1)

            # 2. Ransomware Threat Spawning (Scene 2)
            if 0.19 < progress < 0.78:
                if random.random() < 0.3:
                    add_threat_particles()

            # 5. Shield Impact & Deflection (Scene 5)
            if 0.78 < progress < 0.80:
                if not hasattr(animate_frame, 'impact_done'):
                    animate_frame.impact_done = True
                    add_shield_impact_particles()
                    for p in particles:
                        if p.color == "#ff2a2a":
                            p.color = "#4a6a8a"
                            p.vx = random.uniform(-20, 20)
                            p.vy = random.uniform(-20, 20)
                            p.vz = random.uniform(5, 30)

            # Particle System Update
            alive_particles = []
            for p in particles:
                p.x += p.vx
                p.y += p.vy
                p.z += p.vz
                p.life -= 0.012
                if p.life > 0 and p.z > cam_z:
                    px, py, f = project(p, cx, cy, 400, cam_z)
                    if f > 0:
                        size = max(1, int(p.size * f))
                        if p.type == "dot":
                            canvas.create_oval(px-size, py-size, px+size, py+size, fill=p.color, outline="")
                        elif p.type == "line":
                            px_old, py_old, _ = project(Vec3(p.x-p.vx*3, p.y-p.vy*3, p.z-p.vz*3), cx, cy, 400, cam_z)
                            canvas.create_line(px, py, px_old, py_old, fill=p.color, width=size)
                    alive_particles.append(p)
            particles[:] = alive_particles

            # Shield Drawing (Scene 3+)
            if progress > 0.38:
                shield_prog = min((progress - 0.38) / 0.15, 1.0)
                shield_prog = ease_out_cubic(shield_prog)
                
                shield_rot_y = elapsed_ms * 0.001
                shield_rot_x = 0
                if 0.77 < progress < 0.85:
                    shake = (0.85 - progress) * 0.5
                    shield_rot_x = math.sin(elapsed_ms*0.1) * shake
                    shield_rot_y += math.cos(elapsed_ms*0.1) * shake

                proj_points = []
                for p in shield_points:
                    rp = rotate_x(rotate_y(p, shield_rot_y), shield_rot_x)
                    rp.x *= shield_prog
                    rp.y *= shield_prog
                    rp.z *= shield_prog
                    px, py, f = project(rp, cx, cy, 400, cam_z)
                    proj_points.extend([px, py])

                if len(proj_points) == 12:
                    color = "#00d4ff" if progress < 0.78 else "#00ff88"
                    width = max(1, int(2 + shield_prog*2))
                    canvas.create_polygon(proj_points, fill="", outline=color, width=width)
                    
                    inner = []
                    for i in range(0, len(proj_points), 2):
                        inner.extend([cx + (proj_points[i]-cx)*0.65, cy + (proj_points[i+1]-cy)*0.65])
                    canvas.create_polygon(inner, fill="", outline="#1a5a7a", width=1)
                    
                    # Core "S"
                    canvas.create_text(cx, cy, text="S", font=("Arial", int(36*shield_prog), "bold"), fill=color)

            # --- TEXT SEQUENCING ---
            
            # Scene 2
            if 0.19 < progress < 0.38:
                canvas.create_text(cx, cy - 120, text="SUSPICIOUS ACTIVITY", font=("Consolas", 18, "bold"), fill="#ff2a2a")
                
            # Scene 3
            if 0.38 <= progress < 0.59:
                canvas.create_text(cx, cy - 180, text="SENTINELML V2", font=("Arial", 28, "bold"), fill="#ffffff")
                canvas.create_text(cx, cy - 140, text="BEHAVIORAL DETECTION", font=("Consolas", 14, "bold"), fill="#00d4ff")
                
            # Scene 4
            if 0.59 <= progress < 0.78:
                canvas.create_text(cx, cy - 180, text="BEHAVIOR → 19 FEATURES → ML ANALYSIS", font=("Consolas", 16, "bold"), fill="#00d4ff")
                for i in range(5):
                    px = cx + math.cos(elapsed_ms*0.003 + i*1.2)*140
                    py = cy + math.sin(elapsed_ms*0.003 + i*1.2)*140
                    canvas.create_line(px, py, cx, cy, fill="#006488", dash=(2,4))
                    
            # Scene 5
            if 0.78 <= progress < 0.92:
                ring_prog = min((progress - 0.78) / 0.10, 1.0)
                r = ring_prog * 800
                canvas.create_oval(cx-r, cy-r, cx+r, cy+r, outline="#00ff88", width=max(1, int((1-ring_prog)*10)))
                
            # Scene 6
            if progress >= 0.85:
                fade = min((progress - 0.85) / 0.10, 1.0)
                fade_up = 30 * (1 - ease_out_cubic(fade))
                canvas.create_text(cx, cy - 40 + fade_up, text="SENTINELML V2", font=("Arial", 42, "bold"), fill="#ffffff")
                canvas.create_text(cx, cy + 20 + fade_up, text="DETECT   •   ANALYZE   •   RESPOND", font=("Arial", 14, "bold"), fill="#00d4ff")

            canvas.after(16, animate_frame)

        animate_frame()

    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Animation failed: {e}")
