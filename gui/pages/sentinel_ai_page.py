SENTINEL_AI_GUI_TIMEOUT = 210
from tkinter import Canvas
import math
import time
import threading
import datetime
import customtkinter as ctk
from constants import COLOURS as C
from utils.logging_config import get_gui_logger

log = get_gui_logger()

class SentinelAIPage(ctk.CTkFrame):
    def __init__(self, master, config: dict, **kwargs):
        super().__init__(master, fg_color=C["bg"], **kwargs)
        self._config = config
        self._main_window = master
        self._build()

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # -- Header -------------------------------------------------------
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=32, pady=(28, 16))
        
        ctk.CTkLabel(
            hdr, text="SENTINELAI",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color=C["white"],
        ).pack(side="left")
        
        ctk.CTkLabel(
            hdr, text="Security Copilot",
            font=ctk.CTkFont(size=13),
            text_color=C["accent"],
        ).pack(side="left", padx=(14, 0), pady=(6, 0))

        self._ai_status = ctk.CTkLabel(
            hdr, text="AI Status: INITIALIZING",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        )
        self._ai_status.pack(side="right", pady=(6, 0))

        # -- Content Layout ------------------------------------------------
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=32, pady=(0, 24))
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(2, weight=1)

        # AI Holographic Core
        self.ai_canvas = Canvas(content, height=120, bg="#050810", highlightthickness=0)
        self.ai_canvas.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        self.start_time = time.time()
        self.running = True
        self.after(50, self._animate_ai_core)


        # Top Buttons
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.grid(row=1, column=0, sticky="ew", pady=(0, 16))

        for btn_text in ["ANALYZE LATEST SCAN", "EXPLAIN RESULT", "INCIDENT SUMMARY"]:
            btn = ctk.CTkButton(
                btn_frame, text=btn_text,
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color=C["panel"], hover_color=C["card"], text_color=C["white"],
                command=lambda t=btn_text: self._on_preset_click(t)
            )
            btn.pack(side="left", padx=(0, 10))
            
        btn_clear = ctk.CTkButton(
            btn_frame, text="CLEAR CHAT",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=C["panel"], hover_color=C["red"], text_color=C["muted"],
            command=self._clear_chat
        )
        btn_clear.pack(side="right")

        # Chat Area
        self._chat_display = ctk.CTkTextbox(
            content, font=ctk.CTkFont(size=13),
            fg_color=C["panel"], text_color=C["white"],
            wrap="word", state="disabled"
        )
        self._chat_display.grid(row=1, column=0, sticky="nsew", pady=(0, 16))

        # Preset Questions
        presets_frame = ctk.CTkScrollableFrame(content, height=40, fg_color="transparent", orientation="horizontal")
        presets_frame.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        
        presets = [
            "Why was my system flagged?",
            "Explain my latest scan",
            "What should I do now?",
            "Explain the risk score",
            "What does high entropy mean?",
            "Explain the suspicious processes"
        ]
        for p in presets:
            btn = ctk.CTkButton(
                presets_frame, text=p,
                font=ctk.CTkFont(size=11), height=24,
                fg_color=C["card"], hover_color=C["card"], text_color=C["muted"],
                command=lambda q=p: self._on_preset_click(q)
            )
            btn.pack(side="left", padx=(0, 8))

        # Input Area
        input_frame = ctk.CTkFrame(content, fg_color="transparent")
        input_frame.grid(row=3, column=0, sticky="ew")
        input_frame.grid_columnconfigure(0, weight=1)

        self._chat_input = ctk.CTkEntry(
            input_frame, placeholder_text="Ask SentinelAI...",
            font=ctk.CTkFont(size=13), height=40,
            fg_color=C["card"], border_color=C["border"]
        )
        self._chat_input.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        self._chat_input.bind("<Return>", lambda e: self._send_message())

        self._send_btn = ctk.CTkButton(
            input_frame, text="SEND", width=80, height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=C["accent"], hover_color=C["card"],
            command=self._send_message
        )
        self._send_btn.grid(row=0, column=1)

        self._update_status_task()
        self._append_message(
            "SentinelAI",
            "Hello. I am SentinelAI — the security copilot for SentinelML.\n\n"
            "I can explain scan results, analyze behavioral indicators, and give defensive recommendations.\n\n"
            "If AI Status shows DISABLED:\n"
            "  \u2192 Go to Settings > SentinelAI Copilot and Enable SentinelAI\n\n"
            "If AI Status shows OFFLINE, UNAVAILABLE, ERROR or TIMEOUT:\n"
            "  \u2192 The AI service is temporarily unreachable.\n"
            "  \u2192 Click TEST CONNECTION in Settings to retry, or provide a personal Gemini API key as a fallback.\n\n"
            "If AI Status shows READY, you can start asking questions below."
        )

    def _update_status_task(self):
        if hasattr(self._main_window, 'ai_copilot'):
            status = self._main_window.ai_copilot.status
            color = C["green"] if status == "READY" else C["orange"]
            if status in ["ERROR", "UNAVAILABLE", "TIMEOUT", "OFFLINE"]:
                color = C["red"]
            self._ai_status.configure(text=f"AI Status: {status}", text_color=color)
        self.after(2000, self._update_status_task)

    def _clear_chat(self):
        if hasattr(self._main_window, 'ai_copilot'):
            self._main_window.ai_copilot.clear_history()
        self._chat_display.configure(state="normal")
        self._chat_display.delete("0.0", "end")
        self._chat_display.configure(state="disabled")
        self._append_message("SentinelAI", "Conversation cleared.")
        
    def _append_message(self, sender: str, msg: str):
        self._chat_display.configure(state="normal")
        color = "blue" if sender == "User" else "green"
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self._chat_display.insert("end", f"[{timestamp}] {sender}:\n{msg}\n\n")
        self._chat_display.see("end")
        self._chat_display.configure(state="disabled")

    def _on_preset_click(self, text: str):
        self._chat_input.delete(0, 'end')
        self._chat_input.insert(0, text)
        self._send_message()

    def _send_message(self):
        text = self._chat_input.get().strip()
        if not text:
            return
            
        self._chat_input.delete(0, 'end')
        self._append_message("User", text)
        
        if not hasattr(self._main_window, 'ai_copilot'):
            self._append_message("SentinelAI", "Error: SentinelAI is not initialized. Please restart the application.")
            return
            
        copilot = self._main_window.ai_copilot
        if copilot.status == "NOT_CONFIGURED":
            self._append_message(
                "SentinelAI",
                "SENTINEL AI\n\n"
                "AI assistance is provided through the SentinelML AI service.\n"
                "You do not need to provide your own Gemini API key.\n\n"
                "To get started:\n"
                "  1. Go to Settings (sidebar)\n"
                "  2. Enable SentinelAI (toggle ON)\n"
                "  3. Click TEST CONNECTION"
            )
            return
        elif copilot.status == "DISABLED":
            self._append_message(
                "SentinelAI",
                "SENTINEL AI\n\n"
                "AI assistance is provided through the SentinelML AI service.\n"
                "You do not need to provide your own Gemini API key.\n\n"
                "To get started:\n"
                "  1. Go to Settings (sidebar)\n"
                "  2. Enable SentinelAI (toggle ON)\n"
                "  3. Click TEST CONNECTION"
            )
            return
        elif copilot.status == "AUTHENTICATION_ERROR":
            self._append_message("SentinelAI", f"AUTHENTICATION ERROR\n\nAPI Key is invalid or unauthorized.\n{getattr(copilot, 'status_detail', '')}\n\nGo to Settings > SentinelAI Copilot to update your API key.")
            return
        # MODEL_UNAVAILABLE, TIMEOUT, INITIALIZING, ERROR → attempt anyway, retries in provider will handle it
            
        self._send_btn.configure(state="disabled")
        self._chat_input.configure(state="disabled")
        
        # Display thinking placeholder
        self._chat_display.configure(state="normal")
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self._chat_display.insert("end", f"[{timestamp}] SentinelAI:\n")
        thinking_start = self._chat_display.index("end - 1c")
        self._chat_display.insert("end", "Analyzing your request...\n\n")
        self._chat_display.see("end")
        self._chat_display.configure(state="disabled")
        
        self._request_id = getattr(self, "_request_id", 0) + 1
        current_req = self._request_id
        
        def _process():
            import time, logging
            log = logging.getLogger("sentinel.gui")
            log.info(f"AI_GUI_REQUEST_START | TS: {time.time()} | REQ_ID: {current_req}")
            try:
                scan_res = None
                if "dashboard" in self._main_window._pages:
                    scan_res = getattr(self._main_window._pages["dashboard"], "_last_scan_result", None)

                if text == "ANALYZE LATEST SCAN":
                    if not scan_res:
                        reply = "No recent scan is available to analyze. Please run a scan first."
                    else:
                        reply = copilot.explain_scan(scan_res)
                elif text == "EXPLAIN RESULT":
                    if not scan_res:
                        reply = "No result to explain. Please run a scan first."
                    else:
                        reply = copilot.explain_scan(scan_res)
                elif text == "INCIDENT SUMMARY":
                    if not scan_res:
                        reply = "No incident to summarize. Please run a scan first."
                    else:
                        reply = copilot.ask("Generate a structured INCIDENT SUMMARY for this scan.", scan_res)
                else:
                    reply = copilot.ask(text, scan_res)
                
                if not reply or not str(reply).strip():
                    reply = "SENTINELAI RETURNED AN EMPTY RESPONSE."
                    
                log.info(f"AI_GUI_CALLBACK | REQ_ID: {current_req} | SUCCESS: {bool(reply)}")
                self.after(0, self._on_message_received, thinking_start, reply, current_req)
            except Exception as e:
                

                import logging
                logging.getLogger("sentinel.gui").error("AI Thread crash: %s", e, exc_info=True)
                self.after(0, self._on_message_received, thinking_start, "I couldn't reach the configured AI backend.\n\nAn unexpected network or configuration error occurred. Please check your connectivity.", current_req)
                
        def _timeout_monitor():
            import time
            time.sleep(SENTINEL_AI_GUI_TIMEOUT)
            # Dispatch the timeout message to the main thread
            timeout_msg = f"SENTINELAI NETWORK TIMEOUT\n\nThe AI service could not be reached within {SENTINEL_AI_GUI_TIMEOUT} seconds. Please check your internet connection and try again."
            self.after(0, self._on_message_received, thinking_start, timeout_msg, current_req)

        import threading
        threading.Thread(target=_process, daemon=True, name=f"AIChatThread_{current_req}").start()
        threading.Thread(target=_timeout_monitor, daemon=True, name=f"AITimeoutThread_{current_req}").start()

    def _on_message_received(self, start_idx: str, reply: str, req_id: int = -1):
        import time, logging
        logging.getLogger("sentinel.gui").info(f"AI_GUI_REQUEST_END | TS: {time.time()} | REQ_ID: {req_id}")
        if req_id != -1 and req_id != getattr(self, "_request_id", -1):
            return  # Ignore stale or already-processed request
            
        # Mark as processed by advancing the ID so the monitor/worker doesn't overwrite
        if req_id != -1:
            self._request_id += 1
        
        self._chat_display.configure(state="normal")
        # Replace the 'Analyzing your request...' text
        self._chat_display.delete(start_idx, "end")
        # Add a newline explicitly just in case it was swallowed
        self._chat_display.insert("end", f"\n{reply}\n\n")
        self._chat_display.see("end")
        self._chat_display.configure(state="disabled")
        
        self._send_btn.configure(state="normal")
        self._chat_input.configure(state="normal")
        self._chat_input.focus_set()

    def destroy(self):
        self.running = False
        super().destroy()

    def _animate_ai_core(self):
        if not hasattr(self, "running") or not self.running:
            return
        
        try:
            self.ai_canvas.delete("all")
            w = self.ai_canvas.winfo_width()
            h = self.ai_canvas.winfo_height()
            if w > 100:
                import time, math
                cx, cy = w/2, h/2
                elapsed = time.time() - getattr(self, "start_time", time.time())
                
                # Draw rotating data rings
                r1 = 30 + math.sin(elapsed * 2) * 5
                r2 = 45 + math.cos(elapsed * 1.5) * 5
                
                # Central core
                self.ai_canvas.create_oval(cx-r1, cy-r1, cx+r1, cy+r1, outline="#b800ff", width=2, dash=(4, 4))
                self.ai_canvas.create_oval(cx-r2, cy-r2, cx+r2, cy+r2, outline="#00d4ff", width=1, dash=(2, 6))
                
                # Floating data nodes
                for i in range(5):
                    angle = elapsed * (1 + i*0.2) + i * (math.pi*2 / 5)
                    x = cx + math.cos(angle) * r2 * 1.5
                    y = cy + math.sin(angle) * r2 * 0.5
                    self.ai_canvas.create_oval(x-2, y-2, x+2, y+2, fill="#00ff88", outline="")
                    self.ai_canvas.create_line(cx, cy, x, y, fill="#2a3b5c", dash=(2, 4))
        except Exception:
            pass
            
        self.after(50, self._animate_ai_core)

