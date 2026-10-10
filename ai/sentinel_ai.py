import logging
from typing import Optional, Dict, Tuple
from ai.provider import AIProvider, OllamaProvider, GeminiProvider, SentinelBackendProvider

log = logging.getLogger(__name__)

class DemoProvider(AIProvider):
    def get_name(self) -> str:
        return "Simulated (DEMO MODE)"

    def is_available(self) -> bool:
        return True

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[bool, str]:
        import time
        time.sleep(1.0)

        if "SAFE" in prompt:
            res = "[DEMO MODE] Based on the extracted behavioral indicators, the system appears benign. Filesystem entropy is within normal bounds (avg < 6.5), and process handle counts are standard. No ransomware-like file extensions were detected."
        elif "WARNING" in prompt:
            res = "[DEMO MODE] Suspicious activity detected. The system shows elevated file modification rates and a high process count. While this could be a heavy legitimate workload, the pattern strongly resembles early-stage ransomware preparation. Recommended action: run a deeper scan."
        else:
            res = "[DEMO MODE] High-confidence malicious behavior detected. High entropy files (.encrypted) and elevated vssadmin usage indicate ransomware behavior. Disconnect immediately."

        return True, res



class SentinelAI:
    def __init__(self, config: Dict):
        self.config = config
        self.provider: Optional[AIProvider] = None
        self.status = "NOT_CONFIGURED"
        self.history = []

        self.system_prompt = (
            "You are SentinelAI, a Security Copilot assisting users with SentinelML V2.\n"
            "SentinelML is an ML-powered ransomware and behavioral detection tool.\n"
            "Your role is to EXPLAIN security scans and indicators, NOT to detect them.\n"
            "The Random Forest ML classifier makes the authoritative security decision. You must NEVER override or contradict its classification.\n"
            "If the ML classification is WARNING or THREAT_DETECTED, do NOT say it is SAFE.\n"
            "If the ML classification is SAFE, do NOT invent threats.\n"
            "Do NOT invent file names, processes, or malware families. Base everything on the provided scan context.\n"
            "Always be defensive. Recommend safe practices."
        )

    def initialize(self) -> None:
        self.status = "INITIALIZING"
        self.status_detail = ""
        enabled = self.config.get("enabled", self.config.get("enable_ai", False))
        if not enabled:
            self.status = "DISABLED"
            return

        mode = self.config.get("mode", "backend")

        import sys
        if "--demo" in sys.argv:
            self.provider = DemoProvider()
            self.status = "READY"
            log.info("SentinelAI initialized with Simulated Demo Provider")
            return
            
        prov = None
        backend_status = None
        backend_msg = ""
        
        if mode in ("backend", "auto"):
            url = self.config.get("backend_url", "http://127.0.0.1:8000")
            backend_prov = SentinelBackendProvider(url)
            status_code, msg = backend_prov.is_available()
            if status_code == "READY":
                self.status = status_code
                self.status_detail = msg
                self.provider = backend_prov
                log.info(f"SentinelAI initialized with {backend_prov.get_name()}")
                return
            else:
                backend_status = status_code
                backend_msg = msg
                if mode == "backend":
                    self.status = status_code
                    self.status_detail = msg
                    log.warning(f"SentinelAI backend initialization failed: {msg}")
                    return
        
        # Local / fallback
        if mode in ("local", "auto"):
            backend = self.config.get("backend", "gemini")
            if backend in ("auto", "gemini"):
                api_key = self.config.get("gemini_api_key", "")
                if api_key:
                    prov = GeminiProvider(api_key)
            elif backend == "ollama":
                prov = OllamaProvider()
                
            if prov:
                status_code, msg = prov.is_available()
                if status_code == "READY":
                    self.status = status_code
                    self.status_detail = msg
                    self.provider = prov
                    log.info(f"SentinelAI initialized with {prov.get_name()} (Fallback)")
                    return
                else:
                    log.warning(f"SentinelAI local initialization failed: {msg}")
            
            if mode == "auto" and backend_status:
                self.status = backend_status
                self.status_detail = backend_msg
                log.warning(f"SentinelAI backend failed and no fallback available: {backend_msg}")
            else:
                self.status = "NOT_CONFIGURED"
                self.status_detail = "API Key is missing."

    def _build_context_dict(self, scan_result) -> dict:
        if not scan_result:
            return None
            
        import numpy as np
        d = {
            "scan_state": getattr(scan_result.state, "value", "UNKNOWN") if hasattr(scan_result, "state") else "UNKNOWN",
            "threat_level": getattr(scan_result, 'threat_level', 'Unknown'),
            "ml_probability": float(getattr(scan_result, 'ml_probability', 0.0)),
            "ml_executed": getattr(scan_result, 'ml_executed', False),
            "files_inspected": getattr(scan_result, 'files_inspected', 0),
            "directories_inspected": getattr(scan_result, 'directories_inspected', 0),
            "processes_analyzed": getattr(scan_result, 'processes_analyzed', 0),
            "scan_duration": getattr(scan_result, 'elapsed_seconds', 0.0),
            "skipped_files": getattr(scan_result, 'files_skipped', 0),
            "access_denied": getattr(scan_result, 'access_denied', 0),
            "error_message": getattr(scan_result, 'error_message', None),
        }
        
        feature_names = [
            "total_processes", "suspicious_process_count", "avg_entropy",
            "max_entropy", "high_entropy_region_count", "malfind_injection_count",
            "crypto_dll_count", "cmd_vssadmin_count", "network_connection_count",
            "unique_external_ips", "file_handle_count", "registry_handle_count",
            "orphan_process_count", "powershell_process_count",
            "unsigned_module_count", "suspicious_mutex_count",
            "abnormal_privilege_count", "suspicious_thread_count",
            "defender_tampering_count"
        ]
        d["feature_names"] = feature_names
        
        features = getattr(scan_result, '_features', None)
        if features is not None and hasattr(features, 'shape') and features.shape == (1, 19):
            f_list = features[0].tolist()
            d["features"] = dict(zip(feature_names, f_list))
            d["entropy_samples"] = 200 if f_list[2] > 0 else 0
            d["avg_entropy"] = f_list[2]
            d["max_entropy"] = f_list[3]
            d["high_entropy_region_count"] = int(f_list[4])
            d["network_connections"] = int(f_list[8])
            d["external_ips"] = int(f_list[9])
        else:
            d["features"] = None
            d["entropy_samples"] = 0
            d["avg_entropy"] = 0.0
            d["max_entropy"] = 0.0
            d["high_entropy_region_count"] = 0
            d["network_connections"] = 0
            d["external_ips"] = 0
            
        return d

    def explain_scan(self, scan_result) -> str:
        if not self.provider or self.status != "READY":
            return "SentinelAI is temporarily unavailable. Please try again later. (Check Settings if you wish to configure a personal API key fallback)."

        try:
            return self.ask("Explain my latest scan", scan_result)
        except Exception as e:
            return self._generate_fallback_summary(scan_result, str(e))

    def _generate_fallback_summary(self, scan_result, error_msg: str) -> str:
        """Deterministic fallback summary when generative AI is unavailable."""
        state = getattr(scan_result.state, "value", "UNKNOWN") if hasattr(scan_result, "state") else "UNKNOWN"
        threat = getattr(scan_result, 'threat_level', 'Unknown')
        prob = getattr(scan_result, 'ml_probability', 0.0)
        
        fallback = (
            "SENTINELAI TEMPORARILY UNAVAILABLE\n\n"
            f"AI analysis could not be generated because the configured language model is unreachable or overloaded.\n"
            f"Reason: {error_msg}\n\n"
            "--- SENTINELML RESULT SUMMARY ---\n\n"
            f"Your SentinelML result remains: {threat} ({state})\n"
        )
        if getattr(scan_result, 'ml_executed', False):
            fallback += f"Malicious Probability: {prob:.2f}\n\n"
            if threat == "THREAT DETECTED":
                fallback += "SentinelML classified this scan as a THREAT because the malicious probability exceeded the high-confidence threshold. Immediate defensive action is required.\n"
            elif threat == "WARNING":
                fallback += "SentinelML classified this scan as a WARNING because the malicious probability was elevated above normal bounds but below the high-confidence threat threshold. Review system activity.\n"
            else:
                fallback += "SentinelML classified this scan as SAFE because the behavioral probability was within normal bounds.\n"
        else:
            fallback += "Machine learning analysis was not executed for this scan.\n"
            
        fallback += "\nYou can still view details in the Threat Log or generate an incident report.\n"
        return fallback

    def ask(self, question: str, scan_result=None) -> str:
        if not self.provider or self.status != "READY":
            return "SentinelAI is currently unavailable."

        ctx_dict = self._build_context_dict(scan_result)

        sys_instructions = (
            "RandomForest classification is authoritative. "
            "Use only supplied scan data for scan-specific claims. "
            "Never invent missing values. "
            "Explain evidence separately from interpretation. "
            "Do not change SAFE/WARNING/THREAT classification. "
            "Mention Linux telemetry limitations when relevant. "
            "If no scan context exists, say no active scan data is available."
        )

        # ── Construct the human-readable prompt ──────────────────────────────
        #
        # RULE 1 — SentinelBackendProvider (production backend):
        #   The backend enforces message <= 4000 chars and handles all scan
        #   context server-side via the structured `context` field.
        #   prompt = raw user question ONLY. Never prepend history or embed JSON.
        #
        # RULE 2 — Local providers (Gemini / Ollama):
        #   Prepend bounded recent history for multi-turn context.
        #   Replace any full JSON scan dump with a short plain-text instruction
        #   referencing the structured context — do NOT embed json.dumps(ctx_dict).
        #   Individual history messages are truncated so the total prompt stays
        #   comfortably below 4000 characters even after many turns.

        is_backend_provider = isinstance(self.provider, SentinelBackendProvider)

        if is_backend_provider:
            # Backend path: message = raw user question, always well under 4000 chars.
            # Structured scan data travels separately via scan_context=ctx_dict.
            prompt = question

        else:
            # Local provider path (Gemini / Ollama)
            # Build a bounded history prefix: last 6 turns, each message
            # truncated to 400 chars to cap total history contribution to ~2400 chars.
            MAX_HISTORY_TURNS = 6
            MAX_MSG_CHARS = 400
            history_lines = []
            for role, msg in self.history[-MAX_HISTORY_TURNS:]:
                truncated = msg[:MAX_MSG_CHARS] + ("\u2026" if len(msg) > MAX_MSG_CHARS else "")
                history_lines.append(f"{role}: {truncated}")
            history_str = "\n".join(history_lines)

            # Scan-context reference: a short plain-text instruction, NOT json.dumps.
            # The full structured context is still passed via scan_context=ctx_dict.
            if ctx_dict:
                scan_ref = (
                    "A structured SentinelML scan context is supplied separately "
                    "to the AI provider. Use that structured context as the "
                    "authoritative source of scan values. "
                    "Do not invent or infer missing values."
                )
            else:
                scan_ref = "No active scan data available. The user has not completed a scan yet."

            # Assemble: history (if any) -> scan reference -> user question
            parts = []
            if history_str.strip():
                parts.append(f"Conversation History:\n{history_str}")
            parts.append(f"Scan Context Note: {scan_ref}")
            parts.append(f"User Question: {question}")
            prompt = "\n\n".join(parts)

            # Final safety cap: if somehow still too long, drop history entirely
            if len(prompt) > 3900:
                prompt = "\n\n".join([
                    f"Scan Context Note: {scan_ref}",
                    f"User Question: {question}",
                ])

        self.history.append(("User", question))

        # scan_context=ctx_dict carries structured data for both backend and local
        # providers — do NOT remove this argument.
        success, response = self.provider.generate(prompt, sys_instructions, scan_context=ctx_dict)
        if success:
            self.history.append(("SentinelAI", response))
            return response

        # ── Classify the failure truthfully ──────────────────────────────────
        resp_lower = response.lower()
        if "422" in response or "validation" in resp_lower or "schema" in resp_lower:
            error_category = (
                "Request validation error (HTTP 422). The request payload did not "
                "pass backend schema validation. This is a client-side configuration "
                "issue, not a temporary outage."
            )
        elif "TIMEOUT" in response or "seconds" in response:
            error_category = "Network timeout. The AI service did not respond in time."
        elif "OFFLINE" in response or "Unable to reach" in response:
            error_category = "Network unreachable. Check your internet connection."
        elif "authentication" in resp_lower or "401" in response or "403" in response:
            error_category = "Authentication failure. Check AI configuration in Settings."
        else:
            error_category = response

        return (
            f"SENTINELAI TEMPORARILY UNAVAILABLE\n\n"
            f"The AI model is temporarily unavailable due to provider capacity or connectivity issues.\n\n"
            f"Reason: {error_category}\n\n"
            f"Your SentinelML detection result is unaffected."
        )
    def clear_history(self):
        self.history = []
