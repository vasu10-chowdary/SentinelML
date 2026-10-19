import sys
import re

with open('ai/sentinel_ai.py', 'r', encoding='utf-8') as f:
    text = f.read()
    if text.startswith('\ufeff'):
        text = text[1:]

replacement = '''    def _build_context_dict(self, scan_result) -> dict:
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
            "processes_inspected": getattr(scan_result, 'processes_analyzed', 0),
            "scan_duration": getattr(scan_result, 'elapsed_seconds', 0.0),
            "skipped_files": getattr(scan_result, 'files_skipped', 0),
            "access_denied": getattr(scan_result, 'access_denied_count', 0),
            "errors": getattr(scan_result, 'error_message', None),
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
            return "SentinelAI is currently unavailable. Ensure it is enabled and configured in Settings."

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
            "SENTINELAI TEMPORARILY UNAVAILABLE\\n\\n"
            f"AI analysis could not be generated because the configured language model is unreachable or overloaded.\\n"
            f"Reason: {error_msg}\\n\\n"
            "--- SENTINELML RESULT SUMMARY ---\\n\\n"
            f"Your SentinelML result remains: {threat} ({state})\\n"
        )
        if getattr(scan_result, 'ml_executed', False):
            fallback += f"Malicious Probability: {prob:.2f}\\n\\n"
            if threat == "THREAT DETECTED":
                fallback += "SentinelML classified this scan as a THREAT because the malicious probability exceeded the high-confidence threshold. Immediate defensive action is required.\\n"
            elif threat == "WARNING":
                fallback += "SentinelML classified this scan as a WARNING because the malicious probability was elevated above normal bounds but below the high-confidence threat threshold. Review system activity.\\n"
            else:
                fallback += "SentinelML classified this scan as SAFE because the behavioral probability was within normal bounds.\\n"
        else:
            fallback += "Machine learning analysis was not executed for this scan.\\n"
            
        fallback += "\\nYou can still view details in the Threat Log or generate an incident report.\\n"
        return fallback.replace("\\\\n", "\\n") # Unescape because the f-string evaluates the literal

    def ask(self, question: str, scan_result=None) -> str:
        if not self.provider or self.status != "READY":
            return "SentinelAI is currently unavailable."

        ctx_dict = self._build_context_dict(scan_result)
        
        if not ctx_dict:
            prompt_context = "No active scan data available. The user has not completed a scan yet."
        else:
            import json
            prompt_context = "SentinelML Scan Context (JSON):\\n" + json.dumps(ctx_dict, indent=2)

        sys_instructions = (
            "SentinelML's RandomForest result is authoritative. "
            "Do not change SAFE/WARNING/THREAT. "
            "Do not invent threats. "
            "Do not invent scan values. "
            "Explain what the observed indicators mean. "
            "Distinguish evidence from interpretation. "
            "If SAFE, explain why the result is currently SAFE. "
            "If WARNING, explain the observed indicators and recommended next steps. "
            "If THREAT, explain the evidence and immediate response. "
            "Mention limitations of Linux telemetry where Windows-only features are unavailable."
        )

        history_str = "\\n".join([f"{role}: {msg}" for role, msg in self.history[-6:]])
        
        prompt = (
            f"System Instructions:\\n{sys_instructions}\\n\\n"
            f"{prompt_context}\\n\\n"
            f"Conversation History:\\n{history_str}\\n\\n"
            f"User Question: {question}"
        )
        
        self.history.append(("User", question))
        
        success, response = self.provider.generate(prompt, self.system_prompt, scan_context=ctx_dict)
        if success:
            self.history.append(("SentinelAI", response))
            return response
        return (f"SENTINELAI TEMPORARILY UNAVAILABLE\\n\\nThe AI model is temporarily unavailable due to provider capacity or connectivity issues."
                f"\\n\\nReason: {response}\\n\\nYour SentinelML detection result is unaffected.").replace("\\\\n", "\\n")'''

pattern = re.compile(r'    def explain_scan\(self, scan_result\) -> str:.*?    def clear_history\(self\):', re.DOTALL)
if pattern.search(text):
    text = pattern.sub(replacement + '\n\n    def clear_history(self):', text)
    # Convert exactly "\\n" back to "\n" for correct string literal formatting
    text = text.replace('\\\\n', '\\n')
    with open('ai/sentinel_ai.py', 'w', encoding='utf-8') as f:
        f.write(text)
    print("Successfully patched sentinel_ai.py")
else:
    print("Could not find replacement block")
