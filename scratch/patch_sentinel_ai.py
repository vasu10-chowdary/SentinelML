import sys

with open('ai/sentinel_ai.py', 'r', encoding='utf-8') as f:
    ai = f.read()

# For explain_scan
target1 = '''            success, response = self.provider.generate(prompt, self.system_prompt)
            if success:
                return response
            else:
                return self._generate_fallback_summary(scan_result, response)'''

replacement1 = '''            ctx_dict = {
                "scan_state": getattr(scan_result.state, "value", "UNKNOWN") if hasattr(scan_result, "state") else "UNKNOWN",
                "threat_level": getattr(scan_result, 'threat_level', 'Unknown'),
                "ml_probability": float(getattr(scan_result, 'ml_probability', 0.0)),
                "files_inspected": getattr(scan_result, 'files_inspected', 0),
                "processes_analyzed": getattr(scan_result, 'processes_analyzed', 0),
                "ml_executed": getattr(scan_result, 'ml_executed', False),
                "error_message": getattr(scan_result, 'error_message', None)
            }
            features = getattr(scan_result, '_features', None)
            if features is not None and hasattr(features, 'shape') and features.shape == (1, 19):
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
                ctx_dict["features"] = dict(zip(FEATURE_NAMES, features[0].tolist()))

            success, response = self.provider.generate(prompt, self.system_prompt, scan_context=ctx_dict)
            if success:
                return response
            else:
                return self._generate_fallback_summary(scan_result, response)'''

ai = ai.replace(target1, replacement1)
if target1.replace('\n', '\r\n') in ai:
    ai = ai.replace(target1.replace('\n', '\r\n'), replacement1.replace('\n', '\r\n'))

# For ask
target2 = '''        success, response = self.provider.generate(prompt, self.system_prompt)
        if success:
            return response'''

replacement2 = '''        ctx_dict = None
        if scan_result:
            ctx_dict = {
                "scan_state": getattr(scan_result.state, "value", "UNKNOWN") if hasattr(scan_result, "state") else "UNKNOWN",
                "threat_level": getattr(scan_result, 'threat_level', 'Unknown'),
                "ml_probability": float(getattr(scan_result, 'ml_probability', 0.0)),
                "files_inspected": getattr(scan_result, 'files_inspected', 0),
                "processes_analyzed": getattr(scan_result, 'processes_analyzed', 0),
                "ml_executed": getattr(scan_result, 'ml_executed', False),
                "error_message": getattr(scan_result, 'error_message', None)
            }
            features = getattr(scan_result, '_features', None)
            if features is not None and hasattr(features, 'shape') and features.shape == (1, 19):
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
                ctx_dict["features"] = dict(zip(FEATURE_NAMES, features[0].tolist()))

        success, response = self.provider.generate(prompt, self.system_prompt, scan_context=ctx_dict)
        if success:
            return response'''

ai = ai.replace(target2, replacement2)
if target2.replace('\n', '\r\n') in ai:
    ai = ai.replace(target2.replace('\n', '\r\n'), replacement2.replace('\n', '\r\n'))

with open('ai/sentinel_ai.py', 'w', encoding='utf-8') as f:
    f.write(ai)

print("Updated sentinel_ai.py")
