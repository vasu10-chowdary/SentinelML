import joblib
import numpy as np

m = joblib.load('models/saved_model.pkl')
s = joblib.load('models/scaler.pkl')

x_high2 = np.array([[
    150.0, # total_processes
    25.0,  # suspicious_process_count
    7.98,  # avg_entropy
    8.00,  # max_entropy
    80.0,  # high_entropy_region_count
    20.0,  # malfind_injection_count
    18.0,  # crypto_dll_count
    10.0,  # cmd_vssadmin_count
    120.0, # network_connection_count
    40.0,  # unique_external_ips
    2500.0,# file_handle_count
    500.0, # registry_handle_count
    18.0,  # orphan_process_count
    10.0,  # powershell_process_count
    15.0,  # unsigned_module_count
    8.0,   # suspicious_mutex_count
    12.0,  # abnormal_privilege_count
    60.0,  # suspicious_thread_count
    8.0    # defender_tampering_count
]], dtype=np.float64)

x_scaled2 = s.transform(x_high2)
probs2 = m.predict_proba(x_scaled2)[0]
print(f"Prob: {probs2[1]:.4f}")
