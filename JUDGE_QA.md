# SentinelML V2 — Evaluator & Judge Q&A Defense Manual

This document provides concise, technically rigorous, and scientifically defensible answers to the 12 most probable questions from college evaluators, project guides, and cybersecurity judges.

---

### Q1: What problem does SentinelML solve?
**Answer:**
Traditional antivirus relies heavily on static binary signatures (MD5/SHA256 hashes and known byte sequences). Modern ransomware evasions—such as polymorphic compilation, crypters, and packed payloads—easily generate novel hashes that bypass static signature scanners. SentinelML addresses this by focusing on **runtime behavior**, observing observable effects of unauthorized encryption (burst modifications, Shannon entropy shifts, process anomalies) to identify potential ransomware activity regardless of the binary's hash.

---

### Q2: What is machine learning doing in the current implementation?
**Answer:**
Machine learning performs **multi-variate behavioral classification**. Instead of relying on rigid, single-metric `if/else` threshold checks (which produce frequent false alarms on zip archives or video files), SentinelML feeds a normalized 19-position behavioral vector into a 100-estimator `RandomForestClassifier`. The model aggregates decision trees to output a calibrated threat probability between 0.0 and 1.0, enabling weighted decision-making that considers both filesystem and process-level context simultaneously.

---

### Q3: What are the input features?
**Answer:**
The currently deployed model (Model V1) evaluates 19 numerical features:
1. `total_processes` (psutil process count)
2. `suspicious_process_count` (known ransomware/tool names)
3. `avg_entropy` (Shannon entropy across sampled files, 0.0 - 8.0)
4. `max_entropy` (peak file entropy observed)
5. `high_entropy_region_count` (files with entropy > 7.0)
6. `malfind_injection_count` (unbacked executable memory proxy)
7. `crypto_dll_count` (processes loading bcrypt.dll/crypt32.dll)
8. `cmd_vssadmin_count` (shadow copy deletion invocations)
9. `network_connection_count` (active TCP/UDP sockets)
10. `unique_external_ips` (remote non-private IP count)
11. `file_handle_count` (open filesystem handles)
12. `registry_handle_count` (open registry key handles)
13. `orphan_process_count` (processes with non-existent parent PIDs)
14. `powershell_process_count` (active PowerShell instances)
15. `unsigned_module_count` (DLLs lacking Authenticode signatures)
16. `suspicious_mutex_count` (malware synchronization tokens)
17. `abnormal_privilege_count` (tokens with SeDebugPrivilege)
18. `suspicious_thread_count` (threads executing in RWX memory)
19. `defender_tampering_count` (attempts to stop WinDefend service)

*(For future empirical training, we have designed **Schema V2 with 16 features** focused strictly on observable Windows user-space file and process rates).*

---

### Q4: How was the model trained?
**Answer:**
The deployed Random Forest model (`models/saved_model.pkl`) was trained using synthetic Gaussian distributions modeling Volatility memory-forensics telemetry (`sample_data.csv`). It was fitted using scikit-learn's `RandomForestClassifier(n_estimators=100, criterion='gini')` alongside a `StandardScaler`. 

**Scientific caveat:** We explicitly report that this model was trained on synthetic baseline data, not on wild live malware detonations.

---

### Q5: Are the reported accuracy numbers independently validated?
**Answer:**
Our 40-case benchmark achieves 100% precision, 100% recall, and 100% F1-score **specifically on its matching synthetic evaluation distribution** (20 benign vectors vs. 20 simulated ransomware vectors). 

These numbers **have not been independently validated against wild, zero-day, or polymorphic ransomware**. We explicitly report this 100% score as an evaluation of the mathematical model against its synthetic benchmark, not as a claim of 100% real-world ransomware immunity.

---

### Q6: How does the demonstration work safely?
**Answer:**
The live demonstration operates under strict containment invariants:
1. **Zero Malware**: No malicious binaries, live exploits, or destructive encryption scripts are executed.
2. **Disposable Sandbox**: All operations occur strictly within `temp_sandbox/`.
3. **Path Traversal Protection**: Every file access is checked by `validate_path_safety()`. Any attempt to escape via `../` or access `C:\Windows\` immediately triggers a `SecurityError` and halts execution.
4. **Synthetic Payloads**: Dummy plaintext files are replaced with pseudorandom bytes from `os.urandom(2048)` to simulate the high Shannon entropy of ciphertext without risking real data.
5. **Instant Purge**: `reset_sandbox()` completely purges all generated files immediately after the demo.

---

### Q7: What happens when telemetry or inference fails?
**Answer:**
SentinelML enforces a **strict fail-safe state invariant: missing telemetry or error NEVER defaults to SAFE**.
- If process enumeration or filesystem crawling fails, the scan transitions to `SCAN_INCOMPLETE` with threat level `ANALYSIS_ERROR`.
- If the feature vector contains `NaN` or `Inf`, or if the model file is missing, `MLPredictor.predict()` returns `None`, forcing state `ANALYSIS_ERROR`.
- A scan produces `SAFE` **only** if all sensors complete successfully and the model probability is below `0.50`.

---

### Q8: What is the difference between SAFE, WARNING, and confirmed ransomware?
**Answer:**
- **`SAFE` (p < 0.50)**: Normal system activity under tested checks. Plaintext files (entropy ~4.4) and baseline processes. Does not guarantee absolute absence of unknown threats.
- **`WARNING` (0.50 <= p < 0.90)**: Elevated anomalous behavior (e.g. Shannon entropy > 7.5, or rapid file renaming). Requires user review. In our demo, the simulation triggers `WARNING` (0.57) because entropy was elevated, but no process anomalies were present.
- **`CRITICAL / THREAT DETECTED` (p >= 0.90)**: Multi-signal corroboration. Requires both high-entropy file encryption **and** correlated malicious process behavior (e.g., shadow copy deletion or thread injection).
- **Confirmed Ransomware**: Requires full forensic or reverse-engineering proof of extortion capabilities and key exchange.

---

### Q9: What are the current limitations?
**Answer:**
1. **User-Space Polling Delay**: Operating in Ring-3 without a kernel minifilter driver (`fltmgr.sys`) means SentinelML inspects files *after* modification, not prior to disk commit.
2. **Monitored Scope**: Live background scanning focuses on user profile folders (Desktop, Documents, Downloads). Arbitrary unmonitored directories are blind spots unless explicitly targeted.
3. **Model Baseline**: The model is an experimental synthetic baseline, unvalidated on wild zero-day ransomware.
4. **Intermittent Encryption**: Partial encryption (encrypting only every N-th block) can lower the average entropy to ~5.5, partially evading simple entropy thresholds.

---

### Q10: What is genuinely novel about this implementation?
**Answer:**
While individual concepts (entropy calculation, Random Forests) are established in literature, SentinelML's novelty lies in:
1. **Transparent 6-Stage Evidence Pipeline**: Translates raw file bursts into verifiable stages (Activity -> Observation -> Telemetry -> Validation -> Inference -> Boundary Disclosure) instead of a black-box alert.
2. **Interactive Dual-Schema Feature Inspector**: Enables visitors to inspect both Legacy 19 and Schema V2 16 features with baselines, sensors, and collection costs in real time.
3. **Ethical Pre-Training Data Readiness Gate**: First undergraduate implementation that programmatically halts model training until verified empirical ransomware telemetry is acquired, preventing fabricated models.

---

### Q11: How does SentinelAI differ from the local model?
**Answer:**
- **Local Random Forest**: Operates offline in Ring-3, deterministically computing threat probabilities in ~11 ms. It holds **exclusive, authoritative authority** over the security classification (`SAFE`, `WARNING`, `CRITICAL`).
- **SentinelAI**: An optional, advisory LLM copilot that provides plain-English summaries and defensive recommendations for users. It operates strictly downstream of the classifier and has **zero write permissions** to alter or override the ML decision. If the cloud service times out or is offline, the local ML classification stands unchanged.

---

### Q12: What evidence supports the claims made in the presentation?
**Answer:**
1. **Automated Unit & Regression Tests**: 51 automated tests in `tests/test_exhibition_suite.py` passing with 100% success, verifying sandbox containment, concurrency locking, and fail-safe invariants.
2. **Reproducible Benchmark**: 40-case synthetic benchmark in `tests/run_evaluation_benchmark.py` running in ~15 ms with full precision/recall metrics.
3. **Live Demonstration Output**: Real-time execution logs and exported sanitized reports in `/reports` capturing exact timestamps, entropy jumps (5.02 -> 7.91), and tree vote distributions (57/100).
4. **Comprehensive Documentation**: 7 committed markdown audit reports detailing the exact architecture, limitations, and verification evidence.
