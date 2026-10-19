# SENTINELML V2 — EXHIBITION DEMONSTRATION & BOOTH GUIDE

**Target Event:** College Technical Exhibition / Faculty Evaluation / Project Viva  
**Presenters:** Vasu Chowdary, Moulica Chowdary, D. M. Yashaswini  
**Project:** SentinelML V2 — Behavioral Machine-Learning Endpoint Intrusion Detection System  
**Document Revision:** 2.0.0 (October 2026)  
**Demonstration Mode:** Polished Navy/Muted-Gold Exhibition UI  

---

## 1. Exhibition Objective & Tone

The purpose of this exhibition is to demonstrate **genuine cybersecurity engineering**, **honest machine-learning evaluation**, and **resilient software architecture** to college visitors, professors, and technical evaluators.

### Core Booth Principles
1. **Never Fake Detection:** Do not present simulated files as live malware or claim 100% ransomware immunity.
2. **Deterministic Local ML:** The scikit-learn Random Forest (100 trees, 19 features) is authoritative. The cloud LLM copilot (SentinelAI) is advisory-only and cannot alter security boundaries.
3. **Fail-Safe Integrity:** A scan failure or unhandled exception transitions strictly to `SCAN_INCOMPLETE` or `ANALYSIS_ERROR`. It **never** silently defaults to `SAFE`.
4. **Transparent Boundaries:** Plainly disclose the difference between kernel minifilters (Ring 0) and unprivileged user daemons (Ring 3).

---

## 2. 3–5 Minute Presentation Script & Walkthrough

### Act 1: The Problem (0:00 – 0:45)
- **Visual Action:** Open SentinelML on the **Dashboard** or click **Exhibition** in the left sidebar.
- **Presenter Speaks:**
  > *"Good morning/afternoon. Traditional antivirus software relies primarily on static file signatures—looking for known byte sequences or MD5 hashes. But modern ransomware evades static tools within seconds through polymorphic compilers, runtime packers, and obfuscated droppers.*  
  > *SentinelML addresses this by focusing on **behavioral telemetry**—monitoring what a system is actually doing rather than what a binary looks like. We extract 19 runtime indicators using unprivileged operating-system APIs and evaluate them through a trained Random Forest classifier."*

### Act 2: Genuine System Scan (0:45 – 1:45)
- **Visual Action:** In the **Exhibition** tab, select **A. Live System Scan [REAL]** and click **Start Live System Scan**.
- **What Evaluators See:**
  - Real-time progress counting inspected files and running process descriptors.
  - Duration measured dynamically (3–5 seconds).
  - All 19 extracted features populated in real time (process counts, Shannon entropy, active network sockets, loaded crypto DLLs).
  - ML decision: `SAFE` ($p \approx 0.05 - 0.20$).
- **Presenter Speaks:**
  > *"Notice that this is a 100% genuine live scan. It enumerated active processes via `psutil`, sampled file entropy in user document roots, normalized the values with `StandardScaler`, and ran inference through 100 decision trees.*  
  > *Notice our prominent disclaimer: 'SAFE means this scan did not detect a threat under the checks performed. It does not guarantee that the entire machine is malware-free.' In cybersecurity, intellectual honesty is critical."*

### Act 3: Controlled Behavior Simulation (1:45 – 3:00)
- **Visual Action:** Switch to **B. Behavior Simulator [SANDBOX]** and click **Launch Harmless Simulation**.
- **What Evaluators See:**
  - Synthetic documents created exclusively in the isolated `temp_sandbox` directory.
  - Burst modifications replacing content with high-entropy bytes (Shannon entropy jumping from ~3.5 to >7.8 bits/byte).
  - Rapid file renaming appending `.locked_sim`.
  - Harmless ransom note generated: `READ_ME_RECOVERY_SIM.txt`.
- **Presenter Speaks:**
  > *"Here we simulate the behavioral footprint of ransomware—rapid file writes, elevated entropy, and bulk renaming—without executing a single line of malicious code.*  
  > *All operations are strictly locked to a disposable sandbox folder. Our software rejects any path traversal or symlinks escaping this folder. Notice the Observation vs Reality panel: host telemetry remains SAFE because no real process was hollowed and no user documents were touched. Sandboxing preserves host integrity."*

### Act 4: Worst-Case Security Test Lab (3:00 – 4:15)
- **Visual Action:** Switch to **C. Security Test Lab [WORST-CASE]**. Click **Incomplete Process Telemetry** or **Scan Interruption & Cancellation**.
- **What Evaluators See:**
  - Execution outcome displays `TEST RESULT: PASSED [VERIFIED INVARIANT]`.
  - State transitions immediately to `SCAN_INCOMPLETE` with threat level `ANALYSIS_ERROR`.
- **Presenter Speaks:**
  > *"A critical vulnerability in commercial utilities is 'silent failure'—when an error occurs, naive software catches the exception and displays a green 'System Clean' checkmark.*  
  > *SentinelML enforces formal scan-state machine invariants: any exception, access denial, or mid-scan cancellation branches strictly to `SCAN_INCOMPLETE` or `ANALYSIS_ERROR`. An incomplete scan is NEVER called SAFE."*

### Act 5: Architecture & Limitations (4:15 – 5:00)
- **Visual Action:** Switch to **D. Evidence & Incident Viewer**. Click **Export Demonstration Report (Sanitized)**.
- **Presenter Speaks:**
  > *"Finally, we generate an audit report with sensitive usernames and paths automatically redacted. In conclusion: SentinelML proves that unprivileged user-space machine learning can detect behavioral anomalies while avoiding kernel-driver crashes. While we cannot stop low-level rootkits at Ring 0, our decoupled AI architecture provides explainable endpoint intrusion detection without compromising system stability. Thank you, and we welcome your questions."*

---

## 3. Evaluator Questions & Technical Answers

| Evaluator Question | Recommended Response |
|---|---|
| **"Why not use a kernel minifilter driver (Ring 0) like Windows Defender?"** | *"Kernel drivers offer deeper filesystem control, but they introduce severe stability risks (kernel panics / Blue Screens) and expand the attack surface via BYOVD (Bring Your Own Vulnerable Driver) exploits. SentinelML demonstrates what is achievable purely at user-space (Ring 3), making it lightweight, modular, and portable."* |
| **"Why is SentinelAI decoupled from the ML model?"** | *"Generative AI models are non-deterministic and vulnerable to prompt injection or hallucination. We enforce a strict security boundary: the deterministic local Random Forest authoritatively determines whether an alert is SAFE or CRITICAL. SentinelAI only acts downstream as a human-readable copilot."* |
| **"What if ransomware encrypts files slowly to bypass entropy thresholds?"** | *"That is a documented limitation of heuristic rate-limiting. Low-thread, delayed ransomware is designed to stay beneath burst thresholds. That is why SentinelML combines 19 distinct features—including process hollowing proxies, loaded crypto DLLs, and shadow-copy deletion checks—rather than relying on entropy alone."* |
| **"Can SentinelML automatically decrypt or recover locked files?"** | *"No. SentinelML is an Intrusion Detection System (IDS), not an automatic remediation engine. It detects and alerts. Recovery requires offline, uncorrupted Volume Shadow Copies or immutable cloud backups."* |

---

## 4. Emergency Troubleshooting at the Booth

- **If the application window closes unexpectedly:**
  Launch via command prompt: `python app.py` from `C:\Users\vasur\Desktop\SentinalMl`. All logs are written to `logs/app.log`.
- **If sandbox files are left behind:**
  Click the **↻ Reset Demo** button in the header, or click **Cleanup Sandbox** on Tab B. The directory is safely purged automatically.
- **If the remote AI service is slow or times out:**
  Explain to the evaluator: *"The local Random Forest is operating 100% offline. The cloud LLM copilot is advisory-only, proving our decoupling guarantee."*
