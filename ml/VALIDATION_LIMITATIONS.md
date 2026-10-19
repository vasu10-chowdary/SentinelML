# SENTINELML V2 — VALIDATION LIMITATIONS AND ACADEMIC DISCLOSURE

**Document Date:** October 19, 2026  
**Classification:** Academic Transparency & Operational Risk Disclosure  
**Audience:** Technical Auditors, College Exhibition Evaluators, Engineering Faculty  

---

## 1. Explicit Academic & Scientific Disclosures

To maintain the highest standards of scientific and professional integrity during technical reviews and the upcoming college cybersecurity exhibition, the SentinelML engineering team explicitly documents the following system boundaries and validation limitations.

### 1.1 The Legacy Random Forest Model is Unvalidated Against Wild Malware
- The active model (`models/saved_model.pkl`) was trained on **purely synthetic Gaussian distribution data** (`sample_data.csv`) simulating offline Volatility 3 memory dump analysis.
- The reported 100% accuracy across 40 test cases in `run_evaluation_benchmark.py` reflects mathematical determinism across hand-authored polar feature vectors, not protection against zero-day in-the-wild malware.
- The legacy model must be presented as an **Experimental Synthetic-Data Baseline**, not a field-proven enterprise security shield.

### 1.2 Ring-3 User-Space Visibility Constraints
- SentinelML operates as an **unprivileged user-space (Ring-3) Python application**.
- Modern Windows workstations restrict Ring-3 access to kernel data structures. SentinelML cannot natively inspect Virtual Address Descriptors (VADs), process security tokens (`SeDebugPrivilege`), or the Windows Object Manager mutant directory without triggering `ACCESS_DENIED` errors.
- Any model claiming to inspect these features at runtime from user-space is relying on heuristic approximations.

### 1.3 Behavioral Signal Ambiguity (False Positive Risks)
- **High Shannon Entropy ($H > 7.0$) is NOT exclusive to ransomware.** Legitimate software—including 7-Zip, Handbrake, video editing suites, SQLite encrypted databases, and game asset loaders—routinely generates files with entropy approaching $8.0$ bits/byte.
- **Rapid File Renaming is NOT exclusive to ransomware.** Photo cataloging software, Git branch checkouts, and batch renaming utilities routinely perform hundreds of renames per second.
- Detection requires **multimodal correlation** across filesystem, process, and system recovery indicators. A single elevated metric is insufficient to declare a security emergency.

### 1.4 Evasion Techniques and Operational Blind Spots
- **Intermittent Encryption:** Advanced ransomware (e.g. LockBit 3.0, BlackCat) encrypts only every $N$-th block or the first 5% of a file header. The resulting average file entropy remains below $6.0$, bypassing naive entropy thresholding.
- **Living-off-the-Land (LotL) Attacks:** Attackers leveraging native administrative utilities (PowerShell, WMI, BCDedit) without spawning high-thread processes can evade simple process heuristics.
- **Kernel-Level BYOVD Attacks:** Ransomware deploying vulnerable signed kernel drivers (Bring Your Own Vulnerable Driver) can terminate SentinelML from Ring-0 before detection completes.

---

## 2. Guidelines for Exhibition Demonstrators

When demonstrating SentinelML V2 at the college cybersecurity exhibition:

```
+-----------------------------------------------------------------------------------+
|                            WHAT TO TELL EVALUATORS                                |
+-----------------------------------------------------------------------------------+
| 1. "Our system is a behavioral correlation prototype designed to demonstrate      |
|    multivariate threat scoring across user-space signals."                        |
|                                                                                   |
| 2. "The 40-case synthetic benchmark proves that our Scikit-Learn pipeline and    |
|    thresholding logic execute predictably on defined test profiles."              |
|                                                                                   |
| 3. "We do not claim 100% ransomware immunity. High-entropy encryption elevates    |
|    our probability to WARNING (0.56), requiring process corroboration to reach    |
|    CRITICAL (0.90) to prevent false alarms on legitimate zip compression."        |
|                                                                                   |
| 4. "We have established Feature Schema V2 to eliminate synthetic memory proxies   |
|    and transition toward empirical hypervisor-acquired training data."            |
+-----------------------------------------------------------------------------------+
```

```
+-----------------------------------------------------------------------------------+
|                           WHAT NEVER TO SAY OR CLAIM                              |
+-----------------------------------------------------------------------------------+
| DO NOT CLAIM: "SentinelML has 100% accuracy against all real-world ransomware."   |
| DO NOT CLAIM: "SentinelML inspects kernel memory injections from Python."         |
| DO NOT CLAIM: "High file entropy alone proves that ransomware is attacking."      |
| DO NOT CLAIM: "A simulation test in our sandbox proves live malware detection."   |
+-----------------------------------------------------------------------------------+
```
