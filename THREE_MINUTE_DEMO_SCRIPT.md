# SentinelML V2 — Three-Minute Judge Demonstration Script

## Demonstration Setup & Presenter Checklist
- **Host**: Windows 11 Workstation
- **Application Directory**: `C:\Users\vasur\Desktop\SentinalMl\`
- **Launch Command**: `python app.py` (or click `run_app.bat`)
- **Initial View**: Navigate to sidebar `[ EX ] Exhibition`
- **Required Verification**: Check top command bar displays `[OK] System Diagnostic Ready`
- **Duration**: Exactly 3 minutes (180 seconds)

---

## 0:00 – 0:30 — Introduction & Core Problem

### Presenter Actions:
1. Stand by the main screen showing SentinelML V2 on the **Exhibition** page.
2. Point to the top status bar showing `STATE: IDLE`, mode `[SANDBOX SIMULATION]`, and the 6-stage pipeline layout.

### Spoken Script:
> *"Good morning/afternoon, evaluators and judges. My name is [Presenter Name], and our project is **SentinelML V2**.*
>
> *Modern ransomware attacks—such as LockBit, BlackCat, and Conti—consistently evade traditional antivirus because they rapidly recompile, pack, or obfuscate their binary signatures. Once a malicious binary bypasses signature matching, it executes an encryption burst that can destroy thousands of user files in seconds.*
>
> *SentinelML addresses this by shifting focus from static binary signatures to **behavioral observation**. Our desktop prototype monitors runtime indicators—including file modification rates, Shannon entropy elevation, and process telemetry—and evaluates them using machine learning to detect suspicious behavioral patterns in near real-time."*

---

## 0:30 – 1:00 — Live Host Baseline Scan

### Presenter Actions:
1. Click **Tab B: Live System Scan [REAL HOST]**.
2. Click **`⚡ Start Live System Scan`**.
3. While the scanner inspects the host, point out the real-time file and process counters in the top bar.
4. When scan completes (~30-40 seconds), point to the result.

### Spoken Script:
> *"To prove that SentinelML is not relying on mocked dummy numbers, let's observe a genuine baseline scan of this host workstation.*
>
> *The engine is actively inspecting live running processes via `psutil` and sampling user documents for Shannon entropy. Notice the telemetry values displayed in our 19-position table:*
> - *We enumerated **over 320 genuine active processes**.*
> - *The average Shannon entropy across inspected files is **4.43 bits per byte**.*
>
> *Because standard plaintext documents, source code, and system files have an entropy between 3.5 and 5.5, the 100-tree Random Forest evaluates this workstation at probability **0.46**, remaining safely below our 0.50 warning threshold. The host is correctly classified as **SAFE**."*

---

## 1:00 – 2:00 — Controlled Behavioral Simulation & 6-Stage Pipeline

### Presenter Actions:
1. Switch back to **Tab A: Safe Demo & 6-Stage Pipeline [SANDBOX]**.
2. Point out that the disposable sandbox is clean.
3. Click the prominent gold **`▶ Run Safe Demo`** button.
4. Point to the 6 stage cards as they transition from `READY` to `PASSED`.

### Spoken Script:
> *"Now, let's witness how SentinelML responds when ransomware-like activity occurs.*
>
> *To protect this workstation, we enforce strict ethical containment: zero live malware is used. All activity runs inside an isolated, disposable sandbox directory (`temp_sandbox/`), strictly guarded against path traversal escapes.*
>
> *I click **'Run Safe Demo'**. Watch our six-stage evidence pipeline execute:*
> 1. * **Stage 1 (Simulation)**: 20 synthetic files are created and burst-overwritten with pseudorandom ciphertext bytes, followed by rapid renaming to `.locked_sim` and an instructional recovery note.*
> 2. * **Stage 2 (Observation)**: The filesystem scanner detects the 20 modified files and flags the suspicious extension pattern.*
> 3. * **Stage 3 (Telemetry)**: The extracted Shannon entropy jumps dramatically from 5.02 to **7.75 bits per byte**—characteristic of encrypted data.*
> 4. * **Stage 4 (Validation)**: Vectors are sanitized, checking finite bounds for both the legacy 19-feature format and our proposed Schema V2 16-feature format.*
> 5. * **Stage 5 (Inference)**: Our 100-tree Random Forest executes inference in approximately **11 milliseconds**.*
> 6. * **Stage 6 (Classification)**: 57 of 100 decision trees vote for threat. The model evaluates threat probability at **0.57**, cleanly crossing the 0.50 threshold to trigger a **`WARNING`**."*

---

## 2:00 – 2:30 — Explain the Result & Scientific Invariant

### Presenter Actions:
1. Point to the **Model Decision Card** showing `DECISION: WARNING (p=0.57)`.
2. Point to the **Operational Disclosure Box** below it.

### Spoken Script:
> *"Here is the most critical scientific distinction in our project, and why we do not produce false alarms:*
>
> *Notice that the system flagged this burst as **`WARNING` (0.57)** rather than **`CRITICAL` (0.90)**. Why didn't it cross 0.90?*
>
> *Because our simulation ran safely inside an unprivileged sandbox without executing a live malicious executable. No shadow copies were deleted via `vssadmin`, and no thread injection occurred.*
>
> *If a detector flagged every high-entropy file as a critical ransomware emergency, it would crash legitimate user workflows whenever someone creates a `.zip` archive, renders high-definition video, or updates an encrypted database. SentinelML enforces a **multi-signal corroboration invariant**: entropy elevation flags an alert (`WARNING`), but critical termination requires correlated process-level malicious evidence."*

---

## 2:30 – 3:00 — Limitations, Academic Rigor & Future Work

### Presenter Actions:
1. Switch to **Tab D: Feature Inspector & Audit Evidence**.
2. Click on `avg_shannon_entropy` to show the full audit specification.
3. Click **`↻ Reset to Ready`** on the top bar to show instant sandbox cleanup.

### Spoken Script:
> *"Finally, we maintain strict scientific honesty regarding our prototype's boundaries:*
> 1. * **Model Provenance**: Our deployed Model V1 is an experimental synthetic-data baseline trained on Gaussian distributions modeling memory-forensics specifications. We report 100% accuracy on our 40-case synthetic benchmark, but we explicitly disclose that it is **unvalidated against wild zero-day ransomware**.*
> 2. * **User-Space vs. Kernel Driver**: SentinelML operates in Ring-3 user space. While effective for monitoring and demonstration, production endpoint defense requires a Ring-0 kernel filesystem minifilter (`fltmgr.sys`) to intercept I/O before data hits the disk.*
> 3. * **The V2 Roadmap**: To bridge this gap, we have engineered **Schema V2** with 16 measurable behavioral features, an opt-in benign telemetry collector, and a **Data Readiness Gate** that prevents training until verified empirical malware data is acquired.*
>
> *I click **'Reset to Ready'**—the sandbox is completely purged, 0 files remain, and the system is ready for the next evaluator. Thank you, and we welcome your questions."*
