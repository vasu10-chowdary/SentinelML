# SentinelML V2 — Exhibition Demonstration Guide

## Overview

This guide provides a structured, professional, and scientifically honest demonstration protocol for presenting **SentinelML V2** at public engineering exhibitions, academic project reviews, and cybersecurity symposiums.

---

## 1. Quick-Start Demonstration Protocol (3-Minute Booth Script)

### Step 1: Establish the Problem & Architecture (30 Seconds)
> *"Welcome! SentinelML V2 is an open-source, machine-learning-assisted ransomware detection research project. Unlike traditional signature-based antivirus, SentinelML inspects behavioral indicators such as file modification bursts, Shannon entropy elevation, and process telemetry to identify unauthorized encryption in near real-time."*

Point to the top header banner and pipeline cards:
- **Telemetry Sensors**: Windows user-space polling (`psutil`, filesystem crawlers).
- **Behavioral Vectors**: 19 legacy features & 16 Schema V2 features.
- **Classifier Engine**: 100-estimator Random Forest with `StandardScaler`.
- **Advisory LLM**: SentinelAI (Ring-3 advisory, strictly decoupled from local ML decisions).

---

### Step 2: Run the One-Click Safe Demonstration (90 Seconds)

1. Navigate to **Tab A: Safe Demo & 6-Stage Pipeline [SANDBOX]**.
2. Point out the **Health Diagnostic Status**:
   - `✓ System Diagnostic Ready (Sandbox Safe, Model Loaded, Sensors Active)`
3. Click the prominent gold **`▶ Run Safe Demo`** button.
4. Walk the audience through the **6-Stage Evidence Pipeline** as the cards light up:

| Stage | Name | What the Audience Sees | Scientific Explanation |
| :---: | :--- | :--- | :--- |
| **1** | **Harmless Sandbox Activity** | 20 synthetic files created, modified with pseudorandom bytes, and renamed to `.locked_sim`. | *"Notice that this runs strictly within a dedicated `temp_sandbox/` directory. Zero user documents or system directories are touched."* |
| **2** | **Filesystem Observation** | Scanner enumerates 20 files, flagging 20 `.locked_sim` items and 1 educational note. | *"Our user-space filesystem scanner detects the burst changes and flags the suspicious extension pattern."* |
| **3** | **Telemetry Collection** | Average Shannon entropy jumps from ~4.1 to **~7.89 bits/byte**. | *"Encrypted ciphertext has near-maximum entropy (close to 8.0 bits/byte). Plaintext documents are typically 3.5 to 5.0."* |
| **4** | **Feature Vector Validation** | Validates Legacy 19-position vector and Schema V2 16-position vector. | *"Vectors are sanitized and validated against NaN, infinity, and schema bounds before entering the ML pipeline."* |
| **5** | **Model Inference** | 100-tree Random Forest votes; inference completes in **< 15 ms**. | *"56 out of 100 trees vote for threat based on the elevated entropy profile."* |
| **6** | **Threat Classification** | Final Decision: **`WARNING` (Probability: ~0.56)**. | *"The model assigns probability 0.56, crossing our 0.50 WARNING threshold."* |

---

### Step 3: Explain the "Why Warning and Not Critical" Invariant (45 Seconds)

This is the key academic distinction that impresses judges and senior evaluators:

> *"Notice that the system flagged this as **`WARNING` (0.56)** rather than **`CRITICAL` (0.90)**. Why? Because the simulation operates strictly in an unprivileged sandbox without executing a malicious process. No shadow copies were deleted (`vssadmin`), and no thread injection occurred.*
>
> *If high entropy alone triggered a CRITICAL shutdown, the system would produce false positives whenever a user compresses a `.zip` archive or exports high-definition video. SentinelML enforces a multi-signal corroboration invariant: entropy flags a warning, but critical action requires correlated process anomalies."*

---

### Step 4: Transparent Feature Inspection (30 Seconds)

1. Switch to **Tab D: Feature Inspector & Audit Evidence**.
2. Toggle between **Schema V2 (16 Observable Features)** and **Legacy Baseline (19 Features)**.
3. Click on `avg_shannon_entropy` or `file_mod_rate` to show the full technical audit specification:
   - Measured Value vs Normal Baseline
   - Sensor Source (`psutil`, filesystem crawler)
   - Collection Cost and False Positive Risks
4. Click **`💾 Export Demonstration Report`** to generate a sanitized Markdown & JSON audit bundle in `/reports`.

---

### Step 5: Instant Reset to Ready (15 Seconds)

1. Click the **`↻ Reset to Ready`** button on the top command bar.
2. The sandbox files are purged immediately.
3. Status badge returns to `STATE: RESET` -> `STATE: IDLE`, ready for the next visitor.

---

## 2. Handling Special Demonstration Scenarios

### Scenario A: Offline Booth / Restricted Network
If the exhibition venue lacks internet connectivity:
- The Random Forest classifier and StandardScaler are **100% local** and run offline without latency.
- Click **`📖 Walkthrough`** to run the pre-computed deterministic educational replay, visibly badged as `[EDUCATIONAL WALKTHROUGH — NOT LIVE SCAN]`.

### Scenario B: Technical Judge Asks About Real Malware
**Question:** *"Did you test this against live LockBit or WannaCry?"*
**Approved Answer:**
> *"No, and that is a deliberate ethical and engineering constraint. Executing live ransomware on unsegmented hardware violates university safety protocols. Instead, SentinelML uses a dual validation strategy:
> 1. An automated behavioral simulator that reproduces observable ransomware artifacts (burst entropy, rapid renaming, extortion notes) in disposable sandboxes.
> 2. A 40-sample benchmark suite achieving 100% accuracy on evaluated synthetic test distributions.
>
> In our technical limitations report, we explicitly state that the legacy model is an experimental synthetic baseline unvalidated against wild polymorphic ransomware. We have designed Schema V2 and an empirical benign collector to establish defensible ground truth for future training."*

### Scenario C: Visitor Inquires About False Positives
**Question:** *"What happens if I zip a large folder of photos?"*
**Approved Answer:**
> *"We explicitly test this in Tab C under Scenario 3 ('Benign Bulk File Operations'). Normal bulk document operations remain SAFE (p < 0.20). While archive compression creates high-entropy files, the absence of suspicious process commands (vssadmin, bcdedit) and ransom note patterns prevents the model from crossing the critical escalation threshold."*

---

## 3. Concurrency Protection & Safety Features

1. **Threading Lock (`_demo_lock`)**: If a visitor rapidly double-clicks `▶ Run Safe Demo`, the system rejects the second invocation with an alert (`System Busy`), preventing file race conditions.
2. **Path Traversal Protection**: Every file access is validated via `validate_path_safety()`. Any attempt to escape `temp_sandbox/` raises a `SecurityError` and halts execution.
3. **Automated Sandbox Purge**: `reset_sandbox()` deletes all generated dummy files upon clicking `Reset to Ready` or when tests conclude.
