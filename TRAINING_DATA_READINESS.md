# SENTINELML V2 — TRAINING DATA READINESS ASSESSMENT

**Assessment Date:** October 19, 2026  
**Repository:** `C:\Users\vasur\Desktop\SentinalMl\`  
**Target Branch:** `exhibition-mode`  
**Investigation Team:** Senior Machine Learning Engineer & Cybersecurity Detection Research Assistant  

---

## 1. Executive Summary

This report evaluates the readiness, suitability, and scientific validity of available datasets for training, validating, or rebuilding SentinelML's machine learning ransomware detection engine.

### Core Verdict
1. **Existing Training Dataset (`sample_data.csv`):** Confirmed as a **purely synthetic dataset** generated from Gaussian normal distribution parameters. It does not contain empirical telemetry from real ransomware executions.
2. **Public Malware Datasets:** Standard cybersecurity datasets (EMBER, SOREL-20M, EldeRan, CIC-MalAnal2020) provide static PE headers or Cuckoo API traces, but **none provide the 19 runtime telemetry features** collected by SentinelML's live scanner.
3. **Data Readiness Status:** **UNREADY FOR REAL-WORLD MODEL RETRAINING**. Creating another synthetic dataset to replace the current one would violate academic and engineering integrity. The existing model must remain classified as **unvalidated against in-the-wild ransomware**.

---

## 2. Forensic Audit of Recovered Dataset (`sample_data.csv`)

The dataset recovered from `Major Project/dataset/sample_data.csv` was analyzed to assess its statistical properties and authenticity.

### 2.1 Dataset Composition
- **Total Records:** 1,500 rows.
- **Benign Records:** 500 rows ($33.3\%$).
- **Ransomware Records:** 1,000 rows ($66.7\%$) distributed uniformly across 10 families (100 rows each):
  *WannaCry, Petya, LockBit, REvil, Ryuk, Conti, DarkSide, BlackCat, Hive, BlackMatter*.
- **Features:** 19 numerical columns plus `label` ($0$ or $1$) and `family`.

### 2.2 Proof of Synthetic Generation
Inspection of `Major Project/dataset/generate_dataset.py` proves that all rows were created using NumPy normal distributions:
```python
value = np.random.normal(mean, adjusted_std * (1.8 if np.random.random() < 0.12 else 1.0))
```

#### Statistical Evidence of Synthetic Nature:
1. **Perfect Gaussian Symmetry:** Each feature exhibits mean and variance almost exactly matching the hardcoded `BENIGN_DISTRIBUTIONS` and `FAMILY_DISTRIBUTIONS` parameters.
2. **Integer Truncation:** Continuous normal draws were rounded to non-negative integers (`max(0, int(round(value)))`), producing artificial step distributions.
3. **Rule-Based Correlations:** Relationships such as $\text{max\_entropy} \ge \text{avg\_entropy}$ and $\text{suspicious\_threads} \ge 2 \times \text{malfind}$ were artificially enforced by post-generation `if` statements rather than emerging organically from operating system telemetry.
4. **Artificial Noise Injection:** 75 labels ($5\%$) were flipped at random (`df.loc[noisy_idx, LABEL_COLUMN] = 1 - df.loc[noisy_idx, LABEL_COLUMN]`), creating artificial label contradictions rather than genuine borderline feature samples.

---

## 3. Mathematical Analysis of Distribution Shift on Live Windows Hosts

When the StandardScaler fit on `sample_data.csv` is applied to telemetry from a clean Windows 11 workstation, severe distribution shifts occur:

$$\Delta z = \frac{x_{\text{live}} - \mu_{\text{train}}}{\sigma_{\text{train}}}$$

| Feature | Training Mean ($\mu$) | Training Std ($\sigma$) | Clean Windows 11 Workstation ($x_{\text{live}}$) | Resulting $z$-Score | Interpretation |
|---|:---:|:---:|:---:|:---:|---|
| `total_processes` | 86.05 | 30.68 | ~280 | $+6.32\sigma$ | Shift from isolated single-purpose sandbox to multi-process OS |
| `file_handle_count` | 589.38 | 340.01 | ~135,000 | **$+395.31\sigma$** | Massive scale discrepancy: system-wide handle sum vs per-process sandbox count |
| `crypto_dll_count` | 6.25 | 3.51 | ~130 | **$+35.26\sigma$** | Modern Windows loads `bcrypt.dll` into nearly every GUI process |
| `malfind_injection_count` | 6.79 | 5.80 | ~4 | $-0.48\sigma$ | Proxy counts access-denied services rather than shellcode injections |
| `avg_entropy` | 6.14 | 1.87 | ~3.80 | $-1.25\sigma$ | Normal plaintext files evaluate within expected benign range |

### Consequence for Model Decision Making:
Because handle counts and crypto DLL counts deviate by **$+395\sigma$** and **$+35\sigma$**, the input to the Random Forest model is heavily distorted compared to the training manifold. The model's predictions on a live host are an artifact of out-of-distribution scaling, not genuine ransomware behavioral inference.

---

## 4. Evaluation of Public Cybersecurity Datasets

To evaluate whether an existing open-source or academic dataset could be used for immediate retraining, recognized public malware repositories were surveyed:

| Public Dataset | Source / Reference | Data Modality | Telemetry Compatibility with SentinelML | Feasible for Immediate Retraining? |
|---|---|---|---|:---:|
| **EMBER (2018/2024)** | Anderson et al. | Static PE header features, byte histograms, imported DLLs | Incompatible: Contains static file attributes, not runtime behavioral host telemetry | **NO** |
| **SOREL-20M** | Sophos-ReversingLabs | 20M static binary attributes, disassembly metadata | Incompatible: Static file attributes only; zero runtime process or entropy telemetry | **NO** |
| **EldeRan** | Sgandurra et al. | Dynamic behavioral traces from Cuckoo sandbox (API calls, registry keys) | Incompatible: Textual API sequence logs requiring separate sequence-to-vector embedding | **NO** |
| **CIC-MalAnal2020** | Canadian Institute for Cybersecurity | Network traffic (PCAP) and memory features | Incompatible: Feature schema does not match SentinelML's 19-position vector | **NO** |
| **VirusShare / VirusTotal** | VirusShare.com | Raw PE executables (.exe, .dll) | Requires isolated VM detonation lab to extract telemetry | **NO (Raw Binaries Only)** |

### Conclusion on External Datasets
No public dataset exists in the academic or industrial domain that directly matches SentinelML's 19-feature vector format. Retraining a valid model requires collecting empirical telemetry directly through a dedicated data acquisition pipeline.

---

## 5. Data Readiness Decision & Integrity Constraints

In accordance with Phase 6, Outcome C is enforced:

1. **No Synthetic Retraining:** We will not generate a new synthetic dataset with adjusted parameters and present it as "validated ransomware training data." Synthetic distributions cannot replace empirical telemetry.
2. **No Data Fabrication:** Accuracy figures and validation metrics must reflect only verified empirical measurements.
3. **Explicit Documentation of Unvalidated Status:** The detector is transparently documented as:
   > *"SentinelML V2's Random Forest classifier is trained on synthetic memory forensics distributions and is unvalidated against live in-the-wild ransomware. The current implementation serves as a functional demonstration pipeline."*
4. **Actionable Acquisition Strategy:** The precise instrumentation requirements for building a genuine training corpus are detailed in `MODEL_REBUILD_PLAN.md`.
