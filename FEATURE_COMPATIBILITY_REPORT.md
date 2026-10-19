# SENTINELML V2 — FEATURE COMPATIBILITY & RESEARCH DATASET REPORT

**Document Type:** Feature Engineering & Public Dataset Compatibility Audit  
**Target Architecture:** SentinelML V2 (19-Feature Runtime Behavioral Vector)  
**Project Path:** `C:\Users\vasur\Desktop\SentinalMl\`  
**Date of Audit:** October 19, 2026  

---

## 1. Executive Summary

This report analyzes SentinelML V2's 19 behavioral features, evaluates their cross-platform fidelity, and compares them against established academic cybersecurity benchmarks (EMBER, EldeRan, and Volatility memory dumps).

### Critical Scientific Principle:
**Feature spaces are not interchangeable.** Feeding static Portable Executable (PE) benchmark features (e.g. from the EMBER dataset) or dynamic API n-gram sequences (e.g. from EldeRan) directly into SentinelML's Random Forest classifier is fundamentally invalid. Doing so violates the trained feature ordering, scale parameters, and semantic units, producing meaningless classifications. This report documents the exact compatibility boundaries and outlines an academically sound evaluation approach.

---

## 2. Comprehensive 19-Feature Specification Matrix

Every feature in SentinelML is a 64-bit floating point number extracted at runtime:

| Index | Feature Identifier | Expected Units | Valid Range | Extraction Telemetry Source | Fidelity Category | Windows Support | Linux Support |
|:---:|---|:---:|:---:|---|:---:|:---:|:---:|
| `[00]` | `total_processes` | Process count | $[1, \infty)$ | `psutil.process_iter()` | Direct Telemetry | Full | Full |
| `[01]` | `suspicious_process_count` | Process count | $[0, \infty)$ | Process name match against 23 admin tools | Direct Telemetry | Full | Partial (Win LOLBins) |
| `[02]` | `avg_entropy` | Bits / Byte | $[0.0, 8.0]$ | 4KB Shannon entropy over sampled files | Direct Telemetry | Full | Full |
| `[03]` | `max_entropy` | Bits / Byte | $[0.0, 8.0]$ | Peak file Shannon entropy | Direct Telemetry | Full | Full |
| `[04]` | `high_entropy_region_count` | File count | $[0, 200]$ | Sampled files with entropy $> 7.0$ bits/byte | Direct Telemetry | Full | Full |
| `[05]` | `malfind_injection_count` | Process count | $[0, \infty)$ | Processes with `exe is None or exe == ""` | Heuristic Proxy | Full | Full |
| `[06]` | `crypto_dll_count` | Process count | $[0, \infty)$ | Loaded DLL match against 7 crypto libraries | Direct Telemetry | Full | Incompatible (.so paths) |
| `[07]` | `cmd_vssadmin_count` | Process count | $[0, \infty)$ | Name match against `vssadmin`, `wbadmin`, `bcdedit` | Direct Telemetry | Full | Incompatible (Win only) |
| `[08]` | `network_connection_count` | Socket count | $[0, \infty)$ | `psutil.net_connections(kind="inet")` | Direct Telemetry | Full | Full |
| `[09]` | `unique_external_ips` | IP count | $[0, \infty)$ | Unique non-RFC1918 remote IP addresses | Direct Telemetry | Full | Full |
| `[10]` | `file_handle_count` | Handle count | $[0, \infty)$ | Aggregate `p.info["num_handles"]` | Direct Telemetry | Full | **0.0 (Unsupported)** |
| `[11]` | `registry_handle_count` | Process count | $[0, \infty)$ | Non-system processes with $> 500$ handles | Heuristic Proxy | Full | **0.0 (Unsupported)** |
| `[12]` | `orphan_process_count` | Process count | $[0, \infty)$ | Alive processes whose PPID is dead | Direct Telemetry | Full | Full |
| `[13]` | `powershell_process_count` | Process count | $[0, \infty)$ | Active `powershell.exe` and `pwsh.exe` | Direct Telemetry | Full | Full (pwsh) |
| `[14]` | `unsigned_module_count` | Process count | $[0, \infty)$ | Binaries executing from staging paths | Heuristic Proxy | Full | Full |
| `[15]` | `suspicious_mutex_count` | Process count | $[0, \infty)$ | Non-system processes with $> 50$ threads | Heuristic Proxy | Full | Full |
| `[16]` | `abnormal_privilege_count` | Process count | $[0, \infty)$ | Non-system processes with $> 2000$ handles | Heuristic Proxy | Full | **0.0 (Unsupported)** |
| `[17]` | `suspicious_thread_count` | Process count | $[0, \infty)$ | Non-system processes with $> 100$ threads | Heuristic Proxy | Full | Full |
| `[18]` | `defender_tampering_count` | Service count | $[0, 3]$ | Stopped Windows Defender services | Direct Telemetry | Full | **0.0 (Unsupported)** |

---

## 3. Comparison with Public Academic Research Datasets

A common mistake in student machine-learning projects is attempting to feed public benchmark datasets into an incompatible feature extractor. Below is an academic audit comparing SentinelML's 19-dimensional behavioral vector with major public datasets:

```
+-------------------------------------------------------------------------------------------------+
| DATASET COMPARISON MATRIX                                                                       |
+--------------------------+-----------------------+-----------------------+----------------------+
| Dimension                | EMBER (2018)          | EldeRan (2016)        | SentinelML V2        |
+--------------------------+-----------------------+-----------------------+----------------------+
| Telemetry Domain         | Static Binary Header  | Dynamic Sandbox Calls | Runtime OS Telemetry |
| Observation Vantage Point| Pre-Execution (Disk)  | Dynamic Guest VM      | Live Unprivileged OS |
| Feature Dimensions       | 2,381 Features        | 582 Features          | 19 Features          |
| Features Included        | Byte entropy histogram| API call n-grams      | Process heuristics,  |
|                          | Section sizes, imports| Dropped file count    | Handle counts,       |
|                          | Authenticode certs    | Registry modifications| Filesystem entropy   |
| Real-time Suitability    | Scanning static files | Requires sandbox exec | Continuous host IDS  |
| Incompatibility Root     | Static PE != Runtime  | Dynamic calls != PS   | N/A                  |
+--------------------------+-----------------------+-----------------------+----------------------+
```

### 3.1 EMBER Benchmark Incompatibility
The EMBER benchmark (Anderson et al., 2018) contains 2,381 static features extracted from Windows Portable Executable (PE) binary files:
- Byte histograms and byte-entropy histograms.
- PE section headers, virtual sizes, entropy per section, section names.
- Imported functions, exported DLLs, and Authenticode certificate metadata.

**Scientific Assessment:**  
EMBER evaluates the static structure of a compiled binary sitting idle on disk. SentinelML evaluates running host telemetry (how many processes are currently active, aggregate system handles, external network sockets, live thread counts). Feeding EMBER CSV features into SentinelML's `saved_model.pkl` is **mathematically impossible** without reducing 2,381 static dimensions to 19 dynamic indicators, which would cause severe feature semantic distortion.

### 3.2 EldeRan & Cuckoo Sandbox Incompatibility
EldeRan (Sgandurra et al., 2016) monitors ransomware inside an instrumented Cuckoo sandbox:
- Features include Windows API call frequency vectors (`RegSetValueExW`, `CryptEncrypt`, `CreateFileW`).
- Dynamic directory traversal traces.

**Scientific Assessment:**  
While EldeRan is behavioral, it captures granular API invocation traces via API hooking (API Monitor/Detours). SentinelML operates without API hooking, using snapshot polling via `psutil`.

### 3.3 Volatility Memory Forensics vs SentinelML Proxies
The feature `malfind_injection_count` is named after Volatility's `malfind` plugin.
- In true memory forensics, Volatility walks the Virtual Address Descriptors (VAD), looking for memory allocations with `PAGE_EXECUTE_READWRITE` permissions that lack a backing file on disk.
- In SentinelML's unprivileged user-space daemon, scanning all process memory pages at Ring 3 would require administrative `SeDebugPrivilege` and would take 30–60 seconds per scan.
- Instead, SentinelML uses a **heuristic proxy**: checking processes where `exe is None or exe == ""` (e.g. unlinked process headers). Evaluators must understand this distinction.

---

## 4. Cross-Platform Translation & Asymmetry

SentinelML supports both Windows and Linux hosts via `psutil`. However, four features are architecturally tied to the Windows kernel:
1. `file_handle_count`: Windows tracks handles per process; Linux tracks file descriptors (`num_fds`). While `psutil.Process.num_fds()` exists on Linux, `num_handles` includes mutexes, semaphores, events, and desktop handles.
2. `registry_handle_count` and `abnormal_privilege_count`: The Windows Registry has no direct equivalent in Linux (which uses `/etc/` text configuration files).
3. `defender_tampering_count`: Windows Defender service APIs (`wscsvc`, `WinDefend`) do not exist on Linux.

### Recommended Cross-Platform Strategy:
- When running on Linux, the engine must either:
  a) Explicitly label the scan as a **Partial Platform Scan (15 of 19 Features Active)**, OR
  b) Map `num_fds` to `file_handle_count` and monitor `systemd` security units (`apparmor`, `selinux`) in place of `WinDefend`.
- Retraining on Linux should occur only when genuine Linux behavioral datasets (e.g., eBPF telemetry) are collected, rather than fabricating dummy values.

---

## 5. Missing Value and Non-Finite Data Handling

SentinelML implements strict numerical validation before scaling:
1. **Missing Attributes:** If an unprivileged scan cannot inspect a protected system process (raising `psutil.AccessDenied`), the scanner catches the exception and gracefully ignores that descriptor rather than halting the pipeline.
2. **Non-Finite Value Rejection:** `ml/predictor.py` validates `np.isfinite(features).all()`. If any feature contains `NaN`, `+Inf`, or `-Inf`, the predictor immediately halts and returns `None`, which the state machine converts to `ANALYSIS_ERROR`.
3. **Array Shape Verification:** The predictor strictly enforces shape `(1, 19)`. Truncated or expanded arrays are rejected.
