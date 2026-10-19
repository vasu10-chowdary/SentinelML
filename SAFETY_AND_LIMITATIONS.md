# SENTINELML V2 — SAFETY BOUNDARIES & TECHNICAL LIMITATIONS

**Scope:** College Exhibition Demonstrations, Academic Presentations, and Code Audits  
**Document Revision:** 2.0.0 (October 2026)  
**Classification:** Mandatory Safety & Disclosure Reference  

---

## 1. Absolute Exhibition Safety Guarantees

When demonstrating SentinelML at public exhibitions, academic vivas, or laboratory sessions, the following safety invariants are strictly enforced in software:

### 1.1 Zero Destructive Code Execution
- **No Live Malware:** Live ransomware binaries (e.g. WannaCry, LockBit, Conti) are **never executed** on the host operating system.
- **Harmless Simulation Only:** All behavioral simulations generate pseudorandom byte streams and plain-text files. No real cryptographic ransomware locks are applied.
- **Host Data Protection:** SentinelML never modifies, renames, deletes, or encrypts user files, personal documents, system directories, network shares, or removable drives.

### 1.2 Sandbox Isolation & Path Traversal Prevention
All simulation occurs strictly within a dedicated disposable directory:
$$\text{Sandbox Root} = \texttt{C:\textbackslash Users\textbackslash vasur\textbackslash Desktop\textbackslash SentinalMl\textbackslash temp\_sandbox}$$

Every path accessed by `SandboxSimulator` is validated against path traversal:
```python
resolved_path = path.resolve()
resolved_sandbox = self._sandbox_root.resolve()
if not resolved_path.is_relative_to(resolved_sandbox):
    raise SecurityError("SECURITY VIOLATION: Path resolves outside sandbox!")
```
- Symbolic links attempting to target external system paths are rejected.
- Path traversal sequences (`..\..\`) attempting to escape the sandbox root are blocked.
- Automated cleanup functions (`reset_sandbox()`) are hard-coded to reject deletion if the target resolves to a drive root (`C:\`) or home directory.

---

## 2. Technical Limitations & Visibility Boundaries

In cybersecurity academic review, disclosing what a system **cannot do** is as important as presenting what it can do.

### 2.1 Unprivileged User-Space Boundary (Ring 3 vs Ring 0)
- **Design Trade-off:** SentinelML operates as an unprivileged user-space daemon (Ring 3) using standard Python APIs (`psutil`).
- **Advantage:** It requires no kernel driver installation, avoiding Blue Screens of Death (BSOD), kernel panics, and vulnerability to Bring Your Own Vulnerable Driver (BYOVD) attack chains.
- **Boundary:** Because it lacks a Ring 0 filesystem minifilter driver (such as `fltmgr.sys`), SentinelML cannot intercept kernel-level I/O Request Packets (IRPs) in real time. It cannot detect kernel rootkits or Direct Kernel Object Manipulation (DKOM) that blind user-space process queries.

### 2.2 Heuristic Telemetry Proxies
Of the 19 behavioral features, several are coarse heuristics rather than direct memory forensics:

| Feature Name | Theoretical Concept | SentinelML User-Space Implementation | Operational Limitation |
|---|---|---|---|
| `malfind_injection_count` | Unlinked memory pages / injected shellcode | Checks if process executable path is `None` or `""` | Coarse proxy; does not scan process virtual address descriptors (VAD). |
| `suspicious_mutex_count` | Named mutex indicators created by malware | Checks if a non-system process has $> 50$ active threads | High-thread benign workloads (compilers, video renderers) can trigger this proxy. |
| `unsigned_module_count` | Binaries lacking valid Authenticode signatures | Checks if process executes from `\Temp\`, `\Downloads\`, or `\Public\` | Legitimate portable applications running from `Downloads` may elevate this count. |
| `avg_entropy` / `max_entropy` | Bulk filesystem encryption | Samples up to 200 files in `Documents`, `Desktop`, `Downloads` | Ransomware operating in unmonitored directories or encrypting at low speeds ($\le 10$ files/min) avoids burst detection. |

### 2.3 Cross-Platform Telemetry Asymmetry
- **Windows vs Linux:** Four features rely on Windows-specific APIs:
  - `file_handle_count` (uses `p.info["num_handles"]`)
  - `registry_handle_count`
  - `abnormal_privilege_count`
  - `defender_tampering_count` (checks `WinDefend`, `SecurityHealthService`)
- On Linux, these features return `0.0` by default. Executing the Windows-trained Random Forest model on a Linux host results in a systematic distribution shift. Cross-platform deployment requires training separate OS-specific models or implementing eBPF kernel probes.

### 2.4 Intrusion Detection (IDS) vs Intrusion Prevention (IPS)
- SentinelML is strictly an **Intrusion Detection System (IDS)**.
- It provides immediate desktop alerts, risk meter updates, and structured incident logs.
- It does **not** automatically terminate suspicious processes, quarantine executables, or restore encrypted files. File restoration requires external immutable backups or uncorrupted Volume Shadow Copies.

---

## 3. Safe Guidelines for Future Live-Malware Research

If active, in-the-wild ransomware binaries are to be evaluated in future research phases, testing must strictly adhere to the following containment protocol:

```
+-------------------------------------------------------------------+
| ISOLATED EVALUATION WORKSTATION (Dedicated Hardware)              |
|                                                                   |
|   +-------------------------------------------------------------+ |
|   | AIR-GAPPED VIRTUAL MACHINE (Type-1 / Type-2 Hypervisor)     | |
|   | • Host OS: Hardened Linux or Windows Hyper-V                | |
|   | • Guest OS: Clean Windows 11 Evaluation Snapshot            | |
|   | • Networking: COMPLETELY DISABLED (Host-Only / None)       | |
|   | • Shared Folders: DISABLED                                 | |
|   | • Clipboard / Drag-and-Drop: DISABLED                       | |
|   | • Shared Credentials / Tokens: NONE                         | |
|   | • Execution: Automated Cuckoo / CAPE Sandbox Harness        | |
|   | • Teardown: Immediate non-persistent snapshot revert        | |
|   +-------------------------------------------------------------+ |
+-------------------------------------------------------------------+
```

> [!CAUTION]
> **NEVER** run live ransomware binaries on personal laptops, university workstations, campus networks, or the exhibition demonstration computer.
