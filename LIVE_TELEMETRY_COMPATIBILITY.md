# SENTINELML V2 — LIVE TELEMETRY COMPATIBILITY REPORT

**Audit Date:** October 19, 2026  
**Target Repository:** `C:\Users\vasur\Desktop\SentinalMl\`  
**Target Branch:** `exhibition-mode`  
**Components Audited:**
- `scanner/live_scanner.py`
- `scanner/filesystem_scanner.py`
- `scanner/scan_engine.py`
- `utils/platform_utils.py`

---

## 1. Architectural Overview & Boundary Constraints

SentinelML V2 operates strictly as an **unprivileged user-space (Ring-3) Python application**. It relies on `psutil`, Win32 API queries (via `ctypes` or `psutil`), and local filesystem traversal.

### Fundamental Architectural Limitation
Memory forensics and dynamic malware sandbox features (such as VAD memory injection flags, unbacked thread start addresses, kernel mutex objects, and process token privilege tables) require **Ring-0 kernel-level driver visibility** (e.g., via ETW Threat Intelligence, a filter driver, or raw RAM physical dumps analyzed with Volatility 3).

Because SentinelML runs without a kernel-mode driver, it cannot natively extract raw memory forensics structures without triggering OS access-denied errors. Consequently, the live telemetry pipeline implemented heuristic approximations using `psutil`.

---

## 2. Sandbox Observation Defect & Code Repair

### The Investigation: Why Sandbox Activity Was Not Observed
During the independent source audit, an architectural disconnect was identified between the simulation sandbox and live entropy extraction:

1. **Simulation Workflow:** The test lab executed `SandboxSimulator.run_simulation(num_files=20)`, generating 20 encrypted files with random ciphertext bytes in `temp_sandbox/`.
2. **Filesystem Scan:** `ScanEngine.scan(ScanType.CUSTOM, custom_paths=[sandbox_root])` was called. `FilesystemScanner` successfully traversed `temp_sandbox/`, counting 20 files.
3. **Telemetry Extraction Disconnect:**
   - Next, `ScanEngine` invoked `self._process_scanner.scan_system()`.
   - In `scanner/live_scanner.py`, `scan_system()` called `self._scan_file_entropy()`.
   - `_scan_file_entropy()` queried `PlatformInfo().get_monitored_directories()`, which returned the user's default personal folders: `[Desktop, Documents, Downloads, Music, Pictures, Videos]`.
   - **The sandbox path (`temp_sandbox/`) was never passed to `LiveScanner`!**
4. **Resulting Telemetry:**
   - The files sampled for entropy were benign files on the host's Desktop and Documents (`avg_entropy` $\approx 3.5$, `high_entropy_count` $= 0$).
   - The ML model never received the entropy generated in the sandbox.
   - The ML model classified the scan as `SAFE` ($p \approx 0.08$), completely unaware that 20 encrypted files had been written.
5. **False Assertion in Test Lab:** The test lab previously asserted `sim_res.avg_entropy_after > 7.0` (the simulator's internal calculation) rather than verifying what the detector measured, falsely reporting a passed ransomware detection test.

### Verified Code Repair
To allow genuine telemetry observation of custom scan targets:
1. `LiveScanner.scan_system(target_directories: Optional[List[Path]] = None)` was updated to accept custom target directories.
2. `LiveScanner._scan_file_entropy(target_directories: Optional[List[Path]] = None)` was updated to prioritize `target_directories` when specified, falling back to monitored directories only when `None`.
3. `ScanEngine.scan()` was modified to pass `scan_paths` directly to `_scan_processes(result, target_directories=scan_paths if scan_type == ScanType.CUSTOM else None)`.

---

## 3. Telemetry Response to Sandbox Entropy

With the observation pipeline repaired, when `temp_sandbox/` is scanned:
1. `LiveScanner` samples the sandbox files directly.
2. `avg_entropy` is accurately measured at **7.74 bits/byte**.
3. `high_entropy_region_count` is accurately measured at **20**.
4. The 19-feature vector is passed to `MLPredictor`.

### What the Random Forest Model Actually Predicts
When the feature vector contains high entropy ($7.74$) but benign process indicators ($0$ vssadmin, $0$ suspicious threads, $0$ abnormal handles):
- **Threat Probability:** Evaluates to **0.5600** on modern Windows 11 host telemetry.
- **Classification Mapping:**
  - $p = 0.56$ crosses the $0.50$ WARNING threshold.
  - ML Threat Level: **`WARNING`**.
  - Scan Engine State: **`ScanState.THREAT_DETECTED`**.

### Critical Academic Finding
The Random Forest model requires multimodal corroboration. Even when 100% of the files in the target directory are encrypted with Shannon entropy $> 7.8$, the threat probability reaches only $0.56$ (just crossing into WARNING) rather than CRITICAL ($> 0.90$), because the remaining 16 features represent running process behaviors.

If a benign user creates an encrypted archive (e.g., a `.zip` or `.7z` file with AES-256 encryption), the entropy will also measure $> 7.8$. The model relies on process-level signals to distinguish ransomware from legitimate encryption tools.

---

## 4. Platform Asymmetries: Windows 11 versus Linux

| Telemetry Dimension | Modern Windows 11 Workstation | Linux Host / Container Environment | Impact on ML Feature Vector |
|---|---|---|---|
| **Process Handles** | Win32 `num_handles` via `psutil` (~130,000 system-wide). | Unsupported (`psutil` returns 0 or raises exception). Defaulted to 0. | Extreme scale mismatch on Windows ($+400\sigma$); completely zeroed out on Linux. |
| **Loaded Modules / DLLs** | `p.memory_maps()` returns full DLL paths (`bcrypt.dll`, `crypt32.dll`). | `memory_maps()` returns `.so` paths. Crypto DLL heuristic returns 0. | Windows host has ~130 crypto DLL processes ($+35.5\sigma$); Linux has 0. |
| **Shadow Copies (`vssadmin`)** | Process name matching `vssadmin.exe`, `wbadmin.exe`. | Concept non-existent on Linux. Evaluates to 0. | Feature remains 0 on Linux. |
| **Defender Tampering** | Windows Service Control Manager queries (`WinDefend`, `WdNisSvc`). | Unsupported. Defaulted to 0.0. | Feature remains 0 on Linux. |
| **Filesystem Monitored Paths** | `C:\Users\<user>\Desktop`, `Documents`, etc. | `/home/<user>/Desktop`, `Documents`, etc. | Functional parity achieved via `PlatformInfo`. |

### Conclusion on Cross-Platform Operation
The 19-feature vector was designed with Windows-specific telemetry in mind (handles, DLLs, vssadmin, Defender services). On Linux, 7 of the 19 features are permanently 0.0 due to OS differences. The model cannot be evaluated across platforms without domain adaptation.
