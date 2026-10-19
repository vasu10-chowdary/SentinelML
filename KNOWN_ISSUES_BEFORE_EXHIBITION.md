# SentinelML V2 — Known Issues & Limitations Before Exhibition

## Overview

This document catalogs all known technical limitations, operational boundaries, edge-case caveats, and presenter mitigations for **SentinelML V2** prior to the college exhibition.

---

## 1. Technical Issues & Operational Limitations

### Issue 1: Windows Console CP1252 Encoding Limitation
- **Symptom**: Printing Unicode characters (such as checkmarks `\u2713` or warning triangles `\u26a0`) directly to standard Windows Command Prompt (`cmd.exe`) or legacy PowerShell consoles produces a `UnicodeEncodeError: 'charmap' codec can't encode character`.
- **Root Cause**: The default active code page on standard Windows Indian/US English consoles is `cp1252` (Windows-1252), which lacks glyphs for mathematical and Unicode symbols.
- **Resolution in SentinelML V2**:
  - Replaced Unicode symbol literals in UI text with standard ASCII equivalents (e.g. `[OK]` instead of `✓`).
  - Added `sys.stdout.reconfigure(encoding="utf-8")` in scripts that output formatted audit logs.
- **Presenter Mitigation**: When running CLI diagnostics, use Windows Terminal with UTF-8 or invoke commands through Python with explicit encoding.

---

### Issue 2: Modal Messagebox Blocking in Headless Scripts
- **Symptom**: Calling `_on_reset_demo()` displays a native Tkinter modal dialog (`messagebox.showinfo("Demo Reset", ...)`), which blocks script execution until a user clicks "OK".
- **Impact**: Harmless during interactive GUI usage; causes headless automated scripts to wait indefinitely if not monkeypatched.
- **Presenter Mitigation**: During automated benchmark or test harness runs, automated test scripts monkeypatch `tkinter.messagebox.showinfo` to a no-op. In live exhibition booth operation, the dialog serves as clear feedback to the user that the sandbox has been purged.

---

### Issue 3: Post-Execution Observation vs. Kernel Interception
- **Limitation**: SentinelML operates strictly in **Ring-3 (user space)** without a kernel minifilter driver (`fltmgr.sys`).
- **Impact**:
  - Filesystem polling observes files **after** they have been written or renamed.
  - A fast ransomware variant could encrypt several files before SentinelML's poll interval completes.
- **Talking Point for Judges**:
  > *"SentinelML is designed as an application-level behavioral monitoring study. In enterprise deployment, the detection pipeline would integrate with a kernel minifilter driver to intercept `IRP_MJ_WRITE` packets before commitment to disk."*

---

### Issue 4: Legacy Model Provenance (Model V1)
- **Limitation**: The deployed Random Forest model (`models/saved_model.pkl`) was trained on synthetic Gaussian distributions modeling Volatility memory-forensics fields (`malfind`, `susp_threads`).
- **Impact**:
  - The model has **not** been trained or evaluated on wild ransomware binaries (LockBit, Conti, WannaCry).
  - Its 100% accuracy applies strictly to its matching synthetic evaluation benchmark.
- **Talking Point for Judges**:
  > *"We explicitly disclose that Model V1 is an experimental synthetic baseline. We have implemented Schema V2 and an empirical benign collector to establish defensible ground truth for future training."*

---

### Issue 5: Monitored Directory Scope & Unprivileged Boundaries
- **Limitation**: For CPU efficiency, the live scanner targets designated user profile folders (Desktop, Documents, Downloads).
- **Impact**:
  - Ransomware operating in unmonitored directories (e.g. `C:\Users\vasur\AppData\Local\Temp\` or external network shares) is invisible to the live scanner unless that directory is explicitly included in a custom scan.
  - Without administrative elevation, scanning restricted folders (`C:\System Volume Information`) records access-denied counts.
- **Talking Point for Judges**:
  > *"This reflects unprivileged workstation reality. SentinelML transparently records access-denied paths rather than falsely claiming the uninspected directories are clean."*

---

## 2. Pre-Exhibition Presenter Checklist

- [x] **Verify Model & Scaler**: Ensure `models/saved_model.pkl` and `models/scaler.pkl` exist and load cleanly.
- [x] **Verify Sandbox Isolation**: Ensure `temp_sandbox/` is empty and has write permissions.
- [x] **Verify Concurrency Lock**: Ensure `SecurityTestLab._demo_lock` is unheld before demonstration.
- [x] **Run Pre-Demo Health Check**: Look for `[OK] System Diagnostic Ready` on the exhibition page header.
- [x] **Prepare Offline Fallback**: In case venue Wi-Fi is down or restricted, verify that `📖 Walkthrough` runs deterministically.
- [x] **Report Generation**: Verify that reports export cleanly to the `reports/` folder.
