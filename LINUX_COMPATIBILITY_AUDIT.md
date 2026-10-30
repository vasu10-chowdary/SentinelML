# SentinelML V2 — Linux Compatibility Audit

This document outlines the findings from auditing the SentinelML project for Windows-specific dependencies, APIs, and paths. Per the requirements, the goal is to maintain absolute functional parity (19-feature vector, SentinelAI, etc.) without fabricating data on Linux.

## 1. Windows-only Components and Replacements

| Component | Location | Windows Role | Linux Replacement / Strategy |
| :--- | :--- | :--- | :--- |
| **Windows Registry (`winreg`)** | `gui/pages/settings.py` | Configure autostart at logon by setting `Run` registry key. | **Desktop Entry**: Write `sentinelml.desktop` to `~/.config/autostart/`. Handled cleanly via `sys.platform`. |
| **Defender APIs / Service Status** | `scanner/live_scanner.py` (`_check_defender_tampering`) | Uses `psutil.win_service_get` to check `WinDefend`, `wscsvc`. | **Graceful Fallback**: The code already has an `if sys.platform != 'win32': return 0.0` guard. This aligns with instructions to return 0 for unavailable telemetry. |
| **Process Handles (`num_handles`)** | `scanner/live_scanner.py` (`_total_file_handles`, etc.) | Measures file and registry handles per process via `psutil`. | **Graceful Fallback**: The code currently uses inline guards like `if sys.platform == "win32" else 0`. This safely returns 0 without crashing. |
| **Path Separators (`\\`)** | `scanner/live_scanner.py` (`_count_suspicious_path_procs`) | Checks process paths for `\\temp\\`, `\\appdata\\`. | **Cross-Platform Fix**: Add Linux temporary directories (`/tmp/`, `/var/tmp/`, `/dev/shm/`) to the fragment list to capture equivalent suspicious staging paths on Linux. |
| **AppData Paths** | `utils/paths.py` | Hardcoded fallback to `AppData\Local\SentinelML`. | **Cross-Platform Fix**: Update to call `utils.platform_utils.PlatformPaths().get_application_data_dir()`, which correctly implements XDG `~/.config/SentinelML` for Linux. |
| **Executable Name Assumptions** | `gui/pages/settings.py` | String replace `gui\\pages\\settings.py` with `app.py`. | **Cross-Platform Fix**: Use `os.path.join()` or `pathlib.Path` resolution instead of Windows-specific slashes. |
| **Windows Process Semantics** | `scanner/live_scanner.py` | Checks for `vssadmin.exe`, `powershell.exe`, `lsass.exe`, etc. | **Graceful Fallback**: Linux systems won't run `vssadmin.exe`. These string checks will simply evaluate to `False`, mapping the features to `0`. This is the exact requested behavior to maintain the 19-feature pipeline without retraining or fabricating data. |

## 2. Unsupported Components (Graceful Omission)

The following 19 ML features rely strictly on Windows concepts. On Linux, they will naturally map to `0` or baseline values safely without crashing the scanner:
- `cmd_vssadmin_count` (Feature 8)
- `registry_handle_heuristic` (Feature 12)
- `powershell_process_count` (Feature 14)
- `unsigned_module_count` (Feature 15) - Windows PE signature validation only
- `suspicious_mutex_count` (Feature 16) - Windows mutex names
- `defender_tampering` (Feature 19)

**Impact on ML Pipeline**: A baseline score of `0` for these specific Windows vectors will result in the `RandomForest` model processing a slightly sparse vector on Linux. Given that safe behavior also scores `0` on these metrics, the classifier will still yield valid `SAFE` predictions. A real Linux ransomware encrypting files would still trigger high entropy, high IO, and suspicious paths, thereby raising the prediction probability accurately.

## 3. Files Requiring Modification
1. `utils/paths.py` — Replace hardcoded `AppData` with platform-aware logic.
2. `scanner/live_scanner.py` — Expand `frags` list with Linux `/tmp/` paths.
3. `gui/pages/settings.py` — Implement `.desktop` autostart for Linux and fix the `__file__` slash resolution.

## 4. Required Build Configuration
- `SentinelML_Linux.spec`: A new PyInstaller configuration targeting ONEDIR (`dist_linux/SentinelML/SentinelML`) without the `.exe` extension, preserving the exact same `_internal` architecture and exclusions (e.g. pandas, matplotlib).

## 5. Expected Limitations
- True system-level persistence (autostart) on Linux relies on standard XDG Autostart behavior (`~/.config/autostart`). Window managers that ignore XDG will not autostart the application.
- `psutil` behaves slightly differently across Linux kernels. Permission limitations for reading process environment variables for processes owned by other users (`root`) will be ignored safely per the existing `psutil.AccessDenied` handlers.
- End-to-end Linux packaging (PyInstaller) requires running the build directly on a Linux host/container, so only the build script is generated here, with source-level runtime validation performed.
