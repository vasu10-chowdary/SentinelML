# SentinelML — Supported Platforms (v3.1.0)

**Last verified**: 2026-10-30
**Evidence**: [docs/releases/v3.1.0/](docs/releases/v3.1.0/README.md)

SentinelML distinguishes between platforms that were actually exercised for this release and
platforms that are only architecturally adapted.

---

## 1. Platform support tiers

| Platform | Tier | v3.1.0 evidence | Telemetry | Status |
|---|---|---|---|---|
| **Windows 11 (64-bit)** | Tier 1 — fully verified | Release suite on the build host (357 passed, 2 skipped, 0 failed) | 19/19 | **Verified** |
| **Windows 10 (64-bit)** | Tier 1 — same code path | Not re-run for v3.1.0; earlier VM runs only | 19/19 | **Supported, not re-verified** |
| **Kali Linux 2026.1 (x86_64)** | Tier 2 — verified with limitations | Full demo audit on a headless Xvfb VM: launch, dashboard, Guard, SOC, filesystem, process-only and GUI scans; 355 passed, 4 skipped, 0 failed | 14–15/19 at runtime | **Verified from source** |
| **Ubuntu 22.04 / 24.04 LTS** | Tier 2 — instructions only | Not re-validated for v3.1.0 (prior WSL2 exercises only) | ~15/19 | **Instructions supplied** |
| **Debian / Mint** | Tier 2 — instructions only | Same code path as Kali; not separately exercised | ~15/19 | **Instructions supplied** |
| **macOS 12+ (Darwin)** | Tier 3 — unverified | Static adapter review only; no physical Mac testing | ~15/19 | **Code-ready, unverified** |

No Linux binary is attached to v3.1.0. Linux support is verified by running from source and
by the 359-test suite; an AppImage can be built with `packaging/linux/build_appimage.sh`.

---

## 2. Feature availability by operating system

Sensor availability is probed at runtime. On Linux, 4–5 of the 19 inputs are unavailable,
which forces `QUICK`/`FULL` scans into `INCONCLUSIVE — LIMITED COVERAGE`. `PROCESS` and
`CUSTOM` scans can complete when every required input succeeds.

| Feature key | Windows 10/11 | Linux (Debian/Ubuntu/Kali) | macOS | Reason for platform difference |
|---|---|---|---|---|
| `total_processes` | Active | Active (kernel threads filtered) | Active | `psutil` enumeration |
| `suspicious_process_count` | Active | Active | Active | Keyword heuristics |
| `avg_entropy` | Active | Active | Active | Shannon entropy over sampled files |
| `max_entropy` | Active | Active | Active | Peak entropy across sampled files |
| `high_entropy_region_count` | Active | Active | Active | Files/chunks above entropy 7.2 |
| `malfind_injection_count` | Heuristic proxy | Heuristic proxy | Heuristic proxy | User-space inspection of RWX maps |
| `crypto_dll_count` | Active (`.dll`) | Substituted (`.so`) | Substituted (`.dylib`) | Loaded cryptographic libraries |
| `cmd_vssadmin_count` | Active (`vssadmin`) | Substituted (`snapper`/`lvm`) | Substituted (`tmutil`) | Shadow-copy / backup command monitoring |
| `network_connection_count` | Active | Active | Root required | Socket enumeration |
| `unique_external_ips` | Active | Active | Root required | Remote endpoint enumeration |
| `file_handle_count` | Active | **Unavailable** | **Unavailable** | System-wide open handles need kernel support |
| `registry_handle_count` | Heuristic proxy | **Unavailable** | **Unavailable** | Registry is Windows-specific |
| `orphan_process_count` | Active | Active | Active | Parent verification |
| `powershell_process_count` | Active | Active | Active | Script interpreter detection |
| `unsigned_module_count` | Heuristic proxy | Heuristic proxy | Heuristic proxy | Signature heuristic |
| `suspicious_mutex_count` | Heuristic proxy | Heuristic proxy | Heuristic proxy | Sync-object naming heuristic |
| `abnormal_privilege_count` | Heuristic proxy | **Unavailable** | **Unavailable** | Windows token privileges |
| `suspicious_thread_count` | Heuristic proxy | Heuristic proxy | Heuristic proxy | Thread state/start-address heuristics |
| `defender_tampering_count` | Active | **Unavailable** | **Unavailable** | Windows Defender / WinDefend only |

---

## 3. Security boundary and architectural constraints

1. **User space, not kernel space.**
   SentinelML is a Ring-3 user-space monitor and behavioral classifier. It is not a kernel
   minifilter or ELAM driver and cannot prevent rootkit hooks or kernel-level corruption.
2. **Incomplete scans are never certified safe.**
   When required sensors are unavailable, the engine reports `INCONCLUSIVE — LIMITED
   COVERAGE` rather than `SAFE`. Failure modes report `ANALYSIS_ERROR`; no probability is
   fabricated.
3. **Model scope.**
   The bundled model is an experimental synthetic baseline trained on Windows/Volatility-
   oriented data. Linux vectors are out-of-distribution. See
   [LINUX_DETECTION_ACCURACY_AUDIT.md](LINUX_DETECTION_ACCURACY_AUDIT.md).
4. **macOS.**
   Adapter code exists (POSIX locking, `.dylib` crypto detection, LaunchAgents), but no
   runtime verification has been performed.
