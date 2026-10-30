# SentinelML — Proposed Linux Behavioral Schema v1 (LBS-1)

**Status:** APPROVED 2026-10-30 under decision `LBS1-APPROVAL-2026-10-30`. Implementation has
not started: no collector, model, dataset, or measurement exists yet.
**Date:** 2026-10-30
**Companion documents:** `LINUX_DETECTION_ACCURACY_AUDIT.md` (Phase 1 audit),
`LINUX_LBS1_APPROVED_DECISIONS.md` (binding decisions),
`LINUX_LBS1_IMPLEMENTATION_PLAN.md` (gated plan)
**Scope:** Unprivileged (Ring-3) Linux detection. The Windows 19-feature model, its scaler,
its thresholds, and all existing Windows artifacts remain frozen and untouched.

---

## 0. What this document is and is not

This document specifies a **proposed** Linux-native feature schema, its collection contract,
its evidence-quality contract, and the dataset/training/evaluation plan that would follow
approval. It deliberately contains **no accuracy numbers**, because no Linux dataset has been
collected and no Linux model has been trained.

It does **not** authorize:

- training a model,
- modifying `models/saved_model.pkl`, `models/scaler.pkl`, `models/metrics.json`, or the
  19-feature Windows extractor,
- changing the 0.50 / 0.90 thresholds,
- executing real ransomware,
- adding privileged components (auditd, eBPF, fanotify, kernel modules) to v1.

The decisions were resolved on 2026-10-30; §12 records the approved resolutions and the
binding record is `LINUX_LBS1_APPROVED_DECISIONS.md`.

---

## 1. Why a separate schema is required

The Phase 1 audit established four facts that make reuse of the Windows schema invalid on Linux:

1. **Four of the 19 Windows features are structurally absent on Linux** and are currently
   zero-filled (`file_handle_count`, `registry_handle_count`, `abnormal_privilege_count`,
   `defender_tampering_count`) — 7.60% of the model's Gini decision weight.
2. **Five more are semantically wrong even when numerically non-zero** on Linux
   (`cmd_vssadmin_count`, `crypto_dll_count`, `unsigned_module_count`,
   `suspicious_mutex_count`, `suspicious_thread_count`) — 39.60% of Gini weight.
3. **Four are partially available but scale-shifted** (`process_count`, `network_connection_count`,
   `file_modification_rate`, `file_rename_rate`) — 8.63% of Gini weight. These are not wrong
   in kind, but their Linux magnitudes are drawn from a different distribution than the
   synthetic Windows/Volatility training set.
4. **The remaining six are measured but out-of-distribution** relative to the training data —
   44.17% of Gini weight.

Zero-filling absent features does not make them neutral. A tree ensemble treats `0` as an
observed value. The resulting probability (e.g. 0.37 in the verified WSL run) is an
**artifact of out-of-distribution inputs**, not a calibrated Linux risk estimate. LBS-1 replaces
the Windows proxy features with signals that Linux can actually measure, and — critically —
refuses to produce a probability when they cannot be measured.

---

## 2. Design principles

| # | Principle | Consequence |
|---|---|---|
| P1 | **Measure or refuse.** | No zero-fill, no imputation, no NaN. A feature either has a real observed value or the sensor group is marked degraded and the model is not invoked. |
| P2 | **No fabricated cross-platform equivalence.** | No Linux "registry handle" analogue. If a Windows concept has no honest Linux counterpart, it is dropped, not simulated. |
| P3 | **Unprivileged first.** | v1 uses only data readable by the logged-in user: `psutil`, world-readable `/proc` fields, inotify, file metadata, 4 KB file reads. Privileged escalation is explicitly out of scope for v1. |
| P4 | **Multimodal correlation.** | No single feature (entropy, extension, deletion) is treated as proof. The model sees filesystem velocity, entropy movement, naming, process dynamics, command semantics, privilege, and network together. |
| P5 | **Simulation-honest.** | Training labels come from self-authored, sandboxed ransomware-*like* scripts. Any resulting model can only claim validity on the measured benign workloads and the simulated attack distribution. It cannot claim real-world ransomware accuracy. |
| P6 | **Windows is frozen.** | LBS-1 is a new schema with new artifacts. It never feeds, retrains, or reinterprets the Windows model. |
| P7 | **Uncertainty is a state, not a number.** | Insufficient evidence produces `INCONCLUSIVE`, never `SAFE` and never a manufactured probability. |

---

## 3. LBS-1 feature list (20 features)

All model inputs are `float64`, finite, non-negative unless stated. The vector is ordered;
order, names, and dtypes are part of the artifact contract and hashed.

| Idx | Name | Unit | Definition (exact) | Primary source | Permission | Evidence class |
|---:|---|---|---|---|---|---|
| 0 | `file_mod_rate` | events/s | Count of write-completion events (`IN_CLOSE_WRITE`, `IN_MODIFY` deduplicated per file per window) inside watched roots ÷ window seconds | inotify | user-owned trees; EACCES dirs skipped | GENUINE_MEASURED |
| 1 | `file_rename_rate` | events/s | Count of rename events (`IN_MOVED_FROM`/`IN_MOVED_TO` paired by cookie, plus `IN_MOVE_SELF`) ÷ window seconds | inotify | same | GENUINE_MEASURED |
| 2 | `file_delete_rate` | events/s | Count of `IN_DELETE` + `IN_DELETE_SELF` + unpaired `IN_MOVED_FROM` ÷ window seconds | inotify | same | GENUINE_MEASURED |
| 3 | `files_modified_count` | count | Absolute number of distinct files with write events in the window | inotify | same | GENUINE_MEASURED |
| 4 | `files_renamed_count` | count | Absolute number of distinct files renamed in the window | inotify | same | GENUINE_MEASURED |
| 5 | `distinct_dirs_touched` | count | Number of distinct parent directories containing at least one write/rename/delete event | inotify | same | GENUINE_MEASURED |
| 6 | `avg_shannon_entropy` | bits/byte (0–8) | Mean Shannon entropy of 4 KB head samples of files **written/created/renamed during the window** (see §4.3); `NOT_APPLICABLE_NO_FILE_ACTIVITY` or `NOT_APPLICABLE_NO_SAMPLEABLE_FILES` if that set is empty, making the observation `INSUFFICIENT_ACTIVITY` | file reads | read permission per file | GENUINE_MEASURED (sampled) |
| 7 | `high_entropy_file_ratio` | ratio (0–1) | Fraction of those successfully sampled event-touched files with H ≥ 7.0 bits/byte; same statuses as feature 6 when the sample set is empty | file reads | same | GENUINE_MEASURED (sampled) |
| 8 | `entropy_increase_ratio` | ratio (0–1) | Fraction of the **fixed baseline cohort re-sampled at window end** (surviving readable files; ≤10% permission loss excluded and recorded) whose H rose by ≥ 1.0 bit ÷ **re-sampled cohort files** (see §4.4); `0.0` is a valid measured value (0 of N increased); >10% permission loss → `UNAVAILABLE_PERMISSION` | file reads | same | GENUINE_MEASURED (paired, sampled) |
| 9 | `ransom_extension_match_count` | count | Events whose resulting filename ends with an entry in the versioned ransom-extension list | inotify + list | same | GENUINE_MEASURED (list-dependent) |
| 10 | `ransom_note_match_count` | count | Created/renamed files whose basename matches a versioned ransom-note pattern (instruction tokens + generic names) | inotify + list | same | GENUINE_MEASURED (list-dependent) |
| 11 | `process_create_rate` | procs/s | New PIDs observed across snapshots ÷ window seconds (pid-set diff) | psutil / `/proc` | world-readable enumeration | GENUINE_MEASURED |
| 12 | `process_exit_rate` | procs/s | PIDs present in a prior snapshot but absent later ÷ window seconds | psutil / `/proc` | same | GENUINE_MEASURED |
| 13 | `short_lived_process_ratio` | ratio (0–1) | Created PIDs that exited before window end ÷ created PIDs; `NOT_APPLICABLE_NO_PROCESS_ACTIVITY` when created = 0 (never written as 0.0; G4 remains `OK`, since this is no activity, not a sensor failure) | psutil / `/proc` | same | GENUINE_MEASURED |
| 14 | `destructive_command_count` | count | New processes whose argv matches the versioned destructive-operation rule set (`shred`, `wipe`, `srm`, `dd`, `cryptsetup`, `mkfs*`, `wipefs`, `fdisk`, `parted`, `sgdisk`, `truncate`, and `rm` only with both recursive and force flags) | `/proc/<pid>/cmdline` | world-readable unless `hidepid` | HEURISTIC_PROXY |
| 15 | `shell_spawn_count` | count | New shells (`sh`, `bash`, `dash`, `zsh`, `ksh`, `fish`) whose parent is not a shell and not a terminal emulator | `/proc` cmdline + ppid | same | HEURISTIC_PROXY |
| 16 | `temp_exec_count` | count | New processes whose resolved `exe` (or, for foreign PIDs, absolute `argv[0]`) lies under `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user/<uid>`, or `$XDG_CACHE_HOME` | `/proc/<pid>/exe`, cmdline | same-user `exe`; foreign PIDs fall back to argv[0] | HEURISTIC_PROXY |
| 17 | `privileged_process_count` | count | New processes (not present at window start) with any of real/effective/saved UID = 0 or `CapEff ≠ 0`, excluding kernel threads | `/proc/<pid>/status` | world-readable | GENUINE_MEASURED |
| 18 | `setuid_cap_file_event_count` | count | Write/attribute events on watched files whose resulting mode has S_ISUID/S_ISGID or whose `security.capability` xattr is non-empty | inotify + `stat`/`getxattr` | same | GENUINE_MEASURED |
| 19 | `unique_external_ip_count` | count | Distinct remote IPs of established TCP/UDP sockets where `ipaddress.ip_address(ip).is_global` is true | `psutil.net_connections` | readable unprivileged (verified) | GENUINE_MEASURED |

### 3.1 Definedness layer (no numeric sentinels)

Four features are proportions/means over a population that can be empty. `0/0` has no mathematical
value. LBS-1 therefore attaches a **status** to every feature and never encodes undefined as `0`,
`-1`, a mean, a previous window, or any other sentinel.

| Status | Meaning | Numeric value |
|---|---|---|
| `DEFINED` | The measurement has a defined value: a non-empty population for features 6/7/8/13, or a count/rate over the window for the other sixteen features (zero events is a measured `0`) | `float` |
| `NOT_APPLICABLE_NO_FILE_ACTIVITY` | No write/create/rename events in the window (features 6, 7) | none |
| `NOT_APPLICABLE_NO_SAMPLEABLE_FILES` | Events occurred, but no non-zero readable file (features 6, 7) | none |
| `NOT_APPLICABLE_NO_BASELINE_COHORT` | No readable pre-existing file at window start (feature 8) | none |
| `NOT_APPLICABLE_COHORT_UNAVAILABLE` | All baseline-cohort files were deleted or moved out by window end (an observed activity pattern, not a sensor failure) | none |
| `NOT_APPLICABLE_NO_PROCESS_ACTIVITY` | Zero new PIDs in the window (feature 13) | none |
| `UNAVAILABLE_PERMISSION` | Reads or `/proc/<pid>` access denied, including baseline-cohort re-sampling (sensor failure) | none |
| `UNAVAILABLE_SENSOR` | API failure, unsupported filesystem, inotify overflow, or an unexplained sample shortfall (sensor failure) | none |

**Definedness matrix — the only four population-based features.** The sixteen count/rate
features (0–5, 9–12, 14–19) are always `DEFINED` when their sensor is healthy; zero matching
events is a measured `0`, never an undefined value.

| Feature(s) | Condition | Status | Value | Observation state |
|---|---|---|---|---|
| 6, 7 | No write/create/rename events | `NOT_APPLICABLE_NO_FILE_ACTIVITY` | none | `INSUFFICIENT_ACTIVITY` |
| 6, 7 | Events occurred, every touched file is zero-length | `NOT_APPLICABLE_NO_SAMPLEABLE_FILES` | none | `INSUFFICIENT_ACTIVITY` |
| 6, 7 | Non-zero files existed, reads denied beyond the 10% budget, or the sample shortfall is unexplained | `UNAVAILABLE_PERMISSION` / `UNAVAILABLE_SENSOR` (G2 `DEGRADED`) | none | `DEGRADED` |
| 8 | No readable pre-existing file at window start | `NOT_APPLICABLE_NO_BASELINE_COHORT` | none | `INSUFFICIENT_ACTIVITY` |
| 8 | Cohort existed; all files deleted or moved out by window end | `NOT_APPLICABLE_COHORT_UNAVAILABLE` | none | `INSUFFICIENT_ACTIVITY` |
| 8 | Cohort permission loss above 10% of the start cohort | `UNAVAILABLE_PERMISSION` (G2 `DEGRADED`) | none | `DEGRADED` |
| 8 | Cohort survives; re-sampled in full; none increased | `DEFINED` | `0.0` (0 of N) | `MODEL_READY` if all else defined |
| 13 | Zero PIDs created | `NOT_APPLICABLE_NO_PROCESS_ACTIVITY` | none | `INSUFFICIENT_ACTIVITY` |
| 13 | Created > 0; zero exited | `DEFINED` | `0.0` | `MODEL_READY` if all else defined |

Observation states, derived from feature statuses and sensor groups:

| State | Condition | Vector | Verdict |
|---|---|---|---|
| `MODEL_READY` | All seven sensor groups `OK` **and** all 20 features `DEFINED` | Exactly 20 `float64`, finite, non-negative, schema order | Model is invoked |
| `INSUFFICIENT_ACTIVITY` | No group `DEGRADED`/`UNAVAILABLE`, but ≥1 feature is `NOT_APPLICABLE_*` (equivalently a group is `NOT_APPLICABLE` because there was no population) | `None` — no partial vector | `INCONCLUSIVE`, no probability |
| `DEGRADED` | Any feature `UNAVAILABLE_*`, or any group `DEGRADED`/`UNAVAILABLE` | `None` | `INCONCLUSIVE`, no probability |

A `NOT_APPLICABLE` group means the sensor worked but had nothing to measure (for example G5/G6
when zero PIDs were created). It is distinct from `DEGRADED`, contributes to
`INSUFFICIENT_ACTIVITY` when no sensor is degraded, and never yields `SAFE`.

**Terminology.** In the acceptance criteria, a “healthy observation” means `MODEL_READY`.
Sensor availability alone does not imply model applicability: a quiet system can have working
sensors and still provide no population to measure. This distinction is explicit in the result
and audit record rather than being hidden inside a numeric value.

**Guarantee.** For every `MODEL_READY` observation: `len(vector) == 20`, `dtype == float64`,
every value is finite and `>= 0`, and the order equals `LBS1_FEATURE_NAMES`. This is
property-tested over an enumerated activity matrix (Stage A, `tests/test_lbs1_applicability.py`).
No other state produces a vector.

**Inference invariant.** `features` is non-`None` **if and only if**
`observation_state == MODEL_READY`. For `INSUFFICIENT_ACTIVITY` and `DEGRADED`, `features is None`;
every non-`DEFINED` feature has value `None`; `ml/linux_predictor.py` refuses the call with
`NotApplicableError`; and the verdict path never imports or invokes the predictor for those
states.

**Why these choices**

- **Features 6/7 are event-touched, not a standing corpus.** Measuring the entropy of all files
  in `~/Videos` would report camera/archive content as a behavioral signal with no activity
  whatsoever, inflating false positives and diluting the meaning of the feature. Restricting to
  files written/created/renamed keeps it behavioral. The cost is that a window with no file
  activity has no entropy population, so it is `INSUFFICIENT_ACTIVITY`, not a fabricated zero.
- **Feature 8 uses a fixed cohort re-sampled in full.** The earlier “changed files only”
  denominator is undefined when nothing changed and misses in-place encryption that preserves
  size and timestamps. Re-sampling every surviving baseline file makes the proportion defined
  whenever ≥1 cohort file survives: `0.0` then genuinely means “0 of N re-sampled files increased
  by ≥1 bit,” a measurement, not a substitute for an undefined value.
- **Feature 13 remains a ratio and is not converted to a count.** A proportion over zero created
  processes asserts “no short-lived processes” without having observed any process creation,
  conflating an idle system with benign churn. The honest representation is
  `NOT_APPLICABLE_NO_PROCESS_ACTIVITY` and an `INCONCLUSIVE` verdict. Process volume is already
  represented by features 11/12, so no signal is lost from the schema.

**Deliberate exclusions and their reasons**

| Excluded signal | Reason |
|---|---|
| Registry / Defender / VAD / mutex / handle features | No honest Linux counterpart at Ring-3. Dropped, not proxied. |
| `max_entropy` | Redundant with #6/#7; avoids double-weighting the same sample set. |
| `file_create_rate` | Strongly correlated with write rate on Linux (`IN_CREATE` precedes `IN_CLOSE_WRITE`); kept as a **context metric** for the report, not a model input, until data shows independent value. |
| `disk_write_bytes_per_sec`, `cpu_busy_ratio` | System-wide, not attributable to the attack; retained as context/diagnostic only. |
| Per-process I/O counters | `/proc/<pid>/io` is same-user only; too sparse to be a reliable model input. |
| File content, raw command lines (persisted) | Privacy. Content is read transiently for entropy only; command lines are matched in memory and not stored. |
| Auditd / eBPF / fanotify / netlink connector signals | Require root or kernel policy changes. Explicitly out of scope for v1 (§12, D6). |

---

## 4. Exact collection semantics

### 4.1 Observation window

- Default **15 s** (configurable 10–60 s); fixed per model version, recorded in the artifact.
- Process sampling every **0.5–1.0 s** (≥ 15 snapshots at the default window).
- Filesystem events accumulated continuously; window boundaries are wall-clock aligned.
- One observation = one completed window over a fixed target root set.

### 4.2 Filesystem event accounting (features 0–5, 9, 10, 18)

- Recursive inotify watches on XDG user directories (`Documents`, `Desktop`, `Downloads`,
  `Pictures`, `Videos`, `Music`, `Public`, `Templates`) plus any user-configured target.
- Noise directories pruned identically to the existing scanner (`.git`, `node_modules`,
  `__pycache__`, `.venv`, `build`, `dist`, package caches) — documented as a deliberate blind spot.
- Watch budget capped (default 20,000 watches). If `max_user_watches` is exceeded, the watch
  setup is partial and **G1 is marked DEGRADED**; the shortfall is recorded, not ignored.
- `IN_Q_OVERFLOW` at any point **invalidates the window's filesystem counts** (G1 DEGRADED).
  An overflow means events were dropped; a "quiet" count would be a lie.
- Rename pairing uses the inotify cookie. Unpaired `IN_MOVED_FROM` inside the window counts as
  a delete (the file left the tree).
- Filesystems where inotify semantics are unreliable — `9p`, `drvfs` (`/mnt/c` under WSL),
  `fuse`, `nfs`, `cifs`, `sshfs` — are **detected from `/proc/self/mountinfo`** and mark
  **G1 DEGRADED** for v1. This matters directly: the previous Linux verification ran inside
  WSLg; targets on the Windows-mounted filesystem would not be trustworthy for LBS-1.
- Filename lists (`ransom_extension`, `ransom_note`) are **versioned constants** shipped with the
  schema. They are heuristics, they are evadable, and their contribution is limited to 2 of 20
  features. Changes to either list require a schema version bump for audit purposes even though
  the vector length does not change (recorded as `list_version` in the manifest).

### 4.3 Entropy sampling (features 6, 7)

- **Sample set** = up to 200 distinct files that produced write/create/rename events in the
  window, sampled at event time or at window end. The baseline cohort used by feature 8 is a
  separate set and is **not** included in features 6/7.
- Per file: read the first **4,096 bytes only**, compute Shannon entropy in bits/byte.
  Content is discarded immediately; no bytes, hashes of content, or excerpts are persisted.
- Files with size 0 are counted as "not sampleable" and excluded from the ratio denominator;
  they are still counted in event features.
- **No extension filtering.** Compressed media, archives, and video are *not* excluded from the
  entropy statistics, because extension filtering is trivially evadable (an attacker can keep
  `.jpg`). The resulting false-positive pressure from legitimate compressed data is handled by
  the hard-benign training class (§6.2), not by hiding it.
- Status assignment when the sample set is empty:
  - no write/create/rename events at all → `NOT_APPLICABLE_NO_FILE_ACTIVITY` (G2 is
    `NOT_APPLICABLE`, observation `INSUFFICIENT_ACTIVITY`);
  - events occurred but every touched file is zero-length → `NOT_APPLICABLE_NO_SAMPLEABLE_FILES`
    (observation `INSUFFICIENT_ACTIVITY`);
  - events occurred on non-zero files but reads were denied beyond the 10% failure budget →
    `UNAVAILABLE_PERMISSION`, **G2 `DEGRADED`** (sensor failure, distinct from no activity);
  - fewer than 20 samples while writes occurred → **G2 `DEGRADED`**, feature status
    `UNAVAILABLE_SENSOR`, unless the shortfall is fully explained by zero-length files or a total
    event count below 20.
- No status in this section is ever serialized as `0.0`.

### 4.4 Paired entropy movement (feature 8)

Entropy at the end of a window cannot show whether a *pre-existing* file got encrypted
mid-window. LBS-1 therefore maintains a small in-memory baseline cache:

- At window start, sample up to **200 pre-existing files** (stratified across watched roots,
  weighted toward recently modified files), recording `(path, inode, size, mtime_ns, H)`.
- At window end, re-sample **every surviving baseline-cohort file that is still readable**,
  regardless of whether `(size, mtime_ns)` changed, and recompute H. Re-sampling unchanged
  metadata catches in-place encryption that preserves size and timestamps.
- `entropy_increase_ratio` = re-sampled cohort files with ΔH ≥ 1.0 bit ÷ **re-sampled cohort
  files**. The denominator is the fixed cohort that survived, not only the files that changed.
- If the cohort is non-empty and none increased, the value is exactly `0.0`. This is a measured
  proportion (“0 of N”), not a substitute for an undefined `0/0`.
- **Cohort read-failure budget:** at most 10% of the start cohort may be unreadable at window end
  for permission reasons; those files are excluded from the denominator and recorded. Above 10%,
  the status is `UNAVAILABLE_PERMISSION` and G2 is `DEGRADED` — the remaining sample is too
  incomplete to trust. Files deleted or moved out are not failures; they are removed from the
  denominator and, if none survive, produce `NOT_APPLICABLE_COHORT_UNAVAILABLE`.
- Status assignment:
  - no readable pre-existing file at window start → `NOT_APPLICABLE_NO_BASELINE_COHORT`;
  - cohort non-empty at start but zero files remain at end because they were deleted or moved out
    → `NOT_APPLICABLE_COHORT_UNAVAILABLE`. This includes a mass-deletion window; it is reported
    as INCONCLUSIVE with the reason, never as SAFE;
  - cohort files remain but re-sampling is denied (permission revoked or unreadable) beyond the
    failure budget → `UNAVAILABLE_PERMISSION`, **G2 `DEGRADED`** (sensor failure). A mass deletion
    is activity; a permission wall is a sensor failure, and the two are not merged.
- Files created during the window are excluded from this ratio — they have no baseline, and
  pretending they do would fabricate a delta.
- Baseline cache is never written to disk. It is keyed by inode to survive renames.

### 4.5 Process dynamics (features 11–17)

- Snapshots via `psutil.process_iter` with fields `pid, ppid, name, exe, cmdline, create_time,
  status, uids`; `/proc/<pid>/status` is consulted for `Uid:`/`CapEff` because psutil does not
  expose effective capabilities.
- Kernel threads (`pid` 2 / no `exe` / bracketed name) are excluded from *created process*
  counts; they are not user activity.
- Feature 13 is undefined when zero processes were created. It is **not** written as 0.0 and the
  observation is **not** `MODEL_READY`: it receives `NOT_APPLICABLE_NO_PROCESS_ACTIVITY` and the
  final verdict is `INCONCLUSIVE`. G4 remains `OK` if the sensor demonstrably worked (≥3
  successful snapshots, consistent accounting); “no creation activity” is an applicability
  result, not a sensor failure. Created > 0 with zero exits yields the measured value `0.0`.
- Feature 14 matching happens **in memory** against tokenized argv. Nothing is persisted except
  the count and the matched rule id (e.g. `shred`), never the full command line.
- Features 15–16 depend on parent and executable resolution. On systems with `hidepid=2`,
  foreign-process `cmdline`/`exe` are unreadable; the per-process resolution rate is computed and
  **G5/G4 are DEGRADED below a 90% resolution threshold**. Spoofable `argv[0]` is the reason
  feature 16 is labeled HEURISTIC_PROXY, not measured.
- Feature 17 counts only processes that appeared during this window; long-running root daemons
  are not re-counted every window (which would otherwise make the feature a constant).

### 4.6 Network (feature 19)

- `psutil.net_connections(kind="inet")`, established sockets only, remote address present.
- "External" uses Python's `ipaddress` classification (`is_global`), **not string prefixes**.
  This correctly excludes loopback, RFC1918, link-local, CGNAT `100.64/10`, multicast, and
  reserved ranges — the existing `_is_private_ip` prefix list in `live_scanner.py` would
  miscount CGNAT and IPv6 ULA as external.
- Deduplication is by IP string, not by socket, so one CDN host with ten connections counts once.
- If the call fails, G7 is DEGRADED. Silent success accounting on failure (as in the existing
  `collector_v2.py` network/Defender sensors) is explicitly forbidden by LBS-1.

---

## 5. Evidence-quality contract

### 5.1 Sensor groups

| Group | Covers | Healthy when |
|---|---|---|
| G1 Filesystem events | 0–5, 9, 10, 18 | ≥1 watch installed on a supported local filesystem, no `IN_Q_OVERFLOW`, no watch shortfall |
| G2 Entropy sampling | 6, 7, 8 | **OK** if file events > 0 and ≥20 files sampled with read failures ≤10% (or the event count is <20 and all touched non-zero files were sampled), and baseline-cohort re-sampling stayed within its failure budget. **NOT_APPLICABLE** if there were zero file events, or every touched file was zero-length, or no baseline cohort existed (→ `INSUFFICIENT_ACTIVITY`). **DEGRADED** if non-zero files existed but reads were denied beyond the 10% failure budget, if cohort re-sampling was denied beyond its budget, or if the sample shortfall is not explained by zero-length files or an event count below 20 |
| G3 Filename signatures | 9, 10 | List version loaded and checked; matcher ran over every event |
| G4 Process dynamics | 11–13, 17 | ≥3 successful snapshots, creation/exit accounting consistent. Zero created processes is **not** a G4 failure; it makes feature 13 `NOT_APPLICABLE_NO_PROCESS_ACTIVITY` |
| G5 Command semantics | 14–16 | **OK** if ≥90% of newly created PIDs had readable `cmdline`/`exe` or documented fallback. **NOT_APPLICABLE** when zero PIDs were created (no denominator) |
| G6 Privilege observation | 17 | **OK** if `/proc/<pid>/status` was readable for ≥90% of new PIDs. **NOT_APPLICABLE** when zero PIDs were created (no denominator) |
| G7 Network | 19 | `net_connections` succeeded; explicit "restricted" flag is not healthy |

A `NOT_APPLICABLE` group is never counted as healthy for the purpose of a `SAFE`/`WARNING`
verdict. If no other group is degraded it produces `INSUFFICIENT_ACTIVITY`; if another group is
degraded the observation is `DEGRADED`. Either way the model is not called.

### 5.2 Verdict rules (proposed)

```
if extraction raised / artifact failed to load / schema mismatch / non-finite vector:
    ANALYSIS_ERROR                  # actual failure, never SAFE
elif observation.state == DEGRADED:  # any UNAVAILABLE_* or any group DEGRADED/UNAVAILABLE
    INCONCLUSIVE                    # model NOT invoked; probability None
elif observation.state == INSUFFICIENT_ACTIVITY:  # any NOT_APPLICABLE_* feature/group
    INCONCLUSIVE                    # model NOT invoked; probability None; reason code set
else:                               # MODEL_READY, exactly 20 finite values
    p = calibrated_model.predict_proba(vector)
    if p >= critical_threshold and LBS1_CRITICAL_ENABLED:  CRITICAL
    elif p >= warning_threshold:                            WARNING
    else:                                                   SAFE
```

Consequences, stated plainly:

- **The model is never run on a partially observed vector.** There is no zero-fill path and no
  sentinel value, so an LBS-1 probability is always computed from all 20 real values. This is the
  central fix relative to the Windows-model-on-Linux situation.
- **No activity is not clean.** A quiet window has healthy sensors but no population for features
  6/7/13; it returns `INCONCLUSIVE` with a reason such as `NOT_APPLICABLE_NO_FILE_ACTIVITY` or
  `NOT_APPLICABLE_NO_PROCESS_ACTIVITY`. It is never `SAFE`, and the no-activity reasons are
  distinct from `UNAVAILABLE_PERMISSION`/`UNAVAILABLE_SENSOR` in both the result object and the
  audit record.
- On a restricted system (foreign-user processes unreadable, network sensor blocked), LBS-1 will
  return **INCONCLUSIVE frequently**. That is the intended, honest outcome, not a defect.
- If a future version wants to report an *elevated model score alongside INCONCLUSIVE*, that
  score must be labeled `diagnostic_only=true`, must never raise an alert, and must never be
  rendered as the final assessment. Not part of v1 (see §12, D7).
- `SAFE` requires `MODEL_READY`; low probability alone is insufficient, per the existing project
  invariant that missing/incomplete evidence is never SAFE.
- `ANALYSIS_ERROR` is reserved for real failures. No-activity and degraded telemetry are
  `INCONCLUSIVE`, not errors.

### 5.3 Threshold policy

- Thresholds are **not chosen now**. They will be calibrated on the validation split only,
  after the dataset exists, under a stated objective (e.g. precision ≥ 0.99 on the hard-benign
  set subject to a recall floor), and frozen into the artifact manifest.
- The 0.50 / 0.90 Windows numbers are **not inherited**. They belong to a different model,
  different features, and a different (synthetic) distribution.
- The test split is opened exactly once, after the threshold is frozen. No post-hoc tuning.
- Lowering a threshold to reduce INCONCLUSIVE counts is explicitly forbidden and is not a
  mechanism LBS-1 uses at all — INCONCLUSIVE here is driven by sensor health or by insufficient
  activity, never by score.

---

## 6. Dataset plan

### 6.1 What can and cannot be claimed

Training labels will come from **self-authored, sandboxed ransomware-like behavior
simulations acting on disposable files**. No real ransomware, no malware samples, no
destructive commands against real user data. Any model trained this way may claim:

- validity on the **measured benign workload distribution**, and
- validity on the **simulated attack distribution**.

It may **not** claim real-world ransomware detection accuracy, zero-day coverage, or
enterprise-grade protection. This limitation will appear in the evaluation report, the model
manifest, and the UI's model-details surface.

### 6.2 Benign workload set (target ≥ 30 sessions, ≥ 10 families, ≥ 2,000 **model-ready** windows)

Only `MODEL_READY` windows count toward the volume gates. Windows that are
`INSUFFICIENT_ACTIVITY` or `DEGRADED` are recorded with their status and reported in the dataset
card, but they are never labeled, never used for fitting, and never counted as evidence of
benignness.

| Family | Examples | Why it is included |
|---|---|---|
| Compilation / build | `make`, `cargo build`, `npm install`, `pip install` | High process churn, many short-lived processes, tree-wide writes |
| Version control | `git clone`, `git checkout`, branch switch | Bulk renames and writes — a classic FP trigger |
| Archives | `tar`, `gzip`, `7z a`, `zip -r` | High output entropy |
| Media | photo import/rename, `ffmpeg` encode | Rename storms + high entropy |
| Filesystem maintenance | `rsync` mirroring, `cp -a`, `mv` trees | Mass rename/delete/write |
| Backups | `restic`, `borg`, `duplicity`, `rsync --delete` | Encrypted high-entropy output + bulk I/O |
| Package management | `apt upgrade`, `dnf update` | Privileged processes, setuid/capability file events |
| Databases / logs | SQLite writes, log rotation | Steady write rate, deletes |
| Office / desktop | LibreOffice saves, browser downloads | Ordinary user activity baseline |
| **Hard benign** (explicitly included) | `gpg -c` on a directory, `openssl enc`, 7z AES, VeraCrypt-style containers, video export | Legitimate encryption that *must not* be flagged |
| Idle / light | shell use, editor saves | Low-activity anchor class |

### 6.3 Simulated attack set (target ≥ 60 runs, ≥ 6 families, ≥ 2,000 **model-ready** windows)

A simulation run whose windows are largely `INSUFFICIENT_ACTIVITY` is not evidence of a detection
failure or success; it is reported as non-evaluable, and the run is repeated with a workload that
generates the activity the feature set requires.

All runs execute against a dedicated sandbox directory containing only generated dummy files,
with a hard path guard refusing to operate outside it.

| Family | Behavior (safe simulation) | Stresses |
|---|---|---|
| Bulk overwrite | Random-byte overwrite of sandbox files | Entropy + write rate |
| Extension rewrite | Rename sandbox files to `.locked`-style names + drop note | Rename rate, extension/note features |
| Intermittent | Encrypt every Nth file / first 4 KB only | Low average entropy — expected blind spot |
| Traversal breadth | Touch many directories at low per-directory rate | `distinct_dirs_touched` |
| Command-driven | `dd`/`shred` on sandbox files via a spawned shell | Destructive-command + shell features |
| Destruction | Delete/truncate sandbox files | Delete rate |
| Privilege-adjacent | Copy a setuid-mode file into sandbox, create capability xattr (where permitted) | Feature 18 |
| Near-miss (negative control) | Same I/O volume, no encryption, no rename | Separates volume from malice |

Intensity is varied per family (low/medium/high) so the evaluation can report where the
model degrades rather than hiding it behind one average.

### 6.4 Labeling, splitting, leakage control

- Labels: `BENIGN` / `SIMULATED_RANSOMWARE_LIKE`. Every record carries
  `label_provenance = "SIMULATED"` — a synthetic-flag check that the existing dataset gate
  already enforces must be extended and preserved.
- **Only `MODEL_READY` windows receive labels and enter train/validation/test as model inputs.**
  `INSUFFICIENT_ACTIVITY` and `DEGRADED` windows are retained with their status for coverage
  reporting, but are excluded from fitting, calibration, and classification metrics.
- **Group split by session/run, never by window.** Windows from one run are highly correlated;
  splitting them across train/test would leak the run's identity and inflate scores.
- 70 / 15 / 15 train / validation / test, stratified by family, grouped by run id.
- Target-label boundary: the first and last window of a simulation run are excluded from the
  training labels (ramp-up/tear-down ambiguity), but retained in the test set to measure
  detection latency — if and only if they are `MODEL_READY`. Non-ready boundary windows are
  reported as non-evaluable.
- Deduplication by `(session_id, feature_vector_hash)` before splitting.
- Per-session manifest stored with: OS build, kernel, filesystem type, CPU count, script
  version + hash, seed, target paths (relative only), duration, window count, sensor statuses.
- No file contents, no raw command lines, no usernames, no absolute home paths in stored records.

### 6.5 Size honesty

Window-level sample counts are large but **not independent**. Primary metrics are therefore
reported at both levels:

- **Window-level**: standard classification metrics on held-out `MODEL_READY` windows.
- **Session-level (primary)**: a session is detected if any `MODEL_READY` window crosses the
  threshold; a benign session is a false positive if any window does. This is the operationally
  meaningful number and cannot be inflated by taking many windows from one easy run.
- **Coverage**: for every session and family, report the count and percentage of windows that
  were `MODEL_READY`, `INSUFFICIENT_ACTIVITY`, and `DEGRADED`. A session with zero model-ready
  windows is **non-evaluable** and is reported separately — never counted as a detection, a miss,
  or a false positive. If more than 10% of held-out sessions per class are non-evaluable, the
  evaluation is declared inconclusive and cannot support verdict integration or CRITICAL.

---

## 7. Training and evaluation plan

### 7.1 Candidate models (compared, not assumed)

1. Logistic regression on standardized features — interpretable lower bound.
2. Random forest (bounded depth, balanced class weight) — non-linear, robust to scaling.
3. Histogram gradient boosting — stronger tabular baseline if data volume justifies it.

Selection is by **validation** performance under the threshold policy, not by test performance.
The chosen model is calibrated (Platt or isotonic — decided by validation reliability curves,
not preference) before thresholds are set.

### 7.2 Required reports

- Confusion matrix (window-level and session-level), accuracy, precision, recall, F1,
  FPR, FNR.
- ROC-AUC and **PR-AUC** (class imbalance makes PR-AUC the more informative summary).
- Operating-point table: metrics at several thresholds, with the deployed threshold marked.
- Calibration: reliability curve, Brier score.
- Per-family breakdown for every benign family (including the hard-benign set) and every
  simulation family — no aggregate-only reporting.
- Bootstrap 95% confidence intervals **clustered by session**, since windows are not i.i.d.
- Detection latency within a simulation run (first `MODEL_READY` window until first crossing).
- False positives named by benign family, so the cost is visible.
- Model-ready coverage by class, family, and distro; non-evaluable sessions listed explicitly.
- Environmental performance: CPU %, RSS, added scan latency, inotify overflow count, measured
  independently on native Ubuntu and native Kali. WSL measurements are labeled dev-only and are
  not used in the evaluation report's conclusions.

### 7.3 Explicit failure reporting

If the model cannot separate hard-benign encryption from simulated encryption at acceptable
precision, that is a **finding to publish**, not a reason to drop the hard-benign class, relax
the threshold, or relabel data. The report will state which families are confused and why
(e.g. "legitimate AES archive creation and simulated bulk encryption are feature-identical
at the 15 s window; process ancestry is the only separator, and it is spoofable").

---

## 8. Artifacts, versioning, and isolation

### 8.1 Proposed layout (new directory; nothing existing is overwritten)

```
models/linux_v1/
  model.pkl                 # trained classifier
  calibrator.pkl            # probability calibration
  scaler.pkl                # fitted on Linux training data only
  schema.json               # ordered names, dtypes, units, list_version, window_seconds
  manifest.json             # schema hash, artifact hashes, dataset hash, env, git commit, trained_at
  metrics.json              # full evaluation output incl. per-family tables and CIs
  EVALUATION_REPORT.md      # human-readable, limitations first
```

### 8.2 Guards

- `LINUX_SCHEMA_ID = "LBS-1"`, `PLATFORM_TAG = "linux"` embedded in both schema and model.
- Predictor refuses to load if: platform tag mismatches, feature count ≠ 20, name order
  mismatches, dtype check fails, schema hash mismatches, or any input is non-finite.
  Refusal → `ANALYSIS_ERROR` for artifact/schema failures.
- The predictor also refuses any observation whose state is not `MODEL_READY`, whose vector is
  `None`, or whose feature-status map contains anything other than `DEFINED`. This refusal is a
  guard against caller bugs; the normal path produces `INCONCLUSIVE` before the predictor is
  imported or called.
- Any feature addition/removal/reordering → `LBS-2` + new artifact directory. No in-place edits.
- The Windows loader (`ml/predictor.py`) is **not modified** to know about Linux. Dispatch
  happens above it in `scanner/scan_engine.py`, leaving the Windows call path byte-identical.

### 8.3 Proposed module layout

| Module | Responsibility |
|---|---|
| `scanner/linux_telemetry.py` | inotify watcher, entropy sampler, process/network collectors, sensor-health accounting → `LinuxObservation` |
| `ml/linux_schema.py` | `LBS1_FEATURE_NAMES`, validation, schema hashing |
| `ml/linux_predictor.py` | artifact loading with guards, `predict(vector) → (p, model_version)` |
| `ml/linux_dataset.py` | session JSONL → DataFrame, dedupe, grouped split, provenance checks |
| `ml/linux_train.py` | candidate training, calibration, evaluation, artifact writing (writes only `models/linux_v1/`) |
| `scanner/scan_engine.py` | platform dispatch + LBS-1 verdict mapping (Windows branch untouched) |
| `gui/pages/dashboard.py` | renders the shared result interface; Linux adds coverage/quality detail |

### 8.4 Shared result interface (unchanged externally)

The scan result object continues to expose: `state`, `probability` (nullable for LBS-1),
`threat_level`, `feature_vector`, `feature_names`, `availability`, `missing_features`,
`model_version`, `scan_type`, `duration`, `audit_id`. Linux adds `observation_state`
(`MODEL_READY` / `INSUFFICIENT_ACTIVITY` / `DEGRADED`), `feature_status` (name → status),
`sensor_groups`, and `quality_reasons`. No existing consumer is broken.

---

## 9. Performance budget (to be measured, not assumed)

| Metric | Target | Kill criterion |
|---|---|---|
| Added CPU, steady state | < 3% of one core | > 8% sustained → revisit sampling |
| Added RSS | < 100 MB | > 250 MB → revisit watch/entropy scope |
| Inotify watches | ≤ 20,000 | Exceeded → G1 DEGRADED, not silent truncation |
| Entropy I/O per window | ≤ 4 MB read | Exceeded → reduce sample cap, record it |
| Window overhead | ≤ 250 ms of bookkeeping | — |

These are design budgets. They will be reported as measured values in Phase 4/8, and any
miss will be disclosed rather than adjusted away.

---

## 10. Runtime behavior summary

1. Scan starts → resolve targets → check filesystem types → install watches (record shortfall).
2. Baseline entropy sample taken (§4.4).
3. Window runs: events accumulate; process snapshots at 0.5–1 s; network polled at window end.
4. Window closes → each of the 20 features is computed **with a status**; sensor groups evaluated.
5. If any feature is `NOT_APPLICABLE_*` (and sensors are otherwise healthy) → observation
   `INSUFFICIENT_ACTIVITY` → `INCONCLUSIVE`, no model call, reason codes recorded.
6. Else if any group is degraded or any feature is `UNAVAILABLE_*` → `INCONCLUSIVE`, no model
   call, structured reasons.
7. Else (`MODEL_READY`, exactly 20 finite values) → guarded model load → probability →
   WARNING/SAFE (CRITICAL capped until enabled).
8. Audit record stores: state, observation state, sensor statuses, feature statuses, coverage
   reasons, model version, and (only when the model actually ran) the probability. Windows audit
   schema is extended additively.

---

## 11. Explicit non-claims

- No accuracy figure is claimed in this document.
- LBS-1 is not validated against real ransomware and will not be presented as such.
- Unprivileged visibility blind spots are structural: kernel-level activity, other users'
  processes under `hidepid`, pre-window encryption, inotify overflow, and attacks that stop or
  kill the collector are all out of view.
- A model trained on simulations can be trivially defeated by an adversary who knows the
  simulation's signature (rate, extension list, command set). This is a prototype, not a shield.
- The Windows model's 95.67% synthetic benchmark figure does not transfer to Linux and is not
  reused here in any form.
- Network feature 19 measures *breadth of external connections*, not maliciousness; browsers
  and package managers will produce non-zero values routinely.
- A window with no file or process activity is **not assessed**. It returns `INCONCLUSIVE`, not
  `SAFE`. LBS-1 makes no claim about a host during periods it could not observe meaningfully,
  including activity that occurred before the window opened.

---

## 12. Decisions (resolved 2026-10-30)

| # | Decision | Resolution |
|---|---|---|
| D1 | Approve the 20-feature LBS-1 set | **Approved as proposed** |
| D2 | Accept simulation-only training with its stated claim limits | **Approved** — empirical benign + path-guarded simulations only; limitations published |
| D3 | Observation window | **15 s default** (10–60 s), frozen per model version |
| D4 | Entropy policy | **No extension filtering**; hard-benign class handles false-positive pressure |
| D5 | Threshold policy | **Calibrate on validation only**; never inherit 0.50/0.90; freeze before test |
| D6 | Privileged sensors in v1 | **Excluded** (auditd, eBPF, fanotify) |
| D7 | `diagnostic_only` probability on incomplete telemetry | **Not allowed**; model is not invoked |
| D8 | Artifact location | **`models/linux_v1/`**; Windows artifacts untouched |
| D9 | CRITICAL in v1 | **Disabled initially** — SAFE/WARNING/INCONCLUSIVE only; enable only after the predefined independent criteria in the decision record §5 are met and separately approved |
| D14 | Representation of no-activity features | **Status layer, no numeric sentinel**: `DEFINED` or an explicit `NOT_APPLICABLE_*`/`UNAVAILABLE_*` status. Undefined features never become 0, -1, a mean, or a previous value |
| D15 | Feature 8 denominator | **Fixed baseline cohort re-sampled in full**; `0.0` means “0 of N re-sampled files increased”, a measured value. `NOT_APPLICABLE_*` only when the cohort is absent or entirely lost |
| D16 | Features 6/7 sample set | **Event-touched files only**; no file activity → `NOT_APPLICABLE_NO_FILE_ACTIVITY` → `INCONCLUSIVE`. A standing-corpus variant was rejected as non-behavioral and false-positive-prone |
| D17 | Feature 13 when no processes are created | **`NOT_APPLICABLE_NO_PROCESS_ACTIVITY` → `INCONCLUSIVE`**; not converted to 0.0 and not redefined as a count |

---

## 13. What happens after approval

Phase 2 (collector) → Phase 3 (schema module + guarded artifacts, still untrained) → Phase 4
(dataset collection, training, held-out evaluation) → Phase 5/6 (verdict integration, platform
split) → Phase 7 (full Windows + Linux regression) → Phase 8 (reports, hashes, Linux AppImage
in a separate output directory). Each phase reports measured results, including failures.

Until approval, no code is written, no dataset is collected, and no model is trained.

---

## 14. Clarification log

### 2026-10-30 — definedness layer (reviewer-requested)

- Added the feature-status layer (§3.1). No undefined value is ever encoded as a number; the
  vector is either exactly 20 finite values (`MODEL_READY`) or absent.
- **Feature 8** now divides by the full re-sampled baseline cohort, not only files whose metadata
  changed. This removes the `0/0` case when nothing changed and catches in-place encryption that
  preserves size and timestamps. `0.0` is a real measurement over the cohort.
- **Features 6/7** remain event-touched. A window with no file activity is
  `NOT_APPLICABLE_NO_FILE_ACTIVITY` → `INCONCLUSIVE`; a standing-corpus alternative was rejected
  because it would treat a media library as behavioral evidence.
- **Feature 13** remains a ratio; zero created processes is
  `NOT_APPLICABLE_NO_PROCESS_ACTIVITY` → `INCONCLUSIVE`, never `0.0`.
- **Groups G5/G6** are `NOT_APPLICABLE` when zero PIDs were created, so their 90% resolution rates
  have no zero-denominator case. A `NOT_APPLICABLE` group is not a sensor failure; with no other
  degradation it yields `INSUFFICIENT_ACTIVITY`.
- Added the **definedness matrix** (§3.1) for the only four population-based features. The
  sixteen count/rate features remain `DEFINED` at a measured `0` when no matching event occurred;
  the two are not conflated.
- Added the **inference invariant** (§3.1): `features` is non-`None` iff `MODEL_READY`; every
  other state has `features=None` and cannot invoke the predictor.
- Dataset and evaluation now count only `MODEL_READY` windows; non-ready windows are reported as
  coverage, and sessions with none are non-evaluable rather than detections or false positives.
- Feature count, names, and order are unchanged: still 20. This clarification is subject to the
  same G1 review and does not authorize implementation.
