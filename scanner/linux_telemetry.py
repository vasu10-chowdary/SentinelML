"""LBS-1 telemetry orchestrator.

Assembles the 20-feature observation from collector results. The vector exists only when every
sensor group is OK and every feature is DEFINED; otherwise `features` is None and the reason is
carried explicitly. No numeric sentinel is ever produced.
"""

from __future__ import annotations

import os
import posixpath
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

import numpy as np

from scanner.linux_entropy import (
    BaselineCohort,
    CohortResult,
    EventEntropyResult,
    STATUS_DEFINED,
    STATUS_NO_BASELINE_COHORT,
    STATUS_NO_FILE_ACTIVITY,
    STATUS_NO_PROCESS_ACTIVITY,
    STATUS_NO_SAMPLEABLE_FILES,
    STATUS_UNAVAILABLE_PERMISSION,
    STATUS_UNAVAILABLE_SENSOR,
    sample_event_files,
)
from scanner.linux_fs_types import classify_targets, read_mountinfo
from scanner.linux_inotify import (
    LIST_VERSION,
    DEFAULT_PRUNE,
    FileEventSummary,
    InotifyUnavailable,
    InotifyWatcher,
    WindowAccumulator,
)
from scanner.linux_processes import (
    NetworkResult,
    ProcessSnapshotSession,
    ProcessWindowResult,
    STATUS_DEGRADED,
    STATUS_NOT_APPLICABLE,
    STATUS_OK,
    analyze_process_windows,
    collect_network,
)

# Canonical order and spelling are mirrored in ml/linux_schema.py; Stage B's
# schema-contract test asserts the two tuples are identical.
LBS1_FEATURE_NAMES: tuple[str, ...] = (
    "file_mod_rate",
    "file_rename_rate",
    "file_delete_rate",
    "files_modified_count",
    "files_renamed_count",
    "distinct_dirs_touched",
    "avg_shannon_entropy",
    "high_entropy_file_ratio",
    "entropy_increase_ratio",
    "ransom_extension_match_count",
    "ransom_note_match_count",
    "process_create_rate",
    "process_exit_rate",
    "short_lived_process_ratio",
    "destructive_command_count",
    "shell_spawn_count",
    "temp_exec_count",
    "privileged_process_count",
    "setuid_cap_file_event_count",
    "unique_external_ip_count",
)

FEATURE_COUNT = len(LBS1_FEATURE_NAMES)

STATE_MODEL_READY = "MODEL_READY"
STATE_INSUFFICIENT_ACTIVITY = "INSUFFICIENT_ACTIVITY"
STATE_DEGRADED = "DEGRADED"

GROUP_OK = "OK"
GROUP_DEGRADED = "DEGRADED"
GROUP_UNAVAILABLE = "UNAVAILABLE"
GROUP_NOT_APPLICABLE = "NOT_APPLICABLE"

SENSOR_GROUPS = ("G1", "G2", "G3", "G4", "G5", "G6", "G7")

DEFAULT_WINDOW_SECONDS = 15.0
MIN_WINDOW_SECONDS = 10.0
MAX_WINDOW_SECONDS = 60.0
DEFAULT_SNAPSHOT_INTERVAL = 0.5
MIN_SNAPSHOTS_REQUIRED = 3
NOISE_DIRS = frozenset(DEFAULT_PRUNE)
COLLECTOR_VERSION = "lbs1-collector-1.0.0"

# Features covered by each sensor group; used to mark values unavailable on sensor failure.
GROUP_FEATURES: dict[str, tuple[str, ...]] = {
    "G1": tuple(LBS1_FEATURE_NAMES[index] for index in (0, 1, 2, 3, 4, 5, 9, 10, 18)),
    "G2": tuple(LBS1_FEATURE_NAMES[index] for index in (6, 7, 8)),
    "G3": tuple(LBS1_FEATURE_NAMES[index] for index in (9, 10)),
    "G4": tuple(LBS1_FEATURE_NAMES[index] for index in (11, 12, 13, 17)),
    "G5": tuple(LBS1_FEATURE_NAMES[index] for index in (14, 15, 16)),
    "G6": (LBS1_FEATURE_NAMES[17],),
    "G7": (LBS1_FEATURE_NAMES[19],),
}


class LinuxCollectionUnsupported(RuntimeError):
    """Raised when collection is attempted on a non-Linux platform."""


class ObservationContractError(RuntimeError):
    """Raised if assembly would violate the 20-value MODEL_READY contract."""


@dataclass
class LinuxObservation:
    features: Optional[np.ndarray]
    feature_values: dict[str, Optional[float]]
    feature_status: dict[str, str]
    observation_state: str
    sensor_groups: dict[str, str]
    reasons: tuple[str, ...] = ()
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    overflow: bool = False
    filesystem_types: tuple[str, ...] = ()
    events_processed: int = 0
    platform: str = "linux"
    collector_version: str = COLLECTOR_VERSION
    list_version: str = LIST_VERSION

    def __post_init__(self) -> None:
        if self.features is not None:
            if self.observation_state != STATE_MODEL_READY:
                raise ObservationContractError("vector supplied for a non-MODEL_READY observation")
            if self.features.shape != (FEATURE_COUNT,):
                raise ObservationContractError(f"vector shape {self.features.shape} != ({FEATURE_COUNT},)")
            if self.features.dtype != np.float64:
                raise ObservationContractError(f"vector dtype {self.features.dtype} != float64")


@dataclass
class CollectorInputs:
    file_summary: FileEventSummary
    entropy: EventEntropyResult
    cohort: CohortResult
    processes: ProcessWindowResult
    network: NetworkResult
    fs_supported: bool
    filesystem_types: Sequence[str]
    watch_count: int
    watch_shortfall: int = 0
    overflow: bool = False
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    events_processed: int = 0
    fs_reasons: Sequence[str] = ()
    filename_matcher_error: Optional[str] = None
    platform: str = "linux"


def _group_g1(inputs: CollectorInputs) -> tuple[str, list[str]]:
    if not inputs.fs_supported:
        return GROUP_DEGRADED, list(inputs.fs_reasons) or ["unsupported filesystem"]
    if inputs.watch_count < 1:
        return GROUP_DEGRADED, ["no inotify watch installed"]
    if inputs.watch_shortfall:
        return GROUP_DEGRADED, [f"watch shortfall: {inputs.watch_shortfall} directories"]
    if inputs.overflow:
        return GROUP_DEGRADED, ["IN_Q_OVERFLOW: filesystem counts invalid"]
    return GROUP_OK, []


def _group_g2(inputs: CollectorInputs) -> tuple[str, list[str]]:
    statuses = (inputs.entropy.status, inputs.cohort.status)
    reasons = [status for status in statuses if status != STATUS_DEFINED]
    if any(status in (STATUS_UNAVAILABLE_PERMISSION, STATUS_UNAVAILABLE_SENSOR) for status in statuses):
        return GROUP_DEGRADED, reasons
    if any(status != STATUS_DEFINED for status in statuses):
        return GROUP_NOT_APPLICABLE, reasons
    return GROUP_OK, []


def _group_g3(inputs: CollectorInputs) -> tuple[str, list[str]]:
    if inputs.filename_matcher_error:
        return GROUP_DEGRADED, [inputs.filename_matcher_error]
    return GROUP_OK, []


def _group_g4(inputs: CollectorInputs) -> tuple[str, list[str]]:
    return inputs.processes.g4_status, list(inputs.processes.notes)


def _group_g7(inputs: CollectorInputs) -> tuple[str, list[str]]:
    return inputs.network.status, [inputs.network.error] if inputs.network.error else []


def _feature_statuses(inputs: CollectorInputs) -> tuple[dict[str, Optional[float]], dict[str, str]]:
    summary = inputs.file_summary
    seconds = inputs.window_seconds
    values: dict[str, Optional[float]] = {}
    status: dict[str, str] = {name: STATUS_DEFINED for name in LBS1_FEATURE_NAMES}

    values["file_mod_rate"] = summary.write_events / seconds
    values["file_rename_rate"] = summary.rename_events / seconds
    values["file_delete_rate"] = summary.delete_events / seconds
    values["files_modified_count"] = float(len(summary.modified_paths))
    values["files_renamed_count"] = float(len(summary.renamed_paths))
    values["distinct_dirs_touched"] = float(len(summary.dirs_touched))
    values["ransom_extension_match_count"] = float(summary.ransom_extension_match_count)
    values["ransom_note_match_count"] = float(summary.ransom_note_match_count)
    values["process_create_rate"] = inputs.processes.created_count / seconds
    values["process_exit_rate"] = inputs.processes.exited_count / seconds
    values["destructive_command_count"] = float(inputs.processes.destructive_count)
    values["shell_spawn_count"] = float(inputs.processes.shell_spawn_count)
    values["temp_exec_count"] = float(inputs.processes.temp_exec_count)
    values["privileged_process_count"] = float(inputs.processes.privileged_count)
    values["setuid_cap_file_event_count"] = float(summary.setuid_event_count)
    values["unique_external_ip_count"] = float(inputs.network.unique_external_ip_count)

    status["avg_shannon_entropy"] = inputs.entropy.status
    status["high_entropy_file_ratio"] = inputs.entropy.status
    values["avg_shannon_entropy"] = inputs.entropy.mean_entropy if inputs.entropy.status == STATUS_DEFINED else None
    values["high_entropy_file_ratio"] = (
        inputs.entropy.high_entropy_ratio if inputs.entropy.status == STATUS_DEFINED else None
    )

    status["entropy_increase_ratio"] = inputs.cohort.status
    values["entropy_increase_ratio"] = inputs.cohort.value if inputs.cohort.status == STATUS_DEFINED else None

    if inputs.processes.created_count == 0:
        status["short_lived_process_ratio"] = STATUS_NO_PROCESS_ACTIVITY
        values["short_lived_process_ratio"] = None
    else:
        status["short_lived_process_ratio"] = STATUS_DEFINED
        values["short_lived_process_ratio"] = inputs.processes.short_lived_ratio
        if values["short_lived_process_ratio"] is None:
            raise ObservationContractError("created process count > 0 but ratio is undefined")
    return values, status


def _apply_sensor_failures(
    groups: dict[str, str],
    values: dict[str, Optional[float]],
    status: dict[str, str],
    reasons: list[str],
) -> None:
    for group, group_status in groups.items():
        if group_status in (GROUP_DEGRADED, GROUP_UNAVAILABLE):
            for name in GROUP_FEATURES[group]:
                # Preserve a more specific status already assigned (no-activity or permission).
                if status[name] != STATUS_DEFINED:
                    continue
                status[name] = STATUS_UNAVAILABLE_SENSOR
                values[name] = None
            reasons.append(f"{group}:{group_status}")


def assemble_observation(inputs: CollectorInputs) -> LinuxObservation:
    if inputs.window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    values, status = _feature_statuses(inputs)
    groups: dict[str, str] = {}
    reasons: list[str] = []

    groups["G1"], g1_reasons = _group_g1(inputs)
    groups["G2"], g2_reasons = _group_g2(inputs)
    groups["G3"], g3_reasons = _group_g3(inputs)
    groups["G4"], g4_reasons = _group_g4(inputs)
    groups["G5"] = inputs.processes.g5_status
    groups["G6"] = inputs.processes.g6_status
    groups["G7"], g7_reasons = _group_g7(inputs)
    for prefix, items in (
        ("G1", g1_reasons),
        ("G2", g2_reasons),
        ("G3", g3_reasons),
        ("G4", g4_reasons),
        ("G5", [] if groups["G5"] == GROUP_OK else ["zero created processes" if groups["G5"] == GROUP_NOT_APPLICABLE else "low resolution"]),
        ("G6", [] if groups["G6"] == GROUP_OK else ["zero created processes" if groups["G6"] == GROUP_NOT_APPLICABLE else "low status readability"]),
        ("G7", g7_reasons),
    ):
        for item in items:
            reasons.append(f"{prefix}:{item}")

    _apply_sensor_failures(groups, values, status, reasons)
    for name in LBS1_FEATURE_NAMES:
        if status[name] != STATUS_DEFINED:
            reasons.append(f"{name}:{status[name]}")

    unavailable = any(value in (STATUS_UNAVAILABLE_PERMISSION, STATUS_UNAVAILABLE_SENSOR) for value in status.values())
    degraded_group = any(value in (GROUP_DEGRADED, GROUP_UNAVAILABLE) for value in groups.values())
    not_applicable = any(value != STATUS_DEFINED for value in status.values()) or any(
        value == GROUP_NOT_APPLICABLE for value in groups.values()
    )

    if unavailable or degraded_group:
        state = STATE_DEGRADED
    elif not_applicable:
        state = STATE_INSUFFICIENT_ACTIVITY
    else:
        state = STATE_MODEL_READY

    vector: Optional[np.ndarray] = None
    if state == STATE_MODEL_READY:
        ordered = []
        for name in LBS1_FEATURE_NAMES:
            value = values[name]
            if value is None:
                raise ObservationContractError(f"{name} is DEFINED but has no value")
            if not np.isfinite(value) or value < 0:
                raise ObservationContractError(f"{name} has invalid value {value!r}")
            ordered.append(float(value))
        vector = np.asarray(ordered, dtype=np.float64)

    for name in LBS1_FEATURE_NAMES:
        if status[name] == STATUS_DEFINED:
            value = values[name]
            if value is None or not np.isfinite(value) or value < 0:
                raise ObservationContractError(f"{name} status DEFINED but value {value!r}")

    return LinuxObservation(
        features=vector,
        feature_values=dict(values),
        feature_status=dict(status),
        observation_state=state,
        sensor_groups=groups,
        reasons=tuple(reasons),
        window_seconds=inputs.window_seconds,
        overflow=inputs.overflow,
        filesystem_types=tuple(inputs.filesystem_types),
        events_processed=inputs.events_processed,
        platform=inputs.platform,
    )


def _default_targets() -> list[str]:
    home = os.path.expanduser("~")
    candidates = [
        "Documents",
        "Desktop",
        "Downloads",
        "Pictures",
        "Videos",
        "Music",
        "Public",
        "Templates",
    ]
    targets = [os.path.join(home, name) for name in candidates]
    return [path for path in targets if os.path.isdir(path)]


def _list_pre_existing_files(targets: Sequence[str], limit: int = 500) -> list[str]:
    files: list[str] = []
    for target in targets:
        for root, dirnames, filenames in os.walk(target, followlinks=False):
            dirnames[:] = [name for name in dirnames if name not in NOISE_DIRS]
            for filename in filenames:
                files.append(os.path.join(root, filename))
                if len(files) >= limit:
                    return files
    return files


def _mode_lookup(path: str) -> Optional[int]:
    try:
        return os.stat(path).st_mode
    except OSError:
        return None


def _xattr_lookup(path: str) -> bool:
    try:
        return bool(os.getxattr(path, "security.capability"))
    except (OSError, AttributeError):
        return False


def collect_observation(
    targets: Optional[Sequence[str]] = None,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    snapshot_interval: float = DEFAULT_SNAPSHOT_INTERVAL,
    max_watches: int = 20_000,
) -> LinuxObservation:
    """Collect one unprivileged observation. Refuses to run on non-Linux platforms."""
    if not hasattr(os, "getxattr"):
        raise LinuxCollectionUnsupported("LBS-1 collection requires Linux (inotify/procfs)")
    if window_seconds <= 0 or window_seconds > MAX_WINDOW_SECONDS:
        raise ValueError(f"window_seconds must be in (0, {MAX_WINDOW_SECONDS}]")

    roots = list(targets) if targets is not None else _default_targets()
    if not roots:
        raise ValueError("no collection targets available")

    mounts = read_mountinfo()
    fs_supported, fs_reasons, fs_types = classify_targets(roots, mounts)

    cohort = BaselineCohort.capture(_list_pre_existing_files(roots))

    try:
        watcher = InotifyWatcher(max_watches=max_watches)
    except InotifyUnavailable:
        raise

    accumulator = WindowAccumulator()
    session = ProcessSnapshotSession()
    snapshots = []
    try:
        total_watches = 0
        total_shortfall = 0
        watch_errors: list[str] = []
        for root in roots:
            result = watcher.add_tree(root)
            total_watches += result.watches
            total_shortfall += result.shortfall
            watch_errors.extend(result.errors)

        start = time.monotonic()
        next_snapshot = start
        while True:
            now = time.monotonic()
            elapsed = now - start
            if elapsed >= window_seconds:
                break
            if now >= next_snapshot:
                snapshots.append(session.snapshot())
                next_snapshot = now + snapshot_interval
            for event in watcher.poll(timeout=min(0.05, max(0.0, window_seconds - elapsed))):
                accumulator.consume([(event, watcher.resolve(event))])
        for event in watcher.read_available():
            accumulator.consume([(event, watcher.resolve(event))])
    finally:
        watcher.close()

    if not snapshots:
        snapshots.append(session.full_snapshot())

    summary = accumulator.finalize(mode_lookup=_mode_lookup, xattr_lookup=_xattr_lookup)
    summary.overflow = summary.overflow or watcher.overflowed

    entropy = sample_event_files(summary.event_touched_paths, event_count=summary.write_events)
    cohort_result = cohort.measure()
    processes = analyze_process_windows(snapshots, window_seconds)
    network = collect_network()

    inputs = CollectorInputs(
        file_summary=summary,
        entropy=entropy,
        cohort=cohort_result,
        processes=processes,
        network=network,
        fs_supported=fs_supported and not watch_errors,
        filesystem_types=sorted(fs_types),
        watch_count=total_watches,
        watch_shortfall=total_shortfall,
        overflow=summary.overflow,
        window_seconds=window_seconds,
        events_processed=summary.write_events + summary.rename_events + summary.delete_events,
        fs_reasons=list(fs_reasons) + watch_errors,
    )
    return assemble_observation(inputs)
