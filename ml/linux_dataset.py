"""LBS-1 dataset loading, validation, grouped splitting, and volume gates.

Stage B consumer of the LBS-1 collection layout:

    data/linux_lbs1/
      benign/<session_id>/manifest.json + observations.jsonl
      simulated/<run_id>/manifest.json + observations.jsonl

Rules enforced here:

* only `MODEL_READY` windows are model inputs; every other window is retained as
  provenance/coverage and counted, never imputed;
* `HAND_AUTHORED_VECTOR` data is rejected outright;
* WSL is dev-only and never enters a dataset;
* splits are grouped by session, so no session crosses train/validation/test;
* a split directory is write-once (`split_manifest.json` is the lock).

This module performs no fitting and writes nothing unless `write_splits` is called.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

import numpy as np

from ml import linux_schema as schema

SOURCE_BENIGN = "BENIGN_SESSION"
SOURCE_SIMULATED = "SIMULATED_ATTACK"
SOURCE_HAND_AUTHORED = "HAND_AUTHORED_VECTOR"

DISTRO_KALI = "kali"
DISTRO_UBUNTU = "ubuntu"
VALID_DISTROS = (DISTRO_KALI, DISTRO_UBUNTU)

LABEL_BENIGN = 0
LABEL_ATTACK = 1

HARD_BENIGN_FAMILY = "hard_benign"

MANIFEST_FILENAME = "manifest.json"
OBSERVATIONS_FILENAME = "observations.jsonl"
SPLIT_MANIFEST_FILENAME = "split_manifest.json"

SPLIT_NAMES = ("train", "val", "test")
SPLIT_RATIOS = {"train": 0.70, "val": 0.15, "test": 0.15}

MANIFEST_REQUIRED_FIELDS = (
    "session_id",
    "source_type",
    "label",
    "family",
    "distro",
    "seed",
    "collector_version",
    "list_version",
    "window_seconds",
)


class DatasetError(ValueError):
    """Malformed dataset, manifest, or observation row."""


class ManifestError(DatasetError):
    """Manifest violates the collection contract."""


class SplitLockedError(DatasetError):
    """A split directory was already written; re-splitting is refused."""


@dataclass(frozen=True)
class SessionManifest:
    session_id: str
    source_type: str
    label: int
    family: str
    distro: str
    seed: int
    collector_version: str
    list_version: str
    window_seconds: float
    hard_benign: bool = False
    intensity: Optional[str] = None
    path: Optional[Path] = None

    @property
    def is_benign(self) -> bool:
        return self.source_type == SOURCE_BENIGN


@dataclass
class ObservationRow:
    session_id: str
    window_index: int
    source_type: str
    label: int
    family: str
    distro: str
    observation_state: str
    feature_values: dict[str, Optional[float]]
    feature_status: dict[str, str]
    sensor_groups: dict[str, str]
    reasons: tuple[str, ...] = ()
    feature_vector: Optional[np.ndarray] = None
    observation_id: Optional[str] = None

    @property
    def model_ready(self) -> bool:
        return self.observation_state == schema.STATE_MODEL_READY

    def identity(self) -> str:
        return self.observation_id or f"{self.session_id}:{self.window_index}"

    def fingerprint(self) -> str:
        payload = {
            "session_id": self.session_id,
            "window_index": self.window_index,
            "source_type": self.source_type,
            "label": self.label,
            "observation_state": self.observation_state,
            "feature_values": self.feature_values,
            "feature_status": self.feature_status,
        }
        return hashlib.sha256(schema.canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass
class Coverage:
    total_windows: int = 0
    model_ready_windows: int = 0
    insufficient_activity_windows: int = 0
    degraded_windows: int = 0
    by_family: dict[str, Counter] = field(default_factory=dict)
    by_distro: dict[str, Counter] = field(default_factory=dict)
    by_source: dict[str, Counter] = field(default_factory=dict)
    reason_counts: Counter = field(default_factory=Counter)

    @property
    def non_model_ready_windows(self) -> int:
        return self.total_windows - self.model_ready_windows

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_windows": self.total_windows,
            "model_ready_windows": self.model_ready_windows,
            "non_model_ready_windows": self.non_model_ready_windows,
            "insufficient_activity_windows": self.insufficient_activity_windows,
            "degraded_windows": self.degraded_windows,
            "by_family": {key: dict(value) for key, value in sorted(self.by_family.items())},
            "by_distro": {key: dict(value) for key, value in sorted(self.by_distro.items())},
            "by_source": {key: dict(value) for key, value in sorted(self.by_source.items())},
            "reason_counts": dict(sorted(self.reason_counts.items())),
        }


@dataclass
class DatasetResult:
    root: Optional[Path]
    sessions: list[SessionManifest]
    rows: list[ObservationRow]
    coverage: Coverage
    dataset_sha256: str
    duplicates_removed: int = 0

    @property
    def model_ready_rows(self) -> list[ObservationRow]:
        return [row for row in self.rows if row.model_ready]

    def session_ids(self) -> list[str]:
        return [session.session_id for session in self.sessions]


# --------------------------------------------------------------------- manifests


def load_manifest(path: Path) -> SessionManifest:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"{path}: unreadable manifest: {exc}") from exc
    if not isinstance(payload, dict):
        raise ManifestError(f"{path}: manifest is not a JSON object")

    missing = [name for name in MANIFEST_REQUIRED_FIELDS if name not in payload]
    if missing:
        raise ManifestError(f"{path}: manifest missing fields {missing}")

    source_type = payload["source_type"]
    if source_type == SOURCE_HAND_AUTHORED:
        raise ManifestError(f"{path}: HAND_AUTHORED_VECTOR is not permitted in a dataset")
    if source_type not in (SOURCE_BENIGN, SOURCE_SIMULATED):
        raise ManifestError(f"{path}: unknown source_type {source_type!r}")

    distro = payload["distro"]
    if distro == "wsl":
        raise ManifestError(f"{path}: WSL is dev-only (DEV_ONLY_WSL) and never enters a dataset")
    if distro not in VALID_DISTROS:
        raise ManifestError(f"{path}: unsupported distro {distro!r}")

    family = payload["family"]
    if not isinstance(family, str) or not family.strip():
        raise ManifestError(f"{path}: family must be a non-empty string")

    label = payload["label"]
    if isinstance(label, bool) or label not in (LABEL_BENIGN, LABEL_ATTACK):
        raise ManifestError(f"{path}: label must be 0 or 1")
    expected_label = LABEL_BENIGN if source_type == SOURCE_BENIGN else LABEL_ATTACK
    if label != expected_label:
        raise ManifestError(
            f"{path}: label {label} disagrees with source_type {source_type}"
        )

    seed = payload["seed"]
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ManifestError(f"{path}: seed must be an integer")

    window = payload["window_seconds"]
    if not isinstance(window, (int, float)) or isinstance(window, bool):
        raise ManifestError(f"{path}: window_seconds must be numeric")
    if not (0.0 < float(window) <= schema.WINDOW_SECONDS_MAX):
        raise ManifestError(f"{path}: window_seconds {window!r} outside (0, {schema.WINDOW_SECONDS_MAX}]")

    session_id = payload["session_id"]
    if not isinstance(session_id, str) or not session_id:
        raise ManifestError(f"{path}: session_id must be a non-empty string")

    hard_benign = bool(payload.get("hard_benign", False)) or family == HARD_BENIGN_FAMILY
    intensity = payload.get("intensity")
    if intensity is not None and not isinstance(intensity, str):
        raise ManifestError(f"{path}: intensity must be a string when present")

    return SessionManifest(
        session_id=session_id,
        source_type=source_type,
        label=int(label),
        family=family,
        distro=distro,
        seed=seed,
        collector_version=str(payload["collector_version"]),
        list_version=str(payload["list_version"]),
        window_seconds=float(window),
        hard_benign=hard_benign,
        intensity=intensity,
        path=path.parent,
    )


def _parse_row(path: Path, line_number: int, payload: Any, manifest: SessionManifest) -> ObservationRow:
    where = f"{path}:{line_number}"
    if not isinstance(payload, dict):
        raise DatasetError(f"{where}: observation is not a JSON object")
    for key in ("window_index", "observation_state", "feature_values", "feature_status", "sensor_groups"):
        if key not in payload:
            raise DatasetError(f"{where}: missing {key!r}")

    state = payload["observation_state"]
    if state not in schema.OBSERVATION_STATES:
        raise DatasetError(f"{where}: unknown observation_state {state!r}")

    feature_status = payload["feature_status"]
    sensor_groups = payload["sensor_groups"]
    try:
        schema.validate_feature_status(feature_status)
        schema.validate_sensor_groups(sensor_groups)
        derived = schema.observation_state_from(feature_status, sensor_groups)
    except schema.LinuxSchemaError as exc:
        raise DatasetError(f"{where}: {exc}") from exc
    if derived != state:
        raise DatasetError(f"{where}: state {state!r} disagrees with status maps ({derived!r})")

    feature_values = payload["feature_values"]
    if not isinstance(feature_values, Mapping) or set(feature_values) != set(schema.LBS1_FEATURE_NAMES):
        raise DatasetError(f"{where}: feature_values keys do not match the schema")

    vector: Optional[np.ndarray] = None
    if state == schema.STATE_MODEL_READY:
        try:
            vector = schema.build_vector(feature_values, feature_status)
        except schema.LinuxSchemaError as exc:
            raise DatasetError(f"{where}: {exc}") from exc
    else:
        for name in schema.LBS1_FEATURE_NAMES:
            if feature_status[name] != schema.STATUS_DEFINED and feature_values[name] is not None:
                raise DatasetError(f"{where}: {name} is {feature_status[name]} but carries a value")

    window_index = payload["window_index"]
    if isinstance(window_index, bool) or not isinstance(window_index, int) or window_index < 0:
        raise DatasetError(f"{where}: window_index must be a non-negative integer")

    for key, expected in (("source_type", manifest.source_type), ("family", manifest.family), ("distro", manifest.distro)):
        if key in payload and payload[key] != expected:
            raise DatasetError(f"{where}: {key} {payload[key]!r} disagrees with manifest {expected!r}")

    reasons = payload.get("reasons", ())
    if isinstance(reasons, str):
        reasons = (reasons,)
    if not isinstance(reasons, (list, tuple)) or not all(isinstance(item, str) for item in reasons):
        raise DatasetError(f"{where}: reasons must be a list of strings")

    observation_id = payload.get("observation_id")
    if observation_id is not None and not isinstance(observation_id, str):
        raise DatasetError(f"{where}: observation_id must be a string")

    return ObservationRow(
        session_id=manifest.session_id,
        window_index=window_index,
        source_type=manifest.source_type,
        label=manifest.label,
        family=manifest.family,
        distro=manifest.distro,
        observation_state=state,
        feature_values=dict(feature_values),
        feature_status=dict(feature_status),
        sensor_groups=dict(sensor_groups),
        reasons=tuple(reasons),
        feature_vector=vector,
        observation_id=observation_id,
    )


def load_session(session_dir: Path) -> tuple[SessionManifest, list[ObservationRow]]:
    manifest = load_manifest(session_dir / MANIFEST_FILENAME)
    observations = session_dir / OBSERVATIONS_FILENAME
    if not observations.is_file():
        raise DatasetError(f"{session_dir}: missing {OBSERVATIONS_FILENAME}")

    rows: list[ObservationRow] = []
    seen_indices: set[int] = set()
    with open(observations, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetError(f"{observations}:{line_number}: invalid JSON: {exc}") from exc
            row = _parse_row(observations, line_number, payload, manifest)
            if row.window_index in seen_indices:
                raise DatasetError(f"{observations}:{line_number}: duplicate window_index {row.window_index}")
            seen_indices.add(row.window_index)
            rows.append(row)
    return manifest, rows


def discover_sessions(root: Path) -> list[Path]:
    root = Path(root)
    if not root.is_dir():
        raise DatasetError(f"dataset root not found: {root}")
    directories: list[Path] = []
    for group in (SOURCE_BENIGN, SOURCE_SIMULATED):
        group_dir = root / ("benign" if group == SOURCE_BENIGN else "simulated")
        if not group_dir.is_dir():
            continue
        for child in sorted(group_dir.iterdir()):
            if child.is_dir() and (child / MANIFEST_FILENAME).is_file():
                directories.append(child)
    return directories


def compute_dataset_sha256(rows: Sequence[ObservationRow]) -> str:
    digests = sorted(row.fingerprint() for row in rows)
    return hashlib.sha256("".join(digests).encode("utf-8")).hexdigest()


def _build_coverage(rows: Sequence[ObservationRow]) -> Coverage:
    coverage = Coverage()
    for row in rows:
        coverage.total_windows += 1
        if row.observation_state == schema.STATE_MODEL_READY:
            coverage.model_ready_windows += 1
        elif row.observation_state == schema.STATE_INSUFFICIENT_ACTIVITY:
            coverage.insufficient_activity_windows += 1
        else:
            coverage.degraded_windows += 1
        coverage.by_family.setdefault(row.family, Counter())[row.observation_state] += 1
        coverage.by_distro.setdefault(row.distro, Counter())[row.observation_state] += 1
        coverage.by_source.setdefault(row.source_type, Counter())[row.observation_state] += 1
        for reason in row.reasons:
            coverage.reason_counts[reason] += 1
    return coverage


def dataset_from_rows(
    sessions: Sequence[SessionManifest],
    rows: Sequence[ObservationRow],
    root: Optional[Path] = None,
    duplicates_removed: int = 0,
) -> DatasetResult:
    """Assemble a `DatasetResult` from already-validated in-memory sessions and rows."""
    ordered_rows = sorted(rows, key=lambda row: (row.session_id, row.window_index))
    ordered_sessions = sorted(sessions, key=lambda session: session.session_id)
    return DatasetResult(
        root=root,
        sessions=list(ordered_sessions),
        rows=list(ordered_rows),
        coverage=_build_coverage(ordered_rows),
        dataset_sha256=compute_dataset_sha256(ordered_rows),
        duplicates_removed=duplicates_removed,
    )


def load_dataset(root: Path) -> DatasetResult:
    directories = discover_sessions(root)
    sessions: list[SessionManifest] = []
    rows: list[ObservationRow] = []
    seen_sessions: set[str] = set()
    seen_identities: set[str] = set()
    duplicates = 0

    for directory in directories:
        manifest, session_rows = load_session(directory)
        if manifest.session_id in seen_sessions:
            raise DatasetError(f"duplicate session_id {manifest.session_id!r}")
        seen_sessions.add(manifest.session_id)
        sessions.append(manifest)
        for row in session_rows:
            identity = row.identity()
            if identity in seen_identities:
                duplicates += 1
                continue
            seen_identities.add(identity)
            rows.append(row)

    rows.sort(key=lambda row: (row.session_id, row.window_index))
    sessions.sort(key=lambda session: session.session_id)
    return DatasetResult(
        root=Path(root),
        sessions=sessions,
        rows=rows,
        coverage=_build_coverage(rows),
        dataset_sha256=compute_dataset_sha256(rows),
        duplicates_removed=duplicates,
    )


# ------------------------------------------------------------------- splitting


@dataclass
class SplitAssignment:
    seed: int
    mapping: dict[str, str]

    def sessions_in(self, split: str) -> list[str]:
        return sorted(session for session, assigned in self.mapping.items() if assigned == split)


@dataclass
class SplitResult:
    assignment: SplitAssignment
    splits: dict[str, list[ObservationRow]]
    dataset_sha256: str

    def session_ids(self, split: str) -> list[str]:
        return self.assignment.sessions_in(split)


def _allocate(total: int) -> dict[str, int]:
    counts = {name: 0 for name in SPLIT_NAMES}
    if total <= 0:
        return counts
    if total < 3:
        counts["train"] = total
        return counts
    counts["val"] = max(1, int(round(total * SPLIT_RATIOS["val"])))
    counts["test"] = max(1, int(round(total * SPLIT_RATIOS["test"])))
    while counts["val"] + counts["test"] >= total:
        if counts["val"] >= counts["test"]:
            counts["val"] -= 1
        else:
            counts["test"] -= 1
    counts["train"] = total - counts["val"] - counts["test"]
    return counts


def assign_splits(sessions: Iterable[SessionManifest], seed: int) -> SplitAssignment:
    """Stratified grouped assignment by (label, family). Deterministic for a given seed."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise DatasetError("split seed must be an integer")

    strata: dict[tuple[int, str], list[str]] = defaultdict(list)
    for session in sessions:
        strata[(session.label, session.family)].append(session.session_id)

    mapping: dict[str, str] = {}
    for stratum in sorted(strata):
        ids = sorted(strata[stratum])
        rng = random.Random(f"{seed}:{stratum[0]}:{stratum[1]}")
        rng.shuffle(ids)
        counts = _allocate(len(ids))
        cursor = 0
        for name in ("test", "val", "train"):
            for session_id in ids[cursor : cursor + counts[name]]:
                mapping[session_id] = name
            cursor += counts[name]
    return SplitAssignment(seed=seed, mapping=dict(sorted(mapping.items())))


def build_splits(dataset: DatasetResult, seed: int = 1337) -> SplitResult:
    if not dataset.rows:
        raise DatasetError("dataset has no rows")
    assignment = assign_splits(dataset.sessions, seed)
    splits: dict[str, list[ObservationRow]] = {name: [] for name in SPLIT_NAMES}
    unknown: set[str] = set()
    for row in dataset.rows:
        split = assignment.mapping.get(row.session_id)
        if split is None:
            unknown.add(row.session_id)
            continue
        splits[split].append(row)
    if unknown:
        raise DatasetError(f"rows reference sessions without a split assignment: {sorted(unknown)}")

    for name in SPLIT_NAMES:
        sessions_here = {row.session_id for row in splits[name]}
        for other in SPLIT_NAMES:
            if other == name:
                continue
            overlap = sessions_here & {row.session_id for row in splits[other]}
            if overlap:
                raise DatasetError(f"session overlap between {name} and {other}: {sorted(overlap)}")
    return SplitResult(assignment=assignment, splits=splits, dataset_sha256=dataset.dataset_sha256)


def _row_to_dict(row: ObservationRow) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "window_index": row.window_index,
        "observation_state": row.observation_state,
        "feature_values": {name: row.feature_values[name] for name in schema.LBS1_FEATURE_NAMES},
        "feature_status": {name: row.feature_status[name] for name in schema.LBS1_FEATURE_NAMES},
        "sensor_groups": {group: row.sensor_groups[group] for group in schema.SENSOR_GROUPS},
        "reasons": list(row.reasons),
    }
    if row.observation_id is not None:
        payload["observation_id"] = row.observation_id
    return payload


def write_splits(directory: Path, split_result: SplitResult) -> Path:
    """Write the splits once; `split_manifest.json` acts as a permanent lock."""
    directory = Path(directory)
    lock = directory / SPLIT_MANIFEST_FILENAME
    if lock.exists():
        raise SplitLockedError(f"split manifest already exists: {lock}")

    directory.mkdir(parents=True, exist_ok=True)
    file_hashes: dict[str, str] = {}
    for name in SPLIT_NAMES:
        contents = "".join(
            schema.canonical_json(_row_to_dict(row)) + "\n" for row in split_result.splits[name]
        )
        path = directory / f"{name}.jsonl"
        path.write_text(contents, encoding="utf-8", newline="\n")
        file_hashes[path.name] = hashlib.sha256(contents.encode("utf-8")).hexdigest()

    manifest = {
        "format": "lbs1-split-1",
        "seed": split_result.assignment.seed,
        "dataset_sha256": split_result.dataset_sha256,
        "session_assignment": split_result.assignment.mapping,
        "counts": {name: len(split_result.splits[name]) for name in SPLIT_NAMES},
        "files": file_hashes,
    }
    lock.write_text(schema.canonical_json(manifest) + "\n", encoding="utf-8", newline="\n")
    return lock


def load_split_manifest(directory: Path) -> dict[str, Any]:
    directory = Path(directory)
    lock = directory / SPLIT_MANIFEST_FILENAME
    if not lock.is_file():
        raise DatasetError(f"no split manifest at {lock}")
    try:
        manifest = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetError(f"{lock}: unreadable split manifest: {exc}") from exc
    for filename, expected in manifest.get("files", {}).items():
        path = directory / filename
        if not path.is_file():
            raise DatasetError(f"split file missing: {path}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise DatasetError(f"split file hash mismatch: {filename}")
    return manifest


# ------------------------------------------------------------------ gate checks


@dataclass(frozen=True)
class VolumeGates:
    benign_sessions_min: int = 30
    benign_families_min: int = 10
    benign_model_ready_min: int = 2_000
    hard_benign_sessions_per_distro_min: int = 8
    simulated_runs_min: int = 60
    simulated_families_min: int = 6
    simulated_model_ready_min: int = 2_000


VOLUME_GATES = VolumeGates()


@dataclass
class VolumeReport:
    benign_sessions: int
    benign_families: int
    benign_model_ready: int
    hard_benign_per_distro: dict[str, int]
    simulated_runs: int
    simulated_families: int
    simulated_model_ready: int
    violations: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.violations

    def as_dict(self) -> dict[str, Any]:
        return {
            "benign_sessions": self.benign_sessions,
            "benign_families": self.benign_families,
            "benign_model_ready": self.benign_model_ready,
            "hard_benign_per_distro": dict(self.hard_benign_per_distro),
            "simulated_runs": self.simulated_runs,
            "simulated_families": self.simulated_families,
            "simulated_model_ready": self.simulated_model_ready,
            "violations": list(self.violations),
        }


def check_volume_gates(dataset: DatasetResult, gates: VolumeGates = VOLUME_GATES) -> VolumeReport:
    benign = [session for session in dataset.sessions if session.source_type == SOURCE_BENIGN]
    simulated = [session for session in dataset.sessions if session.source_type == SOURCE_SIMULATED]

    benign_ids = {session.session_id for session in benign}
    simulated_ids = {session.session_id for session in simulated}

    benign_ready = sum(
        1 for row in dataset.rows if row.model_ready and row.session_id in benign_ids
    )
    simulated_ready = sum(
        1 for row in dataset.rows if row.model_ready and row.session_id in simulated_ids
    )

    hard_benign: dict[str, int] = {distro: 0 for distro in VALID_DISTROS}
    for session in benign:
        if session.hard_benign:
            hard_benign[session.distro] += 1

    report = VolumeReport(
        benign_sessions=len(benign),
        benign_families=len({session.family for session in benign}),
        benign_model_ready=benign_ready,
        hard_benign_per_distro=hard_benign,
        simulated_runs=len(simulated),
        simulated_families=len({session.family for session in simulated}),
        simulated_model_ready=simulated_ready,
    )

    if report.benign_sessions < gates.benign_sessions_min:
        report.violations.append(
            f"benign sessions {report.benign_sessions} < {gates.benign_sessions_min}"
        )
    if report.benign_families < gates.benign_families_min:
        report.violations.append(
            f"benign families {report.benign_families} < {gates.benign_families_min}"
        )
    if report.benign_model_ready < gates.benign_model_ready_min:
        report.violations.append(
            f"benign MODEL_READY windows {report.benign_model_ready} < {gates.benign_model_ready_min}"
        )
    for distro in VALID_DISTROS:
        if hard_benign[distro] < gates.hard_benign_sessions_per_distro_min:
            report.violations.append(
                f"hard-benign sessions on {distro}: {hard_benign[distro]} < {gates.hard_benign_sessions_per_distro_min}"
            )
    if report.simulated_runs < gates.simulated_runs_min:
        report.violations.append(
            f"simulated runs {report.simulated_runs} < {gates.simulated_runs_min}"
        )
    if report.simulated_families < gates.simulated_families_min:
        report.violations.append(
            f"simulated families {report.simulated_families} < {gates.simulated_families_min}"
        )
    if report.simulated_model_ready < gates.simulated_model_ready_min:
        report.violations.append(
            f"simulated MODEL_READY windows {report.simulated_model_ready} < {gates.simulated_model_ready_min}"
        )
    return report


def check_split_gates(split_result: SplitResult) -> list[str]:
    """Both native distros must appear in train and test (Stage C requirement)."""
    violations: list[str] = []
    for split in ("train", "test"):
        distros = {row.distro for row in split_result.splits[split]}
        for distro in VALID_DISTROS:
            if distro not in distros:
                violations.append(f"{split} split has no {distro} rows")
    return violations
