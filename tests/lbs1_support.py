"""Synthetic fixtures shared by LBS-1 Stage B tests.

Nothing here reads real telemetry: every artifact, manifest, session, and observation is
fabricated in memory or under pytest's `tmp_path`.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping, Optional

import joblib
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml import linux_dataset as ds
from ml import linux_schema as schema

# Pinned contract hash; any accidental schema edit fails the Stage B schema tests.
EXPECTED_SCHEMA_HASH = "4feba798449bf7525f7d5561cba3215b16fe199870db624d894828ed8c413f4e"

FROZEN_WINDOWS_HASHES = {
    "models/saved_model.pkl": "936d9e3ff0b97d762751bdcba34ad3d247a4280e38f84e32dc4f31bfa1174e33",
    "models/scaler.pkl": "d993e26a313f743bbfc351912f2ac4a3be2642f4722c8c5451baf9eda26281cb",
    "models/metrics.json": "8a24b01aa0d5b38ea099f391afb486fa9310fe0ff39ae645c132172170227c88",
    "ml/predictor.py": "4b4f9c90eff4a4144115b4cb5848a4d9f957032fb81f4af435e18fbfd6beb491",
    "scanner/live_scanner.py": "fe34386fa3612c9cd203e2bc1cbdd4607644a216ce8b2255d122db2997e5ede1",
}

FROZEN_WINDOWS_FEATURES = [
    "total_processes",
    "suspicious_process_count",
    "avg_entropy",
    "max_entropy",
    "high_entropy_region_count",
    "malfind_injection_count",
    "crypto_dll_count",
    "cmd_vssadmin_count",
    "network_connection_count",
    "unique_external_ips",
    "file_handle_count",
    "registry_handle_count",
    "orphan_process_count",
    "powershell_process_count",
    "unsigned_module_count",
    "suspicious_mutex_count",
    "abnormal_privilege_count",
    "suspicious_thread_count",
    "defender_tampering_count",
]


# ------------------------------------------------------------------- estimators


class FixedProbabilityModel:
    """Deterministic stand-in for a trained classifier."""

    def __init__(self, probability: float = 0.10) -> None:
        self.probability = float(probability)
        self.n_features_in_ = schema.FEATURE_COUNT

    def predict_proba(self, X) -> np.ndarray:
        rows = np.asarray(X).shape[0]
        p = self.probability
        return np.tile(np.asarray([1.0 - p, p], dtype=np.float64), (rows, 1))


class IdentityScaler:
    def __init__(self) -> None:
        self.n_features_in_ = schema.FEATURE_COUNT

    def transform(self, X) -> np.ndarray:
        return np.asarray(X, dtype=np.float64)


class IdentityCalibrator:
    def predict_proba(self, X) -> np.ndarray:
        raw = np.asarray(X, dtype=np.float64).reshape(-1)
        return np.column_stack([1.0 - raw, raw])


class ExplodingModel:
    def predict_proba(self, X):  # pragma: no cover - must never run
        raise AssertionError("model.predict_proba must not be called for a non-ready observation")


class ExplodingScaler:
    def transform(self, X):  # pragma: no cover - must never run
        raise AssertionError("scaler.transform must not be called for a non-ready observation")


# --------------------------------------------------------------------- artifacts


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def make_artifact_dir(
    root: Path,
    probability: float = 0.10,
    *,
    manifest_overrides: Optional[Mapping[str, Any]] = None,
    schema_payload: Optional[Mapping[str, Any]] = None,
    model: Any = None,
    tamper: Optional[str] = None,
    drop: Optional[str] = None,
) -> Path:
    artifact_dir = Path(root) / "models" / "linux_v1"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    payload = dict(schema_payload) if schema_payload is not None else schema.schema_dict()
    (artifact_dir / "schema.json").write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    joblib.dump(model if model is not None else FixedProbabilityModel(probability), artifact_dir / "model.pkl")
    joblib.dump(IdentityScaler(), artifact_dir / "scaler.pkl")
    joblib.dump(IdentityCalibrator(), artifact_dir / "calibrator.pkl")

    hashes = {
        name: sha256_file(artifact_dir / name)
        for name in ("schema.json", "model.pkl", "scaler.pkl", "calibrator.pkl")
    }
    manifest: dict[str, Any] = {
        "model_version": "lbs1-test-0.0.0",
        "schema_id": schema.LINUX_SCHEMA_ID,
        "schema_hash": schema.schema_hash(payload),
        "platform": schema.PLATFORM_TAG,
        "feature_count": schema.FEATURE_COUNT,
        "feature_names": list(payload.get("feature_names", schema.LBS1_FEATURE_NAMES)),
        "window_seconds": schema.WINDOW_SECONDS_DEFAULT,
        "list_version": schema.LIST_VERSION,
        "dataset_sha256": "0" * 64,
        "thresholds": {"warning": 0.50, "critical": 0.90},
        "calibration": "sigmoid_on_positive_probability",
        "artifact_hashes": hashes,
    }
    if manifest_overrides:
        manifest.update(dict(manifest_overrides))
    (artifact_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    if tamper:
        with open(artifact_dir / tamper, "ab") as handle:
            handle.write(b"\x00tampered")
    if drop:
        (artifact_dir / drop).unlink()
    return artifact_dir


# ---------------------------------------------------------------- observations


def ready_values(seed: int = 0) -> dict[str, float]:
    return {
        name: float((seed + 3 * index) % 11) / 10.0
        for index, name in enumerate(schema.LBS1_FEATURE_NAMES)
    }


def all_defined() -> dict[str, str]:
    return {name: schema.STATUS_DEFINED for name in schema.LBS1_FEATURE_NAMES}


def all_groups_ok() -> dict[str, str]:
    return {group: schema.GROUP_OK for group in schema.SENSOR_GROUPS}


def quiet_statuses() -> dict[str, str]:
    status = all_defined()
    status["avg_shannon_entropy"] = schema.STATUS_NO_FILE_ACTIVITY
    status["high_entropy_file_ratio"] = schema.STATUS_NO_FILE_ACTIVITY
    status["entropy_increase_ratio"] = schema.STATUS_NO_BASELINE_COHORT
    status["short_lived_process_ratio"] = schema.STATUS_NO_PROCESS_ACTIVITY
    return status


def degraded_statuses() -> dict[str, str]:
    status = all_defined()
    status["avg_shannon_entropy"] = schema.STATUS_UNAVAILABLE_PERMISSION
    status["high_entropy_file_ratio"] = schema.STATUS_UNAVAILABLE_PERMISSION
    return status


def make_observation(
    values: Optional[Mapping[str, Any]] = None,
    status_overrides: Optional[Mapping[str, str]] = None,
    group_overrides: Optional[Mapping[str, str]] = None,
    declared_state: Optional[str] = None,
) -> SimpleNamespace:
    feature_values: dict[str, Any] = dict(values if values is not None else ready_values(1))
    status = all_defined()
    if status_overrides:
        for name, value in status_overrides.items():
            status[name] = value
            if value != schema.STATUS_DEFINED:
                feature_values[name] = None
    groups = all_groups_ok()
    if group_overrides:
        groups.update(dict(group_overrides))

    state = declared_state or schema.observation_state_from(status, groups)
    vector: Optional[np.ndarray]
    if state == schema.STATE_MODEL_READY:
        try:
            vector = schema.build_vector(feature_values, status)
        except schema.LinuxSchemaError:
            # Intentionally invalid construction, used to prove the validator refuses it.
            vector = np.zeros(schema.FEATURE_COUNT, dtype=np.float64)
    else:
        vector = None
    return SimpleNamespace(
        features=vector,
        feature_values=feature_values,
        feature_status=status,
        sensor_groups=groups,
        observation_state=state,
        reasons=(),
    )


def row_payload(
    window_index: int,
    *,
    state: str = schema.STATE_MODEL_READY,
    seed: int = 0,
    observation_id: Optional[str] = None,
) -> dict[str, Any]:
    values: dict[str, Any] = ready_values(seed)
    status = all_defined()
    groups = all_groups_ok()
    reasons: list[str] = []

    if state == schema.STATE_INSUFFICIENT_ACTIVITY:
        status = quiet_statuses()
        groups["G2"] = schema.GROUP_NOT_APPLICABLE
        groups["G5"] = schema.GROUP_NOT_APPLICABLE
        groups["G6"] = schema.GROUP_NOT_APPLICABLE
        reasons = ["G2:NOT_APPLICABLE", "avg_shannon_entropy:NOT_APPLICABLE_NO_FILE_ACTIVITY"]
        for name, value in status.items():
            if value != schema.STATUS_DEFINED:
                values[name] = None
    elif state == schema.STATE_DEGRADED:
        status = degraded_statuses()
        groups["G2"] = schema.GROUP_DEGRADED
        reasons = ["G2:DEGRADED", "avg_shannon_entropy:UNAVAILABLE_PERMISSION"]
        for name, value in status.items():
            if value != schema.STATUS_DEFINED:
                values[name] = None

    payload: dict[str, Any] = {
        "window_index": window_index,
        "observation_state": state,
        "feature_values": values,
        "feature_status": status,
        "sensor_groups": groups,
        "reasons": reasons,
    }
    if observation_id is not None:
        payload["observation_id"] = observation_id
    return payload


def write_session(
    root: Path,
    group: str,
    session_id: str,
    *,
    source_type: str,
    family: str,
    distro: str,
    label: int,
    seed: int = 0,
    window_seconds: float = schema.WINDOW_SECONDS_DEFAULT,
    hard_benign: bool = False,
    ready: int = 3,
    insufficient: int = 0,
    degraded: int = 0,
    shared_observation_id: Optional[str] = None,
    manifest_overrides: Optional[Mapping[str, Any]] = None,
) -> Path:
    session_dir = Path(root) / group / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "session_id": session_id,
        "source_type": source_type,
        "label": label,
        "family": family,
        "distro": distro,
        "seed": seed,
        "collector_version": "lbs1-test",
        "list_version": schema.LIST_VERSION,
        "window_seconds": window_seconds,
        "hard_benign": hard_benign,
    }
    if manifest_overrides:
        manifest.update(dict(manifest_overrides))
    (session_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    lines: list[str] = []
    index = 0
    for _ in range(ready):
        observation_id = shared_observation_id if (shared_observation_id and index == 0) else None
        lines.append(json.dumps(row_payload(index, seed=seed + index, observation_id=observation_id)))
        index += 1
    for _ in range(insufficient):
        lines.append(json.dumps(row_payload(index, state=schema.STATE_INSUFFICIENT_ACTIVITY)))
        index += 1
    for _ in range(degraded):
        lines.append(json.dumps(row_payload(index, state=schema.STATE_DEGRADED)))
        index += 1
    (session_dir / "observations.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return session_dir


# --------------------------------------------------------------- in-memory data


def _session(
    session_id: str,
    source_type: str,
    family: str,
    distro: str,
    seed: int,
    hard_benign: bool = False,
) -> ds.SessionManifest:
    label = ds.LABEL_BENIGN if source_type == ds.SOURCE_BENIGN else ds.LABEL_ATTACK
    return ds.SessionManifest(
        session_id=session_id,
        source_type=source_type,
        label=label,
        family=family,
        distro=distro,
        seed=seed,
        collector_version="lbs1-test",
        list_version=schema.LIST_VERSION,
        window_seconds=schema.WINDOW_SECONDS_DEFAULT,
        hard_benign=hard_benign,
    )


def _row(
    session: ds.SessionManifest,
    window_index: int,
    state: str = schema.STATE_MODEL_READY,
    seed: int = 0,
) -> ds.ObservationRow:
    payload = row_payload(window_index, state=state, seed=seed)
    values = payload["feature_values"]
    status = payload["feature_status"]
    vector = schema.build_vector(values, status) if state == schema.STATE_MODEL_READY else None
    return ds.ObservationRow(
        session_id=session.session_id,
        window_index=window_index,
        source_type=session.source_type,
        label=session.label,
        family=session.family,
        distro=session.distro,
        observation_state=state,
        feature_values=values,
        feature_status=status,
        sensor_groups=payload["sensor_groups"],
        reasons=tuple(payload["reasons"]),
        feature_vector=vector,
    )


def make_dataset_result(
    *,
    benign_families: int = 10,
    sessions_per_family_per_distro: int = 2,
    windows_per_benign: int = 50,
    hard_benign_per_distro: int = 8,
    simulated_families: int = 6,
    runs_per_family: int = 10,
    windows_per_sim: int = 34,
    extra_non_ready: int = 0,
) -> ds.DatasetResult:
    sessions: list[ds.SessionManifest] = []
    rows: list[ds.ObservationRow] = []

    families = [f"benign-{index:02d}" for index in range(benign_families)]
    counter = 0
    for distro in ds.VALID_DISTROS:
        for family in families:
            for _ in range(sessions_per_family_per_distro):
                session = _session(f"{distro}-{family}-{counter}", ds.SOURCE_BENIGN, family, distro, counter)
                counter += 1
                sessions.append(session)
                for window in range(windows_per_benign):
                    rows.append(_row(session, window, seed=window))
        for index in range(hard_benign_per_distro):
            session = _session(
                f"{distro}-hard-benign-{index}", ds.SOURCE_BENIGN, ds.HARD_BENIGN_FAMILY, distro, counter, True
            )
            counter += 1
            sessions.append(session)
            for window in range(windows_per_benign):
                rows.append(_row(session, window, seed=window))

    sim_families = [f"sim-{index:02d}" for index in range(simulated_families)]
    for family in sim_families:
        for index in range(runs_per_family):
            distro = ds.VALID_DISTROS[index % len(ds.VALID_DISTROS)]
            session = _session(f"sim-{family}-{index}", ds.SOURCE_SIMULATED, family, distro, counter)
            counter += 1
            sessions.append(session)
            for window in range(windows_per_sim):
                rows.append(_row(session, window, seed=window))

    for index in range(extra_non_ready):
        session = sessions[index % len(sessions)]
        rows.append(
            _row(session, windows_per_benign + 1000 + index, state=schema.STATE_INSUFFICIENT_ACTIVITY)
        )

    return ds.dataset_from_rows(sessions, rows)
