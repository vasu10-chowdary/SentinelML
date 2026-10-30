"""LBS-1 schema contract (Linux Behavioral Schema v1).

This module is the single authority for the Linux feature contract. It is deliberately
independent of the Windows predictor: nothing here imports `ml.predictor` or touches the
frozen 19-feature Windows artifacts.

The contract enforced here:

* exactly 20 ordered features, `float64`, finite, non-negative;
* every feature carries a status from the approved vocabulary;
* an observation has a vector **if and only if** it is `MODEL_READY`, which in turn holds
  **iff** all seven sensor groups are `OK` and all 20 features are `DEFINED`;
* a non-`DEFINED` feature never yields a number — there is no sentinel, no imputation,
  and no coercion path.

Any violation raises `LinuxSchemaError`; nothing is repaired silently.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Optional, Sequence

import numpy as np

LINUX_SCHEMA_ID = "LBS-1"
SCHEMA_VERSION = "1.0.0"
PLATFORM_TAG = "linux"

WINDOW_SECONDS_DEFAULT = 15.0
WINDOW_SECONDS_MIN = 10.0
WINDOW_SECONDS_MAX = 60.0

# CRITICAL is disabled until an independent validation gate (G5) approves it. The
# predictor reads this constant directly; there is intentionally no runtime override.
LBS1_CRITICAL_ENABLED = False

LIST_VERSION = "lbs1-lists-1.0.0"

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
FEATURE_DTYPE = "float64"

FEATURE_UNITS: dict[str, str] = {
    "file_mod_rate": "events/s",
    "file_rename_rate": "events/s",
    "file_delete_rate": "events/s",
    "files_modified_count": "count",
    "files_renamed_count": "count",
    "distinct_dirs_touched": "count",
    "avg_shannon_entropy": "bits/byte",
    "high_entropy_file_ratio": "ratio",
    "entropy_increase_ratio": "ratio",
    "ransom_extension_match_count": "count",
    "ransom_note_match_count": "count",
    "process_create_rate": "procs/s",
    "process_exit_rate": "procs/s",
    "short_lived_process_ratio": "ratio",
    "destructive_command_count": "count",
    "shell_spawn_count": "count",
    "temp_exec_count": "count",
    "privileged_process_count": "count",
    "setuid_cap_file_event_count": "count",
    "unique_external_ip_count": "count",
}

STATUS_DEFINED = "DEFINED"
STATUS_NO_FILE_ACTIVITY = "NOT_APPLICABLE_NO_FILE_ACTIVITY"
STATUS_NO_SAMPLEABLE_FILES = "NOT_APPLICABLE_NO_SAMPLEABLE_FILES"
STATUS_NO_BASELINE_COHORT = "NOT_APPLICABLE_NO_BASELINE_COHORT"
STATUS_COHORT_UNAVAILABLE = "NOT_APPLICABLE_COHORT_UNAVAILABLE"
STATUS_NO_PROCESS_ACTIVITY = "NOT_APPLICABLE_NO_PROCESS_ACTIVITY"
STATUS_UNAVAILABLE_PERMISSION = "UNAVAILABLE_PERMISSION"
STATUS_UNAVAILABLE_SENSOR = "UNAVAILABLE_SENSOR"

VALID_FEATURE_STATUSES = frozenset(
    {
        STATUS_DEFINED,
        STATUS_NO_FILE_ACTIVITY,
        STATUS_NO_SAMPLEABLE_FILES,
        STATUS_NO_BASELINE_COHORT,
        STATUS_COHORT_UNAVAILABLE,
        STATUS_NO_PROCESS_ACTIVITY,
        STATUS_UNAVAILABLE_PERMISSION,
        STATUS_UNAVAILABLE_SENSOR,
    }
)

NOT_APPLICABLE_STATUSES = frozenset(
    {
        STATUS_NO_FILE_ACTIVITY,
        STATUS_NO_SAMPLEABLE_FILES,
        STATUS_NO_BASELINE_COHORT,
        STATUS_COHORT_UNAVAILABLE,
        STATUS_NO_PROCESS_ACTIVITY,
    }
)

UNAVAILABLE_STATUSES = frozenset({STATUS_UNAVAILABLE_PERMISSION, STATUS_UNAVAILABLE_SENSOR})

# Only these four features are proportions over a population that can be empty.
# Every other feature is a count/rate and is DEFINED (possibly 0.0) when its sensor is healthy.
POPULATION_FEATURES = frozenset(
    {"avg_shannon_entropy", "high_entropy_file_ratio", "entropy_increase_ratio", "short_lived_process_ratio"}
)

STATE_MODEL_READY = "MODEL_READY"
STATE_INSUFFICIENT_ACTIVITY = "INSUFFICIENT_ACTIVITY"
STATE_DEGRADED = "DEGRADED"

OBSERVATION_STATES = (STATE_MODEL_READY, STATE_INSUFFICIENT_ACTIVITY, STATE_DEGRADED)

GROUP_OK = "OK"
GROUP_DEGRADED = "DEGRADED"
GROUP_UNAVAILABLE = "UNAVAILABLE"
GROUP_NOT_APPLICABLE = "NOT_APPLICABLE"

SENSOR_GROUPS: tuple[str, ...] = ("G1", "G2", "G3", "G4", "G5", "G6", "G7")
VALID_GROUP_STATUSES = frozenset({GROUP_OK, GROUP_DEGRADED, GROUP_UNAVAILABLE, GROUP_NOT_APPLICABLE})

# Feature indices covered by each group. Mirrors scanner/linux_telemetry.GROUP_FEATURES,
# which the Stage B schema-contract test cross-checks.
GROUP_FEATURE_NAMES: dict[str, tuple[str, ...]] = {
    "G1": tuple(LBS1_FEATURE_NAMES[i] for i in (0, 1, 2, 3, 4, 5, 9, 10, 18)),
    "G2": tuple(LBS1_FEATURE_NAMES[i] for i in (6, 7, 8)),
    "G3": tuple(LBS1_FEATURE_NAMES[i] for i in (9, 10)),
    "G4": tuple(LBS1_FEATURE_NAMES[i] for i in (11, 12, 13, 17)),
    "G5": tuple(LBS1_FEATURE_NAMES[i] for i in (14, 15, 16)),
    "G6": (LBS1_FEATURE_NAMES[17],),
    "G7": (LBS1_FEATURE_NAMES[19],),
}


class LinuxSchemaError(ValueError):
    """Raised when a value violates the LBS-1 contract. Never coerced, never repaired."""


def feature_index(name: str) -> int:
    try:
        return LBS1_FEATURE_NAMES.index(name)
    except ValueError as exc:
        raise LinuxSchemaError(f"unknown LBS-1 feature: {name!r}") from exc


def schema_dict() -> dict[str, Any]:
    """Canonical, hashable description of the contract (written to schema.json)."""
    return {
        "schema_id": LINUX_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "platform": PLATFORM_TAG,
        "feature_count": FEATURE_COUNT,
        "feature_names": list(LBS1_FEATURE_NAMES),
        "feature_dtypes": [FEATURE_DTYPE] * FEATURE_COUNT,
        "units": dict(FEATURE_UNITS),
        "non_negative": True,
        "window_seconds_default": WINDOW_SECONDS_DEFAULT,
        "window_seconds_min": WINDOW_SECONDS_MIN,
        "window_seconds_max": WINDOW_SECONDS_MAX,
        "list_version": LIST_VERSION,
        "statuses": sorted(VALID_FEATURE_STATUSES),
        "not_applicable_statuses": sorted(NOT_APPLICABLE_STATUSES),
        "unavailable_statuses": sorted(UNAVAILABLE_STATUSES),
        "observation_states": list(OBSERVATION_STATES),
        "group_statuses": sorted(VALID_GROUP_STATUSES),
        "sensor_groups": {
            "names": list(SENSOR_GROUPS),
            "feature_names": {group: list(names) for group, names in GROUP_FEATURE_NAMES.items()},
        },
        "critical_enabled": LBS1_CRITICAL_ENABLED,
    }


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def payload_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def schema_hash(schema: Optional[Mapping[str, Any]] = None) -> str:
    return payload_hash(schema_dict() if schema is None else schema)


def validate_feature_status(feature_status: Mapping[str, str]) -> None:
    if not isinstance(feature_status, Mapping):
        raise LinuxSchemaError(f"feature_status must be a mapping, got {type(feature_status).__name__}")
    missing = [name for name in LBS1_FEATURE_NAMES if name not in feature_status]
    extra = [name for name in feature_status if name not in LBS1_FEATURE_NAMES]
    if missing or extra:
        raise LinuxSchemaError(f"feature_status keys do not match schema (missing={missing}, extra={extra})")
    for name in LBS1_FEATURE_NAMES:
        status = feature_status[name]
        if status not in VALID_FEATURE_STATUSES:
            raise LinuxSchemaError(f"{name}: unknown status {status!r}")


def validate_sensor_groups(sensor_groups: Mapping[str, str]) -> None:
    if not isinstance(sensor_groups, Mapping):
        raise LinuxSchemaError(f"sensor_groups must be a mapping, got {type(sensor_groups).__name__}")
    missing = [group for group in SENSOR_GROUPS if group not in sensor_groups]
    extra = [group for group in sensor_groups if group not in SENSOR_GROUPS]
    if missing or extra:
        raise LinuxSchemaError(f"sensor_groups keys do not match schema (missing={missing}, extra={extra})")
    for group in SENSOR_GROUPS:
        if sensor_groups[group] not in VALID_GROUP_STATUSES:
            raise LinuxSchemaError(f"{group}: unknown sensor status {sensor_groups[group]!r}")


def observation_state_from(
    feature_status: Mapping[str, str],
    sensor_groups: Mapping[str, str],
) -> str:
    """Derive the only permissible observation state for a status map.

    DEGRADED wins over INSUFFICIENT_ACTIVITY: a real sensor failure is never reported as
    merely quiet. MODEL_READY requires every group OK *and* every feature DEFINED.
    """
    validate_feature_status(feature_status)
    validate_sensor_groups(sensor_groups)

    if any(status in UNAVAILABLE_STATUSES for status in feature_status.values()):
        return STATE_DEGRADED
    if any(status in (GROUP_DEGRADED, GROUP_UNAVAILABLE) for status in sensor_groups.values()):
        return STATE_DEGRADED
    if any(status != STATUS_DEFINED for status in feature_status.values()):
        return STATE_INSUFFICIENT_ACTIVITY
    if any(status != GROUP_OK for status in sensor_groups.values()):
        return STATE_INSUFFICIENT_ACTIVITY
    return STATE_MODEL_READY


def _as_float(value: Any, name: str) -> float:
    if value is None:
        raise LinuxSchemaError(f"{name}: value is None while status is DEFINED")
    if isinstance(value, (bool, np.bool_, str, bytes)):
        raise LinuxSchemaError(f"{name}: {type(value).__name__} is not a numeric feature value")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise LinuxSchemaError(f"{name}: non-numeric value {value!r}") from exc
    if not np.isfinite(number):
        raise LinuxSchemaError(f"{name}: non-finite value {number!r}")
    if number < 0.0:
        raise LinuxSchemaError(f"{name}: negative value {number!r}")
    return number


def build_vector(
    feature_values: Mapping[str, Any],
    feature_status: Mapping[str, str],
) -> np.ndarray:
    """Build the ordered 20-value float64 vector, refusing any non-DEFINED feature."""
    validate_feature_status(feature_status)
    if not isinstance(feature_values, Mapping):
        raise LinuxSchemaError("feature_values must be a mapping")
    missing = [name for name in LBS1_FEATURE_NAMES if name not in feature_values]
    extra = [name for name in feature_values if name not in LBS1_FEATURE_NAMES]
    if missing or extra:
        raise LinuxSchemaError(f"feature_values keys do not match schema (missing={missing}, extra={extra})")

    undefined = [name for name in LBS1_FEATURE_NAMES if feature_status[name] != STATUS_DEFINED]
    if undefined:
        raise LinuxSchemaError(f"cannot build a vector from non-DEFINED features: {undefined}")

    ordered = [_as_float(feature_values[name], name) for name in LBS1_FEATURE_NAMES]
    return np.asarray(ordered, dtype=np.float64)


def validate_vector(vector: Any) -> np.ndarray:
    """Validate an already-built vector against the contract and return a float64 copy."""
    if vector is None:
        raise LinuxSchemaError("vector is None")
    array = np.asarray(vector)
    if array.dtype == np.bool_ or not np.issubdtype(array.dtype, np.number):
        raise LinuxSchemaError(f"vector dtype {array.dtype} is not numeric")
    if array.shape != (FEATURE_COUNT,):
        raise LinuxSchemaError(f"vector shape {array.shape} != ({FEATURE_COUNT},)")
    array = array.astype(np.float64, copy=True)
    if not np.all(np.isfinite(array)):
        raise LinuxSchemaError("vector contains non-finite values")
    if np.any(array < 0.0):
        raise LinuxSchemaError("vector contains negative values")
    return array


def validate_observation(observation: Any) -> Optional[np.ndarray]:
    """Validate a `LinuxObservation`-shaped object.

    Returns the ordered vector for `MODEL_READY` and `None` for any other state. Raises
    `LinuxSchemaError` if the declared state disagrees with the status maps, if a
    non-ready observation carries a vector, or if a ready observation's vector is
    missing/malformed.
    """
    for attribute in ("features", "feature_values", "feature_status", "sensor_groups", "observation_state"):
        if not hasattr(observation, attribute):
            raise LinuxSchemaError(f"observation is missing required attribute {attribute!r}")

    feature_status = observation.feature_status
    sensor_groups = observation.sensor_groups
    declared = observation.observation_state

    if declared not in OBSERVATION_STATES:
        raise LinuxSchemaError(f"unknown observation_state {declared!r}")

    derived = observation_state_from(feature_status, sensor_groups)
    if declared != derived:
        raise LinuxSchemaError(f"observation_state {declared!r} disagrees with status maps ({derived!r})")

    if derived != STATE_MODEL_READY:
        if observation.features is not None:
            raise LinuxSchemaError(f"{derived} observation must not carry a feature vector")
        for name in LBS1_FEATURE_NAMES:
            if feature_status[name] != STATUS_DEFINED and observation.feature_values.get(name) is not None:
                raise LinuxSchemaError(f"{name}: non-DEFINED feature carries a numeric value")
        return None

    if observation.features is None:
        raise LinuxSchemaError("MODEL_READY observation has no feature vector")
    vector = validate_vector(observation.features)

    expected = build_vector(observation.feature_values, feature_status)
    if not np.array_equal(vector, expected):
        raise LinuxSchemaError("feature vector disagrees with feature_values")
    return vector
