"""LBS-1 Stage A — exhaustive applicability invariant over an enumerated activity matrix."""

import sys
from dataclasses import replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
for candidate in (PROJECT_ROOT, TESTS_DIR):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import numpy as np
import pytest

from scanner.linux_entropy import (
    CohortResult,
    EventEntropyResult,
    STATUS_COHORT_UNAVAILABLE,
    STATUS_DEFINED,
    STATUS_NO_BASELINE_COHORT,
    STATUS_NO_FILE_ACTIVITY,
    STATUS_NO_PROCESS_ACTIVITY,
    STATUS_NO_SAMPLEABLE_FILES,
    STATUS_UNAVAILABLE_PERMISSION,
)
from scanner.linux_processes import (
    NetworkResult,
    STATUS_DEGRADED,
    STATUS_NOT_APPLICABLE,
    STATUS_OK,
)
from scanner.linux_telemetry import (
    LBS1_FEATURE_NAMES,
    STATE_DEGRADED,
    STATE_INSUFFICIENT_ACTIVITY,
    STATE_MODEL_READY,
    assemble_observation,
)

from test_lbs1_sensor_health import healthy_inputs


def _variant(name):
    inputs = healthy_inputs()
    if name == "healthy":
        return inputs
    if name == "no_file_activity":
        inputs.entropy = EventEntropyResult(status=STATUS_NO_FILE_ACTIVITY)
        inputs.cohort = CohortResult(status=STATUS_NO_BASELINE_COHORT)
    elif name == "no_sampleable_files":
        inputs.entropy = EventEntropyResult(status=STATUS_NO_SAMPLEABLE_FILES)
        inputs.cohort = CohortResult(status=STATUS_NO_BASELINE_COHORT)
    elif name == "no_baseline_cohort":
        inputs.cohort = CohortResult(status=STATUS_NO_BASELINE_COHORT)
    elif name == "cohort_unavailable":
        inputs.cohort = CohortResult(status=STATUS_COHORT_UNAVAILABLE, missing=5)
    elif name == "no_process_activity":
        inputs.processes = replace(
            inputs.processes,
            created_count=0,
            exited_count=0,
            short_lived_count=0,
            short_lived_ratio=None,
            resolution_rate=None,
            status_readable_rate=None,
            g5_status=STATUS_NOT_APPLICABLE,
            g6_status=STATUS_NOT_APPLICABLE,
        )
    elif name == "entropy_permission":
        inputs.entropy = EventEntropyResult(status=STATUS_UNAVAILABLE_PERMISSION)
    elif name == "cohort_permission":
        inputs.cohort = CohortResult(status=STATUS_UNAVAILABLE_PERMISSION)
    elif name == "inotify_overflow":
        inputs.overflow = True
    elif name == "unsupported_fs":
        inputs.fs_supported = False
        inputs.fs_reasons = ("UNSUPPORTED_FILESYSTEM:9p:/mnt/c",)
    elif name == "watch_shortfall":
        inputs.watch_shortfall = 2
    elif name == "few_snapshots":
        inputs.processes = replace(inputs.processes, samples=2, g4_status=STATUS_DEGRADED)
    elif name == "low_resolution":
        inputs.processes = replace(inputs.processes, resolution_rate=0.5, g5_status=STATUS_DEGRADED)
    elif name == "low_status_readability":
        inputs.processes = replace(inputs.processes, status_readable_rate=0.5, g6_status=STATUS_DEGRADED)
    elif name == "network_restricted":
        inputs.network = NetworkResult(status=STATUS_DEGRADED, error="AccessDenied")
    elif name == "list_matcher_error":
        inputs.filename_matcher_error = "LIST_LOAD_ERROR"
    else:
        raise AssertionError(name)
    return inputs


MATRIX = {
    "healthy": STATE_MODEL_READY,
    "no_file_activity": STATE_INSUFFICIENT_ACTIVITY,
    "no_sampleable_files": STATE_INSUFFICIENT_ACTIVITY,
    "no_baseline_cohort": STATE_INSUFFICIENT_ACTIVITY,
    "cohort_unavailable": STATE_INSUFFICIENT_ACTIVITY,
    "no_process_activity": STATE_INSUFFICIENT_ACTIVITY,
    "entropy_permission": STATE_DEGRADED,
    "cohort_permission": STATE_DEGRADED,
    "inotify_overflow": STATE_DEGRADED,
    "unsupported_fs": STATE_DEGRADED,
    "watch_shortfall": STATE_DEGRADED,
    "few_snapshots": STATE_DEGRADED,
    "low_resolution": STATE_DEGRADED,
    "low_status_readability": STATE_DEGRADED,
    "network_restricted": STATE_DEGRADED,
    "list_matcher_error": STATE_DEGRADED,
}


@pytest.mark.parametrize("name,expected_state", sorted(MATRIX.items()))
def test_enumerated_matrix_states(name, expected_state):
    observation = assemble_observation(_variant(name))
    assert observation.observation_state == expected_state
    assert (observation.features is not None) == (expected_state == STATE_MODEL_READY)


@pytest.mark.parametrize("name", sorted(MATRIX))
def test_model_ready_vector_contract(name):
    observation = assemble_observation(_variant(name))
    if observation.features is None:
        return
    vector = observation.features
    assert vector.shape == (20,)
    assert vector.dtype == np.float64
    assert np.all(np.isfinite(vector))
    assert np.all(vector >= 0)
    expected = [observation.feature_values[key] for key in LBS1_FEATURE_NAMES]
    assert vector.tolist() == pytest.approx(expected)
    assert all(status == STATUS_DEFINED for status in observation.feature_status.values())
    assert set(observation.sensor_groups) == {"G1", "G2", "G3", "G4", "G5", "G6", "G7"}
    assert set(observation.sensor_groups.values()) == {STATUS_OK}


@pytest.mark.parametrize("name", sorted(MATRIX))
def test_no_numeric_sentinel_for_undefined_features(name):
    observation = assemble_observation(_variant(name))
    for key, status in observation.feature_status.items():
        if status == STATUS_DEFINED:
            assert observation.feature_values[key] is not None
        else:
            assert observation.feature_values[key] is None


@pytest.mark.parametrize("name", sorted(MATRIX))
def test_only_population_features_can_be_not_applicable(name):
    observation = assemble_observation(_variant(name))
    allowed = {
        "avg_shannon_entropy",
        "high_entropy_file_ratio",
        "entropy_increase_ratio",
        "short_lived_process_ratio",
    }
    not_applicable = {
        key for key, status in observation.feature_status.items() if status.startswith("NOT_APPLICABLE")
    }
    assert not_applicable <= allowed


def test_zero_event_count_features_remain_defined_at_zero():
    observation = assemble_observation(_variant("healthy"))
    for key in (
        "ransom_extension_match_count",
        "ransom_note_match_count",
        "destructive_command_count",
        "shell_spawn_count",
        "temp_exec_count",
        "privileged_process_count",
        "setuid_cap_file_event_count",
    ):
        assert observation.feature_status[key] == STATUS_DEFINED
        assert observation.feature_values[key] == 0.0


def test_no_activity_reason_codes_distinct_from_unavailable():
    insufficient = assemble_observation(_variant("no_file_activity"))
    degraded = assemble_observation(_variant("entropy_permission"))
    assert insufficient.observation_state != degraded.observation_state
    assert any("NOT_APPLICABLE_NO_FILE_ACTIVITY" in reason for reason in insufficient.reasons)
    assert any("NOT_APPLICABLE" in reason for reason in insufficient.reasons)
    assert any("UNAVAILABLE_PERMISSION" in reason for reason in degraded.reasons)
    assert not any("UNAVAILABLE" in reason for reason in insufficient.reasons)


def test_no_process_activity_trait_is_never_zero():
    observation = assemble_observation(_variant("no_process_activity"))
    assert observation.feature_status["short_lived_process_ratio"] == STATUS_NO_PROCESS_ACTIVITY
    assert observation.feature_values["short_lived_process_ratio"] is None
