"""LBS-1 Stage A — sensor-group health and observation-state tests."""

import sys
from dataclasses import replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pytest

from scanner.linux_entropy import (
    CohortResult,
    EventEntropyResult,
    STATUS_COHORT_UNAVAILABLE,
    STATUS_DEFINED,
    STATUS_NO_BASELINE_COHORT,
    STATUS_NO_FILE_ACTIVITY,
    STATUS_NO_SAMPLEABLE_FILES,
    STATUS_UNAVAILABLE_PERMISSION,
)
from scanner.linux_inotify import FileEventSummary
from scanner.linux_processes import (
    NetworkResult,
    ProcessWindowResult,
    STATUS_DEGRADED,
    STATUS_NOT_APPLICABLE,
    STATUS_OK,
)
from scanner.linux_telemetry import (
    CollectorInputs,
    LBS1_FEATURE_NAMES,
    STATE_DEGRADED,
    STATE_INSUFFICIENT_ACTIVITY,
    STATE_MODEL_READY,
    assemble_observation,
)


def healthy_inputs():
    summary = FileEventSummary(
        close_write_events=2,
        close_write_paths={"/root/a", "/root/b"},
        dirs_touched={"/root"},
    )
    summary.renamed_paths = {"/root/c"}
    summary.rename_events = 1
    summary.deleted_paths = {"/root/d"}
    summary.delete_events = 1
    return CollectorInputs(
        file_summary=summary,
        entropy=EventEntropyResult(
            status=STATUS_DEFINED,
            n_candidates=2,
            n_eligible=2,
            n_sampled=2,
            mean_entropy=6.0,
            high_entropy_ratio=0.5,
        ),
        cohort=CohortResult(status=STATUS_DEFINED, value=0.0, start_count=5, sampled=5),
        processes=ProcessWindowResult(
            created_count=2,
            exited_count=1,
            short_lived_count=1,
            short_lived_ratio=0.5,
            resolution_rate=1.0,
            status_readable_rate=1.0,
            samples=15,
            g4_status=STATUS_OK,
            g5_status=STATUS_OK,
            g6_status=STATUS_OK,
        ),
        network=NetworkResult(status=STATUS_OK, external_ips={"8.8.8.8"}, connection_count=1),
        fs_supported=True,
        filesystem_types=("ext4",),
        watch_count=10,
        window_seconds=15.0,
        events_processed=4,
    )


def test_healthy_observation_is_model_ready():
    observation = assemble_observation(healthy_inputs())
    assert observation.observation_state == STATE_MODEL_READY
    assert observation.features is not None
    assert observation.features.shape == (20,)
    assert observation.features.dtype == np.float64
    assert np.all(np.isfinite(observation.features))
    assert np.all(observation.features >= 0)
    assert set(observation.sensor_groups.values()) == {STATUS_OK}
    assert all(status == STATUS_DEFINED for status in observation.feature_status.values())
    assert observation.reasons == ()


def test_no_file_activity_is_insufficient_not_degraded():
    inputs = healthy_inputs()
    inputs.entropy = EventEntropyResult(status=STATUS_NO_FILE_ACTIVITY)
    inputs.cohort = CohortResult(status=STATUS_NO_BASELINE_COHORT)
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_INSUFFICIENT_ACTIVITY
    assert observation.features is None
    assert observation.sensor_groups["G2"] == "NOT_APPLICABLE"
    assert observation.feature_status["avg_shannon_entropy"] == STATUS_NO_FILE_ACTIVITY
    assert observation.feature_status["entropy_increase_ratio"] == STATUS_NO_BASELINE_COHORT
    assert observation.feature_values["avg_shannon_entropy"] is None
    assert any(STATUS_NO_FILE_ACTIVITY in reason for reason in observation.reasons)
    assert not any("UNAVAILABLE" in reason for reason in observation.reasons)


def test_zero_length_files_are_no_sampleable_files():
    inputs = healthy_inputs()
    inputs.entropy = EventEntropyResult(status=STATUS_NO_SAMPLEABLE_FILES)
    inputs.cohort = CohortResult(status=STATUS_NO_BASELINE_COHORT)
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_INSUFFICIENT_ACTIVITY
    assert observation.feature_status["avg_shannon_entropy"] == STATUS_NO_SAMPLEABLE_FILES
    assert observation.feature_values["high_entropy_file_ratio"] is None


def test_cohort_permission_failure_is_degraded():
    inputs = healthy_inputs()
    inputs.cohort = CohortResult(status=STATUS_UNAVAILABLE_PERMISSION)
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_DEGRADED
    assert observation.features is None
    assert observation.sensor_groups["G2"] == STATUS_DEGRADED
    assert observation.feature_status["entropy_increase_ratio"] == STATUS_UNAVAILABLE_PERMISSION
    assert observation.feature_values["entropy_increase_ratio"] is None


def test_cohort_unavailable_activity_is_insufficient():
    inputs = healthy_inputs()
    inputs.cohort = CohortResult(status=STATUS_COHORT_UNAVAILABLE, missing=5)
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_INSUFFICIENT_ACTIVITY
    assert observation.feature_status["entropy_increase_ratio"] == STATUS_COHORT_UNAVAILABLE
    assert observation.sensor_groups["G2"] == "NOT_APPLICABLE"


def test_zero_pid_activity_is_not_applicable():
    inputs = healthy_inputs()
    inputs.processes = ProcessWindowResult(
        created_count=0,
        exited_count=0,
        samples=15,
        g4_status=STATUS_OK,
        g5_status=STATUS_NOT_APPLICABLE,
        g6_status=STATUS_NOT_APPLICABLE,
    )
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_INSUFFICIENT_ACTIVITY
    assert observation.features is None
    assert observation.feature_status["short_lived_process_ratio"] == "NOT_APPLICABLE_NO_PROCESS_ACTIVITY"
    assert observation.feature_values["short_lived_process_ratio"] is None
    assert observation.sensor_groups["G5"] == STATUS_NOT_APPLICABLE
    # Count features remain measured zeros.
    assert observation.feature_values["destructive_command_count"] == 0.0
    assert observation.feature_status["destructive_command_count"] == STATUS_DEFINED


def test_zero_exits_is_a_measured_zero_and_model_ready():
    inputs = healthy_inputs()
    inputs.processes = ProcessWindowResult(
        created_count=2,
        exited_count=0,
        short_lived_count=0,
        short_lived_ratio=0.0,
        resolution_rate=1.0,
        status_readable_rate=1.0,
        samples=15,
        g4_status=STATUS_OK,
        g5_status=STATUS_OK,
        g6_status=STATUS_OK,
    )
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_MODEL_READY
    index = LBS1_FEATURE_NAMES.index("short_lived_process_ratio")
    assert observation.features[index] == 0.0


def test_inotify_overflow_degrades_g1_and_invalidates_counts():
    inputs = replace(healthy_inputs(), overflow=True)
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_DEGRADED
    assert observation.sensor_groups["G1"] == STATUS_DEGRADED
    assert observation.feature_status["file_mod_rate"] == "UNAVAILABLE_SENSOR"
    assert observation.feature_values["file_mod_rate"] is None
    assert observation.overflow is True


def test_watch_shortfall_degrades_g1():
    inputs = replace(healthy_inputs(), watch_shortfall=3)
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_DEGRADED
    assert observation.sensor_groups["G1"] == STATUS_DEGRADED
    assert any("watch shortfall" in reason for reason in observation.reasons)


def test_unsupported_filesystem_degrades_g1():
    inputs = replace(healthy_inputs(), fs_supported=False, fs_reasons=("UNSUPPORTED_FILESYSTEM:9p:/mnt/c",))
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_DEGRADED
    assert observation.sensor_groups["G1"] == STATUS_DEGRADED
    assert observation.feature_status["files_modified_count"] == "UNAVAILABLE_SENSOR"


def test_insufficient_snapshots_degrade_g4():
    inputs = healthy_inputs()
    inputs.processes = replace(inputs.processes, samples=2, g4_status=STATUS_DEGRADED)
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_DEGRADED
    assert observation.sensor_groups["G4"] == STATUS_DEGRADED
    assert observation.feature_status["process_create_rate"] == "UNAVAILABLE_SENSOR"


def test_low_command_resolution_degrades_g5_features():
    inputs = healthy_inputs()
    inputs.processes = replace(inputs.processes, resolution_rate=0.5, g5_status=STATUS_DEGRADED)
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_DEGRADED
    assert observation.feature_status["destructive_command_count"] == "UNAVAILABLE_SENSOR"
    assert observation.feature_status["shell_spawn_count"] == "UNAVAILABLE_SENSOR"
    assert observation.feature_status["temp_exec_count"] == "UNAVAILABLE_SENSOR"
    assert observation.feature_status["privileged_process_count"] == STATUS_DEFINED


def test_network_failure_degrades_g7():
    inputs = healthy_inputs()
    inputs.network = NetworkResult(status=STATUS_DEGRADED, error="AccessDenied")
    observation = assemble_observation(inputs)
    assert observation.observation_state == STATE_DEGRADED
    assert observation.sensor_groups["G7"] == STATUS_DEGRADED
    assert observation.feature_status["unique_external_ip_count"] == "UNAVAILABLE_SENSOR"
    assert observation.feature_values["unique_external_ip_count"] is None


def test_no_activity_and_unavailable_reasons_are_distinct():
    no_activity = healthy_inputs()
    no_activity.entropy = EventEntropyResult(status=STATUS_NO_FILE_ACTIVITY)
    no_activity.cohort = CohortResult(status=STATUS_NO_BASELINE_COHORT)
    insufficient = assemble_observation(no_activity)

    degraded_inputs = healthy_inputs()
    degraded_inputs.entropy = EventEntropyResult(status=STATUS_UNAVAILABLE_PERMISSION)
    degraded = assemble_observation(degraded_inputs)

    assert insufficient.observation_state != degraded.observation_state
    assert insufficient.observation_state == STATE_INSUFFICIENT_ACTIVITY
    assert degraded.observation_state == STATE_DEGRADED
    assert not set(insufficient.reasons) & set(degraded.reasons)
    assert any("NOT_APPLICABLE" in reason for reason in insufficient.reasons)
    assert any("UNAVAILABLE_PERMISSION" in reason for reason in degraded.reasons)
