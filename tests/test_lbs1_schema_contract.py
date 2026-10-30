"""LBS-1 Stage B — schema contract tests."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pytest

import lbs1_support as support
from scanner.linux_telemetry import (
    GROUP_FEATURES,
    LBS1_FEATURE_NAMES as TELEMETRY_FEATURE_NAMES,
    assemble_observation,
)
from test_lbs1_sensor_health import healthy_inputs

from ml import linux_schema as schema


def test_feature_names_exact_order_and_count():
    assert schema.FEATURE_COUNT == 20
    assert len(schema.LBS1_FEATURE_NAMES) == 20
    assert len(set(schema.LBS1_FEATURE_NAMES)) == 20
    assert tuple(schema.LBS1_FEATURE_NAMES) == tuple(TELEMETRY_FEATURE_NAMES)


def test_units_cover_every_feature():
    assert set(schema.FEATURE_UNITS) == set(schema.LBS1_FEATURE_NAMES)
    assert all(unit for unit in schema.FEATURE_UNITS.values())


def test_group_feature_map_matches_collector():
    assert schema.GROUP_FEATURE_NAMES == {group: tuple(names) for group, names in GROUP_FEATURES.items()}


def test_schema_hash_is_pinned_and_stable():
    assert schema.schema_hash() == support.EXPECTED_SCHEMA_HASH
    assert schema.schema_hash(schema.schema_dict()) == support.EXPECTED_SCHEMA_HASH


def test_schema_hash_changes_on_reorder():
    payload = schema.schema_dict()
    payload["feature_names"] = list(reversed(payload["feature_names"]))
    assert schema.schema_hash(payload) != support.EXPECTED_SCHEMA_HASH


def test_critical_disabled_in_schema():
    assert schema.LBS1_CRITICAL_ENABLED is False
    assert schema.schema_dict()["critical_enabled"] is False


@pytest.mark.parametrize("count", [19, 21])
def test_build_vector_rejects_wrong_feature_count(count):
    names = list(schema.LBS1_FEATURE_NAMES)[:count]
    if count > schema.FEATURE_COUNT:
        names = list(schema.LBS1_FEATURE_NAMES) + ["extra_feature"]
    values = {name: 0.0 for name in names}
    status = {name: schema.STATUS_DEFINED for name in names}
    with pytest.raises(schema.LinuxSchemaError):
        schema.build_vector(values, status)


def test_build_vector_rejects_extra_or_missing_keys():
    values = support.ready_values()
    status = support.all_defined()
    extra_values = dict(values, extra=1.0)
    with pytest.raises(schema.LinuxSchemaError):
        schema.build_vector(extra_values, status)
    missing_status = dict(status)
    del missing_status["file_mod_rate"]
    with pytest.raises(schema.LinuxSchemaError):
        schema.build_vector(values, missing_status)


def test_build_vector_refuses_undefined_status_even_with_a_number():
    values = dict(support.ready_values())
    status = support.all_defined()
    status["avg_shannon_entropy"] = schema.STATUS_NO_FILE_ACTIVITY
    values["avg_shannon_entropy"] = 4.2  # a number must not rescue an undefined feature
    with pytest.raises(schema.LinuxSchemaError):
        schema.build_vector(values, status)


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), -0.1, None, "0.5", True])
def test_build_vector_rejects_invalid_values(bad_value):
    values = dict(support.ready_values())
    values["file_mod_rate"] = bad_value
    with pytest.raises(schema.LinuxSchemaError):
        schema.build_vector(values, support.all_defined())


@pytest.mark.parametrize(
    "vector",
    [
        np.zeros(19),
        np.zeros(21),
        np.zeros((1, 20)),
        np.full(20, np.nan),
        np.full(20, np.inf),
        np.full(20, -1.0),
        np.zeros(20, dtype=bool),
        np.zeros(20, dtype=object),
    ],
)
def test_validate_vector_rejects_invalid_vectors(vector):
    with pytest.raises(schema.LinuxSchemaError):
        schema.validate_vector(vector)


def test_validate_vector_returns_float64_copy():
    reference = np.arange(20, dtype=np.int64)
    validated = schema.validate_vector(reference)
    assert validated.dtype == np.float64
    assert validated.shape == (20,)


@pytest.mark.parametrize("group", schema.SENSOR_GROUPS)
def test_each_non_ok_group_prevents_model_ready(group):
    status = support.all_defined()
    groups = support.all_groups_ok()
    groups[group] = schema.GROUP_NOT_APPLICABLE
    assert schema.observation_state_from(status, groups) == schema.STATE_INSUFFICIENT_ACTIVITY
    groups[group] = schema.GROUP_DEGRADED
    assert schema.observation_state_from(status, groups) == schema.STATE_DEGRADED


def test_any_non_defined_feature_prevents_model_ready():
    status = support.all_defined()
    status["short_lived_process_ratio"] = schema.STATUS_NO_PROCESS_ACTIVITY
    assert (
        schema.observation_state_from(status, support.all_groups_ok())
        == schema.STATE_INSUFFICIENT_ACTIVITY
    )
    status["short_lived_process_ratio"] = schema.STATUS_UNAVAILABLE_SENSOR
    assert schema.observation_state_from(status, support.all_groups_ok()) == schema.STATE_DEGRADED


def test_model_ready_requires_every_group_ok_and_every_feature_defined():
    assert (
        schema.observation_state_from(support.all_defined(), support.all_groups_ok())
        == schema.STATE_MODEL_READY
    )


def test_quiet_activity_is_insufficient_not_degraded():
    state = schema.observation_state_from(support.quiet_statuses(), support.all_groups_ok())
    assert state == schema.STATE_INSUFFICIENT_ACTIVITY


def test_degraded_dominates_not_applicable():
    groups = support.all_groups_ok()
    groups["G5"] = schema.GROUP_NOT_APPLICABLE
    groups["G7"] = schema.GROUP_DEGRADED
    assert schema.observation_state_from(support.all_defined(), groups) == schema.STATE_DEGRADED


def test_validate_observation_accepts_stage_a_observation():
    observation = assemble_observation(healthy_inputs())
    vector = schema.validate_observation(observation)
    assert vector is not None
    assert vector.shape == (20,)
    assert np.array_equal(vector, observation.features)


def test_validate_observation_rejects_declared_state_mismatch():
    observation = support.make_observation(
        status_overrides={"avg_shannon_entropy": schema.STATUS_NO_FILE_ACTIVITY},
        group_overrides={"G2": schema.GROUP_NOT_APPLICABLE},
        declared_state=schema.STATE_MODEL_READY,
    )
    with pytest.raises(schema.LinuxSchemaError):
        schema.validate_observation(observation)


def test_validate_observation_rejects_vector_on_non_ready_observation():
    observation = support.make_observation(
        status_overrides={"avg_shannon_entropy": schema.STATUS_UNAVAILABLE_PERMISSION},
        group_overrides={"G2": schema.GROUP_DEGRADED},
    )
    observation.features = np.zeros(20, dtype=np.float64)
    with pytest.raises(schema.LinuxSchemaError):
        schema.validate_observation(observation)


def test_validate_observation_rejects_vector_disagreeing_with_values():
    observation = support.make_observation()
    observation.features[0], observation.features[1] = observation.features[1], observation.features[0]
    with pytest.raises(schema.LinuxSchemaError):
        schema.validate_observation(observation)


def test_non_defined_feature_cannot_carry_a_value():
    observation = support.make_observation(
        status_overrides={"entropy_increase_ratio": schema.STATUS_COHORT_UNAVAILABLE},
        group_overrides={"G2": schema.GROUP_NOT_APPLICABLE},
    )
    observation.feature_values["entropy_increase_ratio"] = 0.0
    with pytest.raises(schema.LinuxSchemaError):
        schema.validate_observation(observation)


def test_non_ready_observation_returns_none():
    observation = support.make_observation(
        status_overrides={"short_lived_process_ratio": schema.STATUS_NO_PROCESS_ACTIVITY},
        group_overrides={"G5": schema.GROUP_NOT_APPLICABLE},
    )
    assert observation.observation_state == schema.STATE_INSUFFICIENT_ACTIVITY
    assert schema.validate_observation(observation) is None
