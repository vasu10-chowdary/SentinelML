"""LBS-1 Stage A — privacy: no content, cmdline, username or absolute home path is persisted."""

import dataclasses
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
for candidate in (PROJECT_ROOT, TESTS_DIR):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from scanner.linux_telemetry import LBS1_FEATURE_NAMES, LinuxObservation, assemble_observation

from test_lbs1_sensor_health import healthy_inputs


def test_observation_has_no_path_or_content_fields():
    names = {field.name for field in dataclasses.fields(LinuxObservation)}
    forbidden = {
        "path",
        "paths",
        "filename",
        "filenames",
        "content",
        "cmdline",
        "argv",
        "username",
        "home",
        "file_bytes",
    }
    assert names.isdisjoint(forbidden)
    assert names == {
        "features",
        "feature_values",
        "feature_status",
        "observation_state",
        "sensor_groups",
        "reasons",
        "window_seconds",
        "overflow",
        "filesystem_types",
        "events_processed",
        "platform",
        "collector_version",
        "list_version",
    }


def test_observation_serialisation_contains_no_event_paths():
    inputs = healthy_inputs()
    # Deliberately put a username-like path in the event summary.
    inputs.file_summary.close_write_paths = {"/home/alice/Documents/secret.txt"}
    observation = assemble_observation(inputs)
    payload = json.dumps(
        {
            "feature_values": observation.feature_values,
            "feature_status": observation.feature_status,
            "state": observation.observation_state,
            "groups": observation.sensor_groups,
            "reasons": list(observation.reasons),
        }
    )
    assert "/home/alice" not in payload
    assert "secret.txt" not in payload
    assert "alice" not in payload
    assert set(observation.feature_values) == set(LBS1_FEATURE_NAMES)


def test_observation_reasons_do_not_embed_target_paths_when_healthy():
    observation = assemble_observation(healthy_inputs())
    assert observation.reasons == ()
    assert observation.platform == "linux"
    assert isinstance(observation.collector_version, str)


def test_entropy_sample_is_transient():
    from scanner.linux_entropy import sample_file

    sample = sample_file(__file__)
    assert sample.entropy is not None
    # The sample object carries a path for internal pairing but no content field.
    assert not hasattr(sample, "data")
    assert not hasattr(sample, "bytes")


def test_process_observation_exposes_only_counts():
    observation = assemble_observation(healthy_inputs())
    values = observation.feature_values
    assert "destructive_command_count" in values
    assert not any("argv" in key or "cmdline" in key for key in values)
