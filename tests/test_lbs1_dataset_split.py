"""LBS-1 Stage B — dataset, coverage, and grouped-split tests (synthetic fixtures only)."""

import dataclasses
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

import lbs1_support as support

from ml import linux_dataset as ds
from ml import linux_evaluate as ev
from ml import linux_schema as schema


def add_benign(root, session_id, family, distro, **kwargs):
    return support.write_session(
        root,
        "benign",
        session_id,
        source_type=ds.SOURCE_BENIGN,
        family=family,
        distro=distro,
        label=ds.LABEL_BENIGN,
        **kwargs,
    )


def add_simulated(root, session_id, family, distro, **kwargs):
    return support.write_session(
        root,
        "simulated",
        session_id,
        source_type=ds.SOURCE_SIMULATED,
        family=family,
        distro=distro,
        label=ds.LABEL_ATTACK,
        **kwargs,
    )


def test_load_dataset_counts_and_coverage(tmp_path):
    add_benign(tmp_path, "b1", "build", "kali", ready=3, insufficient=1)
    add_simulated(tmp_path, "s1", "bulk-overwrite", "ubuntu", ready=2, degraded=1)

    dataset = ds.load_dataset(tmp_path)
    assert len(dataset.sessions) == 2
    assert dataset.coverage.total_windows == 7
    assert dataset.coverage.model_ready_windows == 5
    assert dataset.coverage.insufficient_activity_windows == 1
    assert dataset.coverage.degraded_windows == 1
    assert len(dataset.model_ready_rows) == 5
    assert all(row.feature_vector is not None for row in dataset.model_ready_rows)
    assert dataset.coverage.by_distro["kali"]["MODEL_READY"] == 3


def test_shared_observation_id_is_deduplicated(tmp_path):
    add_benign(tmp_path, "b1", "build", "kali", ready=2, shared_observation_id="dup-row")
    add_benign(tmp_path, "b2", "build", "kali", ready=2, shared_observation_id="dup-row")

    dataset = ds.load_dataset(tmp_path)
    assert dataset.duplicates_removed == 1
    assert len(dataset.rows) == 3


def test_rejects_hand_authored_vector(tmp_path):
    support.write_session(
        tmp_path,
        "benign",
        "b1",
        source_type=ds.SOURCE_HAND_AUTHORED,
        family="build",
        distro="kali",
        label=ds.LABEL_BENIGN,
    )
    with pytest.raises(ds.ManifestError):
        ds.load_dataset(tmp_path)


def test_rejects_wsl_sessions(tmp_path):
    add_benign(tmp_path, "b1", "build", "wsl")
    with pytest.raises(ds.ManifestError):
        ds.load_dataset(tmp_path)


def test_rejects_label_source_mismatch(tmp_path):
    support.write_session(
        tmp_path,
        "benign",
        "b1",
        source_type=ds.SOURCE_BENIGN,
        family="build",
        distro="kali",
        label=ds.LABEL_ATTACK,
    )
    with pytest.raises(ds.ManifestError):
        ds.load_dataset(tmp_path)


def test_rejects_missing_manifest_field(tmp_path):
    add_benign(tmp_path, "b1", "build", "kali", manifest_overrides={"seed": None})
    with pytest.raises(ds.ManifestError):
        ds.load_dataset(tmp_path)


def test_rejects_non_ready_row_carrying_values(tmp_path):
    session_dir = add_benign(tmp_path, "b1", "build", "kali", ready=0)
    payload = support.row_payload(0, state=schema.STATE_INSUFFICIENT_ACTIVITY)
    payload["feature_values"]["avg_shannon_entropy"] = 5.0
    with open(session_dir / "observations.jsonl", "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")
    with pytest.raises(ds.DatasetError):
        ds.load_dataset(tmp_path)


def test_non_model_ready_rows_are_excluded_and_counted(tmp_path):
    add_benign(tmp_path, "b1", "build", "kali", ready=4, insufficient=2, degraded=1)
    dataset = ds.load_dataset(tmp_path)
    assert dataset.coverage.model_ready_windows == 4
    assert dataset.coverage.non_model_ready_windows == 3
    assert len(dataset.model_ready_rows) == 4
    assert all(row.observation_state == schema.STATE_MODEL_READY for row in dataset.model_ready_rows)


def build_balanced_dataset(root):
    for distro in ds.VALID_DISTROS:
        for family in ("build", "archives"):
            for index in range(4):
                add_benign(root, f"{distro}-{family}-{index}", family, distro, ready=2)
        for family in ("bulk-overwrite", "extension-rewrite"):
            for index in range(4):
                add_simulated(root, f"{distro}-{family}-{index}", family, distro, ready=2)
    return ds.load_dataset(root)


def test_no_session_crosses_splits(tmp_path):
    dataset = build_balanced_dataset(tmp_path)
    split = ds.build_splits(dataset, seed=7)

    sets = {name: {row.session_id for row in rows} for name, rows in split.splits.items()}
    assert sets["train"] & sets["val"] == set()
    assert sets["train"] & sets["test"] == set()
    assert sets["val"] & sets["test"] == set()
    assert set().union(*sets.values()) == set(dataset.session_ids())
    assert sum(len(rows) for rows in split.splits.values()) == len(dataset.rows)


def test_family_stratification_puts_every_family_in_train(tmp_path):
    for family in [f"family-{index}" for index in range(10)]:
        for index in range(4):
            add_benign(tmp_path, f"{family}-{index}", family, "kali", ready=1)
    dataset = ds.load_dataset(tmp_path)
    split = ds.build_splits(dataset, seed=11)

    train_families = {row.family for row in split.splits["train"]}
    assert train_families == {f"family-{index}" for index in range(10)}
    for family in train_families:
        assert any(row.family == family for row in split.splits["val"])
        assert any(row.family == family for row in split.splits["test"])


def test_split_assignment_is_deterministic_for_a_seed(tmp_path):
    dataset = build_balanced_dataset(tmp_path)
    first = ds.assign_splits(dataset.sessions, seed=42)
    second = ds.assign_splits(dataset.sessions, seed=42)
    other = ds.assign_splits(dataset.sessions, seed=43)
    assert first.mapping == second.mapping
    assert first.mapping != other.mapping


def test_split_gates_require_both_distros_in_train_and_test(tmp_path):
    dataset = build_balanced_dataset(tmp_path)
    split = ds.build_splits(dataset, seed=3)
    assert ds.check_split_gates(split) == []

    kali_only_root = tmp_path / "kali-only"
    for index in range(4):
        add_benign(kali_only_root, f"k{index}", "build", "kali", ready=2)
    kali_dataset = ds.load_dataset(kali_only_root)
    kali_split = ds.build_splits(kali_dataset, seed=3)
    violations = ds.check_split_gates(kali_split)
    assert any("ubuntu" in violation for violation in violations)


def test_split_lock_prevents_resplit(tmp_path):
    dataset = build_balanced_dataset(tmp_path)
    split = ds.build_splits(dataset, seed=9)
    output = tmp_path / "split"
    lock = ds.write_splits(output, split)
    assert lock.name == ds.SPLIT_MANIFEST_FILENAME
    with pytest.raises(ds.SplitLockedError):
        ds.write_splits(output, split)

    manifest = ds.load_split_manifest(output)
    assert manifest["dataset_sha256"] == dataset.dataset_sha256
    assert manifest["seed"] == 9

    (output / "train.jsonl").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ds.DatasetError):
        ds.load_split_manifest(output)


def test_volume_gates_report_hard_benign_shortfall():
    dataset = support.make_dataset_result(hard_benign_per_distro=0)
    report = ds.check_volume_gates(dataset)
    assert not report.passed
    assert any("hard-benign" in violation for violation in report.violations)


def test_full_synthetic_dataset_passes_volume_gates():
    dataset = support.make_dataset_result()
    report = ds.check_volume_gates(dataset)
    assert report.passed, report.violations
    assert report.benign_sessions == 56
    assert report.benign_families == 11
    assert report.benign_model_ready == 2800
    assert report.hard_benign_per_distro == {"kali": 8, "ubuntu": 8}
    assert report.simulated_runs == 60
    assert report.simulated_families == 6
    assert report.simulated_model_ready == 2040


def test_small_dataset_fails_volume_gates(tmp_path):
    add_benign(tmp_path, "b1", "build", "kali", ready=2)
    dataset = ds.load_dataset(tmp_path)
    report = ds.check_volume_gates(dataset)
    assert not report.passed
    assert any("MODEL_READY windows" in violation for violation in report.violations)


def test_test_split_lock_is_one_shot(tmp_path):
    dataset = build_balanced_dataset(tmp_path)
    split = ds.build_splits(dataset, seed=5)
    artifact_dir = tmp_path / "models" / "linux_v1"
    ev.consume_test_split(artifact_dir, dataset.dataset_sha256)
    with pytest.raises(ev.EvaluationError):
        ev.consume_test_split(artifact_dir, dataset.dataset_sha256)


def test_evaluation_reports_non_evaluable_test_sessions(tmp_path):
    dataset = build_balanced_dataset(tmp_path)
    split = ds.build_splits(dataset, seed=5)
    rows = [row for row in split.splits["test"] if row.model_ready][:4]
    assert rows
    scores = [0.1 if row.label == ds.LABEL_BENIGN else 0.9 for row in rows]
    test_sessions = sorted({row.session_id for row in rows} | {"session-with-no-ready-window"})

    report = ev.evaluate_test(rows, scores, 0.5, test_sessions=test_sessions)
    assert report.non_evaluable_sessions == ["session-with-no-ready-window"]
    assert report.non_evaluable_ratio == pytest.approx(1 / len(test_sessions))
    assert report.conclusion == "INCONCLUSIVE"
    assert report.confusion["tp"] + report.confusion["tn"] == len(rows)


def test_evaluation_refuses_non_ready_rows(tmp_path):
    dataset = build_balanced_dataset(tmp_path)
    split = ds.build_splits(dataset, seed=5)
    ready = split.splits["test"][0]
    degraded = dataclasses.replace(ready, observation_state=schema.STATE_DEGRADED)
    with pytest.raises(ev.EvaluationError):
        ev.evaluate_test([degraded], [0.5], 0.5)


def test_clustered_bootstrap_bounds_are_ordered(tmp_path):
    dataset = build_balanced_dataset(tmp_path)
    split = ds.build_splits(dataset, seed=5)
    rows = split.splits["test"]
    scores = [0.1 if row.label == ds.LABEL_BENIGN else 0.9 for row in rows]
    interval = ev.clustered_bootstrap_ci(
        scores,
        [row.label for row in rows],
        [row.session_id for row in rows],
        metric=lambda counts: ev.metrics_from_confusion(counts)["f1"],
        threshold=0.5,
        resamples=100,
    )
    assert interval is not None
    assert 0.0 <= interval[0] <= interval[1] <= 1.0
