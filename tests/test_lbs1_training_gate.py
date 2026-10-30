"""LBS-1 Stage B — training-gate tests. No fitting, no artifacts, test-only markers."""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

import lbs1_support as support

from ml import linux_dataset as ds
from ml import linux_train as trainer


@pytest.fixture
def approved(tmp_path):
    """Create a test-only approval marker under tmp_path and delete it afterwards."""
    markers: list[Path] = []

    def _create(dataset, **overrides):
        artifact_dir = tmp_path / "models" / "linux_v1"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        payload = trainer.build_marker_payload(
            approval_id=overrides.pop("approval_id", "TEST-APPROVAL"),
            approved_on=overrides.pop("approved_on", "2026-10-30"),
            dataset_sha256=overrides.pop("dataset_sha256", dataset.dataset_sha256),
            artifact_dir=overrides.pop("artifact_dir", artifact_dir),
            **overrides,
        )
        marker = artifact_dir / trainer.APPROVAL_MARKER_NAME
        marker.write_text(json.dumps(payload), encoding="utf-8")
        markers.append(marker)
        return artifact_dir, marker

    yield _create

    for marker in markers:
        marker.unlink(missing_ok=True)


def write_marker(artifact_dir: Path, payload) -> Path:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    marker = artifact_dir / trainer.APPROVAL_MARKER_NAME
    text = payload if isinstance(payload, str) else json.dumps(payload)
    marker.write_text(text, encoding="utf-8")
    return marker


def test_no_marker_blocks_training(tmp_path):
    dataset = support.make_dataset_result()
    artifact_dir = tmp_path / "models" / "linux_v1"
    artifact_dir.mkdir(parents=True)

    with pytest.raises(trainer.TrainingBlocked) as excinfo:
        trainer.train(dataset, artifact_dir, project_root=tmp_path)
    assert excinfo.value.code == trainer.BLOCKED_NO_MARKER
    assert "TRAINING_BLOCKED: NO_APPROVAL_MARKER" in str(excinfo.value)


def test_marker_outside_linux_v1_is_refused_before_anything_else(tmp_path):
    dataset = support.make_dataset_result()
    artifact_dir = tmp_path / "models" / "linux_v2"
    artifact_dir.mkdir(parents=True)
    marker = write_marker(
        artifact_dir,
        trainer.build_marker_payload("TEST", "2026-10-30", dataset.dataset_sha256, artifact_dir),
    )
    try:
        with pytest.raises(trainer.TrainingBlocked) as excinfo:
            trainer.train(dataset, artifact_dir, project_root=tmp_path)
        assert excinfo.value.code == trainer.BLOCKED_ARTIFACT_DIR
    finally:
        marker.unlink(missing_ok=True)


def test_invalid_marker_json_is_refused(tmp_path):
    dataset = support.make_dataset_result()
    artifact_dir = tmp_path / "models" / "linux_v1"
    marker = write_marker(artifact_dir, "{not json")
    try:
        with pytest.raises(trainer.TrainingBlocked) as excinfo:
            trainer.train(dataset, artifact_dir, project_root=tmp_path)
        assert excinfo.value.code == trainer.BLOCKED_INVALID_MARKER
    finally:
        marker.unlink(missing_ok=True)


def test_invalid_approval_date_is_refused(tmp_path, approved):
    dataset = support.make_dataset_result()
    artifact_dir, _ = approved(dataset, approved_on="not-a-date")
    with pytest.raises(trainer.TrainingBlocked) as excinfo:
        trainer.train(dataset, artifact_dir, project_root=tmp_path)
    assert excinfo.value.code == trainer.BLOCKED_INVALID_MARKER


def test_marker_for_another_dataset_is_refused(tmp_path, approved):
    dataset = support.make_dataset_result()
    artifact_dir, _ = approved(dataset, dataset_sha256="f" * 64)
    with pytest.raises(trainer.TrainingBlocked) as excinfo:
        trainer.train(dataset, artifact_dir, project_root=tmp_path)
    assert excinfo.value.code == trainer.BLOCKED_DATASET_MISMATCH


def test_marker_for_another_schema_is_refused(tmp_path, approved):
    dataset = support.make_dataset_result()
    artifact_dir, _ = approved(dataset, schema_hash="0" * 64)
    with pytest.raises(trainer.TrainingBlocked) as excinfo:
        trainer.train(dataset, artifact_dir, project_root=tmp_path)
    assert excinfo.value.code == trainer.BLOCKED_SCHEMA_MISMATCH


def test_marker_for_another_artifact_dir_is_refused(tmp_path, approved):
    dataset = support.make_dataset_result()
    artifact_dir, _ = approved(dataset, artifact_dir=tmp_path / "elsewhere")
    with pytest.raises(trainer.TrainingBlocked) as excinfo:
        trainer.train(dataset, artifact_dir, project_root=tmp_path)
    assert excinfo.value.code == trainer.BLOCKED_INVALID_MARKER


def test_below_volume_thresholds_is_refused(tmp_path, approved):
    small = support.make_dataset_result(
        benign_families=2,
        sessions_per_family_per_distro=1,
        windows_per_benign=5,
        hard_benign_per_distro=1,
        simulated_families=2,
        runs_per_family=2,
        windows_per_sim=5,
    )
    artifact_dir, _ = approved(small)
    with pytest.raises(trainer.TrainingBlocked) as excinfo:
        trainer.train(small, artifact_dir, project_root=tmp_path)
    assert excinfo.value.code == trainer.BLOCKED_VOLUME
    assert "MODEL_READY windows" in str(excinfo.value)


def test_full_dataset_dry_run_plans_without_writing(tmp_path, approved):
    dataset = support.make_dataset_result(extra_non_ready=3)
    artifact_dir, _ = approved(dataset)
    before = sorted(path.name for path in artifact_dir.iterdir())

    plan = trainer.train(dataset, artifact_dir, project_root=tmp_path)

    after = sorted(path.name for path in artifact_dir.iterdir())
    assert after == before
    assert plan.included_windows == len(dataset.model_ready_rows)
    assert plan.excluded_non_model_ready == 3
    assert plan.class_counts == {ds.LABEL_BENIGN: 2800, ds.LABEL_ATTACK: 2040}
    assert plan.gates.passed
    assert plan.artifact_dir == artifact_dir.resolve()


def test_plan_accepts_a_valid_grouped_split(tmp_path, approved):
    dataset = support.make_dataset_result()
    split = ds.build_splits(dataset, seed=23)
    assert ds.check_split_gates(split) == []
    artifact_dir, _ = approved(dataset)

    plan = trainer.train(dataset, artifact_dir, project_root=tmp_path, split_result=split)
    assert plan.split_counts["train"] + plan.split_counts["val"] + plan.split_counts["test"] == plan.included_windows


def test_non_dry_run_is_refused_and_writes_nothing(tmp_path, approved):
    dataset = support.make_dataset_result()
    artifact_dir, _ = approved(dataset)
    before = sorted(path.name for path in artifact_dir.iterdir())

    with pytest.raises(trainer.TrainingBlocked) as excinfo:
        trainer.train(dataset, artifact_dir, project_root=tmp_path, dry_run=False)
    assert excinfo.value.code == trainer.BLOCKED_STAGE_D
    assert sorted(path.name for path in artifact_dir.iterdir()) == before


def test_resolve_artifact_dir_defaults_to_production_path():
    expected = PROJECT_ROOT / "models" / "linux_v1"
    assert trainer.resolve_artifact_dir() == expected.resolve()


def test_no_production_marker_exists():
    assert not (PROJECT_ROOT / "models" / "linux_v1" / trainer.APPROVAL_MARKER_NAME).exists()


def test_held_out_rows_are_never_used_for_fitting(tmp_path, approved):
    dataset = support.make_dataset_result(extra_non_ready=5)
    artifact_dir, _ = approved(dataset)
    plan = trainer.train(dataset, artifact_dir, project_root=tmp_path)
    assert plan.excluded_non_model_ready == 5
    assert plan.included_windows == dataset.coverage.model_ready_windows
    assert plan.included_windows + plan.excluded_non_model_ready == dataset.coverage.total_windows
