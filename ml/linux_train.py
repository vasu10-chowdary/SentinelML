"""LBS-1 training gate.

Stage B builds the gate only; it performs **no fitting**. Training requires an explicit
`APPROVED_FOR_TRAINING` marker (G2) inside `models/linux_v1/`, a dataset that passes the
Stage C volume gates, and a split that keeps both native distros in train and test.

Non-`MODEL_READY` windows are always excluded from model inputs and reported by count —
never imputed, never zero-filled.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ml import linux_dataset as dataset_mod
from ml import linux_schema as schema

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIRNAME = "models"
LINUX_ARTIFACT_DIRNAME = "linux_v1"
APPROVAL_MARKER_NAME = "APPROVED_FOR_TRAINING"

MARKER_REQUIRED_FIELDS = (
    "approval_id",
    "approved_on",
    "dataset_sha256",
    "artifact_dir",
    "schema_hash",
)

BLOCKED_NO_MARKER = "TRAINING_BLOCKED: NO_APPROVAL_MARKER"
BLOCKED_INVALID_MARKER = "TRAINING_BLOCKED: INVALID_APPROVAL_MARKER"
BLOCKED_ARTIFACT_DIR = "TRAINING_BLOCKED: ARTIFACT_DIR_NOT_ALLOWED"
BLOCKED_DATASET_MISMATCH = "TRAINING_BLOCKED: DATASET_MISMATCH"
BLOCKED_SCHEMA_MISMATCH = "TRAINING_BLOCKED: SCHEMA_MISMATCH"
BLOCKED_VOLUME = "TRAINING_BLOCKED: VOLUME_GATES_FAILED"
BLOCKED_SPLIT = "TRAINING_BLOCKED: SPLIT_GATES_FAILED"
BLOCKED_STAGE_D = "TRAINING_BLOCKED: STAGE_D_NOT_IMPLEMENTED"


class TrainingBlocked(RuntimeError):
    """Raised whenever a training precondition is not met."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        message = code if not detail else f"{code}: {detail}"
        super().__init__(message)


@dataclass
class TrainingPlan:
    artifact_dir: Path
    dataset_sha256: str
    included_windows: int
    excluded_non_model_ready: int
    class_counts: dict[int, int]
    family_counts: dict[str, int]
    split_counts: dict[str, int]
    gates: dataset_mod.VolumeReport
    approval: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifact_dir": str(self.artifact_dir),
            "dataset_sha256": self.dataset_sha256,
            "included_windows": self.included_windows,
            "excluded_non_model_ready": self.excluded_non_model_ready,
            "class_counts": dict(self.class_counts),
            "family_counts": dict(self.family_counts),
            "split_counts": dict(self.split_counts),
            "gates": self.gates.as_dict(),
            "approval": dict(self.approval),
        }


def resolve_artifact_dir(
    artifact_dir: Optional[str | Path] = None,
    project_root: str | Path = PROJECT_ROOT,
) -> Path:
    """The only writable artifact location is `<project_root>/models/linux_v1`."""
    expected = (Path(project_root) / MODELS_DIRNAME / LINUX_ARTIFACT_DIRNAME).resolve()
    if artifact_dir is None:
        return expected
    provided = Path(artifact_dir).resolve()
    if provided != expected:
        raise TrainingBlocked(
            BLOCKED_ARTIFACT_DIR,
            f"{provided} is not {expected}",
        )
    return provided


def build_marker_payload(
    approval_id: str,
    approved_on: str,
    dataset_sha256: str,
    artifact_dir: str | Path,
    schema_hash: Optional[str] = None,
) -> dict[str, Any]:
    return {
        "approval_id": approval_id,
        "approved_on": approved_on,
        "dataset_sha256": dataset_sha256,
        "artifact_dir": str(Path(artifact_dir).resolve()),
        "schema_hash": schema_hash or schema.schema_hash(),
    }


def verify_training_approval(
    artifact_dir: Path,
    dataset_sha256: str,
    marker_path: Optional[Path] = None,
) -> dict[str, Any]:
    artifact_dir = Path(artifact_dir).resolve()
    marker = Path(marker_path) if marker_path is not None else artifact_dir / APPROVAL_MARKER_NAME

    if not marker.is_file():
        raise TrainingBlocked(BLOCKED_NO_MARKER, f"no marker at {marker}")

    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrainingBlocked(BLOCKED_INVALID_MARKER, f"{marker}: {exc}") from exc
    if not isinstance(payload, dict):
        raise TrainingBlocked(BLOCKED_INVALID_MARKER, "marker is not a JSON object")

    missing = [name for name in MARKER_REQUIRED_FIELDS if name not in payload]
    if missing:
        raise TrainingBlocked(BLOCKED_INVALID_MARKER, f"marker missing fields {missing}")

    try:
        _dt.date.fromisoformat(str(payload["approved_on"]))
    except ValueError as exc:
        raise TrainingBlocked(BLOCKED_INVALID_MARKER, "approved_on is not an ISO date") from exc

    marker_dir = Path(str(payload["artifact_dir"])).resolve()
    if marker_dir != artifact_dir:
        raise TrainingBlocked(
            BLOCKED_INVALID_MARKER,
            f"marker artifact_dir {marker_dir} != {artifact_dir}",
        )
    if payload["dataset_sha256"] != dataset_sha256:
        raise TrainingBlocked(BLOCKED_DATASET_MISMATCH, "approval does not cover this dataset")
    if payload["schema_hash"] != schema.schema_hash():
        raise TrainingBlocked(BLOCKED_SCHEMA_MISMATCH, "approval does not cover the LBS-1 schema")
    return dict(payload)


def plan_training(
    dataset: dataset_mod.DatasetResult,
    split_result: Optional[dataset_mod.SplitResult] = None,
    gates: dataset_mod.VolumeGates = dataset_mod.VOLUME_GATES,
) -> TrainingPlan:
    """Validate gates and describe the fitting population. No fitting happens here."""
    report = dataset_mod.check_volume_gates(dataset, gates)
    if not report.passed:
        raise TrainingBlocked(BLOCKED_VOLUME, "; ".join(report.violations))

    if split_result is not None:
        split_violations = dataset_mod.check_split_gates(split_result)
        if split_violations:
            raise TrainingBlocked(BLOCKED_SPLIT, "; ".join(split_violations))

    included = dataset.model_ready_rows
    if not included:
        raise TrainingBlocked(BLOCKED_VOLUME, "no MODEL_READY windows")

    class_counts: dict[int, int] = {}
    family_counts: dict[str, int] = {}
    for row in included:
        class_counts[row.label] = class_counts.get(row.label, 0) + 1
        family_counts[row.family] = family_counts.get(row.family, 0) + 1

    split_counts = (
        {name: len(split_result.splits[name]) for name in dataset_mod.SPLIT_NAMES}
        if split_result is not None
        else {}
    )

    return TrainingPlan(
        artifact_dir=Path(""),
        dataset_sha256=dataset.dataset_sha256,
        included_windows=len(included),
        excluded_non_model_ready=dataset.coverage.non_model_ready_windows,
        class_counts=class_counts,
        family_counts=family_counts,
        split_counts=split_counts,
        gates=report,
    )


def train(
    dataset: dataset_mod.DatasetResult,
    artifact_dir: Optional[str | Path] = None,
    project_root: str | Path = PROJECT_ROOT,
    dry_run: bool = True,
    split_result: Optional[dataset_mod.SplitResult] = None,
    gates: dataset_mod.VolumeGates = dataset_mod.VOLUME_GATES,
) -> TrainingPlan:
    """Dry-run the gate chain. Stage B never fits; `dry_run=False` is refused."""
    resolved = resolve_artifact_dir(artifact_dir, project_root)
    approval = verify_training_approval(resolved, dataset.dataset_sha256)

    plan = plan_training(dataset, split_result=split_result, gates=gates)
    plan.artifact_dir = resolved
    plan.approval = {
        "approval_id": approval["approval_id"],
        "approved_on": approval["approved_on"],
    }

    if not dry_run:
        raise TrainingBlocked(
            BLOCKED_STAGE_D,
            "Stage B builds the gate only; fitting belongs to Stage D after G2",
        )
    return plan
