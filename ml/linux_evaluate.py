"""LBS-1 held-out evaluation.

This module never trains, never tunes a threshold, and never opens the test split twice.
It consumes `MODEL_READY` rows scored by `ml.linux_predictor`, and reports what the evidence
supports: confusion matrix at the frozen threshold, per-family tables, session- and
window-level metrics, Brier score, ECE, and clustered bootstrap intervals.

Non-evaluable sessions (no `MODEL_READY` windows) are reported by name rather than silently
dropped; a test split where more than 10% of sessions are non-evaluable is marked
`INCONCLUSIVE` in the report.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

import numpy as np

from ml import linux_dataset as dataset_mod
from ml import linux_schema as schema

TEST_LOCK_NAME = "TEST_SPLIT_OPENED"
MAX_NON_EVALUABLE_SESSION_RATIO = 0.10
BOOTSTRAP_RESAMPLES = 1000
ECE_BINS = 10


class EvaluationError(RuntimeError):
    """Raised when the evaluation protocol is violated."""


@dataclass
class TestSplitLock:
    dataset_sha256: str
    split_manifest_sha256: str
    opened_at: str


def consume_test_split(
    artifact_dir: Path,
    dataset_sha256: str,
    split_manifest_path: Optional[Path] = None,
    opened_at: str = "",
) -> TestSplitLock:
    """Open the test split exactly once; the marker file is the lock."""
    artifact_dir = Path(artifact_dir)
    marker = artifact_dir / TEST_LOCK_NAME
    if marker.exists():
        raise EvaluationError(f"test split already opened: {marker}")
    split_hash = ""
    if split_manifest_path is not None:
        split_hash = hashlib.sha256(Path(split_manifest_path).read_bytes()).hexdigest()
    lock = TestSplitLock(
        dataset_sha256=dataset_sha256,
        split_manifest_sha256=split_hash,
        opened_at=opened_at,
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    marker.write_text(schema.canonical_json(lock.__dict__) + "\n", encoding="utf-8", newline="\n")
    return lock


def confusion_at(scores: Sequence[float], labels: Sequence[int], threshold: float) -> dict[str, int]:
    if len(scores) != len(labels):
        raise EvaluationError("scores and labels length mismatch")
    scores_arr = np.asarray(scores, dtype=np.float64)
    labels_arr = np.asarray(labels, dtype=np.int64)
    if scores_arr.size and not np.all(np.isfinite(scores_arr)):
        raise EvaluationError("non-finite scores")
    predicted = scores_arr >= threshold
    positive = labels_arr == dataset_mod.LABEL_ATTACK
    return {
        "tp": int(np.sum(predicted & positive)),
        "fp": int(np.sum(predicted & ~positive)),
        "tn": int(np.sum(~predicted & ~positive)),
        "fn": int(np.sum(~predicted & positive)),
    }


def _safe_ratio(numerator: float, denominator: float) -> Optional[float]:
    return None if denominator == 0 else float(numerator / denominator)


def metrics_from_confusion(counts: Mapping[str, int]) -> dict[str, Optional[float]]:
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": _safe_ratio(tn, tn + fp),
        "accuracy": _safe_ratio(tp + tn, tp + tn + fp + fn),
    }


def brier_score(scores: Sequence[float], labels: Sequence[int]) -> Optional[float]:
    if not len(scores):
        return None
    scores_arr = np.asarray(scores, dtype=np.float64)
    labels_arr = np.asarray(labels, dtype=np.float64)
    return float(np.mean((scores_arr - labels_arr) ** 2))


def expected_calibration_error(
    scores: Sequence[float], labels: Sequence[int], bins: int = ECE_BINS
) -> Optional[float]:
    if not len(scores):
        return None
    scores_arr = np.asarray(scores, dtype=np.float64)
    labels_arr = np.asarray(labels, dtype=np.float64)
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = len(scores_arr)
    error = 0.0
    for index in range(bins):
        lower, upper = edges[index], edges[index + 1]
        mask = (scores_arr >= lower) & (scores_arr < upper if index < bins - 1 else scores_arr <= upper)
        if not np.any(mask):
            continue
        bin_weight = np.sum(mask) / total
        error += bin_weight * abs(float(np.mean(scores_arr[mask])) - float(np.mean(labels_arr[mask])))
    return float(error)


def clustered_bootstrap_ci(
    scores: Sequence[float],
    labels: Sequence[int],
    clusters: Sequence[str],
    metric: Callable[[Sequence[float], Sequence[int]], Optional[float]],
    threshold: Optional[float] = None,
    resamples: int = BOOTSTRAP_RESAMPLES,
    seed: int = 20261030,
) -> Optional[tuple[float, float]]:
    """Percentile CI resampling whole sessions, never individual windows."""
    if len(scores) != len(labels) or len(scores) != len(clusters):
        raise EvaluationError("scores/labels/clusters length mismatch")
    by_cluster: dict[str, list[int]] = {}
    for index, cluster in enumerate(clusters):
        by_cluster.setdefault(str(cluster), []).append(index)
    keys = sorted(by_cluster)
    if not keys:
        return None

    scores_arr = np.asarray(scores, dtype=np.float64)
    labels_arr = np.asarray(labels, dtype=np.int64)
    rng = np.random.default_rng(seed)
    values: list[float] = []
    for _ in range(resamples):
        chosen = rng.choice(len(keys), size=len(keys), replace=True)
        indices = [i for choice in chosen for i in by_cluster[keys[int(choice)]]]
        if threshold is None:
            value = metric(list(scores_arr[indices]), list(labels_arr[indices]))
        else:
            counts = confusion_at(scores_arr[indices], labels_arr[indices], threshold)
            value = metric(counts)
        if value is not None and np.isfinite(value):
            values.append(float(value))
    if not values:
        return None
    low, high = np.percentile(values, [2.5, 97.5])
    return float(low), float(high)


@dataclass
class EvaluationReport:
    threshold: float
    windows: int
    sessions: int
    confusion: dict[str, int]
    window_metrics: dict[str, Optional[float]]
    session_metrics: dict[str, Optional[float]]
    per_family: dict[str, dict[str, Any]]
    brier: Optional[float]
    ece: Optional[float]
    non_evaluable_sessions: list[str]
    non_evaluable_ratio: float
    conclusion: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "windows": self.windows,
            "sessions": self.sessions,
            "confusion": dict(self.confusion),
            "window_metrics": dict(self.window_metrics),
            "session_metrics": dict(self.session_metrics),
            "per_family": dict(self.per_family),
            "brier": self.brier,
            "ece": self.ece,
            "non_evaluable_sessions": list(self.non_evaluable_sessions),
            "non_evaluable_ratio": self.non_evaluable_ratio,
            "conclusion": self.conclusion,
        }


def evaluate_test(
    rows: Sequence[dataset_mod.ObservationRow],
    scores: Sequence[float],
    threshold: float,
    test_sessions: Optional[Iterable[str]] = None,
) -> EvaluationReport:
    """Evaluate scored test rows. `rows` must already be MODEL_READY-only.

    `test_sessions` is the session list assigned to the test split; sessions assigned to
    test but with no MODEL_READY window are reported as non-evaluable. Do not pass the
    whole dataset's session list here.
    """
    if len(rows) != len(scores):
        raise EvaluationError("rows and scores length mismatch")
    if any(not row.model_ready for row in rows):
        raise EvaluationError("evaluate_test received non-MODEL_READY rows")

    labels = [row.label for row in rows]
    clusters = [row.session_id for row in rows]
    confusion = confusion_at(scores, labels, threshold)

    per_family: dict[str, dict[str, Any]] = {}
    for family in sorted({row.family for row in rows}):
        indices = [i for i, row in enumerate(rows) if row.family == family]
        family_counts = confusion_at([scores[i] for i in indices], [labels[i] for i in indices], threshold)
        per_family[family] = {
            "windows": len(indices),
            "confusion": family_counts,
            "metrics": metrics_from_confusion(family_counts),
        }

    session_scores: dict[str, list[float]] = {}
    session_label: dict[str, int] = {}
    for row, score in zip(rows, scores):
        session_scores.setdefault(row.session_id, []).append(float(score))
        session_label[row.session_id] = row.label
    session_ids = sorted(session_scores)
    aggregate = [max(session_scores[session_id]) for session_id in session_ids]
    session_confusion = confusion_at(aggregate, [session_label[session_id] for session_id in session_ids], threshold)

    known_sessions = sorted(set(test_sessions)) if test_sessions is not None else list(session_ids)
    non_evaluable = [session for session in known_sessions if session not in session_scores]
    ratio = (len(non_evaluable) / len(known_sessions)) if known_sessions else 0.0
    conclusion = "INCONCLUSIVE" if ratio > MAX_NON_EVALUABLE_SESSION_RATIO else "EVALUATED"

    return EvaluationReport(
        threshold=float(threshold),
        windows=len(rows),
        sessions=len(session_ids),
        confusion=confusion,
        window_metrics=metrics_from_confusion(confusion),
        session_metrics=metrics_from_confusion(session_confusion),
        per_family=per_family,
        brier=brier_score(scores, labels),
        ece=expected_calibration_error(scores, labels),
        non_evaluable_sessions=non_evaluable,
        non_evaluable_ratio=ratio,
        conclusion=conclusion,
    )


def score_rows(predictor: Any, rows: Sequence[dataset_mod.ObservationRow]) -> list[float]:
    """Score MODEL_READY rows with the guarded predictor; never touches other states."""
    scores: list[float] = []
    for row in rows:
        if not row.model_ready:
            raise EvaluationError(f"{row.identity()} is {row.observation_state}, not MODEL_READY")
        prediction = predictor.predict(
            row.feature_vector,
            observation_state=row.observation_state,
            feature_status=row.feature_status,
        )
        scores.append(float(prediction.probability))
    return scores


def write_report(report: EvaluationReport, path: Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(report.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return path
