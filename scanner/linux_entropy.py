"""Entropy sampling for LBS-1 features 6, 7 and 8.

Content is read transiently (4 KiB head), never persisted. Every empty population receives an
explicit status; no undefined value is ever converted to a number.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from typing import Iterable, Optional

SAMPLE_BYTES = 4096
SAMPLE_CAP = 200
HIGH_ENTROPY_BITS = 7.0
ENTROPY_INCREASE_BITS = 1.0
MIN_SAMPLE_COUNT = 20
MAX_READ_FAILURE_RATIO = 0.10

STATUS_DEFINED = "DEFINED"
STATUS_NO_FILE_ACTIVITY = "NOT_APPLICABLE_NO_FILE_ACTIVITY"
STATUS_NO_SAMPLEABLE_FILES = "NOT_APPLICABLE_NO_SAMPLEABLE_FILES"
STATUS_NO_BASELINE_COHORT = "NOT_APPLICABLE_NO_BASELINE_COHORT"
STATUS_COHORT_UNAVAILABLE = "NOT_APPLICABLE_COHORT_UNAVAILABLE"
STATUS_NO_PROCESS_ACTIVITY = "NOT_APPLICABLE_NO_PROCESS_ACTIVITY"
STATUS_UNAVAILABLE_PERMISSION = "UNAVAILABLE_PERMISSION"
STATUS_UNAVAILABLE_SENSOR = "UNAVAILABLE_SENSOR"

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


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty input)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


@dataclass(frozen=True)
class FileSample:
    path: str
    entropy: Optional[float]
    size: int
    zero_size: bool
    unreadable: bool
    error: Optional[str] = None


def sample_file(path: str, sample_bytes: int = SAMPLE_BYTES) -> FileSample:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return FileSample(path, None, 0, False, True, exc.__class__.__name__)
    if size == 0:
        return FileSample(path, None, 0, True, False)
    try:
        with open(path, "rb") as handle:
            data = handle.read(sample_bytes)
    except OSError as exc:
        return FileSample(path, None, size, False, True, exc.__class__.__name__)
    return FileSample(path, shannon_entropy(data), size, False, False)


@dataclass
class EventEntropyResult:
    status: str
    n_candidates: int = 0
    n_eligible: int = 0
    n_sampled: int = 0
    n_zero_size: int = 0
    n_unreadable: int = 0
    mean_entropy: Optional[float] = None
    high_entropy_ratio: Optional[float] = None
    detail: str = ""


def sample_event_files(
    paths: Iterable[str],
    event_count: int,
    sample_bytes: int = SAMPLE_BYTES,
    cap: int = SAMPLE_CAP,
    sampler=sample_file,
) -> EventEntropyResult:
    """Compute features 6/7 over the files touched by filesystem events."""
    distinct = sorted(set(paths))
    if not distinct:
        return EventEntropyResult(
            status=STATUS_NO_FILE_ACTIVITY,
            detail="no write/create/rename events in window",
        )

    samples = [sampler(path, sample_bytes) for path in distinct[:cap]]
    zero = sum(1 for sample in samples if sample.zero_size)
    unreadable = sum(1 for sample in samples if sample.unreadable)
    eligible = len(samples) - zero
    if eligible == 0:
        return EventEntropyResult(
            status=STATUS_NO_SAMPLEABLE_FILES,
            n_candidates=len(distinct),
            n_zero_size=zero,
            detail="every touched file is zero-length",
        )

    failure_ratio = unreadable / eligible
    if failure_ratio > MAX_READ_FAILURE_RATIO:
        return EventEntropyResult(
            status=STATUS_UNAVAILABLE_PERMISSION,
            n_candidates=len(distinct),
            n_eligible=eligible,
            n_zero_size=zero,
            n_unreadable=unreadable,
            detail=f"read failure ratio {failure_ratio:.3f} exceeds budget",
        )

    values = [sample.entropy for sample in samples if sample.entropy is not None]
    sampled = len(values)
    # A shortfall is explained when fewer than 20 distinct files were eligible, or when the
    # window produced fewer than 20 events. Otherwise it is an unexplained sensor shortfall.
    explained = eligible < MIN_SAMPLE_COUNT or event_count < MIN_SAMPLE_COUNT
    if not explained and sampled < MIN_SAMPLE_COUNT and unreadable == 0:
        return EventEntropyResult(
            status=STATUS_UNAVAILABLE_SENSOR,
            n_candidates=len(distinct),
            n_eligible=eligible,
            n_sampled=sampled,
            n_zero_size=zero,
            n_unreadable=unreadable,
            detail=f"only {sampled} samples for {event_count} events",
        )

    if sampled == 0:
        # All eligible files failed to read within the budget arithmetic above.
        return EventEntropyResult(
            status=STATUS_UNAVAILABLE_PERMISSION,
            n_candidates=len(distinct),
            n_eligible=eligible,
            n_zero_size=zero,
            n_unreadable=unreadable,
            detail="no file could be sampled",
        )

    mean = sum(values) / sampled
    high = sum(1 for value in values if value >= HIGH_ENTROPY_BITS) / sampled
    return EventEntropyResult(
        status=STATUS_DEFINED,
        n_candidates=len(distinct),
        n_eligible=eligible,
        n_sampled=sampled,
        n_zero_size=zero,
        n_unreadable=unreadable,
        mean_entropy=mean,
        high_entropy_ratio=high,
    )


@dataclass(frozen=True)
class CohortEntry:
    path: str
    inode: int
    size: int
    mtime_ns: int
    entropy: float


@dataclass
class CohortResult:
    status: str
    value: Optional[float] = None
    start_count: int = 0
    sampled: int = 0
    increased: int = 0
    missing: int = 0
    unreadable: int = 0
    detail: str = ""

    @property
    def excluded_ratio(self) -> float:
        if not self.start_count:
            return 0.0
        return self.unreadable / self.start_count


@dataclass
class BaselineCohort:
    """Fixed baseline cohort, re-sampled in full at window end (feature 8)."""

    entries: list[CohortEntry] = field(default_factory=list)
    status: str = STATUS_NO_BASELINE_COHORT

    @classmethod
    def capture(
        cls,
        paths: Iterable[str],
        cap: int = SAMPLE_CAP,
        sample_bytes: int = SAMPLE_BYTES,
        sampler=sample_file,
        mtime_fn=os.stat,
    ) -> "BaselineCohort":
        distinct = sorted(set(paths))
        if not distinct:
            return cls([], STATUS_NO_BASELINE_COHORT)

        def mtime_ns(path: str) -> int:
            try:
                return mtime_fn(path).st_mtime_ns
            except OSError:
                return 0

        ordered = sorted(distinct, key=lambda path: (-mtime_ns(path), path))[:cap]
        entries: list[CohortEntry] = []
        for path in ordered:
            sample = sampler(path, sample_bytes)
            if sample.unreadable:
                continue
            try:
                stat_result = mtime_fn(path)
            except OSError:
                continue
            entries.append(
                CohortEntry(
                    path=path,
                    inode=getattr(stat_result, "st_ino", 0),
                    size=sample.size,
                    mtime_ns=getattr(stat_result, "st_mtime_ns", 0),
                    entropy=sample.entropy if sample.entropy is not None else 0.0,
                )
            )
        if not entries:
            return cls([], STATUS_NO_BASELINE_COHORT)
        return cls(entries, STATUS_DEFINED)

    def measure(
        self,
        sample_bytes: int = SAMPLE_BYTES,
        sampler=sample_file,
        exists_fn=os.path.exists,
    ) -> CohortResult:
        if not self.entries:
            return CohortResult(STATUS_NO_BASELINE_COHORT)

        missing = 0
        unreadable = 0
        values: list[bool] = []
        for entry in self.entries:
            if not exists_fn(entry.path):
                missing += 1
                continue
            sample = sampler(entry.path, sample_bytes)
            if sample.unreadable or sample.entropy is None:
                unreadable += 1
                continue
            values.append(sample.entropy - entry.entropy >= ENTROPY_INCREASE_BITS)

        if unreadable / len(self.entries) > MAX_READ_FAILURE_RATIO:
            return CohortResult(
                status=STATUS_UNAVAILABLE_PERMISSION,
                start_count=len(self.entries),
                sampled=len(values),
                missing=missing,
                unreadable=unreadable,
                detail="cohort permission loss exceeds 10% budget",
            )
        if not values:
            return CohortResult(
                status=STATUS_COHORT_UNAVAILABLE,
                start_count=len(self.entries),
                missing=missing,
                unreadable=unreadable,
                detail="no baseline-cohort file survived",
            )
        increased = sum(1 for flag in values if flag)
        return CohortResult(
            status=STATUS_DEFINED,
            value=increased / len(values),
            start_count=len(self.entries),
            sampled=len(values),
            increased=increased,
            missing=missing,
            unreadable=unreadable,
        )
