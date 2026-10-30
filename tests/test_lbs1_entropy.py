"""LBS-1 Stage A — entropy sampling and fixed-cohort tests."""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from scanner.linux_entropy import (
    BaselineCohort,
    CohortEntry,
    FileSample,
    STATUS_COHORT_UNAVAILABLE,
    STATUS_DEFINED,
    STATUS_NO_BASELINE_COHORT,
    STATUS_NO_FILE_ACTIVITY,
    STATUS_NO_SAMPLEABLE_FILES,
    STATUS_UNAVAILABLE_PERMISSION,
    STATUS_UNAVAILABLE_SENSOR,
    sample_event_files,
    sample_file,
    shannon_entropy,
)

UNIFORM = bytes(range(256)) * 16


def fake_sample(path, entropy=None, zero=False, unreadable=False):
    if zero:
        return FileSample(path, None, 0, True, False)
    if unreadable:
        return FileSample(path, None, 4096, False, True, "PermissionError")
    return FileSample(path, entropy, 4096, False, False)


def test_shannon_entropy_known_content():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 4096) == 0.0
    assert shannon_entropy(UNIFORM) == pytest.approx(8.0)
    assert shannon_entropy(b"abcd" * 1024) == pytest.approx(2.0)


def test_sample_file_reads_head_only(tmp_path):
    path = tmp_path / "head.bin"
    path.write_bytes(b"\x00" * 4096 + UNIFORM)
    sample = sample_file(str(path))
    assert sample.zero_size is False
    assert sample.entropy == pytest.approx(0.0)


def test_sample_file_zero_size_is_excluded(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    sample = sample_file(str(path))
    assert sample.zero_size is True
    assert sample.entropy is None


def test_event_sampling_statuses():
    assert sample_event_files([], event_count=5).status == STATUS_NO_FILE_ACTIVITY
    assert (
        sample_event_files(["a", "b"], event_count=2, sampler=lambda p, n: fake_sample(p, zero=True)).status
        == STATUS_NO_SAMPLEABLE_FILES
    )

    def mostly_unreadable(path, _n):
        return fake_sample(path, unreadable=path.endswith(("0", "1")))

    result = sample_event_files([f"/f{i}" for i in range(10)], event_count=10, sampler=mostly_unreadable)
    assert result.status == STATUS_UNAVAILABLE_PERMISSION
    assert result.n_unreadable == 2


def test_event_sampling_within_budget_is_defined():
    def one_unreadable(path, _n):
        return fake_sample(path, unreadable=path == "/f0", entropy=6.0)

    result = sample_event_files([f"/f{i}" for i in range(10)], event_count=10, sampler=one_unreadable)
    assert result.status == STATUS_DEFINED
    assert result.n_sampled == 9
    assert result.mean_entropy == pytest.approx(6.0)


def test_event_sampling_small_population_is_explained():
    result = sample_event_files(
        [f"/f{i}" for i in range(5)],
        event_count=100,
        sampler=lambda p, n: fake_sample(p, entropy=7.5),
    )
    assert result.status == STATUS_DEFINED
    assert result.n_sampled == 5


def test_event_sampling_unexplained_shortfall_is_sensor_failure():
    def half_missing(path, _n):
        index = int(path.rsplit("f", 1)[1])
        return fake_sample(path, entropy=6.0 if index < 15 else None)

    result = sample_event_files([f"/f{i}" for i in range(30)], event_count=100, sampler=half_missing)
    assert result.status == STATUS_UNAVAILABLE_SENSOR
    assert result.n_sampled == 15


def test_event_sampling_mean_and_high_ratio():
    values = {"a": 7.9, "b": 6.1, "c": 7.0, "d": 3.0}
    result = sample_event_files(
        list(values),
        event_count=4,
        sampler=lambda path, n: fake_sample(path, entropy=values[path]),
    )
    assert result.status == STATUS_DEFINED
    assert result.mean_entropy == pytest.approx(sum(values.values()) / 4)
    assert result.high_entropy_ratio == pytest.approx(0.5)


def test_event_sampling_respects_cap():
    calls = []

    def counting(path, _n):
        calls.append(path)
        return fake_sample(path, entropy=5.0)

    result = sample_event_files([f"/f{i}" for i in range(250)], event_count=1000, sampler=counting)
    assert len(calls) == 200
    assert result.n_sampled == 200


def _write(path, data):
    path.write_bytes(data)


def test_fixed_cohort_unchanged_is_measured_zero(tmp_path):
    paths = []
    for index in range(10):
        path = tmp_path / f"file_{index}.bin"
        _write(path, b"\x00" * 4096)
        paths.append(str(path))
    cohort = BaselineCohort.capture(paths)
    assert cohort.status == STATUS_DEFINED
    result = cohort.measure()
    assert result.status == STATUS_DEFINED
    assert result.value == 0.0
    assert result.sampled == 10
    assert result.increased == 0


def test_fixed_cohort_all_changed(tmp_path):
    paths = []
    for index in range(6):
        path = tmp_path / f"file_{index}.bin"
        _write(path, b"\x00" * 4096)
        paths.append(str(path))
    cohort = BaselineCohort.capture(paths)
    for path in paths:
        _write(Path(path), UNIFORM)
    result = cohort.measure()
    assert result.status == STATUS_DEFINED
    assert result.value == 1.0


def test_in_place_same_size_change_is_detected(tmp_path):
    path = tmp_path / "inplace.bin"
    _write(path, b"\x00" * 4096)
    stat_before = os.stat(path)
    cohort = BaselineCohort.capture([str(path)])
    _write(path, UNIFORM)
    os.utime(path, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
    after = os.stat(path)
    assert after.st_size == stat_before.st_size
    assert after.st_mtime_ns == stat_before.st_mtime_ns
    result = cohort.measure()
    assert result.value == 1.0


def test_cohort_without_baseline():
    cohort = BaselineCohort.capture([])
    assert cohort.status == STATUS_NO_BASELINE_COHORT
    assert cohort.measure().status == STATUS_NO_BASELINE_COHORT


def test_cohort_deleted_or_moved_out(tmp_path):
    paths = []
    for index in range(4):
        path = tmp_path / f"file_{index}.bin"
        _write(path, b"\x00" * 1024)
        paths.append(str(path))
    cohort = BaselineCohort.capture(paths)
    for path in paths:
        Path(path).unlink()
    result = cohort.measure()
    assert result.status == STATUS_COHORT_UNAVAILABLE
    assert result.missing == 4


def _entry(path):
    return CohortEntry(path=path, inode=1, size=4096, mtime_ns=0, entropy=0.0)


def test_cohort_permission_budget():
    entries = [_entry(f"/cohort/{i}") for i in range(10)]

    def two_unreadable(path, _n):
        index = int(path.rsplit("/", 1)[1])
        if index < 2:
            return FileSample(path, None, 4096, False, True, "PermissionError")
        return FileSample(path, 0.0, 4096, False, False)

    cohort = BaselineCohort(entries)
    result = cohort.measure(exists_fn=lambda _p: True, sampler=two_unreadable)
    assert result.status == STATUS_UNAVAILABLE_PERMISSION

    def one_unreadable(path, _n):
        index = int(path.rsplit("/", 1)[1])
        if index == 0:
            return FileSample(path, None, 4096, False, True, "PermissionError")
        return FileSample(path, 5.0, 4096, False, False)

    result = cohort.measure(exists_fn=lambda _p: True, sampler=one_unreadable)
    assert result.status == STATUS_DEFINED
    assert result.value == 1.0
    assert result.sampled == 9


def test_cohort_partial_survival_denominator():
    entries = [_entry(f"/cohort/{i}") for i in range(10)]
    cohort = BaselineCohort(entries)
    alive = {"/cohort/0"}
    result = cohort.measure(
        exists_fn=lambda path: path in alive,
        sampler=lambda p, n: FileSample(p, 0.0, 4096, False, False),
    )
    assert result.status == STATUS_DEFINED
    assert result.value == 0.0
    assert result.sampled == 1
    assert result.missing == 9
