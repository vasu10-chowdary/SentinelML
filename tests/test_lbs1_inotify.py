"""LBS-1 Stage A — inotify parsing, accounting and overflow tests."""

import stat
import struct
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from scanner.linux_inotify import (
    IN_ATTRIB,
    IN_CLOSE_WRITE,
    IN_CREATE,
    IN_DELETE,
    IN_MODIFY,
    IN_MOVE_SELF,
    IN_MOVED_FROM,
    IN_MOVED_TO,
    IN_Q_OVERFLOW,
    InotifyUnavailable,
    InotifyWatcher,
    RawEvent,
    WindowAccumulator,
    parse_events,
    summarize_events,
)


def pack_event(wd, mask, cookie=0, name=""):
    encoded = name.encode() + b"\x00"
    padding = (-len(encoded)) % 4
    total = len(encoded) + padding
    return struct.pack("iIII", wd, mask, cookie, total) + encoded + b"\x00" * padding


def test_parse_events_multiple_records():
    buffer = pack_event(1, IN_CREATE, 0, "a.txt") + pack_event(2, IN_DELETE, 0, "b.txt")
    events = parse_events(buffer)
    assert [(event.wd, event.mask, event.name) for event in events] == [
        (1, IN_CREATE, "a.txt"),
        (2, IN_DELETE, "b.txt"),
    ]


def test_parse_events_rejects_truncated_buffer():
    with pytest.raises(ValueError):
        parse_events(b"\x00" * 8)


def test_write_and_modify_deduplication():
    accumulator = WindowAccumulator()
    events = [
        (RawEvent(1, IN_MODIFY, 0, "a"), "/root/a"),
        (RawEvent(1, IN_MODIFY, 0, "a"), "/root/a"),
        (RawEvent(1, IN_CLOSE_WRITE, 0, "a"), "/root/a"),
        (RawEvent(1, IN_MODIFY, 0, "b"), "/root/b"),
    ]
    accumulator.consume(events)
    summary = accumulator.finalize()
    assert summary.close_write_paths == {"/root/a"}
    assert summary.modify_paths == {"/root/a", "/root/b"}
    # One close-write plus one modify-only file.
    assert summary.write_events == 2
    assert summary.modified_paths == {"/root/a", "/root/b"}
    assert summary.dirs_touched == {"/root"}


def test_rename_pairing_and_unpaired_move():
    accumulator = WindowAccumulator()
    accumulator.consume(
        [
            (RawEvent(1, IN_MOVED_FROM, 7, "a"), "/root/a"),
            (RawEvent(1, IN_MOVED_TO, 7, "b"), "/root/b"),
            (RawEvent(1, IN_MOVED_FROM, 8, "c"), "/root/c"),
        ]
    )
    summary = accumulator.finalize()
    assert summary.rename_events == 1
    assert summary.renamed_paths == {"/root/b"}
    # The unpaired move-out is a delete.
    assert summary.delete_events == 1
    assert summary.deleted_paths == {"/root/c"}


def test_delete_and_move_self_counts():
    summary = summarize_events(
        [
            (RawEvent(1, IN_DELETE, 0, "a"), "/root/a"),
            (RawEvent(1, IN_MOVE_SELF, 0, ""), "/root"),
        ]
    )
    assert summary.delete_events == 1
    assert summary.rename_events == 1


def test_overflow_invalidates_summary():
    accumulator = WindowAccumulator()
    accumulator.consume([(RawEvent(-1, IN_Q_OVERFLOW, 0, ""), None)])
    summary = accumulator.finalize()
    assert summary.overflow is True


def test_ransom_list_matching():
    summary = summarize_events(
        [
            (RawEvent(1, IN_CREATE, 0, "secret.locked"), "/root/secret.locked"),
            (RawEvent(1, IN_CREATE, 0, "README_FOR_DECRYPT.txt"), "/root/README_FOR_DECRYPT.txt"),
            (RawEvent(1, IN_CREATE, 0, "README.md"), "/root/README.md"),
            (RawEvent(1, IN_CREATE, 0, "photo.JPG"), "/root/photo.JPG"),
        ]
    )
    assert summary.ransom_extension_match_count == 1
    assert summary.ransom_note_match_count == 1


def test_setuid_event_count_uses_mode_and_xattr():
    summary = summarize_events(
        [
            (RawEvent(1, IN_CLOSE_WRITE, 0, "suid"), "/root/suid"),
            (RawEvent(1, IN_ATTRIB, 0, "cap"), "/root/cap"),
            (RawEvent(1, IN_CLOSE_WRITE, 0, "plain"), "/root/plain"),
        ],
        mode_lookup=lambda path: (stat.S_ISUID | 0o755) if path.endswith("suid") else 0o644,
        xattr_lookup=lambda path: path.endswith("cap"),
    )
    assert summary.setuid_event_count == 2


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify requires Linux")
def test_watch_budget_shortfall(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    watcher = InotifyWatcher(max_watches=1)
    try:
        result = watcher.add_tree(str(tmp_path))
        assert result.watches == 1
        assert result.shortfall >= 1
        assert watcher.shortfall >= 1
    finally:
        watcher.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify requires Linux")
def test_real_temp_directory_events(tmp_path):
    watcher = InotifyWatcher()
    accumulator = WindowAccumulator()
    try:
        result = watcher.add_tree(str(tmp_path))
        assert result.watches >= 1
        target = tmp_path / "created.txt"
        target.write_text("hello", encoding="utf-8")
        target.rename(tmp_path / "renamed.txt")
        (tmp_path / "renamed.txt").unlink()

        summary = accumulator.finalize()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            events = watcher.poll(timeout=0.1)
            accumulator.consume([(event, watcher.resolve(event)) for event in events])
            summary = accumulator.finalize(mode_lookup=None)
            if summary.rename_events >= 1 and summary.delete_events >= 1:
                break
    finally:
        watcher.close()

    summary = accumulator.finalize()
    assert str(target) in summary.created_paths
    assert str(tmp_path / "renamed.txt") in summary.renamed_paths
    assert summary.delete_events >= 1
    assert summary.rename_events >= 1
    assert summary.write_events >= 1
    assert summary.overflow is False


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="refusal is a non-Linux contract")
def test_watcher_refuses_non_linux():
    with pytest.raises(InotifyUnavailable):
        InotifyWatcher()
