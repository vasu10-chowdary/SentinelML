"""LBS-1 Stage A — mount classification tests."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from scanner.linux_fs_types import (
    MountEntry,
    classify_path,
    classify_targets,
    parse_mountinfo,
    unescape_mount_field,
)

MOUNTINFO = """\
23 1 0:22 / /proc rw,nosuid - proc proc rw
24 1 0:23 / /sys rw,nosuid - sysfs sysfs rw
36 35 98:0 / /mnt/c rw,noatime master:1 - 9p drvfs rw
40 35 8:1 / / rw,relatime - ext4 /dev/sda1 rw
41 40 0:30 / /run rw,nosuid - tmpfs tmpfs rw
42 40 8:2 / /home rw,relatime - ext4 /dev/sda2 rw
43 42 8:2 /subdir /home/user/bind rw,relatime - ext4 /dev/sda2 rw
44 40 0:40 / /mnt/space\\040dir rw - fuse.sshfs sshfs rw
"""


def test_parse_mountinfo_fields():
    entries = parse_mountinfo(MOUNTINFO)
    assert len(entries) == 8
    root = next(entry for entry in entries if entry.mount_point == "/")
    assert root.fs_type == "ext4"
    assert root.source == "/dev/sda1"
    assert root.supported is True
    assert root.is_bind is False

    nine_p = next(entry for entry in entries if entry.fs_type == "9p")
    assert nine_p.supported is False
    assert nine_p.reason == "UNSUPPORTED_FILESYSTEM:9p"


def test_escaped_mount_point_is_decoded():
    entries = parse_mountinfo(MOUNTINFO)
    assert any(entry.mount_point == "/mnt/space dir" for entry in entries)
    assert unescape_mount_field(r"/a\040b\134c") == "/a b\\c"


def test_bind_mount_detection():
    entries = parse_mountinfo(MOUNTINFO)
    bind = next(entry for entry in entries if entry.mount_point == "/home/user/bind")
    assert bind.is_bind is True
    assert bind.supported is True


def test_classify_path_uses_longest_mount():
    entries = parse_mountinfo(MOUNTINFO)
    assert classify_path("/home/user/bind/file.txt", entries).mount_point == "/home/user/bind"
    assert classify_path("/home/user/other.txt", entries).mount_point == "/home"
    assert classify_path("/etc/passwd", entries).mount_point == "/"


def test_classify_targets_marks_unsupported_and_unknown():
    entries = parse_mountinfo(MOUNTINFO)
    ok, reasons, types = classify_targets(["/home/user/Documents"], entries)
    assert ok is True
    assert reasons == []
    assert types == {"ext4"}

    ok, reasons, types = classify_targets(["/mnt/c/Users"], entries)
    assert ok is False
    assert any("UNSUPPORTED_FILESYSTEM:9p" in reason for reason in reasons)
    assert types == {"9p"}

    ok, reasons, _ = classify_targets(["/mnt/space dir/x"], entries)
    assert ok is False
    assert any("fuse" in reason.lower() for reason in reasons)

    ok, reasons, _ = classify_targets(["/nonexistent"], [])
    assert ok is False
    assert reasons == ["UNKNOWN_MOUNT:/nonexistent"]


def test_supported_types_include_overlay():
    entry = MountEntry(1, 0, "0:1", "/", "/", "rw", "overlay", "overlay", "rw")
    assert entry.supported is True


def test_malformed_mountinfo_raises():
    with pytest.raises(ValueError):
        parse_mountinfo("1 2 3 4 5 6\n")
