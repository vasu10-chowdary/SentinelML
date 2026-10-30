"""Linux mount classification for LBS-1 (Stage A).

Parses /proc/self/mountinfo and classifies filesystems as supported or unsupported for
inotify-based telemetry. Unsupported filesystems are reported, never zero-filled.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

SUPPORTED_FS_TYPES = frozenset({"ext4", "xfs", "btrfs", "tmpfs", "overlay"})

UNSUPPORTED_FS_TYPES = frozenset(
    {
        "9p",
        "drvfs",
        "fuse",
        "fuseblk",
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "sshfs",
        "v9fs",
    }
)

_OCTAL_ESCAPES = {
    "040": " ",
    "011": "\t",
    "012": "\n",
    "134": "\\",
}


def unescape_mount_field(value: str) -> str:
    """Decode the octal escapes used by /proc/self/mountinfo."""
    out = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 4 <= len(value) and value[i + 1 : i + 4] in _OCTAL_ESCAPES:
            out.append(_OCTAL_ESCAPES[value[i + 1 : i + 4]])
            i += 4
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


@dataclass(frozen=True)
class MountEntry:
    mount_id: int
    parent_id: int
    major_minor: str
    root: str
    mount_point: str
    mount_options: str
    fs_type: str
    source: str
    super_options: str

    @property
    def is_bind(self) -> bool:
        return self.root not in ("", "/")

    @property
    def supported(self) -> bool:
        return self.fs_type.lower() in SUPPORTED_FS_TYPES

    @property
    def reason(self) -> Optional[str]:
        if self.supported:
            return None
        if self.fs_type.lower() in UNSUPPORTED_FS_TYPES or self.fs_type.lower().startswith(
            ("fuse.", "nfs", "cifs")
        ):
            return f"UNSUPPORTED_FILESYSTEM:{self.fs_type}"
        return f"UNKNOWN_FILESYSTEM:{self.fs_type}"


def parse_mountinfo(text: str) -> list[MountEntry]:
    entries: list[MountEntry] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        try:
            sep = fields.index("-")
        except ValueError as exc:
            raise ValueError(f"malformed mountinfo line: {line!r}") from exc
        if sep < 6 or len(fields) < sep + 3:
            raise ValueError(f"malformed mountinfo line: {line!r}")
        before = fields[:sep]
        after = fields[sep + 1 :]
        entries.append(
            MountEntry(
                mount_id=int(before[0]),
                parent_id=int(before[1]),
                major_minor=before[2],
                root=unescape_mount_field(before[3]),
                mount_point=unescape_mount_field(before[4]),
                mount_options=before[5],
                fs_type=after[0],
                source=unescape_mount_field(after[1]),
                super_options=after[2] if len(after) > 2 else "",
            )
        )
    return entries


def read_mountinfo(path: str = "/proc/self/mountinfo") -> list[MountEntry]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_mountinfo(handle.read())


def _normalise(path: str) -> str:
    normalised = posixpath.normpath(path)
    if normalised.startswith("//"):
        normalised = normalised[1:]
    return normalised


def _is_within(path: str, mount_point: str) -> bool:
    if mount_point == "/":
        return path.startswith("/")
    return path == mount_point or path.startswith(mount_point + "/")


def classify_path(path: str, mounts: Sequence[MountEntry]) -> Optional[MountEntry]:
    """Return the mount entry with the longest mount point containing *path*."""
    target = _normalise(path)
    best: Optional[MountEntry] = None
    for entry in mounts:
        mount_point = _normalise(entry.mount_point)
        if _is_within(target, mount_point):
            if best is None or len(mount_point) > len(_normalise(best.mount_point)):
                best = entry
    return best


def classify_targets(paths: Iterable[str], mounts: Sequence[MountEntry]) -> tuple[bool, list[str], set[str]]:
    """Return (all_supported, reasons, filesystem_types) for the given target roots."""
    reasons: list[str] = []
    fs_types: set[str] = set()
    all_supported = True
    for path in paths:
        entry = classify_path(path, mounts)
        if entry is None:
            all_supported = False
            reasons.append(f"UNKNOWN_MOUNT:{path}")
            continue
        fs_types.add(entry.fs_type)
        if not entry.supported:
            all_supported = False
            reasons.append(f"{entry.reason}:{path}")
    return all_supported, reasons, fs_types
