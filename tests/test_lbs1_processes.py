"""LBS-1 Stage A — process dynamics and network classification tests."""

import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

import scanner.linux_processes as linux_processes
from scanner.linux_processes import (
    ProcessInfo,
    ProcessSnapshotSession,
    STATUS_DEGRADED,
    STATUS_NOT_APPLICABLE,
    STATUS_OK,
    analyze_process_windows,
    count_external_ips,
    match_destructive,
    take_snapshot,
)


def proc(pid, ppid=1, comm="proc", argv=(), exe=None, uid=1000, cap=0, status=True):
    return ProcessInfo(
        pid=pid,
        ppid=ppid,
        comm=comm,
        state="S",
        start_ticks=0,
        exe=exe,
        argv=tuple(argv),
        uid_real=uid,
        uid_eff=uid,
        uid_saved=uid,
        cap_eff=cap,
        status_readable=status,
        exe_readable=exe is not None,
    )


def snapshots(*items):
    return [dict(item) for item in items]


def write_proc(root, pid, ppid=1, comm="proc", argv=(), uid=1000, start=0):
    base = Path(root) / str(pid)
    base.mkdir(parents=True, exist_ok=True)
    rest = f"S {ppid} " + " ".join(["0"] * 17) + f" {start} 0 0"
    (base / "stat").write_text(f"{pid} ({comm}) {rest}\n", encoding="utf-8")
    (base / "status").write_text(
        f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapEff:\t0000000000000000\n",
        encoding="utf-8",
    )
    (base / "cmdline").write_bytes(b"".join(part.encode("utf-8") + b"\x00" for part in argv))


def rewrite_cmdline(root, pid, argv):
    (Path(root) / str(pid) / "cmdline").write_bytes(
        b"".join(part.encode("utf-8") + b"\x00" for part in argv)
    )


@pytest.mark.parametrize(
    "argv,expected",
    [
        (["rm", "file"], None),
        (["rm", "-r", "dir"], None),
        (["rm", "-f", "file"], None),
        (["rm", "-rf", "dir"], "rm"),
        (["rm", "-fr", "dir"], "rm"),
        (["rm", "--recursive", "--force", "dir"], "rm"),
        (["/bin/rm", "-Rf", "dir"], "rm"),
        (["shred", "-u", "file"], "shred"),
        (["dd", "if=/dev/zero", "of=/dev/sda"], "dd"),
        (["dd", "if=/dev/zero", "of=backup.img"], None),
        (["mkfs.ext4", "/dev/sdb1"], "mkfs"),
        (["cryptsetup", "luksFormat", "/dev/sdb1"], "cryptsetup"),
        (["wipefs", "-a", "/dev/sdb"], "wipefs"),
        (["truncate", "-s", "0", "file"], "truncate"),
        (["bash", "-c", "true"], None),
        ([], None),
    ],
)
def test_destructive_rule_matrix(argv, expected):
    assert match_destructive(argv) == expected


def test_created_exited_and_short_lived_accounting():
    first = {1: proc(1, comm="init"), 2: proc(2, comm="[kthreadd]")}
    middle = {
        1: first[1],
        2: first[2],
        100: proc(100, argv=["rm", "-rf", "/tmp/x"], exe="/usr/bin/rm"),
        101: proc(101, ppid=1, comm="bash", argv=["bash"], exe="/bin/bash"),
    }
    last = {1: first[1], 2: first[2], 101: middle[101]}
    result = analyze_process_windows(snapshots(first, middle, last), 15.0)
    assert result.created_count == 2
    assert result.exited_count == 1
    assert result.short_lived_count == 1
    assert result.short_lived_ratio == pytest.approx(0.5)
    assert result.destructive_count == 1
    assert result.destructive_rules == ("rm",)
    assert result.shell_spawn_count == 1
    assert result.g4_status == STATUS_OK
    assert result.g5_status == STATUS_OK
    assert result.g6_status == STATUS_OK


def test_zero_creation_is_not_applicable_not_zero():
    first = {1: proc(1, comm="init")}
    result = analyze_process_windows(snapshots(first, first, first), 15.0)
    assert result.created_count == 0
    assert result.short_lived_ratio is None
    assert result.g4_status == STATUS_OK
    assert result.g5_status == STATUS_NOT_APPLICABLE
    assert result.g6_status == STATUS_NOT_APPLICABLE
    assert result.resolution_rate is None
    assert result.status_readable_rate is None


def test_zero_exits_is_measured_zero():
    first = {1: proc(1, comm="init")}
    last = {1: first[1], 100: proc(100, argv=["sleep", "10"], exe="/usr/bin/sleep")}
    result = analyze_process_windows(snapshots(first, last, last), 15.0)
    assert result.created_count == 1
    assert result.exited_count == 0
    assert result.short_lived_ratio == 0.0


def test_shell_spawn_exclusions():
    terminal = proc(50, comm="xterm", argv=["xterm"])
    shell_parent = proc(60, comm="bash", argv=["bash"])
    root = {1: proc(1, comm="init"), 50: terminal, 60: shell_parent}
    last = {
        **root,
        70: proc(70, ppid=50, comm="bash", argv=["bash"]),
        71: proc(71, ppid=60, comm="bash", argv=["bash"]),
        72: proc(72, ppid=1, comm="zsh", argv=["zsh"]),
    }
    result = analyze_process_windows(snapshots(root, last, last), 15.0)
    assert result.shell_spawn_count == 1


def test_temp_exec_resolution():
    first = {1: proc(1, comm="init")}
    last = {
        1: first[1],
        100: proc(100, argv=["./x"], exe="/tmp/x"),
        101: proc(101, comm="y", argv=["/var/tmp/y"]),
        102: proc(102, argv=["/usr/bin/z"], exe="/usr/bin/z"),
        103: proc(103, comm="sh", argv=["sh"], exe="/dev/shm/sh"),
    }
    result = analyze_process_windows(snapshots(first, last, last), 15.0)
    assert result.temp_exec_count == 3


def test_privileged_counts_only_new_processes():
    first = {1: proc(1, comm="init", uid=0)}
    last = {
        1: first[1],
        100: proc(100, uid=0),
        101: proc(101, cap=1),
        102: proc(102, uid=1000, cap=0),
    }
    result = analyze_process_windows(snapshots(first, last, last), 15.0)
    assert result.privileged_count == 2


def test_resolution_and_status_thresholds():
    first = {1: proc(1, comm="init")}
    created = {}
    for index in range(10):
        pid = 100 + index
        created[pid] = proc(
            pid,
            argv=["cmd"] if index < 8 else (),
            exe="/usr/bin/cmd" if index < 9 else None,
            status=index < 8,
        )
    last = {**first, **created}
    result = analyze_process_windows(snapshots(first, last, last), 15.0)
    assert result.resolution_rate == pytest.approx(0.9)
    assert result.g5_status == STATUS_OK
    assert result.status_readable_rate == pytest.approx(0.8)
    assert result.g6_status == STATUS_DEGRADED


def test_insufficient_snapshots_degrades_g4():
    first = {1: proc(1, comm="init")}
    result = analyze_process_windows(snapshots(first), 15.0)
    assert result.g4_status == STATUS_DEGRADED


def test_network_external_ip_classification():
    connections = [
        {"status": "ESTABLISHED", "raddr": ("8.8.8.8", 443)},
        {"status": "ESTABLISHED", "raddr": ("8.8.8.8", 443)},
        {"status": "ESTABLISHED", "raddr": ("1.1.1.1", 53)},
        {"status": "ESTABLISHED", "raddr": ("192.168.1.10", 22)},
        {"status": "ESTABLISHED", "raddr": ("100.64.0.1", 80)},
        {"status": "ESTABLISHED", "raddr": ("127.0.0.1", 8080)},
        {"status": "ESTABLISHED", "raddr": ("fe80::1", 80)},
        {"status": "LISTEN", "raddr": ("0.0.0.0", 0)},
        {"status": "ESTABLISHED", "raddr": None},
    ]
    result = count_external_ips(connections)
    assert result.status == STATUS_OK
    assert result.unique_external_ip_count == 2
    assert result.external_ips == {"8.8.8.8", "1.1.1.1"}
    assert result.connection_count == 7


def test_invalid_window_rejected():
    with pytest.raises(ValueError):
        analyze_process_windows([], 0)


def test_snapshot_session_first_snapshot_is_full(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    write_proc(root, 1, comm="init", argv=["init"])
    write_proc(root, 100, comm="svc", argv=["svc", "--flag"])
    session = ProcessSnapshotSession(str(root))
    snap = session.snapshot()
    assert set(snap) == {1, 100}
    assert snap[100].argv == ("svc", "--flag")


def test_snapshot_session_rereads_created_pid_until_exec_is_visible(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    write_proc(root, 1, comm="init", argv=["init"])
    session = ProcessSnapshotSession(str(root))
    first = session.snapshot()

    # Fork/exec race: the pid exists for one snapshot with no argv yet.
    write_proc(root, 200, ppid=1, comm="shred", argv=(), start=400)
    pre_exec = session.snapshot()
    assert pre_exec[200].argv == ()
    assert pre_exec[200].resolved is False

    rewrite_cmdline(root, 200, ["shred", "-n", "1", "/tmp/evidence.bin"])
    post_exec = session.snapshot()
    assert post_exec[200].argv == ("shred", "-n", "1", "/tmp/evidence.bin")

    result = analyze_process_windows([first, pre_exec, post_exec], 15.0)
    assert result.created_count == 1
    assert result.destructive_rules == ("shred",)
    assert result.resolution_rate == 1.0


def test_snapshot_session_matches_full_snapshots_for_analysis(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    write_proc(root, 1, comm="init", argv=["init"])
    write_proc(root, 2, comm="[kthreadd]", argv=())
    write_proc(root, 50, comm="xterm", argv=["xterm"])
    write_proc(root, 60, comm="runner", argv=["runner"])

    session = ProcessSnapshotSession(str(root))
    reference = [take_snapshot(str(root))]
    tracked = [session.snapshot()]
    assert set(tracked[-1]) == set(reference[-1])

    # A shell child of a non-shell parent, and a destructive short-lived child.
    write_proc(root, 70, ppid=60, comm="bash", argv=["bash", "-c", "true"], start=100)
    write_proc(root, 71, ppid=50, comm="rm", argv=["rm", "-rf", "/tmp/x"], start=101)
    reference.append(take_snapshot(str(root)))
    tracked.append(session.snapshot())

    # The persisted parent later execs into a shell; take_snapshot sees it, and the
    # session must refresh the parent because its created child is still present.
    rewrite_cmdline(root, 60, ["bash"])
    reference.append(take_snapshot(str(root)))
    tracked.append(session.snapshot())

    # The destructive child exits.
    shutil.rmtree(root / "71")
    reference.append(take_snapshot(str(root)))
    tracked.append(session.snapshot())

    expected = analyze_process_windows(reference, 15.0)
    actual = analyze_process_windows(tracked, 15.0)
    assert vars(actual) == vars(expected)
    assert actual.created_count == 2
    assert actual.exited_count == 1
    assert actual.destructive_rules == ("rm",)
    assert actual.shell_spawn_count == 0


def test_snapshot_session_reuses_stable_pid_details_by_design(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    write_proc(root, 1, comm="init", argv=["init"])
    write_proc(root, 100, comm="victim", argv=["victim", "--old"])
    session = ProcessSnapshotSession(str(root))
    session.snapshot()

    # Stable pids are only consulted as parents of created pids, so their cached
    # details are reused instead of paying for status/cmdline/exe every interval.
    rewrite_cmdline(root, 100, ["victim", "--new"])
    cached = session.snapshot()
    assert cached[100].argv == ("victim", "--old")
    assert take_snapshot(str(root))[100].argv == ("victim", "--new")


def test_snapshot_session_rereads_reappeared_pid(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    write_proc(root, 1, comm="init", argv=["init"])
    write_proc(root, 100, comm="old", argv=["old"], start=5)
    session = ProcessSnapshotSession(str(root))
    session.snapshot()

    shutil.rmtree(root / "100")
    assert set(session.snapshot()) == {1}

    write_proc(root, 100, comm="new", argv=["new"], start=999)
    snap = session.snapshot()
    assert snap[100].argv == ("new",)


def test_snapshot_session_drops_pid_when_read_fails(tmp_path, monkeypatch):
    root = tmp_path / "proc"
    root.mkdir()
    write_proc(root, 1, comm="init", argv=["init"])
    session = ProcessSnapshotSession(str(root))
    session.snapshot()

    write_proc(root, 200, comm="doomed", argv=["doomed"], start=9)
    assert 200 in session.snapshot()

    real_read = linux_processes.read_process

    def failing(pid, proc_root="/proc"):
        if pid == 200:
            return None
        return real_read(pid, proc_root)

    monkeypatch.setattr(linux_processes, "read_process", failing)
    snap = session.snapshot()
    assert 200 not in snap
    assert 200 not in take_snapshot(str(root))


def test_snapshot_session_handles_missing_proc_root(tmp_path):
    session = ProcessSnapshotSession(str(tmp_path / "missing"))
    assert session.snapshot() == {}
    assert session.snapshot() == {}
