"""Measure LBS-1 collector overhead on a native Linux machine (Stage A).

Runs against a disposable fixture directory only; never against user workloads.
Prints JSON to stdout and writes nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time


def _seed_fixture(root: str, count: int) -> None:
    for index in range(count):
        path = os.path.join(root, f"fixture_{index:03d}.bin")
        with open(path, "wb") as handle:
            handle.write(os.urandom(2048 + (index % 7) * 1024))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark the LBS-1 collector")
    parser.add_argument("--window", type=float, default=10.0)
    parser.add_argument("--files", type=int, default=64)
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args(argv)

    if not sys.platform.startswith("linux"):
        print(json.dumps({"status": "UNSUPPORTED_PLATFORM", "platform": sys.platform}))
        return 2

    import psutil

    from scanner.linux_telemetry import collect_observation

    process = psutil.Process()
    with tempfile.TemporaryDirectory(prefix="lbs1_bench_") as root:
        _seed_fixture(root, max(1, args.files))
        cpu_before = process.cpu_times()
        rss_before = process.memory_info().rss
        started = time.monotonic()
        observation = collect_observation(
            targets=[root],
            window_seconds=args.window,
            snapshot_interval=0.5,
        )
        elapsed = time.monotonic() - started
        cpu_after = process.cpu_times()
        rss_after = process.memory_info().rss

    cpu_seconds = (cpu_after.user - cpu_before.user) + (cpu_after.system - cpu_before.system)
    payload = {
        "status": "OK",
        "window_seconds": args.window,
        "elapsed_seconds": round(elapsed, 3),
        "cpu_seconds": round(cpu_seconds, 3),
        "cpu_percent_of_one_core": round(100.0 * cpu_seconds / max(elapsed, 1e-9), 2),
        "rss_delta_mb": round((rss_after - rss_before) / (1024 * 1024), 2),
        "rss_mb": round(rss_after / (1024 * 1024), 2),
        "observation_state": observation.observation_state,
        "feature_count": None if observation.features is None else int(observation.features.size),
        "entropy_io_bytes_max": 4 * 1024 * 200,
        "overflow": observation.overflow,
    }
    if args.json:
        print(json.dumps(payload))
    else:
        for key, value in payload.items():
            print(f"{key}: {value}")
    return 0 if observation.observation_state == "MODEL_READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
