"""Independent LBS-1 artifact verifier.

Recomputes every hash from disk and re-checks the manifest/schema contract without loading
the model. Suitable for CI and delivery checks.

Usage:
    python -m tools.lbs1.verify_artifacts [--artifact-dir models/linux_v1]
Exit code 0 = verified, 1 = verification failed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml import linux_schema as schema

REQUIRED_FILES = ("manifest.json", "schema.json", "model.pkl", "scaler.pkl", "calibrator.pkl")
REQUIRED_MANIFEST_FIELDS = (
    "model_version",
    "schema_id",
    "schema_hash",
    "platform",
    "feature_count",
    "feature_names",
    "window_seconds",
    "list_version",
    "dataset_sha256",
    "thresholds",
    "calibration",
    "artifact_hashes",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(artifact_dir: Path) -> dict:
    errors: list[str] = []
    artifact_dir = Path(artifact_dir)
    if not artifact_dir.is_dir():
        return {"status": "FAILED", "artifact_dir": str(artifact_dir), "errors": ["artifact directory not found"]}

    for filename in REQUIRED_FILES:
        if not (artifact_dir / filename).is_file():
            errors.append(f"missing {filename}")

    manifest: dict = {}
    if (artifact_dir / "manifest.json").is_file():
        try:
            manifest = json.loads((artifact_dir / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"manifest unreadable: {exc}")

    if manifest:
        missing = [name for name in REQUIRED_MANIFEST_FIELDS if name not in manifest]
        if missing:
            errors.append(f"manifest missing fields: {missing}")
        if manifest.get("schema_id") != schema.LINUX_SCHEMA_ID:
            errors.append(f"schema_id {manifest.get('schema_id')!r} != {schema.LINUX_SCHEMA_ID!r}")
        if manifest.get("platform") != schema.PLATFORM_TAG:
            errors.append(f"platform {manifest.get('platform')!r} != {schema.PLATFORM_TAG!r}")
        if manifest.get("feature_count") != schema.FEATURE_COUNT:
            errors.append(f"feature_count {manifest.get('feature_count')!r} != {schema.FEATURE_COUNT}")
        if list(manifest.get("feature_names", [])) != list(schema.LBS1_FEATURE_NAMES):
            errors.append("feature names/order mismatch")

        artifact_hashes = manifest.get("artifact_hashes", {})
        if not isinstance(artifact_hashes, dict):
            errors.append("artifact_hashes is not an object")
        else:
            for filename in ("schema.json", "model.pkl", "scaler.pkl", "calibrator.pkl"):
                path = artifact_dir / filename
                if not path.is_file():
                    continue
                expected = artifact_hashes.get(filename)
                if not isinstance(expected, str):
                    errors.append(f"no SHA-256 recorded for {filename}")
                elif sha256_file(path) != expected:
                    errors.append(f"{filename} SHA-256 mismatch")

        thresholds = manifest.get("thresholds", {})
        try:
            warning = float(thresholds["warning"])
            critical = float(thresholds["critical"])
            if not (0.0 < warning < critical <= 1.0):
                errors.append(f"thresholds out of order: {warning}/{critical}")
        except (KeyError, TypeError, ValueError):
            errors.append("thresholds missing or non-numeric")

    schema_path = artifact_dir / "schema.json"
    if schema_path.is_file():
        try:
            payload = json.loads(schema_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"schema unreadable: {exc}")
        else:
            computed = schema.schema_hash(payload)
            if computed != schema.schema_hash():
                errors.append("schema.json is not the approved LBS-1 contract")
            if manifest and computed != manifest.get("schema_hash"):
                errors.append("schema.json hash disagrees with manifest")
            if payload.get("critical_enabled") is not False:
                errors.append("schema.json must keep critical_enabled=false")

    return {
        "status": "VERIFIED" if not errors else "FAILED",
        "artifact_dir": str(artifact_dir),
        "model_version": manifest.get("model_version"),
        "rows_checked": len(REQUIRED_FILES),
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify LBS-1 artifacts independently of the predictor")
    parser.add_argument(
        "--artifact-dir",
        default=str(Path(__file__).resolve().parents[2] / "models" / "linux_v1"),
        help="artifact directory (default: models/linux_v1)",
    )
    args = parser.parse_args(argv)
    result = verify(Path(args.artifact_dir))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
