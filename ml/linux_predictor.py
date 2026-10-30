"""LBS-1 guarded predictor.

Loads only Linux artifacts from `models/linux_v1/` and refuses to produce a probability for
any observation that is not `MODEL_READY`. Artifact, schema, or input failures raise typed
errors that map to `ANALYSIS_ERROR`; undefined observations raise `NotApplicableError`
(→ `INCONCLUSIVE`) **before** the model is touched.

CRITICAL is capped to WARNING while `LBS1_CRITICAL_ENABLED` is False (G5 not approved).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

import joblib
import numpy as np

from ml import linux_schema as schema

ANALYSIS_ERROR_STATE = "ANALYSIS_ERROR"
INCONCLUSIVE_STATE = "INCONCLUSIVE"

VERDICT_SAFE = "SAFE"
VERDICT_WARNING = "WARNING"
VERDICT_CRITICAL = "CRITICAL"

MANIFEST_FILENAME = "manifest.json"
SCHEMA_FILENAME = "schema.json"
MODEL_FILENAME = "model.pkl"
SCALER_FILENAME = "scaler.pkl"
CALIBRATOR_FILENAME = "calibrator.pkl"
REQUIRED_ARTIFACTS = (MODEL_FILENAME, SCALER_FILENAME, CALIBRATOR_FILENAME, SCHEMA_FILENAME)

MANIFEST_REQUIRED_FIELDS = (
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

DEFAULT_THRESHOLDS = {"warning": 0.50, "critical": 0.90}
CALIBRATION_METHOD = "sigmoid_on_positive_probability"


class LinuxPredictorError(RuntimeError):
    """Base class for guarded failures."""

    analysis_state = ANALYSIS_ERROR_STATE


class ArtifactError(LinuxPredictorError):
    """Artifact missing, unreadable, corrupt, or hash-mismatched."""


class SchemaMismatchError(LinuxPredictorError):
    """Schema id, platform tag, feature count, or feature order mismatch."""


class InputValidationError(LinuxPredictorError):
    """Input vector violates the 20-value float64 non-negative finite contract."""


class NotApplicableError(LinuxPredictorError):
    """Observation is not MODEL_READY; the model must not be invoked."""

    analysis_state = INCONCLUSIVE_STATE


@dataclass(frozen=True)
class Prediction:
    probability: float
    verdict: str
    raw_probability: float
    critical_capped: bool
    model_version: str
    thresholds: Mapping[str, float]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class LinuxPredictor:
    """Artifact-guarded LBS-1 predictor. Construct, then call `load()` explicitly."""

    # Read directly from the schema module: not a constructor argument, not env-configurable.
    CRITICAL_ENABLED = schema.LBS1_CRITICAL_ENABLED

    def __init__(self, artifact_dir: str | Path) -> None:
        self.artifact_dir = Path(artifact_dir)
        self._model: Any = None
        self._scaler: Any = None
        self._calibrator: Any = None
        self._manifest: dict[str, Any] = {}
        self._thresholds = dict(DEFAULT_THRESHOLDS)
        self._model_version = ""
        self._loaded = False

    # ------------------------------------------------------------------ loading

    def load(self) -> "LinuxPredictor":
        self._manifest = self._read_manifest()
        self._verify_manifest_fields(self._manifest)
        self._verify_schema_file(self._manifest)

        artifact_hashes = self._manifest["artifact_hashes"]
        if not isinstance(artifact_hashes, Mapping):
            raise ArtifactError("manifest artifact_hashes is not a mapping")
        for filename in REQUIRED_ARTIFACTS:
            self._verify_artifact_hash(filename, artifact_hashes)

        self._model = self._load_joblib(MODEL_FILENAME)
        self._scaler = self._load_joblib(SCALER_FILENAME)
        self._calibrator = self._load_joblib(CALIBRATOR_FILENAME)

        expected_features = getattr(self._model, "n_features_in_", schema.FEATURE_COUNT)
        if expected_features != schema.FEATURE_COUNT:
            raise SchemaMismatchError(
                f"model expects {expected_features} features, schema requires {schema.FEATURE_COUNT}"
            )
        scaler_features = getattr(self._scaler, "n_features_in_", schema.FEATURE_COUNT)
        if scaler_features != schema.FEATURE_COUNT:
            raise SchemaMismatchError(
                f"scaler expects {scaler_features} features, schema requires {schema.FEATURE_COUNT}"
            )

        self._thresholds = self._verify_thresholds(self._manifest["thresholds"])
        self._model_version = str(self._manifest["model_version"])
        self._loaded = True
        return self

    def _read_manifest(self) -> dict[str, Any]:
        path = self.artifact_dir / MANIFEST_FILENAME
        if not path.is_file():
            raise ArtifactError(f"manifest not found: {path}")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ArtifactError(f"manifest unreadable: {exc}") from exc
        if not isinstance(manifest, dict):
            raise ArtifactError("manifest is not a JSON object")
        return manifest

    def _verify_manifest_fields(self, manifest: Mapping[str, Any]) -> None:
        missing = [field for field in MANIFEST_REQUIRED_FIELDS if field not in manifest]
        if missing:
            raise ArtifactError(f"manifest missing fields: {missing}")
        if manifest["platform"] != schema.PLATFORM_TAG:
            raise SchemaMismatchError(f"platform tag mismatch: {manifest['platform']!r}")
        if manifest["schema_id"] != schema.LINUX_SCHEMA_ID:
            raise SchemaMismatchError(f"schema id mismatch: {manifest['schema_id']!r}")
        if manifest["feature_count"] != schema.FEATURE_COUNT:
            raise SchemaMismatchError(
                f"feature count mismatch: {manifest['feature_count']!r} != {schema.FEATURE_COUNT}"
            )
        if list(manifest["feature_names"]) != list(schema.LBS1_FEATURE_NAMES):
            raise SchemaMismatchError("feature names/order mismatch in manifest")
        if manifest["list_version"] != schema.LIST_VERSION:
            raise SchemaMismatchError(f"list version mismatch: {manifest['list_version']!r}")
        if manifest["calibration"] != CALIBRATION_METHOD:
            raise ArtifactError(f"unsupported calibration method: {manifest['calibration']!r}")
        window = manifest["window_seconds"]
        if not isinstance(window, (int, float)) or not (
            schema.WINDOW_SECONDS_MIN <= float(window) <= schema.WINDOW_SECONDS_MAX
        ):
            raise ArtifactError(f"window_seconds outside schema bounds: {window!r}")

    def _verify_schema_file(self, manifest: Mapping[str, Any]) -> None:
        path = self.artifact_dir / SCHEMA_FILENAME
        if not path.is_file():
            raise ArtifactError(f"schema file not found: {path}")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ArtifactError(f"schema file unreadable: {exc}") from exc
        if not isinstance(payload, dict):
            raise ArtifactError("schema file is not a JSON object")

        if payload.get("schema_id") != schema.LINUX_SCHEMA_ID:
            raise SchemaMismatchError(f"schema id mismatch: {payload.get('schema_id')!r}")
        if payload.get("platform") != schema.PLATFORM_TAG:
            raise SchemaMismatchError(f"platform tag mismatch: {payload.get('platform')!r}")
        if payload.get("feature_count") != schema.FEATURE_COUNT:
            raise SchemaMismatchError(f"schema feature_count mismatch: {payload.get('feature_count')!r}")
        if list(payload.get("feature_names", [])) != list(schema.LBS1_FEATURE_NAMES):
            raise SchemaMismatchError("schema feature names/order mismatch")
        if dict(payload.get("units", {})) != schema.FEATURE_UNITS:
            raise SchemaMismatchError("schema units mismatch")
        if sorted(payload.get("statuses", [])) != sorted(schema.VALID_FEATURE_STATUSES):
            raise SchemaMismatchError("schema status vocabulary mismatch")
        if payload.get("critical_enabled") is not False:
            raise SchemaMismatchError("schema must keep critical_enabled=false at LBS-1 v1")

        computed = schema.schema_hash(payload)
        if computed != manifest["schema_hash"]:
            raise SchemaMismatchError("schema hash disagrees with manifest")
        if computed != schema.schema_hash():
            raise SchemaMismatchError("schema hash is not the approved LBS-1 contract")

    def _verify_artifact_hash(self, filename: str, artifact_hashes: Mapping[str, Any]) -> None:
        path = self.artifact_dir / filename
        if not path.is_file():
            raise ArtifactError(f"artifact not found: {path}")
        expected = artifact_hashes.get(filename)
        if not isinstance(expected, str) or len(expected) != 64:
            raise ArtifactError(f"manifest has no valid SHA-256 for {filename}")
        actual = sha256_file(path)
        if actual != expected:
            raise ArtifactError(f"{filename} SHA-256 mismatch (tampered or corrupt)")

    def _load_joblib(self, filename: str) -> Any:
        try:
            return joblib.load(self.artifact_dir / filename)
        except Exception as exc:  # joblib raises many loader-specific types
            raise ArtifactError(f"{filename} failed to load: {exc}") from exc

    @staticmethod
    def _verify_thresholds(raw: Any) -> dict[str, float]:
        if not isinstance(raw, Mapping):
            raise ArtifactError("manifest thresholds is not a mapping")
        try:
            warning = float(raw["warning"])
            critical = float(raw["critical"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ArtifactError(f"manifest thresholds invalid: {exc}") from exc
        if not (np.isfinite(warning) and np.isfinite(critical)):
            raise ArtifactError("thresholds must be finite")
        if not (0.0 < warning < critical <= 1.0):
            raise ArtifactError(f"thresholds out of order: warning={warning}, critical={critical}")
        return {"warning": warning, "critical": critical}

    # -------------------------------------------------------------- prediction

    def _require_loaded(self) -> None:
        if not self._loaded:
            raise ArtifactError("predictor is not loaded; call load() first")

    @staticmethod
    def _guard_definedness(
        observation_state: Any,
        feature_status: Optional[Mapping[str, str]],
    ) -> None:
        if observation_state is None:
            raise NotApplicableError(
                "observation_state is required; LBS-1 never predicts from an undeclared observation"
            )
        if observation_state != schema.STATE_MODEL_READY:
            raise NotApplicableError(f"observation state {observation_state!r} is not MODEL_READY")
        if feature_status is None:
            return
        try:
            schema.validate_feature_status(feature_status)
        except schema.LinuxSchemaError as exc:
            raise InputValidationError(str(exc)) from exc
        undefined = [name for name in schema.LBS1_FEATURE_NAMES if feature_status[name] != schema.STATUS_DEFINED]
        if undefined:
            raise NotApplicableError(f"non-DEFINED features present: {undefined}")

    @staticmethod
    def _validate_input(features: Any) -> np.ndarray:
        if features is None:
            raise NotApplicableError("feature vector is None")
        try:
            array = np.asarray(features)
        except Exception as exc:
            raise InputValidationError(f"feature vector is not array-like: {exc}") from exc
        if array.dtype == np.bool_ or not np.issubdtype(array.dtype, np.number):
            raise InputValidationError(f"feature dtype {array.dtype} is not numeric")
        if array.shape == (1, schema.FEATURE_COUNT):
            array = array[0]
        if array.shape != (schema.FEATURE_COUNT,):
            raise InputValidationError(
                f"feature shape {array.shape} != ({schema.FEATURE_COUNT},)"
            )
        array = array.astype(np.float64, copy=True)
        if not np.all(np.isfinite(array)):
            raise InputValidationError("feature vector contains NaN or infinite values")
        if np.any(array < 0.0):
            raise InputValidationError("feature vector contains negative values")
        return array

    def _positive_probability(self, scaled: np.ndarray, context: str) -> float:
        try:
            probabilities = np.asarray(self._model.predict_proba(scaled))
        except Exception as exc:
            raise ArtifactError(f"{context}: model prediction failed: {exc}") from exc
        if probabilities.ndim != 2 or probabilities.shape[1] != 2:
            raise ArtifactError(f"{context}: model did not return a two-class probability matrix")
        return float(probabilities[0][1])

    def _calibrate(self, raw: float) -> float:
        estimator = self._calibrator
        if hasattr(estimator, "predict_proba"):
            value = np.asarray(estimator.predict_proba(np.asarray([[raw]], dtype=np.float64)))
            calibrated = float(value[0][1])
        elif hasattr(estimator, "predict"):
            calibrated = float(np.asarray(estimator.predict(np.asarray([[raw]], dtype=np.float64))).ravel()[0])
        else:
            raise ArtifactError("calibrator exposes neither predict_proba nor predict")
        if not np.isfinite(calibrated) or not (0.0 <= calibrated <= 1.0):
            raise ArtifactError(f"calibrator produced invalid probability {calibrated!r}")
        return calibrated

    def _verdict(self, probability: float) -> tuple[str, bool]:
        if probability >= self._thresholds["critical"]:
            if self.CRITICAL_ENABLED:
                return VERDICT_CRITICAL, False
            return VERDICT_WARNING, True
        if probability >= self._thresholds["warning"]:
            return VERDICT_WARNING, False
        return VERDICT_SAFE, False

    def predict(
        self,
        features: Any,
        observation_state: Optional[str] = None,
        feature_status: Optional[Mapping[str, str]] = None,
    ) -> Prediction:
        self._require_loaded()
        self._guard_definedness(observation_state, feature_status)
        vector = self._validate_input(features)

        try:
            scaled = np.asarray(self._scaler.transform(vector.reshape(1, -1)), dtype=np.float64)
        except Exception as exc:
            raise ArtifactError(f"scaler transform failed: {exc}") from exc
        if scaled.shape != (1, schema.FEATURE_COUNT) or not np.all(np.isfinite(scaled)):
            raise ArtifactError("scaler produced an invalid transformed vector")

        raw = self._positive_probability(scaled, "raw")
        if not np.isfinite(raw) or not (0.0 <= raw <= 1.0):
            raise ArtifactError(f"model produced invalid probability {raw!r}")
        probability = self._calibrate(raw)
        verdict, capped = self._verdict(probability)
        return Prediction(
            probability=probability,
            verdict=verdict,
            raw_probability=raw,
            critical_capped=capped,
            model_version=self._model_version,
            thresholds=dict(self._thresholds),
        )

    def predict_observation(self, observation: Any) -> Prediction:
        """Safe path: validate the observation, then predict only if MODEL_READY."""
        try:
            vector = schema.validate_observation(observation)
        except schema.LinuxSchemaError as exc:
            raise InputValidationError(str(exc)) from exc
        if vector is None:
            raise NotApplicableError(
                f"observation state {getattr(observation, 'observation_state', None)!r} is not MODEL_READY"
            )
        return self.predict(
            vector,
            observation_state=observation.observation_state,
            feature_status=observation.feature_status,
        )

    # -------------------------------------------------------------------- info

    def is_loaded(self) -> bool:
        return self._loaded

    def get_model_info(self) -> dict[str, Any]:
        return {
            "loaded": self._loaded,
            "schema_id": schema.LINUX_SCHEMA_ID,
            "platform": schema.PLATFORM_TAG,
            "model_version": self._model_version,
            "thresholds": dict(self._thresholds),
            "critical_enabled": self.CRITICAL_ENABLED,
        }
