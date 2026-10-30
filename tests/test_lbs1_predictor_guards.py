"""LBS-1 Stage B — guarded predictor tests."""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pytest

import lbs1_support as support
from tools.lbs1 import verify_artifacts

from ml import linux_predictor as lp
from ml import linux_schema as schema


def load_predictor(tmp_path, **kwargs):
    return lp.LinuxPredictor(support.make_artifact_dir(tmp_path, **kwargs)).load()


def test_predictor_requires_explicit_load(tmp_path):
    predictor = lp.LinuxPredictor(support.make_artifact_dir(tmp_path))
    with pytest.raises(lp.ArtifactError):
        predictor.predict(np.zeros(20), observation_state=schema.STATE_MODEL_READY)


def test_missing_artifact_directory(tmp_path):
    with pytest.raises(lp.ArtifactError):
        lp.LinuxPredictor(tmp_path / "absent").load()


def test_missing_artifact_file(tmp_path):
    with pytest.raises(lp.ArtifactError):
        load_predictor(tmp_path, drop="model.pkl")


def test_corrupt_manifest(tmp_path):
    artifact_dir = support.make_artifact_dir(tmp_path)
    (artifact_dir / "manifest.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(lp.ArtifactError):
        lp.LinuxPredictor(artifact_dir).load()


@pytest.mark.parametrize("filename", ["model.pkl", "scaler.pkl", "calibrator.pkl"])
def test_tampered_artifact_is_rejected(tmp_path, filename):
    with pytest.raises(lp.ArtifactError):
        load_predictor(tmp_path, tamper=filename)


def test_tampered_scaler_hash_is_rejected(tmp_path):
    artifact_dir = support.make_artifact_dir(tmp_path)
    payload = json.loads((artifact_dir / "manifest.json").read_text(encoding="utf-8"))
    payload["artifact_hashes"]["scaler.pkl"] = "0" * 64
    (artifact_dir / "manifest.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(lp.ArtifactError):
        lp.LinuxPredictor(artifact_dir).load()


def test_schema_file_modified_after_manifest(tmp_path):
    artifact_dir = support.make_artifact_dir(tmp_path)
    payload = json.loads((artifact_dir / "schema.json").read_text(encoding="utf-8"))
    payload["units"]["file_mod_rate"] = "count"
    (artifact_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(lp.SchemaMismatchError):
        lp.LinuxPredictor(artifact_dir).load()


def test_wrong_platform_tag(tmp_path):
    with pytest.raises(lp.SchemaMismatchError):
        load_predictor(tmp_path, manifest_overrides={"platform": "windows"})


def test_wrong_schema_id(tmp_path):
    with pytest.raises(lp.SchemaMismatchError):
        load_predictor(tmp_path, manifest_overrides={"schema_id": "LBS-2"})


def test_wrong_feature_count(tmp_path):
    with pytest.raises(lp.SchemaMismatchError):
        load_predictor(tmp_path, manifest_overrides={"feature_count": 19})


def test_wrong_feature_order_in_manifest(tmp_path):
    with pytest.raises(lp.SchemaMismatchError):
        load_predictor(
            tmp_path,
            manifest_overrides={"feature_names": list(reversed(schema.LBS1_FEATURE_NAMES))},
        )


def test_reordered_schema_payload(tmp_path):
    payload = schema.schema_dict()
    payload["feature_names"] = list(reversed(payload["feature_names"]))
    with pytest.raises(lp.SchemaMismatchError):
        load_predictor(tmp_path, schema_payload=payload)


def test_schema_units_mismatch(tmp_path):
    payload = schema.schema_dict()
    payload["units"]["file_mod_rate"] = "count"
    with pytest.raises(lp.SchemaMismatchError):
        load_predictor(tmp_path, schema_payload=payload)


def test_schema_cannot_enable_critical(tmp_path):
    payload = schema.schema_dict()
    payload["critical_enabled"] = True
    with pytest.raises(lp.SchemaMismatchError):
        load_predictor(tmp_path, schema_payload=payload)


def test_model_feature_count_mismatch(tmp_path):
    model = support.FixedProbabilityModel(0.1)
    model.n_features_in_ = 19
    with pytest.raises(lp.SchemaMismatchError):
        load_predictor(tmp_path, model=model)


def test_invalid_thresholds(tmp_path):
    with pytest.raises(lp.ArtifactError):
        load_predictor(tmp_path, manifest_overrides={"thresholds": {"warning": 0.95, "critical": 0.90}})


@pytest.mark.parametrize(
    "vector",
    [
        np.zeros(19),
        np.zeros(21),
        np.full(20, np.nan),
        np.full(20, np.inf),
        np.full(20, -1.0),
        np.zeros(20, dtype=bool),
        ["a"] * 20,
    ],
)
def test_invalid_input_vectors(tmp_path, vector):
    predictor = load_predictor(tmp_path)
    with pytest.raises(lp.InputValidationError):
        predictor.predict(vector, observation_state=schema.STATE_MODEL_READY)


def test_observation_state_is_required(tmp_path):
    predictor = load_predictor(tmp_path)
    with pytest.raises(lp.NotApplicableError):
        predictor.predict(np.zeros(20))


@pytest.mark.parametrize(
    "state",
    [schema.STATE_DEGRADED, schema.STATE_INSUFFICIENT_ACTIVITY, "SOMETHING_ELSE"],
)
def test_non_ready_observation_states_are_refused(tmp_path, state):
    predictor = load_predictor(tmp_path)
    with pytest.raises(lp.NotApplicableError):
        predictor.predict(np.zeros(20), observation_state=state)


def test_non_defined_status_map_is_refused(tmp_path):
    predictor = load_predictor(tmp_path)
    status = support.all_defined()
    status["avg_shannon_entropy"] = schema.STATUS_NO_FILE_ACTIVITY
    with pytest.raises(lp.NotApplicableError):
        predictor.predict(np.zeros(20), observation_state=schema.STATE_MODEL_READY, feature_status=status)


def test_model_is_not_invoked_for_non_ready_observation(tmp_path):
    predictor = load_predictor(tmp_path)
    predictor._model = support.ExplodingModel()
    predictor._scaler = support.ExplodingScaler()
    with pytest.raises(lp.NotApplicableError):
        predictor.predict(np.zeros(20), observation_state=schema.STATE_DEGRADED)


def test_predict_observation_ready(tmp_path):
    predictor = load_predictor(tmp_path, probability=0.10)
    observation = support.make_observation()
    prediction = predictor.predict_observation(observation)
    assert prediction.probability == pytest.approx(0.10)
    assert prediction.raw_probability == pytest.approx(0.10)
    assert prediction.verdict == lp.VERDICT_SAFE
    assert prediction.critical_capped is False
    assert prediction.model_version == "lbs1-test-0.0.0"


@pytest.mark.parametrize(
    "status_overrides,group_overrides",
    [
        (
            {"avg_shannon_entropy": schema.STATUS_NO_FILE_ACTIVITY},
            {"G2": schema.GROUP_NOT_APPLICABLE},
        ),
        (
            {"avg_shannon_entropy": schema.STATUS_UNAVAILABLE_PERMISSION},
            {"G2": schema.GROUP_DEGRADED},
        ),
    ],
)
def test_predict_observation_refuses_unready(tmp_path, status_overrides, group_overrides):
    predictor = load_predictor(tmp_path)
    observation = support.make_observation(
        status_overrides=status_overrides, group_overrides=group_overrides
    )
    with pytest.raises(lp.NotApplicableError):
        predictor.predict_observation(observation)


def test_predict_observation_rejects_inconsistent_vector(tmp_path):
    predictor = load_predictor(tmp_path)
    observation = support.make_observation()
    observation.features[0] = observation.features[0] + 1.0
    with pytest.raises(lp.InputValidationError):
        predictor.predict_observation(observation)


def test_critical_cap_at_high_probability(tmp_path):
    assert schema.LBS1_CRITICAL_ENABLED is False
    predictor = load_predictor(tmp_path, probability=0.99)
    prediction = predictor.predict_observation(support.make_observation())
    assert prediction.probability == pytest.approx(0.99)
    assert prediction.verdict == lp.VERDICT_WARNING
    assert prediction.critical_capped is True


def test_warning_band(tmp_path):
    predictor = load_predictor(tmp_path, probability=0.70)
    prediction = predictor.predict_observation(support.make_observation())
    assert prediction.verdict == lp.VERDICT_WARNING
    assert prediction.critical_capped is False


def test_safe_band(tmp_path):
    predictor = load_predictor(tmp_path, probability=0.20)
    prediction = predictor.predict_observation(support.make_observation())
    assert prediction.verdict == lp.VERDICT_SAFE


def test_error_to_analysis_state_mapping():
    assert lp.ArtifactError.analysis_state == lp.ANALYSIS_ERROR_STATE
    assert lp.SchemaMismatchError.analysis_state == lp.ANALYSIS_ERROR_STATE
    assert lp.InputValidationError.analysis_state == lp.ANALYSIS_ERROR_STATE
    assert lp.NotApplicableError.analysis_state == lp.INCONCLUSIVE_STATE
    assert issubclass(lp.NotApplicableError, lp.LinuxPredictorError)


def test_verifier_accepts_valid_artifacts(tmp_path):
    artifact_dir = support.make_artifact_dir(tmp_path)
    result = verify_artifacts.verify(artifact_dir)
    assert result["status"] == "VERIFIED"
    assert result["errors"] == []


def test_verifier_rejects_tampered_artifacts(tmp_path):
    artifact_dir = support.make_artifact_dir(tmp_path)
    with open(artifact_dir / "model.pkl", "ab") as handle:
        handle.write(b"tampered")
    result = verify_artifacts.verify(artifact_dir)
    assert result["status"] == "FAILED"
    assert any("model.pkl" in error for error in result["errors"])


def test_verifier_rejects_missing_directory(tmp_path):
    result = verify_artifacts.verify(tmp_path / "absent")
    assert result["status"] == "FAILED"


def test_verifier_cli_exit_codes(tmp_path, capsys):
    artifact_dir = support.make_artifact_dir(tmp_path)
    assert verify_artifacts.main(["--artifact-dir", str(artifact_dir)]) == 0
    (artifact_dir / "scaler.pkl").write_bytes(b"corrupt")
    assert verify_artifacts.main(["--artifact-dir", str(artifact_dir)]) == 1
    capsys.readouterr()
