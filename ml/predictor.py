import threading
"""
SentinelML V2 - ML Predictor
==============================
Handles model loading, scaling, prediction, and threat classification.
"""

import json
import logging
import math
import warnings
from pathlib import Path
from typing import Any, Optional, Tuple

import joblib
import numpy as np

from utils.logging_config import get_ml_logger
from utils.paths import get_models_dir

log = get_ml_logger()


def validate_model_probability(val: Any) -> Tuple[bool, float, Optional[str]]:
    """
    Documented Model Output Contract:
    The ML predictor must return a finite float strictly within the closed interval [0.0, 1.0].

    Returns:
        (is_valid: bool, probability: float, error_message: Optional[str])

    Rejects missing values, non-numeric types, non-finite values (NaN, Inf),
    and out-of-range values (e.g. < 0.0 or > 1.0) without heuristic scale guessing.
    """
    if val is None:
        return False, 0.0, "Missing probability value (None)"
    try:
        fval = float(val)
    except (ValueError, TypeError) as e:
        return False, 0.0, f"Non-numeric probability value: {val!r} ({e})"
    if math.isnan(fval) or math.isinf(fval):
        return False, 0.0, f"Non-finite probability value: {fval!r}"
    if not (0.0 <= fval <= 1.0):
        return False, 0.0, f"Probability {fval!r} violates model contract bounds [0.0, 1.0]"
    return True, fval, None


def normalize_risk_score(val: Any) -> Tuple[float, int, str]:
    """
    Validates and formats probability according to documented model contract.
    Returns (prob_0_to_1, percent_0_to_100, status_string).
    Rejects any value outside [0.0, 1.0] without scale guessing.
    """
    is_valid, fval, err = validate_model_probability(val)
    if not is_valid:
        log.error("Model output contract violation: %s", err)
        return 0.0, 0, "INVALID"
    pct = int(round(fval * 100.0))
    return fval, pct, "VALID"

# Feature names in exact order expected by scaler/model
FEATURE_NAMES = [
    "total_processes","suspicious_process_count","avg_entropy","max_entropy",
    "high_entropy_region_count","malfind_injection_count","crypto_dll_count",
    "cmd_vssadmin_count","network_connection_count","unique_external_ips",
    "file_handle_count","registry_handle_count","orphan_process_count",
    "powershell_process_count","unsigned_module_count","suspicious_mutex_count",
    "abnormal_privilege_count","suspicious_thread_count","defender_tampering_count",
]


class MLPredictor:
    """Manages ML model and scaler, performs predictions and classification."""

    _DEFAULT_THRESHOLD_CRITICAL = 0.9
    _DEFAULT_THRESHOLD_WARNING = 0.5

    _shared_model = None
    _shared_scaler = None
    _shared_metrics = None
    _shared_lock = threading.Lock()

    def __init__(self):
        self._model = None
        self._scaler = None
        self._threshold_critical = self._DEFAULT_THRESHOLD_CRITICAL
        self._threshold_warning = self._DEFAULT_THRESHOLD_WARNING
        self._model_loaded = False
        self._model_type = "Unknown"
        self._expected_features = 19

    def load_model(self) -> bool:
        with MLPredictor._shared_lock:
            if MLPredictor._shared_model is not None and MLPredictor._shared_scaler is not None:
                self._model = MLPredictor._shared_model
                self._scaler = MLPredictor._shared_scaler
                self._model_type = type(self._model).__name__
                if hasattr(self._model, "n_features_in_"):
                    self._expected_features = self._model.n_features_in_
                if MLPredictor._shared_metrics is not None:
                    opt = MLPredictor._shared_metrics.get("optimal_threshold")
                    if opt is not None:
                        self._threshold_critical = float(opt)
                self._model_loaded = True
                return True
        models_dir = get_models_dir()
        model_path = models_dir / "saved_model.pkl"
        scaler_path = models_dir / "scaler.pkl"
        metrics_path = models_dir / "metrics.json"

        log.info("Loading ML model from: %s", model_path)

        if not model_path.exists():
            log.error("Model file not found: %s", model_path)
            return False
        if not scaler_path.exists():
            log.error("Scaler file not found: %s", scaler_path)
            return False

        try:
            self._model = joblib.load(model_path)
            self._model_type = type(self._model).__name__
            
            if hasattr(self._model, "n_features_in_"):
                self._expected_features = self._model.n_features_in_

            self._scaler = joblib.load(scaler_path)
            
            if metrics_path.exists():
                try:
                    with open(metrics_path, "r", encoding="utf-8") as f:
                        metrics = json.load(f)
                    opt_threshold = metrics.get("optimal_threshold")
                    if opt_threshold is not None:
                        self._threshold_critical = float(opt_threshold)
                except Exception as e:
                    log.warning("Failed to read metrics.json thresholds: %s", e)

            MLPredictor._shared_model = self._model
            MLPredictor._shared_scaler = self._scaler
            if metrics_path.exists():
                try:
                    with open(metrics_path, "r", encoding="utf-8") as f:
                        MLPredictor._shared_metrics = json.load(f)
                except Exception:
                    pass

            self._model_loaded = True
            log.info("ML pipeline loaded successfully (critical=%.2f, warning=%.2f)",
                     self._threshold_critical, self._threshold_warning)
            return True

        except Exception as e:
            log.error("Failed to load ML model: %s", e, exc_info=True)
            self._model_loaded = False
            return False

    def predict(self, features: np.ndarray) -> Optional[Tuple[str, float]]:
        if not self._model_loaded:
            return None

        if features is None or features.shape != (1, self._expected_features):
            log.error("Invalid feature shape")
            return None

        if not np.isfinite(features).all():
            log.error("Feature vector contains NaN or infinite values")
            return None

        try:
            # Temporarily ignore sklearn's warning about missing feature names
            # This avoids needing to import pandas in the frozen PyInstaller executable
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=UserWarning)
                
                log.debug("Scaling %d features...", self._expected_features)
                scaled = self._scaler.transform(features)
    
                log.debug("Running model prediction...")
                probabilities = self._model.predict_proba(scaled)

            threat_prob = float(probabilities[0][1])
            log.info("Threat probability: %.4f", threat_prob)

            if not (0.0 <= threat_prob <= 1.0):
                return None

            threat_level = self._classify(threat_prob)
            return (threat_level, threat_prob)

        except Exception as e:
            log.error("Prediction failed: %s", e, exc_info=True)
            return None

    def _classify(self, probability: float) -> str:
        if probability >= self._threshold_critical:
            return "CRITICAL"
        elif probability >= self._threshold_warning:
            return "WARNING"
        else:
            return "SAFE"

    def is_loaded(self) -> bool:
        return self._model_loaded

    def has_scaler(self) -> bool:
        """Read-only: whether a fitted scaler was loaded alongside the model."""
        return self._scaler is not None

    def get_model_info(self) -> dict:
        return {
            "type": self._model_type,
            "expected_features": self._expected_features,
            "threshold_critical": self._threshold_critical,
            "threshold_warning": self._threshold_warning,
            "loaded": self._model_loaded,
            "scaler_loaded": self._scaler is not None,
        }

    def get_thresholds(self) -> dict:
        return {
            "critical": self._threshold_critical,
            "warning": self._threshold_warning,
        }

    def get_feature_importances(self) -> Optional[np.ndarray]:
        """Read-only global feature importance from the trained forest, aligned to
        ``FEATURE_NAMES`` order. Returns ``None`` if the model is not loaded or does
        not expose ``feature_importances_``.

        IMPORTANT: this is a model-level aggregate (Gini importance) describing
        which features the forest used across all training samples. It is NOT a
        per-prediction explanation of any individual scan and must not be
        presented as such. The model, scaler, feature order and thresholds are
        never modified by this accessor.
        """
        if not self._model_loaded or self._model is None:
            return None
        importances = getattr(self._model, "feature_importances_", None)
        if importances is None:
            return None
        try:
            arr = np.asarray(importances, dtype=float)
        except Exception:
            return None
        if arr.ndim != 1 or arr.shape[0] != self._expected_features:
            return None
        return arr
