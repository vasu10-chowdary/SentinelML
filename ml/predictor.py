"""
SentinelML V2 - ML Predictor
==============================
Handles model loading, scaling, prediction, and threat classification.
"""

import json
import logging
import warnings
from pathlib import Path
from typing import Optional, Tuple

import joblib
import numpy as np

from utils.logging_config import get_ml_logger
from utils.paths import get_models_dir

log = get_ml_logger()

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

    def __init__(self):
        self._model = None
        self._scaler = None
        self._threshold_critical = self._DEFAULT_THRESHOLD_CRITICAL
        self._threshold_warning = self._DEFAULT_THRESHOLD_WARNING
        self._model_loaded = False
        self._model_type = "Unknown"
        self._expected_features = 19

    def load_model(self) -> bool:
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

    def get_model_info(self) -> dict:
        return {
            "type": self._model_type,
            "expected_features": self._expected_features,
            "threshold_critical": self._threshold_critical,
            "threshold_warning": self._threshold_warning,
            "loaded": self._model_loaded,
        }

    def get_thresholds(self) -> dict:
        return {
            "critical": self._threshold_critical,
            "warning": self._threshold_warning,
        }
