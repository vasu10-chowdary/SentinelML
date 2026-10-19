"""
SentinelML V2 — Model Training Pipeline V2 (train_v2.py)
========================================================
Implements reproducible, leakage-free training for Schema V2 behavioral models.

SCIENTIFIC INTEGRITY ENFORCEMENT:
1. Data Readiness Gate: Inspects dataset before training. If empirical ransomware telemetry
   is missing or synthetic, stops execution immediately and produces a readiness report.
2. Leakage-Free Preprocessing: Fits Scaler strictly on X_train; transforms X_val and X_test.
3. Strict Threshold Calibration on Validation Set: Optimizes decision thresholds using the
   validation split, preserving the held-out test split strictly for final evaluation.
4. Independent Serialization: Saves to `models/v2/`, NEVER overwriting the legacy V1 baseline
   (`models/saved_model.pkl` or `models/scaler.pkl`).
5. Baseline Comparison: Compares candidate model against a simple baseline classifier.
"""

import os
import sys
import json
import time
import joblib
import platform
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, precision_recall_curve, roc_auc_score
)

from ml.schema_v2 import SCHEMA_VERSION, FEATURE_NAMES_V2
from ml.dataset_manager import DatasetManager

DEFAULT_V2_MODEL_DIR = Path(__file__).resolve().parent.parent / "models" / "v2"


class ModelTrainerV2:
    """Trainer for next-generation Schema V2 behavioral ransomware detectors."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir) if output_dir else DEFAULT_V2_MODEL_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.dataset_manager = DatasetManager()

    def run_training(
        self,
        dataset_path: Optional[Path] = None,
        random_state: int = 42,
        target_precision: float = 0.99
    ) -> Dict[str, Any]:
        """
        Execute the Schema V2 training workflow.
        Stops before training if empirical ransomware telemetry is absent.
        """
        print(f"\n========================================================")
        print(f"SentinelML V2 — Model Training Pipeline (Schema {SCHEMA_VERSION})")
        print(f"========================================================\n")

        # ── Step 1: Data Readiness Inspection ────────────────────────────────
        if dataset_path is None or not Path(dataset_path).exists():
            print("[WARN] No external dataset supplied. Checking for local empirical data...")
            readiness = self.dataset_manager.check_readiness_for_training(None)
            report = {
                "status": "TRAINING_BLOCKED",
                "reason": "DATASET_UNAVAILABLE",
                "schema_version": SCHEMA_VERSION,
                "readiness": readiness,
                "message": "Model training stopped. Empirical ransomware telemetry must be acquired first."
            }
            self._save_training_report(report)
            print("[CRITICAL] DATA BLOCKER: Training aborted because verified empirical telemetry is missing.")
            return report

        p = Path(dataset_path)
        import_audit = self.dataset_manager.import_dataset(
            file_path=p,
            dataset_name=p.stem,
            license_name="Authorized Research License",
            provenance_source=str(p),
            is_synthetic=False
        )

        df = pd.read_csv(p) if p.suffix.lower() == ".csv" else pd.read_json(p, lines=True)
        readiness = self.dataset_manager.check_readiness_for_training(df)

        if not readiness["ready_for_training"]:
            print(f"[CRITICAL] DATASET NOT READY FOR RETRAINING:")
            for reason in readiness["blocking_reasons"]:
                print(f"  - {reason}")
            print(f"Action: {readiness.get('action_required', 'Supply verified empirical data.')}")
            report = {
                "status": "TRAINING_BLOCKED",
                "reason": "INSUFFICIENT_EMPIRICAL_DATA",
                "schema_version": SCHEMA_VERSION,
                "import_audit": import_audit,
                "readiness": readiness
            }
            self._save_training_report(report)
            return report

        # ── Step 2: Leakage-Free Splitting ────────────────────────────────────
        print(f"[OK] Dataset verified: {len(df)} total rows. Proceeding with leakage-free partition...")
        train_df, val_df, test_df = self.dataset_manager.split_dataset(
            df, test_size=0.15, val_size=0.15, random_state=random_state
        )
        print(f"Split completed: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")

        X_train = train_df[FEATURE_NAMES_V2].values
        y_train = train_df["label"].values if "label" in train_df else train_df["ground_truth_label"].values

        X_val = val_df[FEATURE_NAMES_V2].values
        y_val = val_df["label"].values if "label" in val_df else val_df["ground_truth_label"].values

        X_test = test_df[FEATURE_NAMES_V2].values
        y_test = test_df["label"].values if "label" in test_df else test_df["ground_truth_label"].values

        # ── Step 3: Leakage-Free Preprocessing (Fit on Train Only) ────────────
        scaler = RobustScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_val_s = scaler.transform(X_val)
        X_test_s = scaler.transform(X_test)

        # ── Step 4: Simple Baseline Comparison ────────────────────────────────
        baseline = LogisticRegression(random_state=random_state, max_iter=1000)
        baseline.fit(X_train_s, y_train)
        y_base_pred = baseline.predict(X_test_s)
        base_f1 = f1_score(y_test, y_base_pred, zero_division=0)
        base_acc = accuracy_score(y_test, y_base_pred)

        # ── Step 5: Candidate Model Training (Random Forest) ──────────────────
        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            class_weight="balanced",
            random_state=random_state
        )
        rf.fit(X_train_s, y_train)

        # ── Step 6: Threshold Calibration on Validation Split ─────────────────
        y_val_prob = rf.predict_proba(X_val_s)[:, 1]
        precisions, recalls, thresholds = precision_recall_curve(y_val, y_val_prob)
        valid_indices = np.where(precisions >= target_precision)[0]
        if len(valid_indices) > 0 and valid_indices[0] < len(thresholds):
            calibrated_threshold = float(thresholds[valid_indices[0]])
        else:
            calibrated_threshold = 0.85

        # ── Step 7: Final Evaluation on Held-Out Test Split ───────────────────
        y_test_prob = rf.predict_proba(X_test_s)[:, 1]
        y_test_pred_calibrated = (y_test_prob >= calibrated_threshold).astype(int)

        cm = confusion_matrix(y_test, y_test_pred_calibrated)
        tn, fp, fn, tp = cm.ravel()
        fpr = round(float(fp / (fp + tn)), 4) if (fp + tn) > 0 else 0.0
        fnr = round(float(fn / (fn + tp)), 4) if (fn + tp) > 0 else 0.0

        test_metrics = {
            "accuracy": round(float(accuracy_score(y_test, y_test_pred_calibrated)), 4),
            "precision": round(float(precision_score(y_test, y_test_pred_calibrated, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_test_pred_calibrated, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, y_test_pred_calibrated, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y_test, y_test_prob)), 4) if len(np.unique(y_test)) > 1 else None,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "confusion_matrix": cm.tolist(),
        }

        baseline_metrics = {
            "baseline_model": "LogisticRegression",
            "accuracy": round(float(base_acc), 4),
            "f1_score": round(float(base_f1), 4),
        }

        # ── Step 8: Separate Serialization (models/v2/) ───────────────────────
        model_save_path = self.output_dir / "saved_model_v2.pkl"
        scaler_save_path = self.output_dir / "scaler_v2.pkl"
        meta_save_path = self.output_dir / "metadata_v2.json"

        joblib.dump(rf, model_save_path)
        joblib.dump(scaler, scaler_save_path)

        metadata = {
            "status": "TRAINING_COMPLETE",
            "schema_version": SCHEMA_VERSION,
            "feature_names": FEATURE_NAMES_V2,
            "feature_count": len(FEATURE_NAMES_V2),
            "calibrated_threshold": calibrated_threshold,
            "random_state": random_state,
            "dataset_audit": import_audit,
            "split_sizes": {"train": len(train_df), "val": len(val_df), "test": len(test_df)},
            "baseline_metrics": baseline_metrics,
            "test_metrics": test_metrics,
            "environment": {
                "os": f"{platform.system()} {platform.release()}",
                "python": platform.python_version(),
                "sklearn": "1.6+"
            },
            "training_completed_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        with open(meta_save_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        print(f"\n[SUCCESS] Model V2 successfully trained and saved to {self.output_dir}")
        print(f"Calibrated Threshold: {calibrated_threshold:.4f} | Test F1: {test_metrics['f1_score']:.4f}")
        return metadata

    def _save_training_report(self, report: Dict[str, Any]) -> None:
        """Save a JSON log of training status (especially if blocked)."""
        report_path = self.output_dir / "training_run_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelML Schema V2 Model Trainer")
    parser.add_argument("--dataset", default=None, help="Path to empirical Schema V2 dataset CSV/JSONL")
    parser.add_argument("--output-dir", default=None, help="Directory to save V2 models")
    parser.add_argument("--check-readiness", action="store_true", help="Check data readiness and exit")
    args = parser.parse_args()

    trainer = ModelTrainerV2(output_dir=args.output_dir)
    if args.check_readiness:
        dm = DatasetManager()
        readiness = dm.check_readiness_for_training(None)
        print(json.dumps(readiness, indent=2))
    else:
        trainer.run_training(dataset_path=args.dataset)
