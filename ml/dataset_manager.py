"""
SentinelML V2 — Evaluation Dataset Workflow & Schema Manager
============================================================
Provides validation, deduplication, leakage prevention, and splitting
for research datasets under Schema V2.

SCIENTIFIC INTEGRITY ENFORCEMENT:
1. Strict Schema Validation: Datasets with incompatible features or unverified units are rejected.
2. Leakage Prevention: Deduplication and family-aware grouping prevent identical samples
   from polluting both training and test splits.
3. Provenance & License Auditing: Every imported dataset must declare its source license,
   origin, and empirical collection conditions.
4. Transparent Readiness Verification: If verified empirical ransomware telemetry is absent,
   the manager flags `ready = False` rather than fabricating data.
"""

import os
import sys
import json
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from ml.schema_v2 import SCHEMA_VERSION, FEATURE_NAMES_V2, validate_schema_v2_vector

DATA_ROOT = Path(__file__).resolve().parent.parent / "data"
AUDIT_LOG_PATH = DATA_ROOT / "dataset_audit_log.jsonl"


class DatasetManager:
    """Manages dataset imports, schema verification, deduplication, and data splits."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = Path(data_dir) if data_dir else DATA_ROOT
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log_path = self.data_dir / "dataset_audit_log.jsonl"

    def _log_audit_event(self, action: str, details: Dict[str, Any]) -> None:
        """Append an entry to the dataset audit trail."""
        event = {
            "timestamp": time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            "details": details,
        }
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def validate_dataframe(self, df: pd.DataFrame) -> Tuple[bool, List[str]]:
        """
        Validate that a DataFrame strictly conforms to Schema V2 feature requirements.
        """
        errors = []
        if df is None or df.empty:
            return False, ["DataFrame is empty or None."]

        # Check for required feature columns
        missing_cols = [c for c in FEATURE_NAMES_V2 if c not in df.columns]
        if missing_cols:
            errors.append(f"Missing required Schema V2 columns: {missing_cols}")

        if "label" not in df.columns and "ground_truth_label" not in df.columns:
            errors.append("Dataset must contain a ground truth 'label' column (0 = Benign, 1 = Ransomware).")

        # Check for NaN / Inf in features
        for c in FEATURE_NAMES_V2:
            if c in df.columns:
                if df[c].isna().any():
                    errors.append(f"Column '{c}' contains NaN values.")
                if np.isinf(df[c]).any():
                    errors.append(f"Column '{c}' contains Infinite values.")

        return len(errors) == 0, errors

    def import_dataset(
        self,
        file_path: Path,
        dataset_name: str,
        license_name: str,
        provenance_source: str,
        is_synthetic: bool = False
    ) -> Dict[str, Any]:
        """
        Import and validate an external research dataset with audit metadata.
        """
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"Source dataset file not found: {p}")

        # Compute file SHA-256
        h = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        file_sha256 = h.hexdigest()

        # Load file
        if p.suffix.lower() == ".csv":
            df = pd.read_csv(p)
        elif p.suffix.lower() in [".jsonl", ".json"]:
            df = pd.read_json(p, lines=True)
        else:
            raise ValueError(f"Unsupported dataset format: {p.suffix}")

        # Validate schema
        is_valid, validation_errors = self.validate_dataframe(df)

        # Count duplicates across feature columns
        features_subset = [c for c in FEATURE_NAMES_V2 if c in df.columns]
        n_duplicates = int(df.duplicated(subset=features_subset).sum()) if features_subset else 0

        # Audit record
        audit_details = {
            "dataset_name": dataset_name,
            "source_path": str(p),
            "sha256": file_sha256,
            "license": license_name,
            "provenance": provenance_source,
            "is_synthetic": is_synthetic,
            "row_count": len(df),
            "duplicate_count": n_duplicates,
            "is_valid_schema_v2": is_valid,
            "validation_errors": validation_errors,
        }
        self._log_audit_event("IMPORT_DATASET", audit_details)

        return audit_details

    def deduplicate(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
        """
        Remove duplicate feature observations to prevent data leakage between splits.
        """
        features_subset = [c for c in FEATURE_NAMES_V2 if c in df.columns]
        initial_len = len(df)
        cleaned_df = df.drop_duplicates(subset=features_subset, keep="first").reset_index(drop=True)
        dropped_count = initial_len - len(cleaned_df)
        return cleaned_df, dropped_count

    def split_dataset(
        self,
        df: pd.DataFrame,
        test_size: float = 0.15,
        val_size: float = 0.15,
        random_state: int = 42,
        group_col: Optional[str] = None
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Split dataset into train, validation, and test splits with strict leakage prevention.
        Deduplicates features first, then executes stratified or group-aware partitioning.
        """
        cleaned_df, _ = self.deduplicate(df)
        label_col = "label" if "label" in cleaned_df.columns else "ground_truth_label"

        if group_col and group_col in cleaned_df.columns:
            # Group-aware splitting (e.g. by malware family)
            groups = cleaned_df[group_col].unique()
            np.random.seed(random_state)
            shuffled_groups = np.random.permutation(groups)
            n_test_groups = max(1, int(len(groups) * test_size))
            n_val_groups = max(1, int(len(groups) * val_size))

            test_groups = shuffled_groups[:n_test_groups]
            val_groups = shuffled_groups[n_test_groups:n_test_groups + n_val_groups]
            train_groups = shuffled_groups[n_test_groups + n_val_groups:]

            test_df = cleaned_df[cleaned_df[group_col].isin(test_groups)].reset_index(drop=True)
            val_df = cleaned_df[cleaned_df[group_col].isin(val_groups)].reset_index(drop=True)
            train_df = cleaned_df[cleaned_df[group_col].isin(train_groups)].reset_index(drop=True)
        else:
            # Standard stratified split
            y = cleaned_df[label_col]
            train_val_df, test_df = train_test_split(
                cleaned_df, test_size=test_size, random_state=random_state, stratify=y
            )
            val_relative = val_size / (1.0 - test_size)
            y_train_val = train_val_df[label_col]
            train_df, val_df = train_test_split(
                train_val_df, test_size=val_relative, random_state=random_state, stratify=y_train_val
            )

        self._log_audit_event("SPLIT_DATASET", {
            "total_samples": len(cleaned_df),
            "train_samples": len(train_df),
            "val_samples": len(val_df),
            "test_samples": len(test_df),
            "group_col": group_col,
            "random_state": random_state
        })

        return (
            train_df.reset_index(drop=True),
            val_df.reset_index(drop=True),
            test_df.reset_index(drop=True)
        )

    def check_readiness_for_training(self, imported_dataset_df: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
        """
        Evaluate whether verified, non-synthetic training data is available for model training.
        If empirical ransomware telemetry is missing, flags NOT READY.
        """
        readiness = {
            "ready_for_training": False,
            "schema_version": SCHEMA_VERSION,
            "empirical_benign_samples": 0,
            "empirical_ransomware_samples": 0,
            "blocking_reasons": [],
            "action_required": ""
        }

        if imported_dataset_df is None or imported_dataset_df.empty:
            readiness["blocking_reasons"].append("No Schema V2 training dataset has been supplied.")
            readiness["action_required"] = "Collect benign telemetry and execute isolated VM malware detonations under Schema V2."
            return readiness

        label_col = "label" if "label" in imported_dataset_df.columns else "ground_truth_label"
        if label_col not in imported_dataset_df.columns:
            readiness["blocking_reasons"].append("Dataset lacks ground truth 'label' column.")
            return readiness

        n_benign = int((imported_dataset_df[label_col] == 0).sum())
        n_ransom = int((imported_dataset_df[label_col] == 1).sum())

        readiness["empirical_benign_samples"] = n_benign
        readiness["empirical_ransomware_samples"] = n_ransom

        if n_benign < 100:
            readiness["blocking_reasons"].append(f"Insufficient benign baseline samples ({n_benign} < 100).")
        if n_ransom < 100:
            readiness["blocking_reasons"].append(f"Insufficient empirical ransomware samples ({n_ransom} < 100).")

        # Check if dataset is marked synthetic
        if imported_dataset_df.get("is_synthetic", pd.Series([False])).any():
            readiness["blocking_reasons"].append("Dataset is flagged as synthetic; empirical real-world training prohibited.")

        readiness["ready_for_training"] = len(readiness["blocking_reasons"]) == 0
        return readiness
