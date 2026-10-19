"""
SentinelML V2 — Observable Behavioral Feature Schema (Schema V2)
================================================================
Defines the versioned, empirically measurable behavioral feature schema for Windows.
This schema replaces the legacy 19-position memory-forensics schema with signals
that can be genuinely, reliably, and unprivilegedly extracted from Windows workstations.

IMPORTANT SCIENTIFIC CAVEAT:
Features in this schema are candidate behavioral signals, NOT definitive proofs of
ransomware. Legitimate applications (e.g. archiving tools, video renderers, compilers)
can exhibit elevated entropy or file modification rates. Detection requires multi-signal
corroboration and calibrated decision boundaries.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

SCHEMA_VERSION = "2.0.0"

# Ordered list of the 16 core numerical features used for model input
FEATURE_NAMES_V2: List[str] = [
    "file_mod_rate",                # [0] Files modified per second
    "file_rename_rate",             # [1] Files renamed per second
    "files_modified_count",         # [2] Total files modified in observation window
    "files_renamed_count",          # [3] Total files renamed in observation window
    "avg_shannon_entropy",          # [4] Mean Shannon entropy of sampled files (bits/byte)
    "max_shannon_entropy",          # [5] Peak Shannon entropy observed (bits/byte)
    "high_entropy_file_ratio",      # [6] Fraction of sampled files with entropy > 7.0
    "ransom_extension_match_count", # [7] Count of files matching ransomware extension signatures
    "ransom_note_match_count",      # [8] Count of dropped instructional extortion notes
    "suspicious_process_count",     # [9] Active processes matching recovery-deletion tools
    "powershell_process_count",     # [10] Active PowerShell script execution engines
    "crypto_dll_process_count",     # [11] Non-system processes actively loading crypto libraries
    "defender_service_tampered",    # [12] Binary indicator (1 if WinDefend stopped, 0 otherwise)
    "total_process_count",          # [13] Total active operating system processes
    "network_connection_count",     # [14] Total active TCP/UDP network connections
    "unique_external_ip_count",     # [15] Count of remote non-private IP endpoints
]

# Known ransomware extension signatures for candidate feature [7]
KNOWN_RANSOM_EXTENSIONS = {
    ".locked", ".crypto", ".enc", ".lockbit", ".wannacry", ".wncry",
    ".conti", ".revil", ".darkside", ".blackcat", ".hive", ".ryuk",
    ".stop", ".djvu", ".phobos", ".dharma", ".makop", ".cuba"
}

# Known instructional ransom note filenames for candidate feature [8]
KNOWN_RANSOM_NOTE_NAMES = {
    "readme_to_decrypt.txt", "decrypt_instructions.html", "how_to_recover.txt",
    "restore_my_files.txt", "lockbit_readme.txt", "readme.txt", "decryptor.html",
    "@readme_now@.txt", "help_decrypt.txt", "recovery_key.txt"
}


@dataclass
class FeatureSpec:
    """Formal technical specification for an individual Schema V2 feature."""
    name: str
    index: int
    dtype: str
    unit: str
    min_value: float
    max_value: Optional[float]
    default_missing_value: float
    description: str
    collection_method: str
    collection_cost: str
    false_positive_risks: str


FEATURE_SPECIFICATIONS: Dict[str, FeatureSpec] = {
    "file_mod_rate": FeatureSpec(
        name="file_mod_rate", index=0, dtype="float64", unit="files/sec",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Rate of file content write/modification events observed over the measurement window.",
        collection_method="Filesystem polling or ReadDirectoryChangesW / ETW file IO events.",
        collection_cost="Low (metadata timestamp polling) to Moderate (filesystem watcher).",
        false_positive_risks="Batch compilers, git checkouts, video renders, cache updates."
    ),
    "file_rename_rate": FeatureSpec(
        name="file_rename_rate", index=1, dtype="float64", unit="renames/sec",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Rate of file rename operations observed over the measurement window.",
        collection_method="Directory change notification buffer inspection.",
        collection_cost="Low.",
        false_positive_risks="Bulk media renaming utilities, refactoring tools, photo import managers."
    ),
    "files_modified_count": FeatureSpec(
        name="files_modified_count", index=2, dtype="float64", unit="count",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Total distinct files modified in the monitored tree during observation.",
        collection_method="Aggregated count of unique file modification events.",
        collection_cost="Low.",
        false_positive_risks="Software installations, package manager updates."
    ),
    "files_renamed_count": FeatureSpec(
        name="files_renamed_count", index=3, dtype="float64", unit="count",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Total distinct files renamed in the monitored tree during observation.",
        collection_method="Aggregated count of unique file rename events.",
        collection_cost="Low.",
        false_positive_risks="User bulk reorganization."
    ),
    "avg_shannon_entropy": FeatureSpec(
        name="avg_shannon_entropy", index=4, dtype="float64", unit="bits/byte",
        min_value=0.0, max_value=8.0, default_missing_value=4.0,
        description="Mean Shannon entropy of 4KB chunks across sampled modified files.",
        collection_method="Chunked file byte frequency evaluation: H = -sum(p * log2(p)).",
        collection_cost="Moderate (disk read of 4KB per file).",
        false_positive_risks="Compressed archives (.zip, .7z, .tar.gz), media files (.mp4, .jpg), encrypted databases."
    ),
    "max_shannon_entropy": FeatureSpec(
        name="max_shannon_entropy", index=5, dtype="float64", unit="bits/byte",
        min_value=0.0, max_value=8.0, default_missing_value=4.0,
        description="Peak Shannon entropy observed across sampled modified files.",
        collection_method="Maximum Shannon entropy computed over sample population.",
        collection_cost="Moderate.",
        false_positive_risks="Single compressed or encrypted file operation."
    ),
    "high_entropy_file_ratio": FeatureSpec(
        name="high_entropy_file_ratio", index=6, dtype="float64", unit="ratio",
        min_value=0.0, max_value=1.0, default_missing_value=0.0,
        description="Proportion of sampled files exhibiting Shannon entropy strictly > 7.0.",
        collection_method="Count(files with H > 7.0) / Total files sampled.",
        collection_cost="Moderate.",
        false_positive_risks="Directory containing purely compressed media or archives."
    ),
    "ransom_extension_match_count": FeatureSpec(
        name="ransom_extension_match_count", index=7, dtype="float64", unit="count",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Count of files in monitored directory ending with recognized ransomware extensions.",
        collection_method="Case-insensitive suffix matching against KNOWN_RANSOM_EXTENSIONS set.",
        collection_cost="Very Low (string suffix lookup).",
        false_positive_risks="Security research folders, simulated tests, encrypted file backups."
    ),
    "ransom_note_match_count": FeatureSpec(
        name="ransom_note_match_count", index=8, dtype="float64", unit="count",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Count of files matching recognized ransom note instructional naming patterns.",
        collection_method="Case-insensitive filename matching against KNOWN_RANSOM_NOTE_NAMES set.",
        collection_cost="Very Low.",
        false_positive_risks="Documentation files named 'readme.txt' (disambiguated by directory context)."
    ),
    "suspicious_process_count": FeatureSpec(
        name="suspicious_process_count", index=9, dtype="float64", unit="count",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Active processes executing shadow copy deletion or boot recovery tampering.",
        collection_method="psutil process enumeration matching vssadmin.exe, bcdedit.exe, wbadmin.exe, cipher.exe.",
        collection_cost="Low.",
        false_positive_risks="Legitimate system administrator backup routines or maintenance scripts."
    ),
    "powershell_process_count": FeatureSpec(
        name="powershell_process_count", index=10, dtype="float64", unit="count",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Active instances of PowerShell command line interpreters.",
        collection_method="psutil process name match for powershell.exe and pwsh.exe.",
        collection_cost="Low.",
        false_positive_risks="Developer terminal sessions, scheduled enterprise automation scripts."
    ),
    "crypto_dll_process_count": FeatureSpec(
        name="crypto_dll_process_count", index=11, dtype="float64", unit="count",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Count of non-system processes with loaded Windows cryptographic libraries.",
        collection_method="psutil memory_maps() filtering for bcrypt.dll / ncrypt.dll.",
        collection_cost="Moderate to High (requires walking process module lists).",
        false_positive_risks="Web browsers, HTTPS networking software, SSH clients."
    ),
    "defender_service_tampered": FeatureSpec(
        name="defender_service_tampered", index=12, dtype="float64", unit="binary",
        min_value=0.0, max_value=1.0, default_missing_value=0.0,
        description="Binary flag indicating whether Windows Defender service has been forcibly stopped.",
        collection_method="Query Windows Service Control Manager via Win32 API / win32service.",
        collection_cost="Very Low.",
        false_positive_risks="Third-party antivirus replacing Windows Defender legitimately."
    ),
    "total_process_count": FeatureSpec(
        name="total_process_count", index=13, dtype="float64", unit="count",
        min_value=0.0, max_value=None, default_missing_value=100.0,
        description="Total active operating system processes running on the host.",
        collection_method="len(psutil.pids()).",
        collection_cost="Very Low.",
        false_positive_risks="Baseline scaling variation across hardware configurations."
    ),
    "network_connection_count": FeatureSpec(
        name="network_connection_count", index=14, dtype="float64", unit="count",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Total active TCP and UDP sockets established on the host.",
        collection_method="len(psutil.net_connections()).",
        collection_cost="Low.",
        false_positive_risks="P2P applications, web browsing, cloud syncing agents."
    ),
    "unique_external_ip_count": FeatureSpec(
        name="unique_external_ip_count", index=15, dtype="float64", unit="count",
        min_value=0.0, max_value=None, default_missing_value=0.0,
        description="Count of unique non-RFC1918 external remote IP endpoints.",
        collection_method="Filtering psutil.net_connections remote IPs against private CIDRs.",
        collection_cost="Low.",
        false_positive_risks="Multi-CDN web browsing, media streaming."
    ),
}


@dataclass
class BehavioralVectorV2:
    """Represents a measured 16-feature Schema V2 observation with metadata."""
    features: np.ndarray  # 1D array of length 16, dtype float64
    timestamp: float
    os_version: str
    collector_version: str = SCHEMA_VERSION
    schema_version: str = SCHEMA_VERSION
    telemetry_quality_score: float = 1.0  # Fraction of sensors that executed cleanly (0.0 to 1.0)
    missing_sensor_count: int = 0
    workload_type: str = "UNKNOWN"       # e.g., BENIGN_IDLE, BENIGN_ARCHIVE, SIMULATED_ATTACK
    ground_truth_label: Optional[int] = None  # 0 = Benign, 1 = Ransomware, None = Unlabelled

    def __post_init__(self):
        if not isinstance(self.features, np.ndarray):
            self.features = np.asarray(self.features, dtype=np.float64)
        if self.features.ndim == 1:
            if self.features.shape[0] != len(FEATURE_NAMES_V2):
                raise ValueError(
                    f"Expected {len(FEATURE_NAMES_V2)} features, got {self.features.shape[0]}"
                )
        elif self.features.ndim == 2:
            if self.features.shape != (1, len(FEATURE_NAMES_V2)):
                raise ValueError(
                    f"Expected shape (1, {len(FEATURE_NAMES_V2)}), got {self.features.shape}"
                )
            self.features = self.features.flatten()
        else:
            raise ValueError(f"Invalid feature array dimension: {self.features.ndim}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert observation to dictionary for JSON/CSV serialization."""
        data = {
            "schema_version": self.schema_version,
            "collector_version": self.collector_version,
            "timestamp": self.timestamp,
            "os_version": self.os_version,
            "workload_type": self.workload_type,
            "ground_truth_label": self.ground_truth_label,
            "telemetry_quality_score": round(self.telemetry_quality_score, 4),
            "missing_sensor_count": self.missing_sensor_count,
        }
        for idx, name in enumerate(FEATURE_NAMES_V2):
            data[name] = float(self.features[idx])
        return data

    def to_model_input(self) -> np.ndarray:
        """Return 2D array formatted for Scikit-Learn inference: shape (1, 16)."""
        return self.features.reshape(1, -1)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BehavioralVectorV2":
        """Instantiate BehavioralVectorV2 from a dictionary."""
        feats = []
        for name in FEATURE_NAMES_V2:
            if name in data:
                feats.append(float(data[name]))
            else:
                spec = FEATURE_SPECIFICATIONS[name]
                feats.append(spec.default_missing_value)

        return cls(
            features=np.array(feats, dtype=np.float64),
            timestamp=float(data.get("timestamp", 0.0)),
            os_version=str(data.get("os_version", "Windows")),
            collector_version=str(data.get("collector_version", SCHEMA_VERSION)),
            schema_version=str(data.get("schema_version", SCHEMA_VERSION)),
            telemetry_quality_score=float(data.get("telemetry_quality_score", 1.0)),
            missing_sensor_count=int(data.get("missing_sensor_count", 0)),
            workload_type=str(data.get("workload_type", "UNKNOWN")),
            ground_truth_label=data.get("ground_truth_label"),
        )


def validate_schema_v2_vector(vec: np.ndarray) -> Tuple[bool, List[str]]:
    """
    Validate that an input array conforms strictly to Schema V2 constraints.
    Returns (is_valid, list_of_error_strings).
    """
    errors = []
    if vec is None:
        return False, ["Feature vector is None"]

    arr = np.asarray(vec, dtype=np.float64)
    if arr.ndim == 2:
        if arr.shape[0] != 1 or arr.shape[1] != len(FEATURE_NAMES_V2):
            errors.append(f"Invalid 2D shape {arr.shape}; expected (1, {len(FEATURE_NAMES_V2)})")
            return False, errors
        arr = arr.flatten()
    elif arr.ndim == 1:
        if arr.shape[0] != len(FEATURE_NAMES_V2):
            errors.append(f"Invalid 1D length {arr.shape[0]}; expected {len(FEATURE_NAMES_V2)}")
            return False, errors
    else:
        errors.append(f"Invalid dimension {arr.ndim}; expected 1D or 2D")
        return False, errors

    if not np.isfinite(arr).all():
        errors.append("Feature vector contains non-finite values (NaN or Inf)")

    for idx, name in enumerate(FEATURE_NAMES_V2):
        spec = FEATURE_SPECIFICATIONS[name]
        val = arr[idx]
        if spec.min_value is not None and val < spec.min_value:
            errors.append(f"Feature '{name}' value {val} is below minimum {spec.min_value}")
        if spec.max_value is not None and val > spec.max_value:
            errors.append(f"Feature '{name}' value {val} is above maximum {spec.max_value}")

    return len(errors) == 0, errors
