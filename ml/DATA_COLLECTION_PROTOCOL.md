# SENTINELML V2 — BENIGN TELEMETRY DATA COLLECTION PROTOCOL

**Protocol Version:** 2.0.0  
**Effective Date:** October 19, 2026  
**Implementation:** `ml/collector_v2.py`  
**Storage Path:** `data/telemetry_v2/`  

---

## 1. Objectives & Privacy Safeguards

The objective of the SentinelML V2 Benign Telemetry Collector is to gather empirical behavioral distributions of legitimate Windows workloads without capturing sensitive user information or executing live malware.

### Strict Privacy & Ethical Rules:
1. **Zero File Content Capture:** The collector reads only the first 4KB of files to compute numerical byte frequency distributions (Shannon entropy). **No file text, image data, database content, or document payloads are ever stored or transmitted**.
2. **Zero Credential or Private Key Inspection:** The collector does not inspect registry credential stores, browser cookies, SSH keys, or memory buffers.
3. **No PII in File Path Strings:** Telemetry records store numerical metrics (rates, counts, ratios). Individual file paths are processed ephemerally in volatile memory and are not persisted in telemetry records.
4. **Explicit Opt-In & Control:** Collection runs only when explicitly initiated via `start_collection()`. The user retains the right to inspect, audit, or delete all captured sessions.

---

## 2. Session Directory Structure

Every collection session is stored in an isolated, timestamped subdirectory under `data/telemetry_v2/`:

```
data/telemetry_v2/
  └── session_20261019_164500/
        ├── manifest.json       # Session metadata, OS version, timestamps, schema version
        └── records.jsonl       # JSON Lines: each line is an independent Schema V2 observation
```

### Manifest Schema (`manifest.json`):
```json
{
  "session_id": "session_20261019_164500",
  "session_name": "developer_workload",
  "schema_version": "2.0.0",
  "collector_version": "2.0.0",
  "start_time": 1792408500.123,
  "start_time_iso": "2026-10-19T11:15:00Z",
  "os_version": "Windows 11 (AMD64)",
  "python_version": "3.14.3",
  "target_directory": "C:\\Users\\vasur\\Desktop\\project",
  "workload_description": "Normal python package build and git checkout",
  "status": "COMPLETED",
  "total_records": 120,
  "duration_seconds": 360.5,
  "mean_quality_score": 0.985
}
```

---

## 3. Representative Benign Workload Harnesses

The collector provides built-in workload runners to capture empirical baseline variations across four common workstation activities:

1. **Ordinary Document Operations (`run_workload_ordinary_file_ops`):**  
   Simulates editing and saving plain text files, spreadsheets, and configuration files.  
   *Expected Telemetry:* Low modification rates ($1 - 5$ files/sec), normal entropy ($3.0 - 4.5$ bits/byte), zero high-entropy files ($H > 7.0$), zero ransom extensions.
2. **Archive Compression (`run_workload_archive_creation`):**  
   Simulates creating `.zip` or `.7z` backup archives.  
   *Expected Telemetry:* High entropy on the generated archive ($H > 7.5$), but zero file renames and zero suspicious processes. Validates that the model does not trigger false positives on legitimate encryption/compression.
3. **Software Development Builds (`run_workload_development_build`):**  
   Simulates compiler output, intermediate bytecode (`.pyc`, `.obj`), and Git repository checkouts.  
   *Expected Telemetry:* Burst file creation rates ($10 - 30$ files/sec), moderate entropy ($4.0 - 5.5$), moderate handle usage.
4. **Large File Transfers (`run_workload_large_file_transfer`):**  
   Simulates copying multi-megabyte media or database files across directories.  
   *Expected Telemetry:* Sustained disk I/O, low file counts, low process anomalies.

---

## 4. User Review and Deletion Commands

Users can inspect or purge stored telemetry at any time using Python or the SentinelML CLI:

```python
from ml.collector_v2 import BenignTelemetryCollector

collector = BenignTelemetryCollector()

# List all sessions
sessions = collector.list_sessions()
print(f"Recorded sessions: {len(sessions)}")

# Review details of a specific session
details = collector.review_session("session_20261019_164500")
print(f"Records count: {details['records_count']}")
print(f"First record sample: {details['records_sample'][0]}")

# Delete a session permanently
collector.delete_session("session_20261019_164500")
```
