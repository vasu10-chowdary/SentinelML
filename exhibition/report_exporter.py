"""
SentinelML V2 — Exhibition Report Exporter
===========================================
Generates comprehensive, sanitized demonstration reports in Markdown and JSON.
Automatically redacts sensitive local usernames and absolute file paths.
"""

import re
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

from utils.paths import get_reports_dir

log = logging.getLogger("sentinel.exhibition.exporter")


def sanitize_path(text: str) -> str:
    """
    Redact personal usernames and local drive paths from text strings.
    E.g., C:\\Users\\vasur\\Desktop -> [USER_PROFILE]/Desktop
    """
    if not text:
        return ""
    # Redact Windows user home paths
    text = re.sub(r"[A-Za-z]:\\Users\\[^\\]+", "[USER_PROFILE]", text, flags=re.IGNORECASE)
    # Redact Unix user home paths
    text = re.sub(r"/home/[^/]+", "[USER_PROFILE]", text)
    return text


class ExhibitionReportExporter:
    """Exports structured, privacy-preserving demonstration reports."""

    def __init__(self, output_dir: Optional[Path] = None):
        self._output_dir = output_dir or get_reports_dir()
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def export_report(
        self,
        mode_title: str,
        scan_state: str,
        ml_prediction: Optional[str],
        probability: Optional[float],
        duration_s: float,
        features: Optional[Dict[str, float]],
        evidence_events: List[Dict[str, Any]],
        scanned_stats: Optional[Dict[str, Any]] = None,
        errors: Optional[List[str]] = None,
        notes: str = "",
        ground_truth_label: Optional[str] = None,
        score_interpretation: Optional[str] = None
    ) -> Dict[str, Path]:
        """
        Export both Markdown and JSON reports.
        Returns dictionary containing paths to both exported files.
        """
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"exhibition_demo_{timestamp_str}"

        # Build clean sanitized data dictionary
        sanitized_events = []
        for evt in (evidence_events or []):
            sanitized_events.append({
                "timestamp": evt.get("timestamp", ""),
                "phase": evt.get("phase", ""),
                "action": evt.get("action", ""),
                "target": sanitize_path(evt.get("target_path", "")),
                "details": sanitize_path(evt.get("details", "")),
                "entropy": evt.get("entropy", 0.0)
            })

        sanitized_features = {}
        if features:
            for k, v in features.items():
                sanitized_features[k] = round(float(v), 4)

        sem_interp = score_interpretation or (
            "Fraction of positive voting trees in 100-estimator Random Forest (p in [0, 1]). "
            "< 0.50 is classified as SAFE; 0.50 <= p < 0.90 is WARNING; >= 0.90 is CRITICAL."
        )

        report_data = {
            "report_id": base_filename,
            "test_timestamp": datetime.now().isoformat(),
            "scenario": mode_title,
            "demonstration_mode": mode_title,
            "ground_truth_label": ground_truth_label or "UNSPECIFIED",
            "scan_state": scan_state,
            "ml_prediction": ml_prediction or "N/A",
            "score_semantics": "Fraction of positive voting trees in 100-estimator Random Forest (p in [0, 1])",
            "score_interpretation": sem_interp,
            "malicious_probability": round(probability, 4) if probability is not None else None,
            "elapsed_seconds": round(duration_s, 3),
            "telemetry_stats": scanned_stats or {},
            "extracted_features": sanitized_features,
            "evidence_events": sanitized_events,
            "errors_encountered": [sanitize_path(e) for e in (errors or [])],
            "notes": sanitize_path(notes),
            "model_evaluated": "EXPERIMENTAL_SYNTHETIC_BASELINE_V1",
            "is_simulation": ("simulation" in mode_title.lower() or "synthetic" in mode_title.lower() or "scenario" in mode_title.lower() or "test" in mode_title.lower()),
            "observable_schema": "SCHEMA_V2_COMPATIBLE",
            "safety_disclaimer": (
                "SAFE means this scan did not detect a threat under the checks performed. "
                "It does not guarantee that the entire system is malware-free."
            ),
            "system_limitations": [
                "Evaluated using experimental synthetic-data baseline model (unvalidated against live ransomware)",
                "Unprivileged user-space (Ring-3) visibility limits",
                "Heuristic proxy fidelity (e.g. malfind and mutex approximation)",
                "Platform asymmetry: Windows handles and services unavailable on Linux"
            ]
        }

        # 1. Write JSON
        json_path = self._output_dir / f"{base_filename}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        # 2. Write Markdown
        md_path = self._output_dir / f"{base_filename}.md"
        md_content = self._render_markdown(report_data)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        log.info("Demonstration reports exported: %s and %s", json_path.name, md_path.name)
        return {"json": json_path, "md": md_path}

    def _render_markdown(self, data: Dict[str, Any]) -> str:
        """Render a readable Markdown exhibition summary."""
        lines = [
            "# SENTINELML V2 — EXHIBITION DEMONSTRATION & AUDIT REPORT",
            f"**Report ID:** `{data['report_id']}`  ",
            f"**Test Timestamp:** `{data.get('test_timestamp', '')}`  ",
            f"**Scenario:** `{data.get('scenario', data.get('demonstration_mode', ''))}`  ",
            f"**Ground-Truth Label:** `{data.get('ground_truth_label', 'UNSPECIFIED')}`  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            f"- **Final Scan State:** `{data['scan_state']}`",
            f"- **Model Threat Level:** `{data['ml_prediction']}`",
            f"- **Raw Threat Score:** `{data['malicious_probability']}`",
            f"- **Score Interpretation:** {data.get('score_interpretation', data.get('score_semantics', ''))}",
            f"- **Execution Duration:** `{data['elapsed_seconds']} s`",
            "",
            "> **Safety Disclaimer:**  ",
            f"> *{data['safety_disclaimer']}*",
            "",
            "---",
            "",
            "## 2. Telemetry and Feature Analysis (19 Features)",
            "| Feature Index | Telemetry Name | Extracted Value |",
            "|---|---|---|"
        ]

        feats = data.get("extracted_features", {})
        if feats:
            for idx, (fname, fval) in enumerate(feats.items()):
                lines.append(f"| `[{idx:02d}]` | `{fname}` | `{fval}` |")
        else:
            lines.append("| - | *No feature telemetry recorded* | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Evidence and Event Timeline",
            "| Timestamp | Phase | Action | Target | Details | Entropy |",
            "|---|---|---|---|---|---|"
        ])

        events = data.get("evidence_events", [])
        if events:
            for evt in events[:50]:  # Cap at 50 for markdown readability
                ent_str = f"{evt['entropy']:.2f}" if evt.get("entropy") else "-"
                lines.append(
                    f"| {evt.get('timestamp','')} | {evt.get('phase','')} | "
                    f"`{evt.get('action','')}` | `{evt.get('target','')}` | "
                    f"{evt.get('details','')} | {ent_str} |"
                )
        else:
            lines.append("| - | - | *No simulation events recorded* | - | - | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Operational Invariants and System Limitations",
            "1. **Deterministic Local ML:** The Random Forest classifier authoritatively controls detection. SentinelAI is advisory only.",
            "2. **State Failure Integrity:** Unhandled exceptions or missing models branch exclusively to `SCAN_INCOMPLETE` or `ANALYSIS_ERROR`—never defaulting to `SAFE`.",
            "3. **Documented Limitations:**"
        ])
        for lim in data.get("system_limitations", []):
            lines.append(f"   - {lim}")

        if data.get("errors_encountered"):
            lines.extend([
                "",
                "### Errors Recorded During Execution:",
                "```"
            ])
            for err in data["errors_encountered"]:
                lines.append(err)
            lines.append("```")

        lines.append("")
        return "\n".join(lines)
