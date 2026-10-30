"""
SentinelML V2 — Incident / Integrity Report Writer
===================================================
Privacy-preserving report generation shared by the File Integrity Watchtower
and (later) the incident workflow.

Guarantees:
  * No file contents, credentials, or unrelated private text are included —
    only paths (sanitised), hashes, counts, timestamps and provenance.
  * The report is an investigation aid, NOT a forensic certification.
  * Filenames are deterministic; collisions get a numeric suffix instead of
    overwriting earlier reports.
  * Every observation carries its provenance; limitations are always recorded.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from exhibition.report_exporter import sanitize_path
from exhibition.ai_observatory import (
    classification_from_scan,
    coverage_summary,
    feature_rows,
)
from utils.paths import get_reports_dir

log = logging.getLogger("sentinel.exhibition.incident_report")

REPORT_VERSION = "1.0"
REPORT_NOTICE = ("Investigation aid produced by SentinelML. This is not a "
                 "forensic certification and does not prove malware.")
MAX_ROWS_PER_SECTION = 200
MAX_EVIDENCE_ROWS = 400

_INCIDENT_LIMITATIONS = [
    "This report is an investigation aid, not a forensic certification, and does not prove malware.",
    "Every observation carries its provenance; SIMULATED and HEURISTIC items are not host measurements.",
    "Missing or unavailable evidence must not be read as evidence of absence.",
    "A model probability is an estimate under the trained model, not a diagnosis.",
]

NEXT_STEPS = [
    "Preserve the evidence listed above before making further changes to the system.",
    "Investigate each indicator in context (file, process, account, network) rather than in isolation.",
    "If compromise is suspected, isolate the host from the network using your existing incident process.",
    "Validate a trusted backup before restoring anything.",
    "Corroborate before acting: a changed hash or a prediction alone does not prove ransomware.",
]

_EVIDENCE_STRING_FIELDS = ("title", "detail", "source")


def _sanitize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize user-path-bearing strings in one evidence dict."""
    clean = dict(event)
    for key in _EVIDENCE_STRING_FIELDS:
        if key in clean and isinstance(clean[key], str):
            clean[key] = sanitize_path(clean[key])
    for key in ("evidence", "limitations"):
        if isinstance(clean.get(key), list):
            clean[key] = [sanitize_path(str(x)) for x in clean[key]]
    return clean


def _scan_block(scan_result: Any) -> Dict[str, Any]:
    """Honest scan summary; never fabricates a SAFE verdict or a probability."""
    if scan_result is None:
        return {
            "available": False,
            "scan_id": "UNAVAILABLE",
            "state": "UNAVAILABLE",
            "scan_origin": "UNAVAILABLE",
            "is_simulation": False,
            "classification": "UNAVAILABLE",
            "probability": None,
            "probability_status": "UNAVAILABLE",
            "probability_note": "No scan result was supplied.",
            "scan_timestamp": None,
            "timestamp_note": "No scan was supplied, so no scan time is recorded.",
            "elapsed_seconds": 0.0,
            "telemetry": {},
            "features": [],
            "feature_coverage": coverage_summary([]),
        }

    state = getattr(scan_result, "state", None)
    state_name = str(getattr(state, "value", state) or "UNAVAILABLE").upper()
    origin = str(getattr(scan_result, "scan_origin", "") or "LIVE_HOST_SCAN")
    simulated = bool(getattr(scan_result, "is_simulation", False)) or origin == "CONTROLLED_SIMULATION"
    label, prob, note = classification_from_scan(scan_result)

    features = getattr(scan_result, "_features", None)
    availability = getattr(scan_result, "telemetry_availability", {}) or {}
    if state_name in ("ERROR", "ANALYSIS_ERROR"):
        source = "error"
    elif features is None:
        source = "unavailable"
    elif simulated:
        source = "simulated"
    else:
        source = "real"
    rows = feature_rows(features, availability, source=source)
    coverage = coverage_summary(rows)

    telemetry = {
        "files_inspected": int(getattr(scan_result, "files_inspected", 0) or 0),
        "directories_inspected": int(getattr(scan_result, "directories_inspected", 0) or 0),
        "files_skipped": int(getattr(scan_result, "files_skipped", 0) or 0),
        "access_denied": int(getattr(scan_result, "access_denied", 0) or 0),
        "filesystem_errors": int(getattr(scan_result, "filesystem_errors", 0) or 0),
        "processes_analyzed": int(getattr(scan_result, "processes_analyzed", 0) or 0),
        "process_errors": int(getattr(scan_result, "process_errors", 0) or 0),
        "elapsed_seconds": round(float(getattr(scan_result, "elapsed_seconds", 0.0) or 0.0), 3),
        "ml_executed": bool(getattr(scan_result, "ml_executed", False)),
        "cancelled": bool(getattr(scan_result, "cancelled", False)),
        "model_source": str(getattr(scan_result, "model_source", "UNAVAILABLE") or "UNAVAILABLE"),
        "missing_features": list(getattr(scan_result, "missing_features", []) or []),
        "available_feature_count": int(getattr(scan_result, "available_feature_count", 0) or 0),
        "telemetry_coverage_ratio": round(
            float(getattr(scan_result, "telemetry_coverage_ratio", 0.0) or 0.0), 3),
        "error_message": sanitize_path(str(getattr(scan_result, "error_message", "") or "")),
    }

    return {
        "available": True,
        "scan_id": str(getattr(scan_result, "scan_id", "") or "UNIDENTIFIED"),
        "state": state_name,
        "scan_origin": origin,
        "is_simulation": simulated,
        "classification": label,
        "probability": prob,
        "probability_status": "MEASURED" if prob is not None else "UNAVAILABLE",
        "probability_note": note,
        "scan_timestamp": getattr(scan_result, "timestamp", None),
        "timestamp_note": ("The scan engine records elapsed duration, not wall-clock "
                           "start/end timestamps."),
        "elapsed_seconds": round(float(getattr(scan_result, "elapsed_seconds", 0.0) or 0.0), 3),
        "telemetry": telemetry,
        "features": [
            {"index": r["index"], "name": r["name"], "value": r["value"],
             "status": r["status"], "description": r.get("description", "")}
            for r in rows
        ],
        "feature_coverage": coverage,
    }


def _correlation_block(correlator: Any) -> Dict[str, Any]:
    if correlator is None:
        return {
            "available": False,
            "summary": {"total": 0},
            "findings": [{
                "kind": "NO_EVIDENCE",
                "statement": "No evidence was supplied to the correlator.",
                "provenance": "UNAVAILABLE",
                "caveat": "Collect scan, integrity, or timeline evidence first.",
            }],
            "events": [],
            "events_truncated": False,
        }
    try:
        events = [_sanitize_event(dict(e)) for e in correlator.to_dicts()]
    except Exception:
        events = []
    try:
        summary = dict(correlator.summary())
    except Exception:
        summary = {"total": len(events)}
    try:
        findings = [dict(f) for f in correlator.findings()]
    except Exception:
        findings = []
    return {
        "available": True,
        "summary": summary,
        "findings": findings,
        "events": events[:MAX_EVIDENCE_ROWS],
        "events_truncated": len(events) > MAX_EVIDENCE_ROWS,
    }


def build_incident_report(scan_result: Any = None,
                          correlator: Any = None,
                          integrity_report: Optional[Dict[str, Any]] = None,
                          ai_summary: Optional[str] = None,
                          scenario: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a structured, provenance-aware incident report.

    Nothing is fabricated: unavailable values stay ``None`` with an explicit
    ``UNAVAILABLE`` status, and a failed/cancelled/incomplete scan is never
    converted into SAFE.
    """
    generated = _iso_now()
    scan_block = _scan_block(scan_result)
    correlation = _correlation_block(correlator)
    scan_id = scan_block.get("scan_id", "UNIDENTIFIED")
    report_id = f"INCIDENT-{scan_id}-{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    limitations = list(_INCIDENT_LIMITATIONS)
    cov = scan_block.get("feature_coverage", {})
    if cov.get("unavailable"):
        limitations.append(
            f"{cov['unavailable']} of {cov['total']} model inputs were unavailable on this host.")
    if scan_block.get("is_simulation"):
        limitations.append("The supplied scan was a controlled simulation, not a live-host measurement.")
    if integrity_report:
        for lim in integrity_report.get("limitations", [])[:4]:
            if lim not in limitations:
                limitations.append(str(lim))
    if getattr(scan_result, "is_inconclusive", False):
        limitations.append("The scan was flagged inconclusive; coverage was insufficient for a verdict.")

    measured = int(correlation.get("summary", {}).get("measured", 0) or 0)
    simulated = int(correlation.get("summary", {}).get("simulated", 0) or 0)

    report = {
        "report_type": "INCIDENT",
        "report_version": REPORT_VERSION,
        "report_id": report_id,
        "generated_at": generated,
        "notice": REPORT_NOTICE,
        "scenario": (scenario or {}).get("name") if scenario else None,
        "scan": scan_block,
        "correlation": correlation,
        "integrity": integrity_report,
        "ai_summary": sanitize_path(ai_summary) if ai_summary else None,
        "measured_vs_simulated": {
            "scan_is_simulation": scan_block.get("is_simulation", False),
            "evidence_measured": measured,
            "evidence_simulated": simulated,
            "note": ("Evidence items are labelled individually; counts describe provenance, "
                     "not severity."),
        },
        "next_steps": list(NEXT_STEPS),
        "limitations": limitations,
    }
    if scenario:
        report["scenario"] = {
            "id": scenario.get("scenario_id"),
            "key": scenario.get("scenario_key"),
            "name": scenario.get("name"),
            "purpose": scenario.get("purpose"),
            "expected_outcome": scenario.get("expected_outcome"),
            "expectation_met": scenario.get("expectation_met"),
        }
    return report


def render_incident_markdown(report: Dict[str, Any]) -> str:
    scan = report.get("scan", {})
    tel = scan.get("telemetry", {})
    cov = scan.get("feature_coverage", {})
    corr = report.get("correlation", {})
    integrity = report.get("integrity") or {}
    lines = [
        "# SENTINELML V2 — INCIDENT INVESTIGATION REPORT",
        "",
        f"**Report ID:** `{report.get('report_id', '')}`  ",
        f"**Generated:** `{report.get('generated_at', '')}`  ",
        f"**Version:** `{report.get('report_version', REPORT_VERSION)}`  ",
        "",
        f"> {report.get('notice', REPORT_NOTICE)}",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Scan ID:** `{scan.get('scan_id', 'UNAVAILABLE')}`",
        f"- **Scan state:** `{scan.get('state', 'UNAVAILABLE')}`",
        f"- **Classification:** `{scan.get('classification', 'UNAVAILABLE')}`",
        f"- **Model probability:** " + (
            f"`{scan['probability']:.4f}` ({scan.get('probability_status', 'MEASURED')})"
            if scan.get("probability") is not None else
            "`UNAVAILABLE` — " + (scan.get("probability_note") or "not reported")),
        f"- **Origin:** `{scan.get('scan_origin', 'UNAVAILABLE')}`"
        + (" — **SIMULATED, not a live-host measurement**" if scan.get("is_simulation") else ""),
        f"- **Duration:** `{scan.get('elapsed_seconds', 0.0)} s`",
        "",
    ]
    if scan.get("timestamp_note"):
        lines.append(f"> Scan timestamp note: {scan['timestamp_note']}")
        lines.append("")

    lines.extend([
        "## 2. Telemetry and Coverage",
        "",
        f"- Files inspected: `{tel.get('files_inspected', 0)}` "
        f"(skipped `{tel.get('files_skipped', 0)}`, access denied `{tel.get('access_denied', 0)}`, "
        f"filesystem errors `{tel.get('filesystem_errors', 0)}`)",
        f"- Directories inspected: `{tel.get('directories_inspected', 0)}`",
        f"- Processes analyzed: `{tel.get('processes_analyzed', 0)}` "
        f"(process errors `{tel.get('process_errors', 0)}`)",
        f"- ML executed: `{tel.get('ml_executed', False)}` · model source: `{tel.get('model_source', 'UNAVAILABLE')}`",
        f"- Feature coverage: `{cov.get('measured', 0)}/{cov.get('total', 0)}` measured "
        f"({float(cov.get('coverage_ratio', 0.0)) * 100:.0f}%)",
    ])
    missing = cov.get("not_measured") or tel.get("missing_features") or []
    if missing:
        lines.append(f"- Not measured / unavailable: {', '.join(str(m) for m in missing[:12])}"
                     + (f" +{len(missing) - 12} more" if len(missing) > 12 else ""))
    lines.append("")

    lines.extend([
        "## 3. Model Inputs (19, exact trained order)",
        "",
        "| # | Input | Value | Status | Meaning |",
        "|---|---|---|---|---|",
    ])
    for row in scan.get("features", []):
        value = "—" if row.get("value") is None else f"{float(row['value']):.4g}"
        lines.append(
            f"| `[{int(row.get('index', 0)):02d}]` | `{row.get('name', '')}` | `{value}` | "
            f"`{row.get('status', 'UNAVAILABLE')}` | {row.get('description', '')} |")
    if not scan.get("features"):
        lines.append("| - | *No feature rows available* | - | - | - |")
    lines.append("")

    lines.extend([
        "## 4. Evidence Timeline and Provenance",
        "",
        f"- Correlated evidence items: `{corr.get('summary', {}).get('total', 0)}` "
        f"(measured `{corr.get('summary', {}).get('measured', 0)}`, "
        f"simulated `{corr.get('summary', {}).get('simulated', 0)}`, "
        f"heuristic `{corr.get('summary', {}).get('heuristic', 0)}`, "
        f"unavailable/errors `{corr.get('summary', {}).get('unavailable', 0) + corr.get('summary', {}).get('errors', 0)}`)",
        "",
    ])
    events = corr.get("events", [])
    if events:
        lines.extend(["| Seq | Time | Provenance | Category | Title | Detail |",
                      "|---|---|---|---|---|---|"])
        for ev in events[:60]:
            lines.append(
                f"| {ev.get('seq', '')} | {ev.get('time', 'UNAVAILABLE')} | "
                f"`{ev.get('provenance', 'UNAVAILABLE')}` | {ev.get('category', '')} | "
                f"{sanitize_path(str(ev.get('title', '')))} | {sanitize_path(str(ev.get('detail', '')))} |")
        if len(events) > 60:
            lines.append(f"| … | … | … | … | *{len(events) - 60} more rows in JSON* | |")
    else:
        lines.append("*No correlated evidence was supplied.*")
    lines.append("")

    lines.extend(["## 5. Correlation Findings", ""])
    findings = corr.get("findings", [])
    if findings:
        for finding in findings:
            lines.append(
                f"- **{finding.get('kind', 'FINDING')}** "
                f"(`{finding.get('provenance', 'UNAVAILABLE')}`): {finding.get('statement', '')}")
            if finding.get("caveat"):
                lines.append(f"  - Caveat: {finding['caveat']}")
    else:
        lines.append("*No findings recorded.*")
    lines.append("")

    lines.extend(["## 6. File Integrity Results", ""])
    if integrity:
        summary = integrity.get("summary", {})
        lines.append(
            f"- Baseline: `{integrity.get('baseline_at', 'UNAVAILABLE')}` · "
            f"compared: `{integrity.get('compared_at', 'UNAVAILABLE')}`")
        lines.append(
            f"- Added `{summary.get('added', 0)}` · modified `{summary.get('modified', 0)}` · "
            f"deleted `{summary.get('deleted', 0)}` · unchanged `{summary.get('unchanged', 0)}`")
        if integrity.get("partial") or integrity.get("limited"):
            lines.append("- **This comparison was partial / limited — rows may be missing.**")
        for section in ("added", "modified", "deleted"):
            rows = integrity.get(section) or []
            for row in rows[:20]:
                lines.append(f"  - `{section}` {row.get('path', '')}")
    else:
        lines.append("*No file-integrity comparison was supplied for this incident.*")
    lines.append("")

    lines.extend(["## 7. Next Steps", ""])
    for i, step in enumerate(report.get("next_steps", []), 1):
        lines.append(f"{i}. {step}")
    lines.append("")

    lines.extend(["## 8. Limitations", ""])
    for lim in report.get("limitations", []):
        lines.append(f"- {lim}")
    lines.append("")

    if report.get("ai_summary"):
        lines.extend(["## Appendix — SentinelAI Advisory Text", "",
                      str(report["ai_summary"]), "",
                      "*SentinelAI is advisory only; the Random Forest classifier remains authoritative.*",
                      ""])
    return "\n".join(lines)

_INTEGRITY_LIMITATIONS = [
    "A changed hash proves only that file content changed — not why, when, or by what.",
    "Files skipped as unreadable, vanished, or symlinked are absent from the comparison.",
    "This tool is read-only: nothing was quarantined, deleted, or restored.",
    "Coverage is limited to the selected folder, at the moments the baseline and comparison ran.",
]


def _iso_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def unique_output_path(directory: Path, stem: str, ext: str) -> Path:
    """Return a non-existing path inside ``directory`` without overwriting."""
    directory.mkdir(parents=True, exist_ok=True)
    candidate = directory / f"{stem}{ext}"
    n = 2
    while candidate.exists():
        candidate = directory / f"{stem}_{n}{ext}"
        n += 1
    return candidate


def _rows(changes: List[Any], status: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for ch in changes[:MAX_ROWS_PER_SECTION]:
        row = {
            "path": sanitize_path(ch.relpath),
            "status": status,
            "old_hash": ch.old_hash or None,
            "new_hash": ch.new_hash or None,
            "old_observed_at": ch.old_ts or None,
            "new_observed_at": ch.new_ts or None,
            "old_size": None if ch.old_size < 0 else ch.old_size,
            "new_size": None if ch.new_size < 0 else ch.new_size,
        }
        rows.append(row)
    return rows


def build_integrity_report(diff, folder, baseline_at: Optional[str] = None,
                           compared_at: Optional[str] = None,
                           skipped: Optional[List[str]] = None,
                           partial: bool = False) -> Dict[str, Any]:
    """Build a structured, sanitised integrity report (no file contents)."""
    added = _rows(list(diff.added), "added")
    modified = _rows(list(diff.modified), "modified")
    deleted = _rows(list(diff.deleted), "deleted")
    skipped_items = [sanitize_path(s) for s in (skipped if skipped is not None else diff.skipped)]

    return {
        "report_type": "FILE_INTEGRITY",
        "report_version": REPORT_VERSION,
        "generated_at": _iso_now(),
        "folder": sanitize_path(str(folder)) if folder else "UNAVAILABLE",
        "baseline_at": baseline_at or "UNAVAILABLE",
        "compared_at": compared_at or "UNAVAILABLE",
        "partial": bool(partial),
        "limited": bool(getattr(diff, "limited", False)),
        "summary": {
            "added": len(diff.added),
            "modified": len(diff.modified),
            "deleted": len(diff.deleted),
            "unchanged": int(diff.unchanged_count),
            "total_compared": int(diff.total),
            "skipped": len(skipped_items),
            "rows_truncated": any(len(s) > MAX_ROWS_PER_SECTION for s in (
                diff.added, diff.modified, diff.deleted)),
        },
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "skipped": skipped_items[:MAX_ROWS_PER_SECTION],
        "limitations": list(_INTEGRITY_LIMITATIONS),
        "notice": REPORT_NOTICE,
    }


def render_integrity_markdown(report: Dict[str, Any]) -> str:
    s = report.get("summary", {})
    lines = [
        "# SENTINELML V2 — FILE INTEGRITY REPORT",
        "",
        f"**Report version:** `{report.get('report_version', REPORT_VERSION)}`  ",
        f"**Generated:** `{report.get('generated_at', '')}`  ",
        f"**Folder:** `{report.get('folder', 'UNAVAILABLE')}`  ",
        f"**Baseline captured:** `{report.get('baseline_at', 'UNAVAILABLE')}`  ",
        f"**Comparison captured:** `{report.get('compared_at', 'UNAVAILABLE')}`  ",
        "",
        f"> {report.get('notice', REPORT_NOTICE)}",
        "",
        "## Summary",
        "",
        "| Added | Modified | Deleted | Unchanged | Skipped |",
        "|---|---|---|---|---|",
        f"| {s.get('added', 0)} | {s.get('modified', 0)} | {s.get('deleted', 0)} "
        f"| {s.get('unchanged', 0)} | {s.get('skipped', 0)} |",
        "",
    ]
    if report.get("partial"):
        lines.extend(["> **PARTIAL:** this comparison was cancelled before it "
                      "finished. Candidate rows are incomplete.", ""])
    if report.get("limited"):
        lines.extend(["> **LIMITED:** the folder exceeded this tool's file cap; "
                      "the comparison is incomplete.", ""])

    sections = (
        ("Added files", report.get("added", [])),
        ("Modified files", report.get("modified", [])),
        ("Deleted files", report.get("deleted", [])),
    )
    for title, rows in sections:
        lines.extend([f"## {title}", ""])
        if not rows:
            lines.extend(["*None recorded.*", ""])
            continue
        lines.extend(["| Path | Old hash | New hash | Old observed | New observed |",
                      "|---|---|---|---|---|"])
        for row in rows:
            lines.append(
                f"| `{row.get('path', '')}` | `{row.get('old_hash') or '—'}` | "
                f"`{row.get('new_hash') or '—'}` | `{row.get('old_observed_at') or '—'}` | "
                f"`{row.get('new_observed_at') or '—'}` |")
        lines.append("")

    if report.get("skipped"):
        lines.extend(["## Skipped paths", ""])
        for item in report["skipped"]:
            lines.append(f"- `{item}`")
        lines.append("")

    lines.extend(["## Limitations", ""])
    for lim in report.get("limitations", []):
        lines.append(f"- {lim}")
    lines.append("")
    return "\n".join(lines)


def write_report(report: Dict[str, Any], output_dir: Optional[Path] = None,
                 stem: Optional[str] = None) -> Dict[str, Path]:
    """Write JSON + Markdown with collision-safe deterministic filenames."""
    directory = Path(output_dir) if output_dir else get_reports_dir()
    base = stem or f"{report.get('report_type', 'report').lower()}_" \
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    json_path = unique_output_path(directory, base, ".json")
    md_path = unique_output_path(directory, base, ".md")

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    if report.get("report_type") == "FILE_INTEGRITY":
        markdown = render_integrity_markdown(report)
    elif report.get("report_type") == "INCIDENT":
        markdown = render_incident_markdown(report)
    else:
        markdown = report.get("markdown") or json.dumps(report, indent=2)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(markdown)

    log.info("Report written: %s and %s", json_path.name, md_path.name)
    return {"json": json_path, "md": md_path}
