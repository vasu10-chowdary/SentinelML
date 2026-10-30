"""
SentinelML V2 — Live SOC telemetry collector.
==============================================
Collects real host telemetry into a single, self-describing snapshot.

Safety invariants:
  * Only real values are reported. A source that cannot be read is reported
    with ``available=False`` and an explicit capability status; it is never
    rendered as a zero.
  * Filesystem checks are metadata-only (size + mtime) and bounded by an
    explicit scope, depth, and file budget. No full-disk walk, no hashing.
  * Alerts are read from AlertManager; no alert, count, or timestamp is
    invented.
  * A scan that failed, was cancelled, or had incomplete coverage is reported
    as INCONCLUSIVE, never as SAFE.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils.platform_capabilities import (
    STATUS_AVAILABLE,
    STATUS_ERROR,
    STATUS_PERMISSION_REQUIRED,
    STATUS_UNAVAILABLE,
    PlatformCapabilities,
    get_platform_capabilities,
)

log = logging.getLogger("sentinel.livemon")

QUALITY_LIVE = "LIVE"
QUALITY_PARTIAL = "PARTIAL"
QUALITY_FAILED = "FAILED"

DEFAULT_FILE_DEPTH = 1
DEFAULT_MAX_FILES = 2000
DEFAULT_SCAN_STALE_S = 24 * 60 * 60

# A snapshot is LIVE only when these sources are readable. Optional sources
# (registry, handles, event channel) can be unavailable and still be LIVE.
REQUIRED_FOR_LIVE = ("process_enumeration", "system_cpu_memory", "file_metadata")


@dataclass
class SOCTelemetry:
    """One collection cycle of real host telemetry."""

    seq: int = 0
    generation: int = 0
    collected_at: float = 0.0
    collected_at_iso: str = ""
    duration_s: float = 0.0
    quality: str = QUALITY_FAILED
    errors: List[Dict[str, str]] = field(default_factory=list)
    capabilities: Dict[str, Dict[str, str]] = field(default_factory=dict)
    process: Dict[str, Any] = field(default_factory=dict)
    system: Dict[str, Any] = field(default_factory=dict)
    filesystem: Dict[str, Any] = field(default_factory=dict)
    network: Dict[str, Any] = field(default_factory=dict)
    guard: Dict[str, Any] = field(default_factory=dict)
    app_security: Dict[str, Any] = field(default_factory=dict)
    threats: Dict[str, Any] = field(default_factory=dict)
    last_scan: Optional[Dict[str, Any]] = None
    classification: str = "NOT_SCANNED"
    classification_detail: str = ""
    events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Default providers (overridable for tests) ─────────────────────────────

def _default_scope() -> List[Path]:
    from utils.platform_utils import get_monitored_directories
    return list(get_monitored_directories())


def _default_process_rows() -> List[Dict[str, Any]]:
    import psutil
    from utils.platform_adapter import get_platform_adapter
    adapter = get_platform_adapter()
    rows: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "memory_percent"]):
        try:
            info = proc.info or {}
            name = info.get("name") or ""
            rows.append({
                "pid": info.get("pid"),
                "name": name,
                "memory_percent": info.get("memory_percent"),
                "suspicious": bool(adapter.is_suspicious_process_name(name)),
            })
        except Exception:
            continue
    return rows


def _default_alert_provider() -> List[Dict[str, Any]]:
    from alerts.alert_manager import get_alert_manager
    return list(get_alert_manager().get_alerts())


def _default_guard_provider() -> Dict[str, Any]:
    from guard.sentinel_guard import get_guard_instance
    return dict(get_guard_instance().get_stats())


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def _cap_view(cap) -> Dict[str, str]:
    return {
        "label": cap.label,
        "status": cap.status,
        "detail": cap.detail,
        "source": cap.source,
    }


def _ip_is_external(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except Exception:
        return False


def _short_name(key: str) -> str:
    if "::" in key:
        root, name = key.split("::", 1)
        return f"{Path(root).name}/{name}"
    return Path(key).name


class SOCTelemetryCollector:
    """Builds ``SOCTelemetry`` snapshots from real host sources.

    The collector is stateful only to compute deltas between cycles (process
    IDs, file metadata, capability transitions). It never persists anything.
    """

    def __init__(
        self,
        capabilities: Optional[PlatformCapabilities] = None,
        scope_provider: Optional[Callable[[], List[Path]]] = None,
        process_provider: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        alert_provider: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        guard_provider: Optional[Callable[[], Dict[str, Any]]] = None,
        file_depth: int = DEFAULT_FILE_DEPTH,
        max_files: int = DEFAULT_MAX_FILES,
        scan_stale_seconds: int = DEFAULT_SCAN_STALE_S,
    ) -> None:
        self.capabilities = capabilities or get_platform_capabilities()
        self._scope_provider = scope_provider or _default_scope
        self._process_provider = process_provider or _default_process_rows
        self._alert_provider = alert_provider or _default_alert_provider
        self._guard_provider = guard_provider or _default_guard_provider
        self.file_depth = max(1, int(file_depth))
        self.max_files = max(1, int(max_files))
        self.scan_stale_seconds = max(60, int(scan_stale_seconds))

        self._lock = threading.Lock()
        self._prev_pids: Optional[set] = None
        self._prev_fs: Optional[Dict[str, Tuple[int, int]]] = None
        self._prev_cap_status: Dict[str, str] = {}
        self._seen_alert_ids: set = set()
        self._alerts_primed = False
        self._last_scan: Optional[Dict[str, Any]] = None
        self._cpu_primed = False

    # ── Scan record ───────────────────────────────────────────────────────
    def record_scan(self, result) -> None:
        """Record the most recent scan result for classification display."""
        if result is None:
            return
        data = self._scan_to_dict(result)
        with self._lock:
            self._last_scan = data

    def _scan_to_dict(self, result) -> Dict[str, Any]:
        if isinstance(result, dict):
            data = dict(result)
            data.setdefault("timestamp_epoch", time.time())
            data.setdefault("timestamp", _iso(data["timestamp_epoch"]))
            return data
        try:
            unified = result.get_unified_classification()
        except Exception:
            unified = {}
        state = getattr(result, "state", None)
        state_name = getattr(state, "name", None) or getattr(state, "value", None) or str(state or "")
        try:
            successful = bool(result.was_successful())
        except Exception:
            successful = False
        inconclusive = bool(getattr(result, "is_inconclusive", False))
        level = unified.get("level") or getattr(result, "threat_level", "") or ""
        if not successful or inconclusive:
            level = "INCONCLUSIVE"
        now = time.time()
        return {
            "scan_id": getattr(result, "scan_id", "") or "",
            "scan_type": getattr(getattr(result, "scan_type", None), "value", "") or "",
            "state": state_name,
            "threat_level": getattr(result, "threat_level", "") or "",
            "ml_probability": float(getattr(result, "ml_probability", 0.0) or 0.0),
            "successful": successful,
            "inconclusive": inconclusive,
            "inconclusive_reason": getattr(result, "inconclusive_reason", "") or "",
            "classification": level,
            "scan_origin": getattr(result, "scan_origin", "") or "",
            "is_simulation": bool(getattr(result, "is_simulation", False)),
            "missing_features": list(getattr(result, "missing_features", []) or []),
            "telemetry_coverage_ratio": float(getattr(result, "telemetry_coverage_ratio", 1.0) or 0.0),
            "elapsed_seconds": float(getattr(result, "elapsed_seconds", 0.0) or 0.0),
            "files_inspected": int(getattr(result, "files_inspected", 0) or 0),
            "processes_analyzed": int(getattr(result, "processes_analyzed", 0) or 0),
            "access_denied": int(getattr(result, "access_denied", 0) or 0),
            "timestamp": _iso(now),
            "timestamp_epoch": now,
        }

    def _classify_scan(self) -> Tuple[str, str]:
        with self._lock:
            scan = dict(self._last_scan) if self._last_scan else None
        if not scan:
            return "NOT_SCANNED", "No ML scan has completed in this session."
        if scan.get("is_simulation"):
            return "CONTROLLED_SIMULATION", "Latest record is a controlled simulation, not host telemetry."
        if not scan.get("successful") or scan.get("inconclusive"):
            reason = scan.get("inconclusive_reason") or "Last scan did not complete with valid coverage."
            return "INCONCLUSIVE", reason
        level = scan.get("classification") or scan.get("threat_level") or "INCONCLUSIVE"
        epoch = scan.get("timestamp_epoch")
        if epoch is None:
            return level, "Scan timestamp unavailable."
        age = max(0.0, time.time() - float(epoch))
        if age > self.scan_stale_seconds:
            return level, f"Last scan {int(age // 3600)} h ago (stale)"
        return level, f"Last scan {max(0, int(age // 60))} min ago"

    # ── Main entry point ──────────────────────────────────────────────────
    def collect(
        self,
        seq: int = 0,
        generation: int = 0,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> SOCTelemetry:
        started_wall = time.time()
        started_mono = time.monotonic()
        errors: List[Dict[str, str]] = []

        caps: Dict[str, Dict[str, str]] = {}
        try:
            probed = self.capabilities.probe_all()
            caps = {key: _cap_view(cap) for key, cap in probed.items()}
        except Exception as exc:
            errors.append({"source": "capabilities", "message": str(exc)})

        system = self._collect_system(caps, errors)
        process = self._collect_processes(caps, errors, cancel_check)
        filesystem = self._collect_filesystem(caps, errors, cancel_check)
        network = self._collect_network(caps, errors)
        guard = self._collect_guard(errors)
        alerts = self._collect_alerts(errors)
        threats = self._summarise_alerts(alerts)
        classification, classification_detail = self._classify_scan()
        with self._lock:
            last_scan = dict(self._last_scan) if self._last_scan else None

        finished = time.time()
        events = self._build_events(alerts, filesystem, caps, finished)
        quality = self._quality(caps, system, process, errors)

        return SOCTelemetry(
            seq=seq,
            generation=generation,
            collected_at=finished,
            collected_at_iso=_iso(finished),
            duration_s=round(max(0.0, time.monotonic() - started_mono), 3),
            quality=quality,
            errors=errors,
            capabilities=caps,
            process=process,
            system=system,
            filesystem=filesystem,
            network=network,
            guard=guard,
            app_security={
                "event_channel": caps.get("event_log", {}),
                "alerts_total": len(alerts),
                "critical": threats.get("counts_24h", {}).get("critical", 0),
                "high": threats.get("counts_24h", {}).get("high", 0),
            },
            threats=threats,
            last_scan=last_scan,
            classification=classification,
            classification_detail=classification_detail,
            events=events,
        )

    # ── Source collectors ─────────────────────────────────────────────────
    def _collect_system(self, caps, errors) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "available": False,
            "cpu_percent": None,
            "memory_percent": None,
            "memory_used_bytes": None,
            "memory_total_bytes": None,
            "boot_time": None,
            "uptime_s": None,
            "status": STATUS_UNAVAILABLE,
            "detail": "",
        }
        cap = caps.get("system_cpu_memory", {})
        if cap.get("status") != STATUS_AVAILABLE:
            out["status"] = cap.get("status", STATUS_UNAVAILABLE)
            out["detail"] = cap.get("detail", "System metrics unavailable")
            return out
        try:
            import psutil
            cpu = float(psutil.cpu_percent(interval=0.1))
            vm = psutil.virtual_memory()
            out.update({
                "available": True,
                "cpu_percent": cpu,
                "memory_percent": float(vm.percent),
                "memory_used_bytes": int(vm.used),
                "memory_total_bytes": int(vm.total),
                "status": STATUS_AVAILABLE,
                "detail": "Real psutil sample",
            })
            try:
                boot = float(psutil.boot_time())
                out["boot_time"] = boot
                out["uptime_s"] = max(0.0, time.time() - boot)
            except Exception:
                pass
        except Exception as exc:
            errors.append({"source": "system_cpu_memory", "message": str(exc)})
            out["status"] = STATUS_ERROR
            out["detail"] = str(exc)
        return out

    def _collect_processes(self, caps, errors, cancel_check) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "available": False,
            "count": None,
            "new_pids": None,
            "ended_pids": None,
            "suspicious_count": None,
            "top_memory": [],
            "status": STATUS_UNAVAILABLE,
            "detail": "",
        }
        cap = caps.get("process_enumeration", {})
        if cap.get("status") != STATUS_AVAILABLE:
            out["status"] = cap.get("status", STATUS_UNAVAILABLE)
            out["detail"] = cap.get("detail", "Process table unavailable")
            return out
        try:
            rows = self._process_provider() or []
            pids = {int(r["pid"]) for r in rows if r.get("pid") is not None}
            suspicious = sum(1 for r in rows if r.get("suspicious"))
            out.update({
                "available": True,
                "count": len(pids),
                "suspicious_count": suspicious,
                "status": STATUS_AVAILABLE,
                "detail": f"{len(pids)} processes enumerated",
            })
            if self._prev_pids is not None:
                out["new_pids"] = len(pids - self._prev_pids)
                out["ended_pids"] = len(self._prev_pids - pids)
            self._prev_pids = pids

            mem_rows = [
                {
                    "pid": r.get("pid"),
                    "name": r.get("name", ""),
                    "memory_percent": float(r["memory_percent"]),
                }
                for r in rows
                if r.get("memory_percent") is not None
            ]
            mem_rows.sort(key=lambda item: item["memory_percent"], reverse=True)
            out["top_memory"] = mem_rows[:3]
        except Exception as exc:
            errors.append({"source": "process_enumeration", "message": str(exc)})
            out["status"] = STATUS_ERROR
            out["detail"] = str(exc)
        return out

    def _collect_filesystem(self, caps, errors, cancel_check) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "available": False,
            "scope": [],
            "file_count": None,
            "added": None,
            "modified": None,
            "deleted": None,
            "unchanged": None,
            "baseline": False,
            "truncated": False,
            "samples": {},
            "depth": self.file_depth,
            "max_files": self.max_files,
            "status": STATUS_UNAVAILABLE,
            "detail": "",
        }
        cap = caps.get("file_metadata", {})
        if cap.get("status") != STATUS_AVAILABLE:
            out["status"] = cap.get("status", STATUS_UNAVAILABLE)
            out["detail"] = cap.get("detail", "File scope unavailable")
            return out
        try:
            roots = [Path(p) for p in self._scope_provider() if Path(p).exists()]
            out["scope"] = [str(p) for p in roots]
            if not roots:
                out["status"] = STATUS_UNAVAILABLE
                out["detail"] = "No monitored directories exist"
                return out
            entries: Dict[str, Tuple[int, int]] = {}
            truncated = False
            denied = 0
            cancelled = False
            for root in roots:
                if cancel_check is not None and cancel_check():
                    cancelled = True
                    break
                if len(entries) >= self.max_files:
                    truncated = True
                    break
                try:
                    self._walk(Path(root), 1, entries, cancel_check)
                except PermissionError:
                    denied += 1
                except Exception as exc:
                    errors.append({"source": "file_metadata", "message": f"{root}: {exc}"})
            if len(entries) >= self.max_files:
                truncated = True

            if cancelled:
                out.update({
                    "available": True,
                    "file_count": len(entries),
                    "truncated": truncated,
                    "cancelled": True,
                    "status": STATUS_AVAILABLE,
                    "detail": "Collection cancelled before the scope pass completed",
                })
                return out

            prev = self._prev_fs
            if prev is None:
                out["baseline"] = True
            else:
                cur_keys = set(entries)
                prev_keys = set(prev)
                added = cur_keys - prev_keys
                deleted = prev_keys - cur_keys
                modified = {
                    key for key in (cur_keys & prev_keys)
                    if entries[key][0] != prev[key][0] or entries[key][1] != prev[key][1]
                }
                out["added"] = len(added)
                out["modified"] = len(modified)
                out["deleted"] = len(deleted)
                out["unchanged"] = len(cur_keys & prev_keys) - len(modified)
                out["samples"] = {
                    "added": [_short_name(k) for k in sorted(added)[:3]],
                    "modified": [_short_name(k) for k in sorted(modified)[:3]],
                    "deleted": [_short_name(k) for k in sorted(deleted)[:3]],
                }

            self._prev_fs = entries
            out.update({
                "available": True,
                "file_count": len(entries),
                "truncated": truncated,
                "status": STATUS_AVAILABLE if denied == 0 else STATUS_PERMISSION_REQUIRED,
                "detail": f"{len(entries)} files metadata-scanned at depth {self.file_depth}",
            })
            if denied:
                out["detail"] += f" ({denied} scope dir(s) denied)"
        except Exception as exc:
            errors.append({"source": "file_metadata", "message": str(exc)})
            out["status"] = STATUS_ERROR
            out["detail"] = str(exc)
        return out

    def _walk(self, directory: Path, depth: int, entries: Dict[str, Tuple[int, int]],
              cancel_check) -> None:
        with os.scandir(directory) as it:
            for entry in it:
                if len(entries) >= self.max_files:
                    return
                if cancel_check is not None and cancel_check():
                    return
                try:
                    if entry.is_file(follow_symlinks=False):
                        st = entry.stat(follow_symlinks=False)
                        key = f"{os.path.abspath(directory)}::{entry.name}"
                        entries[key] = (int(st.st_size), int(st.st_mtime_ns))
                    elif depth < self.file_depth and entry.is_dir(follow_symlinks=False):
                        self._walk(Path(entry.path), depth + 1, entries, cancel_check)
                except OSError:
                    continue

    def _collect_network(self, caps, errors) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "available": False,
            "count": None,
            "external_ips": None,
            "status": STATUS_UNAVAILABLE,
            "detail": "",
        }
        cap = caps.get("network_connections", {})
        if cap.get("status") != STATUS_AVAILABLE:
            out["status"] = cap.get("status", STATUS_UNAVAILABLE)
            out["detail"] = cap.get("detail", "Connection table unavailable")
            return out
        try:
            import psutil
            conns = psutil.net_connections(kind="inet")
            external = set()
            for conn in conns:
                raddr = getattr(conn, "raddr", None)
                ip = getattr(raddr, "ip", None) if raddr else None
                if ip and _ip_is_external(ip):
                    external.add(ip)
            out.update({
                "available": True,
                "count": len(conns),
                "external_ips": len(external),
                "status": STATUS_AVAILABLE,
                "detail": f"{len(conns)} inet connections, {len(external)} external endpoints",
            })
        except Exception as exc:
            errors.append({"source": "network_connections", "message": str(exc)})
            out["status"] = STATUS_ERROR
            out["detail"] = str(exc)
        return out

    def _collect_guard(self, errors) -> Dict[str, Any]:
        try:
            stats = self._guard_provider() or {}
            return {
                "available": True,
                "running": bool(stats.get("running")),
                "files_monitored": stats.get("files_monitored"),
                "events_detected": stats.get("events_detected"),
                "threats_found": stats.get("threats_found"),
                "monitored_paths": stats.get("monitored_paths"),
                "detail": "SentinelGuard statistics",
            }
        except Exception as exc:
            errors.append({"source": "guard", "message": str(exc)})
            return {"available": False, "running": None, "detail": str(exc)}

    def _collect_alerts(self, errors) -> List[Dict[str, Any]]:
        try:
            return list(self._alert_provider() or [])
        except Exception as exc:
            errors.append({"source": "alerts", "message": str(exc)})
            return []

    def _summarise_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        counts_24h = {key: 0 for key in counts}
        now = time.time()
        for alert in alerts:
            sev = str(alert.get("severity", "INFO")).upper()
            if sev == "WARNING":
                sev = "MEDIUM"
            key = sev.lower()
            if key not in counts:
                continue
            counts[key] += 1
            try:
                parsed = datetime.fromisoformat(str(alert.get("timestamp", "")))
                if now - parsed.timestamp() <= 86400:
                    counts_24h[key] += 1
            except Exception:
                pass
        return {
            "total": len(alerts),
            "counts": counts,
            "counts_24h": counts_24h,
            "threats_24h": counts_24h["critical"] + counts_24h["high"],
        }

    def _quality(self, caps, system, process, errors) -> str:
        core_ok = bool(system.get("available")) and bool(process.get("available"))
        if not core_ok:
            return QUALITY_FAILED
        required_missing = any(
            caps.get(key, {}).get("status") != STATUS_AVAILABLE for key in REQUIRED_FOR_LIVE
        )
        if errors or required_missing:
            return QUALITY_PARTIAL
        return QUALITY_LIVE

    # ── Event timeline ────────────────────────────────────────────────────
    def _build_events(self, alerts, filesystem, caps, now) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        iso_now = _iso(now)

        # Application alerts: only alerts not seen before are emitted.
        if not self._alerts_primed:
            for alert in alerts:
                aid = str(alert.get("id") or "")
                if aid:
                    self._seen_alert_ids.add(aid)
            self._alerts_primed = True
        else:
            for alert in alerts:
                aid = str(alert.get("id") or "")
                if not aid or aid in self._seen_alert_ids:
                    continue
                self._seen_alert_ids.add(aid)
                events.append({
                    "id": f"alert-{aid}",
                    "dedupe_key": f"alert:{aid}",
                    "kind": "alert",
                    "severity": str(alert.get("severity", "INFO")).upper(),
                    "title": str(alert.get("title", "Security event")),
                    "detail": str(alert.get("message", "")),
                    "source": str(alert.get("source", "AlertManager")),
                    "timestamp": str(alert.get("timestamp", iso_now)),
                })
            if len(self._seen_alert_ids) > 1000:
                self._seen_alert_ids = set(list(self._seen_alert_ids)[-500:])

        if filesystem.get("samples"):
            added = filesystem.get("added") or 0
            modified = filesystem.get("modified") or 0
            deleted = filesystem.get("deleted") or 0
            if added or modified or deleted:
                detail_bits = []
                for kind in ("added", "modified", "deleted"):
                    names = filesystem["samples"].get(kind) or []
                    if names:
                        detail_bits.append(f"{kind}: {', '.join(names)}")
                events.append({
                    "id": f"fs-{int(now)}",
                    "dedupe_key": f"fs:{added}:{modified}:{deleted}:{'|'.join(detail_bits)}",
                    "kind": "filesystem",
                    "severity": "INFO",
                    "title": f"File metadata changes: {added} added, {modified} modified, {deleted} deleted",
                    "detail": "; ".join(detail_bits),
                    "source": "SOC file scope",
                    "timestamp": iso_now,
                })

        for key, view in caps.items():
            status = view.get("status")
            previous = self._prev_cap_status.get(key)
            if previous is not None and previous != status and status != STATUS_AVAILABLE:
                events.append({
                    "id": f"cap-{key}-{status}",
                    "dedupe_key": f"cap:{key}:{status}",
                    "kind": "capability",
                    "severity": "INFO",
                    "title": f"{view.get('label', key)}: {status.replace('_', ' ')}",
                    "detail": view.get("detail", ""),
                    "source": "Platform capability probe",
                    "timestamp": iso_now,
                })
            self._prev_cap_status[key] = status
        return events
