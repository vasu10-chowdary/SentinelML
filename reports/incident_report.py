"""
SentinelML V2 — Incident Report Generator
===========================================
Generates comprehensive incident reports.

Report Contents:
---------------
- Timestamp
- System state
- All 19 feature values
- ML probability
- ML classification
- Recent alerts
- Scan statistics
- System information

Storage: reports/incident_YYYYMMDD_HHMMSS.json
"""

import json
import logging
import platform
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

from utils.logging_config import get_reports_logger
from utils.paths import get_reports_dir

log = get_reports_logger()


class IncidentReporter:
    """Generates and stores incident reports."""
    
    def __init__(self):
        self._reports_dir = get_reports_dir()
    
    def generate_report(
        self,
        features: Optional[np.ndarray] = None,
        prediction: Optional[tuple] = None,
        scan_stats: Optional[Dict] = None,
        alerts: Optional[List[Dict]] = None
    ) -> Optional[Path]:
        """
        Generate a comprehensive incident report.
        
        Args:
            features: 19-feature array from scanner
            prediction: (threat_level, probability) from ML
            scan_stats: Scanner statistics
            alerts: Recent alerts
        
        Returns:
            Path to report file or None if failed
        """
        try:
            timestamp = datetime.now()
            report_id = timestamp.strftime("%Y%m%d_%H%M%S")
            
            report = {
                "report_id": report_id,
                "timestamp": timestamp.isoformat(),
                "system": self._get_system_info(),
                "scan": self._format_scan_data(features, scan_stats),
                "prediction": self._format_prediction(prediction),
                "alerts": self._format_alerts(alerts),
                "metadata": {
                    "sentinelml_version": "2.0.0",
                    "report_type": "incident",
                }
            }
            
            # Save report
            report_file = self._reports_dir / f"incident_{report_id}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            
            log.info("Incident report generated: %s", report_file.name)
            return report_file
            
        except Exception as e:
            log.error("Failed to generate report: %s", e, exc_info=True)
            return None
    
    def _get_system_info(self) -> Dict:
        """Get system information."""
        try:
            return {
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "hostname": platform.node(),
                "python_version": platform.python_version(),
            }
        except Exception as e:
            log.warning("Failed to get system info: %s", e)
            return {}
    
    def _format_scan_data(
        self,
        features: Optional[np.ndarray],
        stats: Optional[Dict]
    ) -> Dict:
        """Format scan data for report."""
        if features is None:
            return {
                "status": "no_scan",
                "features": None,
                "statistics": stats or {}
            }
        
        try:
            feature_list = features[0].tolist() if features.shape == (1, 19) else []
            
            return {
                "status": "completed",
                "features": {
                    "count": len(feature_list),
                    "values": feature_list,
                    "shape": str(features.shape),
                },
                "statistics": stats or {}
            }
        except Exception as e:
            log.warning("Failed to format scan data: %s", e)
            return {"status": "error", "error": str(e)}
    
    def _format_prediction(self, prediction: Optional[tuple]) -> Dict:
        """Format ML prediction for report."""
        if prediction is None:
            return {
                "status": "no_prediction",
                "threat_level": None,
                "probability": None
            }
        
        try:
            threat_level, probability = prediction
            return {
                "status": "completed",
                "threat_level": threat_level,
                "probability": float(probability),
                "confidence": f"{probability*100:.2f}%"
            }
        except Exception as e:
            log.warning("Failed to format prediction: %s", e)
            return {"status": "error", "error": str(e)}
    
    def _format_alerts(self, alerts: Optional[List[Dict]]) -> Dict:
        """Format alerts for report."""
        if alerts is None:
            return {
                "count": 0,
                "items": []
            }
        
        try:
            # Include only recent alerts (limit to 20)
            recent = alerts[:20] if len(alerts) > 20 else alerts
            
            return {
                "count": len(alerts),
                "included": len(recent),
                "items": recent
            }
        except Exception as e:
            log.warning("Failed to format alerts: %s", e)
            return {"count": 0, "items": [], "error": str(e)}
    
    def list_reports(self, limit: Optional[int] = None) -> List[Path]:
        """
        List all incident reports (newest first).
        
        Args:
            limit: Maximum number of reports to return
        
        Returns:
            List of report file paths
        """
        try:
            reports = sorted(
                self._reports_dir.glob("incident_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )
            
            if limit:
                reports = reports[:limit]
            
            return reports
            
        except Exception as e:
            log.error("Failed to list reports: %s", e)
            return []
    
    def get_report(self, report_id: str) -> Optional[Dict]:
        """Load a specific report by ID."""
        try:
            report_file = self._reports_dir / f"incident_{report_id}.json"
            
            if not report_file.exists():
                log.warning("Report not found: %s", report_id)
                return None
            
            with open(report_file, 'r', encoding='utf-8') as f:
                return json.load(f)
                
        except Exception as e:
            log.error("Failed to load report %s: %s", report_id, e)
            return None


# ── Singleton ─────────────────────────────────────────────────────────────

_reporter: Optional[IncidentReporter] = None


def get_incident_reporter() -> IncidentReporter:
    """Get the singleton incident reporter."""
    global _reporter
    
    if _reporter is None:
        _reporter = IncidentReporter()
    
    return _reporter


# ── Testing ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from utils.logging_config import setup_logging
    
    setup_logging()
    
    print("SentinelML V2 — Incident Reporter Test")
    print("="*70)
    
    reporter = get_incident_reporter()
    
    # Create test data
    print("\n1. Generating test report...")
    
    import numpy as np
    test_features = np.random.rand(1, 19)
    test_prediction = ("WARNING", 0.65)
    test_stats = {
        "duration": 4.2,
        "processes_scanned": 320,
        "errors": 0
    }
    test_alerts = [
        {
            "severity": "WARNING",
            "title": "Test Alert",
            "message": "This is a test",
            "timestamp": datetime.now().isoformat()
        }
    ]
    
    report_file = reporter.generate_report(
        features=test_features,
        prediction=test_prediction,
        scan_stats=test_stats,
        alerts=test_alerts
    )
    
    if report_file:
        print(f"✓ Report generated: {report_file.name}")
        print(f"  Size: {report_file.stat().st_size} bytes")
    else:
        print("✗ Report generation failed")
        exit(1)
    
    # List reports
    print("\n2. Listing reports...")
    reports = reporter.list_reports(limit=5)
    print(f"✓ Found {len(reports)} reports")
    
    for i, rpt in enumerate(reports, 1):
        print(f"   {i}. {rpt.name}")
    
    # Load report
    print("\n3. Loading generated report...")
    report_id = report_file.stem.replace("incident_", "")
    loaded = reporter.get_report(report_id)
    
    if loaded:
        print("✓ Report loaded successfully")
        print(f"  Timestamp: {loaded['timestamp']}")
        print(f"  Threat Level: {loaded['prediction']['threat_level']}")
        print(f"  Probability: {loaded['prediction']['probability']}")
    else:
        print("✗ Failed to load report")
    
    print("\n[OK] Incident Reporter test complete")
