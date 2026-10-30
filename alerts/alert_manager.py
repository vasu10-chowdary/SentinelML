"""
SentinelML V2 — Alert Manager
===============================
Manages structured alerts with persistent storage.

Alert Structure:
---------------
{
    "id": "unique_id",
    "timestamp": "2026-08-24T20:40:00",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "category": "scanner|guard|system",
    "title": "Brief description",
    "message": "Detailed message",
    "source": "Component that generated alert",
    "metadata": { ... additional data ... }
}

Storage:
-------
Location: alerts/alerts.json
Format: JSON array of alert objects
Handling: Atomic writes, concurrent-safe, corruption recovery
"""

import json
import logging
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from utils.logging_config import get_alerts_logger
from utils.paths import get_alerts_dir

log = get_alerts_logger()


class AlertManager:
    """
    Manages alert generation and storage.
    
    Thread-safe for concurrent alert generation.
    """
    
    def __init__(self):
        self._alerts_file = get_alerts_dir() / "alerts.json"
        self._lock = threading.Lock()
        self._ensure_file_exists()
    
    def _ensure_file_exists(self) -> None:
        """Create alerts file if it doesn't exist."""
        if not self._alerts_file.exists():
            try:
                with open(self._alerts_file, 'w', encoding='utf-8') as f:
                    json.dump([], f)
                log.info("Created alerts file: %s", self._alerts_file)
            except Exception as e:
                log.error("Failed to create alerts file: %s", e)
    
    def add_alert(
        self,
        severity: str,
        category: str,
        title: str,
        message: str,
        source: str,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Add a new alert.
        
        Args:
            severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            category: scanner, guard, system
            title: Brief description
            message: Detailed message
            source: Component that generated alert
            metadata: Additional data (optional)
        
        Returns:
            True if alert added successfully, False otherwise
        """
        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "severity": severity.upper(),
            "category": category.lower(),
            "title": title,
            "message": message,
            "source": source,
            "metadata": metadata or {},
            "status": "new"
        }
        
        log.info(
            "Alert generated: [%s] %s - %s",
            severity.upper(),
            category,
            title
        )
        
        return self._save_alert(alert)
    
    def _save_alert(self, alert: Dict) -> bool:
        """Save alert to file (thread-safe)."""
        with self._lock:
            try:
                # Read existing alerts
                alerts = self._read_alerts_unsafe()
                
                # Add new alert
                alerts.append(alert)
                
                # Write atomically
                temp_file = self._alerts_file.with_suffix('.tmp')
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(alerts, f, indent=2)
                
                temp_file.replace(self._alerts_file)
                
                log.debug("Alert saved: %s", alert['id'])
                return True
                
            except Exception as e:
                log.error("Failed to save alert: %s", e, exc_info=True)
                return False
    
    def get_alerts(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Get all alerts (newest first).
        
        Args:
            limit: Maximum number of alerts to return (None = all)
        
        Returns:
            List of alert dictionaries
        """
        with self._lock:
            alerts = self._read_alerts_unsafe()
            
            # Sort by timestamp (newest first)
            alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            if limit:
                alerts = alerts[:limit]
            
            return alerts
    
    def get_alerts_by_severity(self, severity: str) -> List[Dict]:
        """Get alerts filtered by severity."""
        alerts = self.get_alerts()
        return [a for a in alerts if a.get('severity') == severity.upper()]
    
    def get_alerts_by_category(self, category: str) -> List[Dict]:
        """Get alerts filtered by category."""
        alerts = self.get_alerts()
        return [a for a in alerts if a.get('category') == category.lower()]
    
    def clear_alerts(self) -> bool:
        """Clear all alerts."""
        with self._lock:
            try:
                with open(self._alerts_file, 'w', encoding='utf-8') as f:
                    json.dump([], f)
                log.info("All alerts cleared")
                return True
            except Exception as e:
                log.error("Failed to clear alerts: %s", e)
                return False
    
    def get_alert_count(self) -> int:
        """Get total number of alerts."""
        return len(self.get_alerts())
    
    def _read_alerts_unsafe(self) -> List[Dict]:
        """
        Read alerts from file (NOT thread-safe, must hold lock).
        
        Handles corrupted files gracefully.
        """
        try:
            if not self._alerts_file.exists():
                return []
            
            with open(self._alerts_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
                if not content:
                    return []
                
                alerts = json.loads(content)
                
                if not isinstance(alerts, list):
                    log.error("Alerts file is not a list, resetting")
                    return []
                
                return alerts
                
        except json.JSONDecodeError as e:
            log.error("Alerts file corrupted (JSON): %s", e)
            # Backup corrupted file
            backup = self._alerts_file.with_suffix('.corrupted')
            try:
                self._alerts_file.rename(backup)
                log.info("Corrupted file backed up to: %s", backup)
            except Exception:
                pass
            return []
            
        except Exception as e:
            log.error("Failed to read alerts: %s", e)
            return []


# ── Singleton Instance ────────────────────────────────────────────────────

_alert_manager: Optional[AlertManager] = None
_manager_lock = threading.Lock()


def get_alert_manager() -> AlertManager:
    """Get the singleton alert manager instance."""
    global _alert_manager
    
    with _manager_lock:
        if _alert_manager is None:
            _alert_manager = AlertManager()
        return _alert_manager


# ── Testing ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from utils.logging_config import setup_logging
    
    setup_logging()
    
    print("SentinelML V2 — Alert Manager Test")
    print("="*70)
    
    manager = get_alert_manager()
    
    # Clear existing alerts
    print("\n1. Clearing old alerts...")
    manager.clear_alerts()
    print(f"✓ Alerts cleared. Count: {manager.get_alert_count()}")
    
    # Add test alerts
    print("\n2. Adding test alerts...")
    
    manager.add_alert(
        severity="CRITICAL",
        category="scanner",
        title="Ransomware Detected",
        message="High probability ransomware behavior detected",
        source="MLPredictor",
        metadata={"probability": 0.95}
    )
    
    manager.add_alert(
        severity="WARNING",
        category="guard",
        title="Rapid File Modifications",
        message="50 files modified in 10 seconds",
        source="SentinelGuard",
        metadata={"file_count": 50, "duration": 10}
    )
    
    manager.add_alert(
        severity="INFO",
        category="system",
        title="Scan Completed",
        message="System scan completed successfully",
        source="LiveScanner"
    )
    
    print(f"✓ Added 3 alerts. Total: {manager.get_alert_count()}")
    
    # Retrieve alerts
    print("\n3. Retrieving alerts...")
    alerts = manager.get_alerts()
    
    for i, alert in enumerate(alerts, 1):
        print(f"\n   Alert {i}:")
        print(f"   ID: {alert['id']}")
        print(f"   Time: {alert['timestamp']}")
        print(f"   Severity: {alert['severity']}")
        print(f"   Category: {alert['category']}")
        print(f"   Title: {alert['title']}")
        print(f"   Message: {alert['message']}")
    
    # Filter by severity
    print("\n4. Filtering by severity...")
    critical = manager.get_alerts_by_severity("CRITICAL")
    print(f"✓ Critical alerts: {len(critical)}")
    
    warnings = manager.get_alerts_by_severity("WARNING")
    print(f"✓ Warning alerts: {len(warnings)}")
    
    print("\n[OK] Alert Manager test complete")
