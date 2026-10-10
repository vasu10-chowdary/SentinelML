"""
SentinelML V2 — Demo Mode Data
================================
Pre-generated demo data for safe college presentations.
No live malware required.
"""

import random
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Demo scan results (simulated)
DEMO_SCAN_RESULTS = [
    {
        "timestamp": "2026-08-25 09:15:32",
        "duration": 4.2,
        "process_count": 324,
        "threat_level": "SAFE",
        "probability": 0.12,
        "features": [324, 0.45, 8192, 45.2, 12, 0.15, 280, 44, 0, 8, 16, 324, 0, 0, 1.2, 280, 44, 0, 3.5],
        "message": "System appears normal. No immediate threats detected."
    },
    {
        "timestamp": "2026-08-25 10:30:15",
        "duration": 4.5,
        "process_count": 342,
        "threat_level": "WARNING",
        "probability": 0.67,
        "features": [342, 0.52, 9856, 62.3, 18, 0.28, 295, 47, 2, 12, 24, 342, 0, 0, 2.1, 295, 47, 0, 4.8],
        "message": "Suspicious activity detected. Several processes showing elevated resource usage."
    },
    {
        "timestamp": "2026-08-25 14:22:48",
        "duration": 4.8,
        "process_count": 387,
        "threat_level": "CRITICAL",
        "probability": 0.94,
        "features": [387, 0.78, 15234, 89.7, 45, 0.62, 325, 62, 8, 28, 52, 387, 2, 1, 8.7, 325, 62, 3, 12.4],
        "message": "CRITICAL THREAT DETECTED! Multiple indicators of ransomware-like behavior."
    },
    {
        "timestamp": "2026-08-25 15:45:10",
        "duration": 4.1,
        "process_count": 315,
        "threat_level": "SAFE",
        "probability": 0.08,
        "features": [315, 0.38, 7680, 38.5, 10, 0.12, 275, 40, 0, 6, 14, 315, 0, 0, 0.9, 275, 40, 0, 2.8],
        "message": "System operating normally after threat remediation."
    },
]

# Demo alerts (simulated)
DEMO_ALERTS = [
    {
        "id": 1,
        "timestamp": "2026-08-25 10:30:15",
        "threat_level": "WARNING",
        "probability": 0.67,
        "process_count": 342,
        "message": "Suspicious activity: Elevated resource usage detected",
        "details": {
            "suspicious_processes": ["cryptolocker_sim.exe", "file_encryptor.exe"],
            "cpu_usage": 62.3,
            "memory_usage": 52,
        }
    },
    {
        "id": 2,
        "timestamp": "2026-08-25 14:22:48",
        "threat_level": "CRITICAL",
        "probability": 0.94,
        "process_count": 387,
        "message": "CRITICAL: Ransomware-like behavior pattern detected",
        "details": {
            "suspicious_processes": ["wannacry_sim.exe", "locky_sim.exe", "cerber_sim.exe"],
            "cpu_usage": 89.7,
            "memory_usage": 78,
            "file_modifications": 1247,
            "network_connections": 28,
        }
    },
    {
        "id": 3,
        "timestamp": "2026-08-24 16:45:30",
        "threat_level": "WARNING",
        "probability": 0.72,
        "process_count": 298,
        "message": "Suspicious file access patterns detected",
        "details": {
            "suspicious_processes": ["file_scanner.exe"],
            "file_reads": 2845,
            "file_writes": 156,
        }
    },
]

# Demo incident reports (simulated)
DEMO_INCIDENTS = [
    {
        "id": "incident_demo_001",
        "timestamp": "2026-08-25 14:22:48",
        "threat_level": "CRITICAL",
        "probability": 0.94,
        "classification": "Ransomware Simulation",
        "process_count": 387,
        "description": "Demo incident showing ransomware-like behavior detection",
        "indicators": [
            "High CPU usage (89.7%)",
            "Elevated memory consumption (78%)",
            "Multiple suspicious processes",
            "Rapid file modifications (1247 files)",
            "Unusual network activity (28 connections)",
        ],
        "recommended_actions": [
            "Isolate affected system from network",
            "Terminate suspicious processes",
            "Run full system scan",
            "Review recent file changes",
            "Check backup integrity",
        ]
    },
]

# Demo system information
DEMO_SYSTEM_INFO = {
    "os": "Windows 11 Pro",
    "version": "22H2",
    "machine": "AMD64",
    "processor": "Intel Core i7-9700K @ 3.60GHz",
    "ram": "16 GB",
    "python_version": "3.14.3",
}


def get_demo_scan_result(threat_level: str = "random") -> Dict[str, Any]:
    """
    Get a demo scan result.
    
    Args:
        threat_level: "SAFE", "WARNING", "CRITICAL", or "random"
    
    Returns:
        Dict with demo scan data
    """
    if threat_level == "random":
        return random.choice(DEMO_SCAN_RESULTS)
    
    for result in DEMO_SCAN_RESULTS:
        if result["threat_level"] == threat_level:
            return result
    
    return DEMO_SCAN_RESULTS[0]  # Default to SAFE


def get_demo_alerts(count: int = None) -> List[Dict[str, Any]]:
    """
    Get demo alerts.
    
    Args:
        count: Number of alerts to return (None = all)
    
    Returns:
        List of demo alerts
    """
    if count is None:
        return DEMO_ALERTS.copy()
    return DEMO_ALERTS[:count]


def get_demo_incident(incident_id: str = None) -> Dict[str, Any]:
    """
    Get a demo incident report.
    
    Args:
        incident_id: Specific incident ID (None = first)
    
    Returns:
        Demo incident report
    """
    if incident_id:
        for incident in DEMO_INCIDENTS:
            if incident["id"] == incident_id:
                return incident
    return DEMO_INCIDENTS[0]


def get_demo_system_info() -> Dict[str, str]:
    """Get demo system information."""
    return DEMO_SYSTEM_INFO.copy()


def generate_random_demo_scan() -> Dict[str, Any]:
    """Generate a random demo scan result with some variation."""
    base = random.choice(DEMO_SCAN_RESULTS).copy()
    
    # Add slight randomization
    base["duration"] = round(base["duration"] + random.uniform(-0.5, 0.5), 1)
    base["process_count"] = base["process_count"] + random.randint(-10, 10)
    base["probability"] = max(0.0, min(1.0, base["probability"] + random.uniform(-0.05, 0.05)))
    
    # Update timestamp to now
    base["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return base


# Demo mode configuration
DEMO_CONFIG = {
    "enabled": False,  # Set to True to enable demo mode
    "show_banner": True,  # Show "DEMO MODE" banner
    "banner_text": "🎓 DEMO MODE - SIMULATED DATA 🎓",
    "banner_color": "#ff6b00",  # Orange
    "auto_scan_interval": 10,  # Seconds between auto-scans in demo
    "randomize_results": True,  # Add randomization to demo data
}


def is_demo_mode() -> bool:
    """Check if demo mode is enabled."""
    return DEMO_CONFIG["enabled"]


def enable_demo_mode():
    """Enable demo mode."""
    DEMO_CONFIG["enabled"] = True


def disable_demo_mode():
    """Disable demo mode."""
    DEMO_CONFIG["enabled"] = False


if __name__ == '__main__':
    # Test demo data
    print("=" * 60)
    print("SENTINELML V2 — DEMO DATA TEST")
    print("=" * 60)
    print()
    
    print("Demo Scan Results:")
    for i, result in enumerate(DEMO_SCAN_RESULTS, 1):
        print(f"\n{i}. {result['threat_level']} (Probability: {result['probability']:.2f})")
        print(f"   Time: {result['timestamp']}")
        print(f"   Processes: {result['process_count']}")
        print(f"   Message: {result['message']}")
    
    print("\n" + "=" * 60)
    print("Demo Alerts:")
    for alert in DEMO_ALERTS:
        print(f"\n{alert['id']}. [{alert['threat_level']}] {alert['message']}")
        print(f"   Time: {alert['timestamp']}")
        print(f"   Probability: {alert['probability']:.2f}")
    
    print("\n" + "=" * 60)
    print("Demo Incidents:")
    for incident in DEMO_INCIDENTS:
        print(f"\n{incident['id']}: {incident['classification']}")
        print(f"   Threat Level: {incident['threat_level']}")
        print(f"   Time: {incident['timestamp']}")
        print(f"   Indicators: {len(incident['indicators'])}")
    
    print("\n" + "=" * 60)
    print("Random Demo Scan:")
    random_scan = generate_random_demo_scan()
    print(f"Threat Level: {random_scan['threat_level']}")
    print(f"Probability: {random_scan['probability']:.2f}")
    print(f"Message: {random_scan['message']}")
    
    print("\n" + "=" * 60)
