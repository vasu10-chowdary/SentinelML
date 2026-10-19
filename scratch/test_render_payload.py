import requests

payload = {
    "message": "Explain my latest scan",
    "context": {
        "scan_state": "SAFE",
        "threat_level": "SAFE",
        "ml_probability": 0.44,
        "files_inspected": 1913,
        "directories_inspected": 279,
        "processes_analyzed": 27,
        "features": {
            "total_processes": 27,
            "avg_entropy": 5.98,
            "max_entropy": 7.95,
            "high_entropy_region_count": 51,
            "network_connection_count": 9,
            "unique_external_ips": 1
        }
    },
    "system_instructions": "This is a test instruction"
}

r = requests.post("https://sentinelml-ai-backend.onrender.com/api/v1/ai/chat", json=payload)
print(r.status_code)
print(r.text)
