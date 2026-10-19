import requests
import json
import time

url = "https://sentinelml-ai-backend.onrender.com/api/v1/ai/chat"

print("Waiting for deployment to settle...")
time.sleep(10)

print("\n--- TEST 5: Generic AI ---")
try:
    r = requests.post(url, json={"message": "What is ransomware?"})
    print(f"HTTP {r.status_code}")
    print(json.dumps(r.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")

print("\n--- TEST 6: Structured Scan Context ---")
scan_context = {
    "scan_state": "SAFE",
    "threat_level": "SAFE",
    "ml_executed": True,
    "ml_probability": 0.44,
    "files_inspected": 10913,
    "directories_inspected": 280,
    "processes_analyzed": 28,
    "scan_duration": 1.2,
    "entropy_samples": 200,
    "avg_entropy": 5.98,
    "max_entropy": 7.95,
    "high_entropy_region_count": 51,
    "network_connections": 9,
    "external_ips": 1,
    "features": {
        "entropy": 0.12,
        "cpu_usage": 3.5
    }
}
try:
    r = requests.post(url, json={
        "message": "Explain my latest scan",
        "context": scan_context,
        "system_instructions": "Do not hallucinate. Use only the provided context."
    })
    print(f"HTTP {r.status_code}")
    print(json.dumps(r.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")
