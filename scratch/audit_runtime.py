import sys
import json
from pathlib import Path
import joblib
import numpy as np

print("Python version:", sys.version)

model_path = Path("models/saved_model.pkl")
scaler_path = Path("models/scaler.pkl")
metrics_path = Path("models/metrics.json")

m = joblib.load(model_path)
s = joblib.load(scaler_path)
with open(metrics_path, "r", encoding="utf-8") as f:
    metrics = json.load(f)

print("Model:", type(m).__name__, "Estimators:", getattr(m, "n_estimators", None))
print("Expected features (model):", getattr(m, "n_features_in_", None))
print("Expected features (scaler):", getattr(s, "n_features_in_", None))
print("Optimal threshold:", metrics.get("optimal_threshold"))

# Test prediction with zero vector
x_zero = np.zeros((1, 19), dtype=np.float64)
x_zero_scaled = s.transform(x_zero)
prob_zero = float(m.predict_proba(x_zero_scaled)[0][1])
print("Zero vector probability:", prob_zero)

# Test prediction with typical benign vector
x_benign = np.array([[200, 0, 3.5, 5.0, 0, 0, 1, 0, 20, 2, 5000, 2, 1, 0, 0, 0, 0, 0, 0]], dtype=np.float64)
x_benign_scaled = s.transform(x_benign)
prob_benign = float(m.predict_proba(x_benign_scaled)[0][1])
print("Benign baseline probability:", prob_benign)

# Test with elevated ransomware indicators (high entropy, vssadmin, defender tampering)
x_ransom = np.array([[300, 3, 7.8, 7.99, 150, 2, 5, 2, 80, 15, 25000, 10, 5, 2, 5, 4, 2, 3, 2]], dtype=np.float64)
x_ransom_scaled = s.transform(x_ransom)
prob_ransom = float(m.predict_proba(x_ransom_scaled)[0][1])
print("Elevated threat vector probability:", prob_ransom)
