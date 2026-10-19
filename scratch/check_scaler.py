import joblib

s = joblib.load('models/scaler.pkl')
print("Scaler feature names:", list(s.feature_names_in_))
print("Scaler mean:", list(s.mean_))
print("Scaler scale (std):", list(s.scale_))
