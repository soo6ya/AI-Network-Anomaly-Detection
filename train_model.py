import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

INPUT_FILE = "combined_normal_traffic_features.csv"
OUTPUT_FILE = "anomaly_results.csv"
MODEL_FILE = "network_anomaly_model.pkl"

# Load feature dataset
df = pd.read_csv(INPUT_FILE)

print(f"Loaded {len(df)} traffic windows.")

# Features used by the ML model
feature_columns = [
    "packet_count",
    "total_bytes",
    "average_packet_size",
    "tcp_count",
    "udp_count",
    "unique_destinations",
    "unique_source_ports",
    "unique_destination_ports",
    "ipv4_count",
    "ipv6_count",
    "packets_per_second",
    "bytes_per_second",
    "tcp_ratio",
    "udp_ratio"
]

X = df[feature_columns]

# Create Isolation Forest
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42
)

# Train the model
model.fit(X)

# Save trained model
joblib.dump(
    {
        "model": model,
        "features": feature_columns
    },
    MODEL_FILE
)

print(f"Model saved to: {MODEL_FILE}")

# Predict on training data for baseline inspection
df["prediction"] = model.predict(X)

df["status"] = df["prediction"].map({
    1: "Normal",
    -1: "Anomaly"
})

df["anomaly_score"] = model.decision_function(X)

# Save results
df.to_csv(OUTPUT_FILE, index=False)

normal_count = (df["status"] == "Normal").sum()
anomaly_count = (df["status"] == "Anomaly").sum()

print("\n========================================")
print(" Isolation Forest Results")
print("========================================")

print(f"Total windows : {len(df)}")
print(f"Normal        : {normal_count}")
print(f"Anomalies     : {anomaly_count}")

print(f"\nResults saved to: {OUTPUT_FILE}")