import pandas as pd
import joblib

INPUT_FILE = "traffic_20260823_170526_features.csv"
OUTPUT_FILE = "test_predictions.csv"
MODEL_FILE = "network_anomaly_model.pkl"

# Load saved model
saved_model = joblib.load(MODEL_FILE)

model = saved_model["model"]
feature_columns = saved_model["features"]

# Load unseen traffic features
df = pd.read_csv(INPUT_FILE)

print(f"Loaded {len(df)} unseen traffic windows.")

# Select exactly the same features used during training
X = df[feature_columns]

# Predict using the saved model
df["prediction"] = model.predict(X)

# Convert predictions to readable labels
df["status"] = df["prediction"].map({
    1: "Normal",
    -1: "Anomaly"
})

# Calculate anomaly score
df["anomaly_score"] = model.decision_function(X)

# Save predictions
df.to_csv(OUTPUT_FILE, index=False)

# Count results
normal_count = (df["status"] == "Normal").sum()
anomaly_count = (df["status"] == "Anomaly").sum()

print("\n========================================")
print(" Unseen Traffic Test")
print("========================================")

print(f"Total windows : {len(df)}")
print(f"Normal        : {normal_count}")
print(f"Anomalies     : {anomaly_count}")

print(f"\nResults saved to: {OUTPUT_FILE}")

print("\nMost anomalous windows:")
print(
    df.sort_values("anomaly_score")
      [["time_window",
        "packet_count",
        "total_bytes",
        "tcp_count",
        "udp_count",
        "anomaly_score",
        "status"]]
      .head(10)
      .to_string(index=False)
)