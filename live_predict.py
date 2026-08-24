import pandas as pd
import joblib

MODEL_FILE = "network_anomaly_model.pkl"
INPUT_FILE = "live_features.csv"
OUTPUT_FILE = "live_predictions.csv"

print("========================================")
print(" AI Live Traffic Prediction")
print("========================================")

# Load trained model
saved_model = joblib.load(MODEL_FILE)

model = saved_model["model"]
feature_columns = saved_model["features"]

# Load live features
df = pd.read_csv(INPUT_FILE)

print(f"Loaded {len(df)} live traffic windows.")

# Select exactly the features used during training
X = df[feature_columns]

# Predict
df["prediction"] = model.predict(X)

df["status"] = df["prediction"].map({
    1: "Normal",
    -1: "Anomaly"
})

# Anomaly score
df["anomaly_score"] = model.decision_function(X)

# Save results
df.to_csv(OUTPUT_FILE, index=False)

# Statistics
normal_count = (df["status"] == "Normal").sum()
anomaly_count = (df["status"] == "Anomaly").sum()

print()
print("========================================")
print(" Live Prediction Results")
print("========================================")

print(f"Total windows : {len(df)}")
print(f"Normal        : {normal_count}")
print(f"Anomalies     : {anomaly_count}")

print(f"\nResults saved to: {OUTPUT_FILE}")

# Show anomalies
anomalies = df[df["status"] == "Anomaly"]

if len(anomalies) > 0:

    print("\nDetected anomalies:")

    print(
        anomalies[
            [
                "time_window",
                "packet_count",
                "total_bytes",
                "anomaly_score",
                "status"
            ]
        ].sort_values("anomaly_score")
        .to_string(index=False)
    )

else:

    print("\nNo anomalies detected in this capture.")