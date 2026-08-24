import pandas as pd

INPUT_FILE = "test_predictions.csv"

df = pd.read_csv(INPUT_FILE)

# Separate anomalies
anomalies = df[df["status"] == "Anomaly"].copy()

print("========================================")
print(" Unseen Traffic Analysis")
print("========================================")

print(f"Total windows : {len(df)}")
print(f"Normal        : {(df['status'] == 'Normal').sum()}")
print(f"Anomalies     : {len(anomalies)}")

# Baseline statistics from the unseen session
features = [
    "packet_count",
    "total_bytes",
    "average_packet_size",
    "unique_destinations",
    "unique_source_ports",
    "unique_destination_ports"
]

print("\nAverage values - all unseen traffic:")
print(df[features].mean().round(2))

print("\nAverage values - detected anomalies:")
print(anomalies[features].mean().round(2))

print("\n========================================")
print(" Strongest Anomalies")
print("========================================")

print(
    anomalies.sort_values("anomaly_score")
    [
        [
            "time_window",
            "packet_count",
            "total_bytes",
            "average_packet_size",
            "tcp_count",
            "udp_count",
            "unique_destinations",
            "unique_source_ports",
            "unique_destination_ports",
            "anomaly_score"
        ]
    ]
    .head(15)
    .to_string(index=False)
)

# Compare anomaly averages with normal averages
normal = df[df["status"] == "Normal"]

print("\n========================================")
print(" Anomaly vs Normal Comparison")
print("========================================")

comparison = pd.DataFrame({
    "Normal_Average": normal[features].mean(),
    "Anomaly_Average": anomalies[features].mean()
})

comparison["Difference_Percent"] = (
    (comparison["Anomaly_Average"] - comparison["Normal_Average"])
    / comparison["Normal_Average"]
    * 100
)

print(comparison.round(2))