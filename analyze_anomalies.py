import pandas as pd

INPUT_FILE = "anomaly_results.csv"
OUTPUT_FILE = "anomaly_analysis.csv"

# Load results from the ML model
df = pd.read_csv(INPUT_FILE)

# Calculate baseline statistics using all traffic windows
baseline = {
    "packet_count": df["packet_count"].mean(),
    "total_bytes": df["total_bytes"].mean(),
    "average_packet_size": df["average_packet_size"].mean(),
    "unique_destinations": df["unique_destinations"].mean(),
    "unique_source_ports": df["unique_source_ports"].mean(),
    "unique_destination_ports": df["unique_destination_ports"].mean()
}


def explain_anomaly(row):
    reasons = []

    # High packet volume
    if row["packet_count"] > baseline["packet_count"] * 2:
        reasons.append("High packet rate")

    # High bandwidth
    if row["total_bytes"] > baseline["total_bytes"] * 2:
        reasons.append("High data volume")

    # Unusual packet size
    if row["average_packet_size"] > baseline["average_packet_size"] * 2:
        reasons.append("Large average packet size")

    # Many destinations
    if row["unique_destinations"] > baseline["unique_destinations"] * 2:
        reasons.append("Many destinations")

    # Many source ports
    if row["unique_source_ports"] > baseline["unique_source_ports"] * 2:
        reasons.append("Many source ports")

    # Many destination ports
    if row["unique_destination_ports"] > baseline["unique_destination_ports"] * 2:
        reasons.append("Many destination ports")

    if not reasons:
        reasons.append("Unusual combination of traffic features")

    return ", ".join(reasons)


# Only explain traffic already classified as anomalous
df["explanation"] = "Normal traffic"

anomaly_mask = df["status"] == "Anomaly"

df.loc[anomaly_mask, "explanation"] = (
    df.loc[anomaly_mask]
    .apply(explain_anomaly, axis=1)
)

# Save analysis
df.to_csv(OUTPUT_FILE, index=False)

# Display results
anomalies = df[df["status"] == "Anomaly"]

print("========================================")
print(" Anomaly Analysis")
print("========================================")

print(f"Total windows : {len(df)}")
print(f"Anomalies     : {len(anomalies)}")

print("\nDetected anomalies:")
print(
    anomalies[
        [
            "time_window",
            "packet_count",
            "total_bytes",
            "tcp_count",
            "udp_count",
            "anomaly_score",
            "explanation"
        ]
    ].head(15).to_string(index=False)
)

print(f"\nAnalysis saved to: {OUTPUT_FILE}")