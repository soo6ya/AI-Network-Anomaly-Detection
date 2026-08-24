import pandas as pd
import matplotlib.pyplot as plt

INPUT_FILE = "anomaly_analysis.csv"

# Load anomaly results
df = pd.read_csv(INPUT_FILE)

# Convert timestamp
df["time_window"] = pd.to_datetime(df["time_window"])

# Create anomaly mask
anomalies = df["status"] == "Anomaly"

# -------------------------------
# 1. Packet Count
# -------------------------------

plt.figure(figsize=(12, 5))

plt.plot(
    df["time_window"],
    df["packet_count"],
    label="Packet Count"
)

plt.scatter(
    df.loc[anomalies, "time_window"],
    df.loc[anomalies, "packet_count"],
    label="Anomaly"
)

plt.xlabel("Time")
plt.ylabel("Packets")
plt.title("Network Packet Count Over Time")
plt.xticks(rotation=45)
plt.legend()
plt.tight_layout()

plt.savefig("packet_count.png")
plt.show()


# -------------------------------
# 2. Total Bytes
# -------------------------------

plt.figure(figsize=(12, 5))

plt.plot(
    df["time_window"],
    df["total_bytes"],
    label="Total Bytes"
)

plt.scatter(
    df.loc[anomalies, "time_window"],
    df.loc[anomalies, "total_bytes"],
    label="Anomaly"
)

plt.xlabel("Time")
plt.ylabel("Bytes")
plt.title("Network Traffic Volume Over Time")
plt.xticks(rotation=45)
plt.legend()
plt.tight_layout()

plt.savefig("traffic_volume.png")
plt.show()


# -------------------------------
# 3. Anomaly Score
# -------------------------------

plt.figure(figsize=(12, 5))

plt.plot(
    df["time_window"],
    df["anomaly_score"],
    label="Anomaly Score"
)

plt.scatter(
    df.loc[anomalies, "time_window"],
    df.loc[anomalies, "anomaly_score"],
    label="Anomaly"
)

plt.axhline(0, linestyle="--")

plt.xlabel("Time")
plt.ylabel("Anomaly Score")
plt.title("Network Anomaly Score Over Time")
plt.xticks(rotation=45)
plt.legend()
plt.tight_layout()

plt.savefig("anomaly_score.png")
plt.show()


# -------------------------------
# 4. Summary
# -------------------------------

print("========================================")
print(" Visualization Completed")
print("========================================")

print(f"Total windows : {len(df)}")
print(f"Normal        : {(df['status'] == 'Normal').sum()}")
print(f"Anomalies     : {anomalies.sum()}")

print("\nCreated:")
print("packet_count.png")
print("traffic_volume.png")
print("anomaly_score.png")