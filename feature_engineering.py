import sys
import os
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

OUTPUT_SUFFIX = "_features.csv"


# ============================================================
# CHECK COMMAND-LINE ARGUMENT
# ============================================================

if len(sys.argv) < 2:

    print(
        "Usage:"
    )

    print(
        "python feature_engineering.py <input_csv>"
    )

    raise SystemExit(1)


INPUT_FILE = sys.argv[1]


# ============================================================
# OUTPUT FILE
# ============================================================

base_name = os.path.splitext(
    INPUT_FILE
)[0]

OUTPUT_FILE = (
    base_name
    +
    OUTPUT_SUFFIX
)


# ============================================================
# LOAD DATASET
# ============================================================

print(
    f"Loading: {INPUT_FILE}"
)


try:

    df = pd.read_csv(
        INPUT_FILE
    )

except FileNotFoundError:

    print(
        f"ERROR: File not found: {INPUT_FILE}"
    )

    raise SystemExit(1)

except Exception as e:

    print(
        f"ERROR loading dataset: {e}"
    )

    raise SystemExit(1)


print(
    f"Packets loaded: {len(df)}"
)


# ============================================================
# REQUIRED COLUMNS
# ============================================================

required_columns = [

    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_size",
    "ip_version"

]


missing_columns = [

    column
    for column in required_columns
    if column not in df.columns

]


if missing_columns:

    print()
    print(
        "ERROR: Missing required columns:"
    )

    for column in missing_columns:

        print(
            f" - {column}"
        )

    raise SystemExit(1)


# ============================================================
# TIMESTAMP CONVERSION
# ============================================================
#
# Different capture files can contain timestamps such as:
#
# 2026-08-23 16:17:00
#
# and:
#
# 2026-08-23 20:33:46.182043
#
# format="mixed" allows pandas to handle both.
# ============================================================

df["timestamp"] = pd.to_datetime(

    df["timestamp"],

    format="mixed",

    errors="coerce"

)


# ============================================================
# REMOVE INVALID TIMESTAMPS
# ============================================================

invalid_timestamps = (
    df["timestamp"].isna().sum()
)


if invalid_timestamps > 0:

    print(
        f"Warning: {invalid_timestamps} "
        "invalid timestamps removed."
    )

    df = df.dropna(
        subset=["timestamp"]
    ).copy()


if len(df) == 0:

    print(
        "ERROR: No valid timestamp data remains."
    )

    raise SystemExit(1)


# ============================================================
# SORT BY TIME
# ============================================================

df = df.sort_values(
    "timestamp"
).reset_index(
    drop=True
)


# ============================================================
# CREATE 1-SECOND TIME WINDOW
# ============================================================

df["time_window"] = (
    df["timestamp"]
    .dt.floor("1s")
)


# ============================================================
# FEATURE ENGINEERING
# ============================================================

print()
print(
    "Creating traffic features..."
)


# ------------------------------------------------------------
# Helper function
# ------------------------------------------------------------

def safe_nunique(series):

    return series.nunique(
        dropna=True
    )


# ============================================================
# GROUP TRAFFIC INTO 1-SECOND WINDOWS
# ============================================================

groups = df.groupby(
    "time_window",
    sort=True
)


feature_rows = []


for time_window, group in groups:

    # --------------------------------------------------------
    # Basic packet information
    # --------------------------------------------------------

    packet_count = len(
        group
    )


    total_bytes = group[
        "packet_size"
    ].sum()


    if packet_count > 0:

        average_packet_size = (
            group["packet_size"].mean()
        )

    else:

        average_packet_size = 0


    # --------------------------------------------------------
    # Protocol counts
    # --------------------------------------------------------

    tcp_count = (
        group["protocol"]
        .astype(str)
        .str.upper()
        .eq("TCP")
        .sum()
    )


    udp_count = (
        group["protocol"]
        .astype(str)
        .str.upper()
        .eq("UDP")
        .sum()
    )


    # --------------------------------------------------------
    # Unique network information
    # --------------------------------------------------------

    unique_destinations = safe_nunique(
        group["destination_ip"]
    )


    unique_source_ports = safe_nunique(
        group["source_port"]
    )


    unique_destination_ports = safe_nunique(
        group["destination_port"]
    )


    # --------------------------------------------------------
    # IP versions
    # --------------------------------------------------------

    ipv4_count = (
        pd.to_numeric(
            group["ip_version"],
            errors="coerce"
        )
        .eq(4)
        .sum()
    )


    ipv6_count = (
        pd.to_numeric(
            group["ip_version"],
            errors="coerce"
        )
        .eq(6)
        .sum()
    )


    # --------------------------------------------------------
    # Rate features
    #
    # Each group represents one second.
    # --------------------------------------------------------

    packets_per_second = (
        packet_count
    )


    bytes_per_second = (
        total_bytes
    )


    # --------------------------------------------------------
    # Protocol ratios
    # --------------------------------------------------------

    if packet_count > 0:

        tcp_ratio = (
            tcp_count
            /
            packet_count
        )


        udp_ratio = (
            udp_count
            /
            packet_count
        )

    else:

        tcp_ratio = 0.0

        udp_ratio = 0.0


    # --------------------------------------------------------
    # Store feature row
    # --------------------------------------------------------

    feature_rows.append({

        "time_window":
            time_window,

        "packet_count":
            packet_count,

        "total_bytes":
            total_bytes,

        "average_packet_size":
            average_packet_size,

        "tcp_count":
            tcp_count,

        "udp_count":
            udp_count,

        "unique_destinations":
            unique_destinations,

        "unique_source_ports":
            unique_source_ports,

        "unique_destination_ports":
            unique_destination_ports,

        "ipv4_count":
            ipv4_count,

        "ipv6_count":
            ipv6_count,

        "packets_per_second":
            packets_per_second,

        "bytes_per_second":
            bytes_per_second,

        "tcp_ratio":
            tcp_ratio,

        "udp_ratio":
            udp_ratio

    })


# ============================================================
# CREATE FEATURE DATAFRAME
# ============================================================

features_df = pd.DataFrame(
    feature_rows
)


# ============================================================
# HANDLE NUMERIC VALUES
# ============================================================

numeric_columns = [

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


for column in numeric_columns:

    features_df[column] = pd.to_numeric(

        features_df[column],

        errors="coerce"

    )


# ============================================================
# REMOVE INVALID NUMERIC ROWS
# ============================================================

features_df = features_df.dropna(
    subset=numeric_columns
).reset_index(
    drop=True
)


# ============================================================
# SAVE FEATURE DATASET
# ============================================================

features_df.to_csv(

    OUTPUT_FILE,

    index=False

)


# ============================================================
# RESULTS
# ============================================================

print()
print(
    "Feature engineering completed!"
)

print(
    f"Created: {OUTPUT_FILE}"
)

print(
    f"Traffic windows: {len(features_df)}"
)


# ============================================================
# SHOW FIRST 5 ROWS
# ============================================================

print()
print(
    "First 5 rows:"
)

print(
    features_df.head()
)


# ============================================================
# SHOW FEATURE INFORMATION
# ============================================================

print()
print(
    "Feature columns:"
)

for column in numeric_columns:

    print(
        f" - {column}"
    )


print()
print(
    "Done."
)