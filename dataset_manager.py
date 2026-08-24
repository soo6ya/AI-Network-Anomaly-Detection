import os
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

TRAINING_DIR = "training_captures"
OUTPUT_FILE = "combined_normal_traffic.csv"


# ============================================================
# FIND TRAINING CSV FILES
# ============================================================

csv_files = []

for root, dirs, files in os.walk(TRAINING_DIR):

    for filename in files:

        if not filename.lower().endswith(".csv"):
            continue

        full_path = os.path.join(
            root,
            filename
        )

        # Never include the generated combined dataset
        if os.path.abspath(full_path) == os.path.abspath(
            OUTPUT_FILE
        ):
            continue

        csv_files.append(full_path)


# Remove duplicate paths and sort
csv_files = sorted(
    set(csv_files)
)


# ============================================================
# CHECK
# ============================================================

if not csv_files:

    print("No training CSV files found.")
    raise SystemExit


print("Training capture files found:")

for file in csv_files:

    print(f" - {file}")


# ============================================================
# LOAD FILES
# ============================================================

dataframes = []

total_loaded = 0


for file in csv_files:

    try:

        df = pd.read_csv(file)

        print(
            f"Loaded {len(df)} packets from {file}"
        )

        dataframes.append(df)

        total_loaded += len(df)

    except Exception as e:

        print(
            f"ERROR loading {file}: {e}"
        )


if not dataframes:

    print("No valid training data found.")
    raise SystemExit


# ============================================================
# COMBINE
# ============================================================

combined_df = pd.concat(
    dataframes,
    ignore_index=True
)


# ============================================================
# REMOVE EXACT DUPLICATES
# ============================================================

before_duplicates = len(
    combined_df
)


combined_df = combined_df.drop_duplicates(
    keep="first"
).reset_index(drop=True)


after_duplicates = len(
    combined_df
)


duplicates_removed = (
    before_duplicates
    -
    after_duplicates
)


# ============================================================
# SAVE FINAL DATASET
# ============================================================

combined_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# VERIFY SAVED FILE
# ============================================================

saved_df = pd.read_csv(
    OUTPUT_FILE
)


# ============================================================
# SUMMARY
# ============================================================

print()
print("========================================")
print(" Training Dataset Manager")
print("========================================")

print(
    f"Training files       : {len(csv_files)}"
)

print(
    f"Packets loaded       : {total_loaded}"
)

print(
    f"Duplicates removed   : {duplicates_removed}"
)

print(
    f"Final packets        : {len(combined_df)}"
)

print(
    f"Saved file rows      : {len(saved_df)}"
)

print(
    f"Output file          : {OUTPUT_FILE}"
)

print()


# ============================================================
# SAFETY CHECK
# ============================================================

if len(saved_df) != len(combined_df):

    print(
        "WARNING: Saved row count does not match "
        "the final dataframe!"
    )

else:

    print(
        "Dataset verification: PASSED"
    )