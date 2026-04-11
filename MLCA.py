# #MLCA - MACHINE LEARNING FOR CYBERSECURITY APPLICATIONS

# # UNDERSTANDING NUMPY
# import numpy as np
# # Create a 1D array
# sbytes = np.array([120, 240, 0, 500, 1500, 0, 800, 950])
# print("1D Array (sbytes):", sbytes)

# # Having Mean, Standard Deviation, Min and Max of the Array
# print("Mean of sbytes:", np.mean(sbytes))
# print("Standard Deviation of sbytes:", np.std(sbytes))
# print("Minimum of sbytes:", np.min(sbytes))
# print("Maximum of sbytes:", np.max(sbytes))

# threshold = sbytes.mean() + 2 * sbytes.std()

# anomalies = sbytes[sbytes > threshold]
# print("Suspicious flows:", anomalies)

# # Reshaping — prepare for ML model input
# X = sbytes.reshape(-1, 1)   # Column vector: shape (8, 1) explain this 
# print("Reshaped Array (X):", X)
# #why
# # Percentiles — used in IQR outlier detection
# Q1 = np.percentile(sbytes, 25)
# print(f"Q1 (25th percentile) of sbytes: {Q1}")
# Q3 = np.percentile(sbytes, 75)
# print(f"Q3 (75th percentile) of sbytes: {Q3}")
# #what is this , why 25 and 75 , how sytax works, what is percentile, how to interpret it why to use it what the case for it  


# IQR = Q3 - Q1
# print(f"Q1={Q1}, Q3={Q3}, IQR={IQR}")

#print("-------------------------------------------------------")

import pandas as pd

# Load training and testing files
df_train = pd.read_csv("UNSW_NB15_training-set.csv")
df_test  = pd.read_csv("UNSW_NB15_testing-set.csv")

# Merge into one dataset for unified analysis
df = pd.concat([df_train, df_test], ignore_index=True)

# # FIRST INSPECTION CHECKLIST — always run these after loading
# print("Shape of the dataset:", df.shape)            # (rows, columns) — e.g. (257673, 45)
# print("Data types of each column:", df.dtypes)           # Data type of every column
# print("First 5 rows:", df.head())           # First 5 rows — eyeball the content
# print("Last 5 rows:", df.tail())           # Last 5 rows — check end of file
# print("Dataset info:", df.info())           # Non-null counts + memory usage
# print("Statistical summary:", df.describe())       # Statistical summary of numerical columns
# print("Feature names:", df.columns.tolist()) # Full list of feature names
# sbytes_col = df["sbytes"]
# print("sbytes column (Series):\n", sbytes_col)

# # Select multiple columns (returns a DataFrame)
# flow_basics = df[["proto", "sbytes", "dbytes", "dur", "rate", "label"]]
# print("Selected columns (DataFrame):", flow_basics)

# # Filter rows — only attack records
# attacks = df[df["label"] == 1]
# print("Attack records (label=1):", attacks)

# # Filter by attack category
# dos_flows = df[df["attack_cat"] == "DoS"]
# print("DoS attack records:", dos_flows)

# # Multiple conditions — combine with & (AND) or | (OR)
# suspicious = df[(df["sbytes"] > 10000) & (df["label"] == 1)]
# print("Suspicious records:", suspicious)

# # Check missing values per column
# print("Missing values per column:")
# print(df.isnull().sum())

# # Fill missing categorical values
# print("Missing values in 'service' before filling:", df["service"].isnull().sum())
# df["service"] = df["service"].fillna("unknown")
# print("Missing values in 'service' after filling:", df["service"].isnull().sum())

# # Fill missing numerical values with column median
# print("Missing values in 'dur' before filling:", df["dur"].isnull().sum())
# df["dur"] = df["dur"].fillna(df["dur"].median())
# print("Missing values in 'dur' after filling:", df["dur"].isnull().sum())
# # Remove duplicate rows

# df = df.drop_duplicates()
# print("Shape after removing duplicates:", df.shape)
# # Rename columns for clarity
# df = df.rename(columns={"dur": "duration", "sbytes": "src_bytes"})
# print("Renamed columns:", df.columns.tolist())

# # Drop columns not useful for ML
# df = df.drop(columns=["srcip", "dstip", "sport", "dsport"],errors="ignore")
# print("Shape after dropping columns:", df.shape)

# Mean bytes per attack category
print(df.groupby("attack_cat")["sbytes"].mean())

# Count records per protocol
print(df.groupby("proto")["label"].value_counts())

# Multiple aggregations at once
summary = df.groupby("attack_cat").agg(
    count=("label","count"),
    mean_bytes=("sbytes","mean"),
    max_dur=("dur","max")
)
print(summary)

