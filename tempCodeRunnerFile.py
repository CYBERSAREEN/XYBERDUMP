
# # Filter rows — only attack records
# attacks = df[df["label"] == 1]
# print("Attack records (label=1):", attacks)

# # Filter by attack category
# dos_flows = df[df["attack_cat"] == "DoS"]
# print("DoS attack records:", dos_flows)

# # Multiple conditions — combine with & (AND) or | (OR)
# suspicious = df[(df["sbytes"] > 10000) & (df["label"] == 1)]
# print("Suspicious records:", suspicious)

