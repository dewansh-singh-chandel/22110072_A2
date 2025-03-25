import json
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Load commit-based security data
with open("stable-diffusion-webui_commit_analysis.json", "r") as commit_file:
    commit_info = json.load(commit_file)

# Load CWE frequency data
with open("stable-diffusion-webui_cwe_summary.json", "r") as cwe_file:
    cwe_distribution = json.load(cwe_file)

# Sort commits by index number
sorted_commit_entries = sorted(commit_info.items(), key=lambda entry: int(entry[0].split("_")[1]))

# Define commit index range (1 to 100 for consistency)
commit_indices = list(range(1, 101))

# Utility function to ensure lists have exactly 100 values
def extend_list(data, target_length=100):
    if len(data) < target_length:
        data += [data[-1]] * (target_length - len(data))  # Repeat last value
    return data[:target_length]  # Trim excess if needed

# Extract severity counts per commit
low_sev = extend_list([entry[1]["severity"]["LOW"] for entry in sorted_commit_entries])
medium_sev = extend_list([entry[1]["severity"]["MEDIUM"] for entry in sorted_commit_entries])
high_sev = extend_list([entry[1]["severity"]["HIGH"] for entry in sorted_commit_entries])

# Extract confidence levels per commit
low_conf = extend_list([entry[1]["confidence"]["LOW"] for entry in sorted_commit_entries])
medium_conf = extend_list([entry[1]["confidence"]["MEDIUM"] for entry in sorted_commit_entries])
high_conf = extend_list([entry[1]["confidence"]["HIGH"] for entry in sorted_commit_entries])

# Sort CWE data by frequency (descending)
sorted_cwe_entries = sorted(cwe_distribution.items(), key=lambda item: item[1], reverse=True)
cwe_labels, cwe_counts = zip(*sorted_cwe_entries)

# Apply Seaborn theme
sns.set_style("whitegrid")

#  CHART 1: HIGH SEVERITY OVER TIME 
plt.figure(figsize=(12, 6))
sns.lineplot(x=commit_indices, y=high_sev, label="High Severity", color="red")
plt.xlabel("Commit Index", fontsize=12)
plt.ylabel("High Severity Count", fontsize=12)
plt.title("Trend of High Severity Issues Across Commits", fontsize=14)
plt.legend()
plt.show()

# CHART 2: SEVERITY LEVELS OVER TIME 
plt.figure(figsize=(12, 6))
sns.lineplot(x=commit_indices, y=low_sev, label="Low", color="blue")
sns.lineplot(x=commit_indices, y=medium_sev, label="Medium", color="orange")
sns.lineplot(x=commit_indices, y=high_sev, label="High", color="red")
plt.xlabel("Commit Index", fontsize=12)
plt.ylabel("Severity Count", fontsize=12)
plt.title("Severity Levels Over Commits", fontsize=14)
plt.legend(title="Severity Level")
plt.show()

# CHART 3: CONFIDENCE LEVELS OVER TIME 
plt.figure(figsize=(12, 6))
sns.lineplot(x=commit_indices, y=low_conf, label="Low Confidence", color="blue")
sns.lineplot(x=commit_indices, y=medium_conf, label="Medium Confidence", color="orange")
sns.lineplot(x=commit_indices, y=high_conf, label="High Confidence", color="red")
plt.xlabel("Commit Index", fontsize=12)
plt.ylabel("Confidence Count", fontsize=12)
plt.title("Confidence Levels Over Commits", fontsize=14)
plt.legend()
plt.show()

#CHART 4: CWE OCCURRENCE FREQUENCY 
plt.figure(figsize=(12, 6))
sns.barplot(x=np.arange(len(cwe_labels)), y=cwe_counts, palette="Blues_r")
plt.xticks(ticks=np.arange(len(cwe_labels)), labels=cwe_labels, rotation=45, ha="right")
plt.xlabel("CWE Identifiers", fontsize=12)
plt.ylabel("Occurrence Count", fontsize=12)
plt.title("Most Frequent CWE Issues in the Repository", fontsize=14)
plt.show()
