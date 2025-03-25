import json
import os
from collections import Counter

# Get script directory
base_dir = os.path.dirname(os.path.abspath(__file__))

# Define the folder containing Bandit reports
bandit_reports_dir = os.path.join(base_dir, "results/manim")

# Dictionaries to track severity and confidence levels
severity_tracker = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
confidence_tracker = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
cwe_summary = Counter()
commit_analysis = {}

# Set to track globally unique CWE issues (across all commits)
unique_cwe_issues = set()

# Ensure the report directory exists
if not os.path.exists(bandit_reports_dir):
    print(f"Error: Cannot locate '{bandit_reports_dir}'.")
    exit(1)

# Process Bandit reports in order of commit history
for report_file in sorted(os.listdir(bandit_reports_dir)):
    if report_file.endswith(".json"):
        commit_id = report_file.replace("bandit_report_", "").replace(".json", "")

        # Read JSON file safely
        report_path = os.path.join(bandit_reports_dir, report_file)
        try:
            if os.stat(report_path).st_size == 0:
                print(f"Warning: Skipping empty file {report_file}")
                continue  # Skip empty files

            with open(report_path, "r") as file:
                report_data = json.load(file)

        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in {report_file}, skipping...")
            continue  # Skip corrupt files

        # Initialize commit-specific counters
        commit_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        commit_confidence = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        commit_cwe_count = Counter()
        unique_commit_issues = set()  # Track unique (file, line, CWE) per commit

        # Process security issues
        for issue in report_data.get("results", []):
            severity = issue["issue_severity"]
            confidence = issue["issue_confidence"]
            cwe_data = issue.get("issue_cwe", "Unknown CWE")

            # Extract CWE ID if it's a dictionary
            if isinstance(cwe_data, dict):
                cwe_data = cwe_data.get("id", "Unknown CWE")

            # Identify issue uniquely based on file, line, and CWE
            issue_identifier = (issue["filename"], issue["line_number"], cwe_data)

            # Count CWEs uniquely per commit
            if issue_identifier not in unique_commit_issues:
                unique_commit_issues.add(issue_identifier)
                commit_cwe_count[cwe_data] += 1

            # Track CWEs uniquely across all commits
            if issue_identifier not in unique_cwe_issues:
                unique_cwe_issues.add(issue_identifier)
                cwe_summary[cwe_data] += 1  # Count CWE globally only once

            # Update severity and confidence counts
            commit_severity[severity] += 1
            commit_confidence[confidence] += 1

        # Store commit-wise analysis
        commit_analysis[commit_id] = {
            "severity": commit_severity,
            "confidence": commit_confidence,
            "cwe_counts": dict(commit_cwe_count)
        }

# Define output file paths
commit_timeline_file = os.path.join(base_dir, "manim_commit_analysis.json")
global_cwe_file = os.path.join(base_dir, "manim_cwe_summary.json")

# Save per-commit analysis results
with open(commit_timeline_file, "w") as file:
    json.dump(commit_analysis, file, indent=4)

# Save the unique CWE occurrences across all commits
with open(global_cwe_file, "w") as file:
    json.dump(dict(cwe_summary), file, indent=4)

print(f"Commit analysis saved in '{commit_timeline_file}'.")
print(f"Global CWE summary saved in '{global_cwe_file}'.")
