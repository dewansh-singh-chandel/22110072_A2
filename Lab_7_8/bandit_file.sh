#!/bin/bash

# Define CSV file containing repository names and URLs
CSV_FILE="repo_names.csv"

# Create a directory to store analysis results
RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"

# Read repository information from CSV (excluding the header)
tail -n +2 "$CSV_FILE" | while IFS=, read -r repo_name repo_url; do
    echo "Processing repository: $repo_name"

    # Clone the repository into a directory named after the repo
    git clone "$repo_url" "$repo_name"
    cd "$repo_name" || exit

    # Set up a virtual environment
    python3 -m venv venv
    source venv/bin/activate

    # Install dependencies if a requirements file is present
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    fi

    # Create a dedicated directory for storing Bandit results
    REPO_RESULTS_DIR="../$RESULTS_DIR/$repo_name"
    mkdir -p "$REPO_RESULTS_DIR"

    # Retrieve the last 100 non-merge commit hashes
    git log --pretty=format:"%H" --no-merges -n 100 > commit_list.txt

    # Counter to keep track of commits
    commit_num=1

    # Analyze each commit using Bandit
    while read -r commit_hash; do
        echo "Analyzing commit #$commit_num with Bandit"
        git checkout "$commit_hash"
        bandit -r . --format json --output "$REPO_RESULTS_DIR/bandit_report_commit_$commit_num.json"
        
        # Increment the commit counter
        ((commit_num++))
    done < commit_list.txt

    # Return to the parent directory after processing
    cd ..

    echo "Completed analysis for $repo_name"
done

echo "All repositories have been processed successfully!"

