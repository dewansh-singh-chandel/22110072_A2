#!/bin/bash

REPO_DIR="algorithms"  # Adjust the path to your repo
FAIL_LOG="failing_tests.txt"
FLAKY_LOG="flaky_tests.txt"
STABLE_TESTS="stable_tests.txt"

# Move into the repository
cd "$REPO_DIR" || exit 1

echo "Executing stable test suite 3 times..."
total_time=0
for i in {1..3}; do
    start_time=$(date +%s.%N)
    pytest $(cat "$STABLE_TESTS") --tb=short
    end_time=$(date +%s.%N)
    elapsed_time=$(echo "$end_time - $start_time" | bc)
    total_time=$(echo "$total_time + $elapsed_time" | bc)
done


# Compute average execution time
Tseq=$(echo "scale=2; $total_time / 3" | bc)
echo "Average execution time (Tseq): $Tseq seconds"