#!/bin/bash

REPO_DIR="algorithms"  # Adjust the path to your repo
FAIL_LOG="failing_tests.txt"
FLAKY_LOG="flaky_tests.txt"
STABLE_TESTS="stable_tests.txt"

# Move into the repository
cd "$REPO_DIR" || exit 1

# Run the test suite 10 times and log results
echo "Running full test suite 10 times..."
declare -A test_results
for i in {1..10}; do
    echo "Iteration $i..."
    pytest --tb=short | tee tmp_results.log
    grep -E 'FAILED|ERROR' tmp_results.log | awk '{print $1}' >> all_failures.txt
done

# Identify failing and flaky tests
sort all_failures.txt | uniq -c | awk '$1 < 10 {print $2}' > "$FLAKY_LOG"
sort all_failures.txt | uniq -c | awk '$1 == 10 {print $2}' > "$FAIL_LOG"

