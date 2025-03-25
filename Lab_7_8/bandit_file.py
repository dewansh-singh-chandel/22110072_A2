import os
import subprocess
import json
import sys

REPO_LIST_FILE = "repos.txt"
BASE_DIR = os.getcwd()


def run_command(cmd, cwd=None):
    """Run a shell command and return the output."""
    result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"Error running command {' '.join(cmd)}: {result.stderr}", file=sys.stderr)
    return result.stdout.strip()


def get_repo_name(repo_url, index):
    """Creates a unique numbered folder name."""
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    return f"repo{index}_{repo_name}"


def get_default_branch(repo_dir):
    """Detects the default branch name (main, master, etc.)."""
    branch = run_command(["git", "symbolic-ref", "refs/remotes/origin/HEAD"], cwd=repo_dir)
    if branch:
        return branch.split("/")[-1]  # Extract last part (branch name)
    return "main"  # Fallback

def get_commits(repo_dir):
    """Fetches the last 100 non-merge commits from the default branch."""
    branch = get_default_branch(repo_dir)
    print(f"Detected default branch: {branch}")  # Debugging output
    cmd = ['git', 'rev-list', '--no-merges', branch, '-n', '100']
    return run_command(cmd, cwd=repo_dir).splitlines()


def run_bandit(repo_dir, venv_python):
    """Runs Bandit on the cloned repo."""
    cmd = [venv_python, "-m", "bandit", "-r", ".", "-f", "json"]
    output = run_command(cmd, cwd=repo_dir)
    try:
        return json.loads(output) if output else None
    except json.JSONDecodeError:
        print(f"Error parsing Bandit output for {repo_dir}", file=sys.stderr)
        return None


def analyze_bandit_output(bandit_json):
    """Extracts confidence, severity, and CWE counts."""
    confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    cwes = set()

    for issue in bandit_json.get("results", []):
        confidence_counts[issue.get("issue_confidence", "").upper()] += 1
        severity_counts[issue.get("issue_severity", "").upper()] += 1
        if issue.get("cwe"):
            cwes.add(issue["cwe"])

    return confidence_counts, severity_counts, list(cwes)


def analyze_repo(repo_url, index):
    """Clones repo, sets up virtual environment, and runs Bandit analysis."""
    repo_folder = get_repo_name(repo_url, index)
    repo_dir = os.path.join(BASE_DIR, repo_folder)
    cloned_repo_dir = os.path.join(repo_dir, "cloned_repo")
    venv_dir = os.path.join(repo_dir, "myenv")

    if os.path.exists(repo_dir):
        print(f"Skipping {repo_folder}, folder already exists.")
        return

    # Step 1: Create main repo folder
    os.makedirs(repo_dir, exist_ok=True)

    # Step 2: Clone the repository into cloned_repo/
    print(f"Cloning {repo_url} into {repo_folder}...")
    run_command(["git", "clone", repo_url, cloned_repo_dir])

    # Step 3: Create virtual environment
    print(f"Setting up virtual environment for {repo_folder}...")
    run_command(["python", "-m", "venv", venv_dir])

    # Step 4: Install Bandit
    venv_python = os.path.join(venv_dir, "bin", "python")  # Windows: myenv\Scripts\python
    run_command([venv_python, "-m", "pip", "install", "--upgrade", "pip", "bandit"])

    # Step 5: Analyze commits
    commits = get_commits(cloned_repo_dir)
    if not commits:
        print(f"No commits found in {repo_folder}, skipping analysis.")
        return

    original_branch = run_command(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=cloned_repo_dir)

    analysis_results = {}
    for commit in commits:
        print(f"Checking commit {commit} in {repo_folder}...")

        # Checkout commit
        run_command(["git", "checkout", commit], cwd=cloned_repo_dir)

        # Run Bandit
        bandit_json = run_bandit(cloned_repo_dir, venv_python)
        if not bandit_json:
            continue

        # Analyze results
        conf_counts, sev_counts, cwe_list = analyze_bandit_output(bandit_json)

        analysis_results[commit] = {
            "confidence": conf_counts,
            "severity": sev_counts,
            "cwes": cwe_list
        }

    # Restore original branch
    run_command(["git", "checkout", original_branch], cwd=cloned_repo_dir)

    # Step 6: Save results
    results_file = os.path.join(repo_dir, "bandit_analysis.json")
    with open(results_file, "w") as f:
        json.dump(analysis_results, f, indent=4)

    print(f"Analysis for {repo_folder} complete. Results saved in {results_file}.")


def main():
    """Reads repositories from file and processes them."""
    if not os.path.exists(REPO_LIST_FILE):
        print(f"File {REPO_LIST_FILE} not found!", file=sys.stderr)
        return

    with open(REPO_LIST_FILE, "r") as file:
        repo_urls = [line.strip() for line in file.readlines() if line.strip()]

    for index, repo_url in enumerate(repo_urls, start=1):
        analyze_repo(repo_url, index)

    print("All repositories processed.")


if __name__ == "__main__":
    main()
