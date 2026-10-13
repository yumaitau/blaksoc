"""Fail closed unless this exact main commit has successful CI and security checks."""
import json
import os
import re
import sys
import time
import urllib.request

REPOSITORY = "yumaitau/blaksoc"
REQUIRED = {f".github/workflows/{name}.yml" for name in ("ci", "security", "codeql")}


def check_runs(runs, sha):
    latest = {}
    for run in runs:
        path = run.get("path")
        if (path not in REQUIRED or run.get("head_sha") != sha
                or run.get("event") != "push" or run.get("head_branch") != "main"
                or run.get("head_repository", {}).get("full_name") != REPOSITORY):
            continue
        if path not in latest or (run["id"], run.get("run_attempt", 1)) > (
                latest[path]["id"], latest[path].get("run_attempt", 1)):
            latest[path] = run
    for path, run in latest.items():
        if run["status"] == "completed" and run.get("conclusion") != "success":
            raise RuntimeError(f"{path} did not pass: {run.get('conclusion')}")
    return REQUIRED == latest.keys() and all(r["status"] == "completed" for r in latest.values())


def github(path):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{REPOSITORY}/{path}",
        headers={"Authorization": f"Bearer {os.environ['GH_TOKEN']}",
                 "Accept": "application/vnd.github+json", "User-Agent": "blaksoc-deploy"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def output(sha, deploy):
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as target:
        target.write(f"deploy={str(deploy).lower()}\nsha={sha}\ntag={sha[:12]}\n")


def main():
    sha = os.environ["RELEASE_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Expected a full commit SHA")
    for _ in range(120):
        if github("git/ref/heads/main")["object"]["sha"] != sha:
            print("Skipping a commit superseded on main.")
            output(sha, False)
            return
        runs = github(f"actions/runs?head_sha={sha}&event=push&per_page=100")["workflow_runs"]
        if check_runs(runs, sha):
            output(sha, True)
            print(f"CI, security and CodeQL passed for {sha}.")
            return
        print("Waiting for checks on this commit.", flush=True)
        time.sleep(10)
    raise TimeoutError("Required checks did not complete within 20 minutes")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Release gate failed: {error}", file=sys.stderr)
        sys.exit(1)
