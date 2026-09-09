#!/usr/bin/env python3
"""Wait for the full Release workflow gate for this exact tagged commit.

Publishers retain their existing workflow identity for trusted publishing.
Missing, failed, cancelled, or timed-out checks never authorize publication.
"""
import json
import os
import time
import urllib.request


def get(path):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{os.environ['GITHUB_REPOSITORY']}/{path}",
        headers={"Authorization": f"Bearer {os.environ['GH_TOKEN']}",
                 "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    sha = os.environ["GITHUB_SHA"]
    tag = os.environ["GITHUB_REF_NAME"]
    deadline = time.monotonic() + 45 * 60
    while time.monotonic() < deadline:
        runs = get(f"actions/workflows/release.yml/runs?event=push&head_sha={sha}&per_page=100")["workflow_runs"]
        matches = [run for run in runs if run["head_sha"] == sha and run["head_branch"] == tag]
        if matches:
            run = max(matches, key=lambda value: (value["run_number"], value["run_attempt"]))
            jobs = get(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100")["jobs"]
            gate = next((job for job in jobs if job["name"] == "Release gate"), None)
            if gate and gate["conclusion"] == "success":
                print(f"Full release gate passed for {tag} ({sha}).")
                return
            if (gate and gate["status"] == "completed") or run["status"] == "completed":
                raise SystemExit(f"Release gate did not pass: {run['html_url']}")
        print(f"Waiting for full release gate: {tag} ({sha})", flush=True)
        time.sleep(15)
    raise SystemExit("Timed out waiting for the full release gate")


if __name__ == "__main__":
    main()
