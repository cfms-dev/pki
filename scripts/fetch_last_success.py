#!/usr/bin/env python3
"""Fetch the start timestamp of the last successful CRL workflow run from GitHub Actions API."""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime


def fetch_last_successful_run(
    repo: str | None = None,
    workflow_name: str = "crl-pages.yml",
    token: str | None = None,
    branch: str = "main",
) -> datetime | None:
    """Fetch the start time (run_started_at) of the last successful workflow run from GitHub API."""
    target_repo = repo or os.environ.get("GITHUB_REPOSITORY")
    if not target_repo:
        print(
            "Notice: GITHUB_REPOSITORY not set. Cannot query GitHub API for last successful run.",
            file=sys.stderr,
        )
        return None

    auth_token = token or os.environ.get("GITHUB_TOKEN")
    url = (
        f"https://api.github.com/repos/{target_repo}/actions/workflows/{workflow_name}/runs"
        f"?status=success&branch={branch}&per_page=1"
    )

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "cfms-pki-ci",
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        print(
            f"Warning: GitHub API returned HTTP {exc.code} while fetching workflow runs: {exc.reason}",
            file=sys.stderr,
        )
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(
            f"Warning: Network error querying GitHub API for workflow runs: {exc}",
            file=sys.stderr,
        )
        return None
    except json.JSONDecodeError as exc:
        print(
            f"Warning: Failed to decode GitHub API JSON response: {exc}",
            file=sys.stderr,
        )
        return None

    runs = data.get("workflow_runs", [])
    if not runs:
        print(
            f"Notice: No successful previous workflow runs found for '{workflow_name}' on {branch}.",
            file=sys.stderr,
        )
        return None

    last_run = runs[0]
    started_at_str = last_run.get("run_started_at") or last_run.get("created_at")
    if not started_at_str:
        return None

    try:
        return datetime.fromisoformat(started_at_str).astimezone(UTC)
    except ValueError as exc:
        print(
            f"Warning: Failed to parse workflow run start timestamp '{started_at_str}': {exc}",
            file=sys.stderr,
        )
        return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch start timestamp of last successful CRL issuing workflow run."
    )
    parser.add_argument(
        "--repo",
        type=str,
        default=None,
        help="GitHub repository in 'owner/repo' format (defaults to GITHUB_REPOSITORY env var)",
    )
    parser.add_argument(
        "--workflow",
        type=str,
        default="crl-pages.yml",
        help="workflow file name (defaults to crl-pages.yml)",
    )
    parser.add_argument(
        "--branch",
        type=str,
        default="main",
        help="target branch (defaults to main)",
    )
    parser.add_argument(
        "--token",
        type=str,
        default=None,
        help="GitHub personal access token or actions token (defaults to GITHUB_TOKEN env var)",
    )
    parser.add_argument(
        "--github-output",
        action="store_true",
        help="explicitly write 'timestamp=<val>' to $GITHUB_OUTPUT file if env var is set",
    )
    args = parser.parse_args()

    last_run = fetch_last_successful_run(
        repo=args.repo,
        workflow_name=args.workflow,
        token=args.token,
        branch=args.branch,
    )

    iso_str = last_run.isoformat() if last_run else ""

    if iso_str:
        print(iso_str)

    github_output_path = os.environ.get("GITHUB_OUTPUT")
    if github_output_path:
        with open(github_output_path, "a", encoding="utf-8") as f:
            f.write(f"timestamp={iso_str}\n")


if __name__ == "__main__":
    main()
