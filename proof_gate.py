"""
proof_gate.py: Read-only GitHub REST API client, POSIX glob path matcher,
CI check-run inspector, and TOCTOU freshness guard for Saarathi Zero-Trust Auditor.
Strictly adheres to LLD 2 & LLD 3.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger("saarathi.proof_gate")

GITHUB_API_BASE = os.getenv("GITHUB_API_BASE", "https://api.github.com")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")


class CheckRun(BaseModel):
    id: int
    name: str
    head_sha: str
    status: str  # queued, in_progress, completed
    conclusion: Optional[str] = None  # success, failure, neutral, cancelled, timed_out, action_required
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    app_id: Optional[int] = None
    app_slug: Optional[str] = None
    check_suite_id: Optional[int] = None
    check_suite_created_at: Optional[str] = None
    run_attempt: Optional[int] = None
    run_started_at: Optional[str] = None
    html_url: Optional[str] = None


class ChangedFile(BaseModel):
    filename: str
    status: str  # added, removed, modified, renamed
    previous_filename: Optional[str] = None
    additions: int = 0
    deletions: int = 0
    changes: int = 0


class VerificationInput(BaseModel):
    task_id: str
    pr_url: str
    expected_paths: List[str]
    allowed_authors: List[str]  # Github logins (owner + delegates)
    policy_id: str
    policy_revision: int
    policy_hash: str
    repo_full_name: str
    required_checks: List[Dict[str, Any]]  # [{"name": "...", "app_id": Optional[int]}]


class VerifiedSnapshot(BaseModel):
    attempt_id: str
    task_id: str
    task_version: int
    repo_full_name: str
    pr_number: int
    author_login: str
    head_sha: str
    policy_id: str
    policy_revision: int
    policy_hash: str
    changed_paths: List[str]
    selected_checks: List[Dict[str, Any]]
    final_read_at: str
    verified_at: Optional[str] = None
    source_event_id: Optional[str] = None


class RetryableFailure(BaseModel):
    reason: str
    error_type: str = "GitHubTransient"  # ChecksPending, MissingCheck, SnapshotChanged, GitHubTransient, RateLimit
    retry_after_seconds: int = 30


class PermanentFailure(BaseModel):
    reason: str
    error_type: str = "PermanentProofFailure"  # InvalidRepo, UnauthorizedAuthor, ScopeMismatch, EmptyDiff, CheckFailed


VerificationResult = Union[VerifiedSnapshot, RetryableFailure, PermanentFailure]


def match_posix_glob(path_str: str, pattern: str) -> bool:
    """
    Match repo-relative POSIX glob case-sensitively according to LLD 2:
    - * and ? match within one path segment.
    - ** can cross directory boundaries.
    Uses pathlib.PurePosixPath.match with POSIX glob wildcard semantics.
    """
    clean_path = path_str.strip().lstrip("/")
    clean_pat = pattern.strip().lstrip("/")
    p = PurePosixPath(clean_path)

    # 1. Check native PurePosixPath match
    if p.match(clean_pat):
        return True

    # 2. When pattern includes '**' crossing directories (Python 3.11 compatibility)
    if "**" in clean_pat:
        tokens = re.split(r"(\*\*|\*|\?)", clean_pat)
        res = []
        for t in tokens:
            if t == "**":
                res.append(".*")
            elif t == "*":
                res.append("[^/]*")
            elif t == "?":
                res.append("[^/]")
            else:
                res.append(re.escape(t))
        regex_str = "^" + "".join(res) + "$"
        if re.match(regex_str, clean_path):
            return True

    return False


def parse_pr_url(pr_url: str) -> Tuple[str, int]:
    """
    Parse canonical GitHub PR URL:
    https://github.com/{owner}/{repo}/pull/{pr_number}
    Returns (repo_full_name, pr_number).
    """
    parsed = urlparse(pr_url.strip())
    if parsed.netloc not in ("github.com", "www.github.com"):
        raise ValueError(f"Invalid GitHub PR URL host: {parsed.netloc}")

    match = re.match(r"^/([^/]+/[^/]+)/pull/(\d+)", parsed.path)
    if not match:
        raise ValueError(f"URL format must be https://github.com/owner/repo/pull/123, got {pr_url}")

    repo_full_name = match.group(1).lower()
    pr_number = int(match.group(2))
    return repo_full_name, pr_number


class GitHubVerifier:
    def __init__(
        self,
        token: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
        api_base: str = GITHUB_API_BASE,
    ):
        self.token = token or GITHUB_TOKEN
        self.api_base = api_base.rstrip("/")
        self._external_client = client

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Saarathi-ZeroTrust-Auditor/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def verify(
        self,
        attempt_id: str,
        task_version: int,
        v_input: VerificationInput,
        client: Optional[httpx.AsyncClient] = None,
    ) -> VerificationResult:
        """
        Execute read-only verification against GitHub according to LLD 2 & LLD 3 contracts:
        1. Validate PR URL repo matches policy allowlisted repo.
        2. Fetch PR details (author, head SHA, state).
        3. Validate PR author in allowed_authors (task owner or delegate).
        4. Fetch changed files: check non-empty diff and POSIX globs for every file.
        5. Fetch check-runs for head SHA: select newest execution by stable sort order.
        6. Verify all required checks are completed with conclusion=success.
        7. TOCTOU Re-read: Re-fetch PR head and check-runs, compare fingerprint.
        8. Return VerifiedSnapshot with final_read_at timestamp.
        """
        http = client or self._external_client or httpx.AsyncClient(timeout=15.0)
        own_client = (client is None and self._external_client is None)

        try:
            # 1. URL and Repo Validation
            try:
                repo_full_name, pr_number = parse_pr_url(v_input.pr_url)
            except ValueError as e:
                return PermanentFailure(reason=str(e), error_type="InvalidRepo")

            if repo_full_name != v_input.repo_full_name.lower():
                return PermanentFailure(
                    reason=f"PR repository '{repo_full_name}' does not match policy repo '{v_input.repo_full_name}'",
                    error_type="InvalidRepo",
                )

            # 2. Fetch PR metadata
            pr_url = f"{self.api_base}/repos/{repo_full_name}/pulls/{pr_number}"
            resp = await http.get(pr_url, headers=self._get_headers())
            if resp.status_code == 404:
                return PermanentFailure(
                    reason=f"PR #{pr_number} not found in repository '{repo_full_name}'",
                    error_type="PermanentProofFailure",
                )
            if resp.status_code in (401, 403):
                return RetryableFailure(
                    reason=f"GitHub access denied or rate limited ({resp.status_code}): {resp.text}",
                    error_type="RateLimit" if resp.status_code == 403 else "GitHubTransient",
                )
            if resp.status_code >= 500:
                return RetryableFailure(
                    reason=f"GitHub API server error ({resp.status_code})",
                    error_type="GitHubTransient",
                )
            if resp.status_code != 200:
                return RetryableFailure(
                    reason=f"GitHub API unexpected status {resp.status_code}",
                    error_type="GitHubTransient",
                )

            pr_data = resp.json()
            author_login = pr_data.get("user", {}).get("login", "")
            head_sha = pr_data.get("head", {}).get("sha", "")

            # 3. Check PR Author against Task Owner and Delegates
            allowed_logins = [a.lower() for a in v_input.allowed_authors if a]
            if author_login.lower() not in allowed_logins:
                return PermanentFailure(
                    reason=(
                        f"PR author '{author_login}' does not match task owner or delegates "
                        f"(allowed: {', '.join(allowed_logins) if allowed_logins else 'none'})"
                    ),
                    error_type="UnauthorizedAuthor",
                )

            # 4. Fetch changed files & validate scope
            files_url = f"{self.api_base}/repos/{repo_full_name}/pulls/{pr_number}/files?per_page=100"
            f_resp = await http.get(files_url, headers=self._get_headers())
            if f_resp.status_code != 200:
                return RetryableFailure(
                    reason=f"Failed to fetch PR changed files ({f_resp.status_code})",
                    error_type="GitHubTransient",
                )

            changed_files_data = f_resp.json()
            if not changed_files_data or len(changed_files_data) == 0:
                return PermanentFailure(reason="PR has an empty diff (0 changed files)", error_type="EmptyDiff")

            changed_paths: List[str] = []
            for f in changed_files_data:
                fname = f.get("filename", "")
                status = f.get("status", "")
                prev_fname = f.get("previous_filename")

                changed_paths.append(fname)
                if prev_fname:
                    changed_paths.append(prev_fname)

                # Scope check: every changed path must match an expected glob
                # Rename checks BOTH filename and previous_filename
                paths_to_check = [fname]
                if status == "renamed" and prev_fname:
                    paths_to_check.append(prev_fname)

                for p_check in paths_to_check:
                    matched = any(
                        match_posix_glob(p_check, pattern)
                        for pattern in v_input.expected_paths
                    )
                    if not matched:
                        return PermanentFailure(
                            reason=(
                                f"Changed file '{p_check}' violates task expected scope. "
                                f"Allowed patterns: {v_input.expected_paths}"
                            ),
                            error_type="ScopeMismatch",
                        )

            # 5. Fetch Check Runs for head SHA
            runs_result = await self._fetch_and_select_checks(
                http, repo_full_name, head_sha, v_input.required_checks
            )
            if isinstance(runs_result, (RetryableFailure, PermanentFailure)):
                return runs_result

            selected_checks = runs_result

            # 6. TOCTOU Re-read: Re-fetch PR head & checks within 5s window
            second_read_time = datetime.now(timezone.utc).isoformat()
            recheck_resp = await http.get(pr_url, headers=self._get_headers())
            if recheck_resp.status_code != 200:
                return RetryableFailure(
                    reason="Failed to re-read PR metadata during TOCTOU verification",
                    error_type="GitHubTransient",
                )

            recheck_pr_data = recheck_resp.json()
            recheck_head_sha = recheck_pr_data.get("head", {}).get("sha", "")
            if recheck_head_sha != head_sha:
                return RetryableFailure(
                    reason=(
                        f"PR head SHA changed mid-validation from {head_sha[:7]} to {recheck_head_sha[:7]} (SnapshotChanged)"
                    ),
                    error_type="SnapshotChanged",
                )

            # Re-read check-runs and compare fingerprints
            recheck_runs_result = await self._fetch_and_select_checks(
                http, repo_full_name, head_sha, v_input.required_checks
            )
            if isinstance(recheck_runs_result, (RetryableFailure, PermanentFailure)):
                return recheck_runs_result

            recheck_selected_checks = recheck_runs_result
            fingerprint_1 = self._compute_checks_fingerprint(selected_checks)
            fingerprint_2 = self._compute_checks_fingerprint(recheck_selected_checks)

            if fingerprint_1 != fingerprint_2:
                return RetryableFailure(
                    reason="Check runs execution fingerprint changed during TOCTOU second read (SnapshotChanged)",
                    error_type="SnapshotChanged",
                )

            # Verification Passed! Return immutable snapshot
            return VerifiedSnapshot(
                attempt_id=attempt_id,
                task_id=v_input.task_id,
                task_version=task_version,
                repo_full_name=repo_full_name,
                pr_number=pr_number,
                author_login=author_login,
                head_sha=head_sha,
                policy_id=v_input.policy_id,
                policy_revision=v_input.policy_revision,
                policy_hash=v_input.policy_hash,
                changed_paths=sorted(list(set(changed_paths))),
                selected_checks=[(c.model_dump() if hasattr(c, "model_dump") else c.dict()) for c in recheck_selected_checks],
                final_read_at=second_read_time,
                verified_at=datetime.now(timezone.utc).isoformat(),
            )

        finally:
            if own_client:
                await http.aclose()

    async def _fetch_and_select_checks(
        self,
        http: httpx.AsyncClient,
        repo_full_name: str,
        head_sha: str,
        required_checks: List[Dict[str, Any]],
    ) -> Union[List[CheckRun], RetryableFailure, PermanentFailure]:
        """
        Fetch check runs and select newest run by stable sort order per LLD 2:
        - Actions: highest run_attempt, then run_started_at, then id
        - Other: check_suite_created_at, then started_at, then id
        Fail closed: missing/pending -> RetryableFailure; failure -> PermanentFailure.
        """
        url = f"{self.api_base}/repos/{repo_full_name}/commits/{head_sha}/check-runs?per_page=100"
        resp = await http.get(url, headers=self._get_headers())
        if resp.status_code != 200:
            return RetryableFailure(
                reason=f"Failed to fetch commit check-runs ({resp.status_code})",
                error_type="GitHubTransient",
            )

        data = resp.json()
        raw_runs = data.get("check_runs", [])
        all_runs: List[CheckRun] = []

        for r in raw_runs:
            app = r.get("app") or {}
            suite = r.get("check_suite") or {}
            all_runs.append(
                CheckRun(
                    id=r.get("id"),
                    name=r.get("name", ""),
                    head_sha=r.get("head_sha", ""),
                    status=r.get("status", ""),
                    conclusion=r.get("conclusion"),
                    started_at=r.get("started_at"),
                    completed_at=r.get("completed_at"),
                    app_id=app.get("id"),
                    app_slug=app.get("slug"),
                    check_suite_id=suite.get("id"),
                    check_suite_created_at=suite.get("created_at"),
                    run_attempt=r.get("run_attempt", 1),
                    run_started_at=r.get("run_started_at") or r.get("started_at"),
                    html_url=r.get("html_url"),
                )
            )

        selected: List[CheckRun] = []
        for req in required_checks:
            req_name = req["name"]
            req_app_id = req.get("app_id")

            # Filter matching runs
            candidates = [
                c for c in all_runs
                if c.name == req_name and (req_app_id is None or c.app_id == req_app_id)
            ]

            if not candidates:
                return RetryableFailure(
                    reason=f"Required check '{req_name}' has not run on commit {head_sha[:7]}",
                    error_type="MissingCheck",
                )

            # Sort by stable priority according to LLD 2
            def check_sort_key(c: CheckRun):
                is_actions = (c.app_slug == "github-actions" or c.run_attempt is not None)
                if is_actions:
                    return (
                        c.run_attempt or 1,
                        c.run_started_at or c.started_at or "",
                        c.id,
                    )
                else:
                    return (
                        c.check_suite_created_at or "",
                        c.started_at or "",
                        c.id,
                    )

            candidates.sort(key=check_sort_key, reverse=True)
            newest = candidates[0]

            # Enforce pass rules
            if newest.head_sha != head_sha:
                return RetryableFailure(
                    reason=f"Check '{req_name}' SHA mismatch (expected {head_sha[:7]}, got {newest.head_sha[:7]})",
                    error_type="SnapshotChanged",
                )

            if newest.status != "completed":
                return RetryableFailure(
                    reason=f"Required check '{req_name}' is currently '{newest.status}' (pending/running)",
                    error_type="ChecksPending",
                )

            if newest.conclusion != "success":
                return PermanentFailure(
                    reason=f"Required check '{req_name}' concluded with '{newest.conclusion}' (expected success)",
                    error_type="CheckFailed",
                )

            selected.append(newest)

        return selected

    @staticmethod
    def _compute_checks_fingerprint(checks: List[CheckRun]) -> List[Tuple]:
        """Compute stable fingerprint for TOCTOU check-run comparison."""
        return sorted([
            (
                c.name,
                c.app_id,
                c.head_sha,
                c.id,
                c.check_suite_id,
                c.status,
                c.conclusion,
                c.started_at,
                c.completed_at,
                c.run_attempt,
                c.run_started_at,
            )
            for c in checks
        ])
