import pytest
import asyncio
import httpx
from proof_gate import (
    GitHubVerifier,
    VerificationInput,
    VerifiedSnapshot,
    RetryableFailure,
    PermanentFailure,
    match_posix_glob,
    parse_pr_url,
)

def test_url_parsing():
    repo, num = parse_pr_url("https://github.com/switch-org/switch-core/pull/42")
    assert repo == "switch-org/switch-core"
    assert num == 42

    with pytest.raises(ValueError):
        parse_pr_url("https://gitlab.com/org/repo/pull/1")

    with pytest.raises(ValueError):
        parse_pr_url("https://github.com/switch-org/switch-core/issues/42")

def test_posix_glob_matching():
    # Segment matching
    assert match_posix_glob("src/main.py", "src/*.py")
    assert not match_posix_glob("src/sub/main.py", "src/*.py")
    # Recursive matching
    assert match_posix_glob("src/sub/deep/main.py", "src/**")
    assert match_posix_glob("src/main.py", "src/**")
    assert match_posix_glob("tests/test_audit.py", "tests/**")
    assert not match_posix_glob("other/evil.sh", "src/**")
    assert not match_posix_glob("src_fake/evil.sh", "src/**")

@pytest.mark.asyncio
async def test_verifier_mocked_success():
    head_sha = "abc1234567890abcdef1234567890abcdef1234"
    
    # Mock transport
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/pulls/42/files" in url:
            return httpx.Response(200, json=[
                {"filename": "src/core.py", "status": "modified"},
                {"filename": "tests/test_core.py", "status": "added"}
            ])
        elif "/pulls/42" in url:
            return httpx.Response(200, json={
                "number": 42,
                "user": {"login": "alice"},
                "head": {"sha": head_sha}
            })
        elif "/check-runs" in url:
            return httpx.Response(200, json={
                "check_runs": [
                    {
                        "id": 101,
                        "name": "test",
                        "head_sha": head_sha,
                        "status": "completed",
                        "conclusion": "success",
                        "started_at": "2026-11-06T10:00:00Z",
                        "completed_at": "2026-11-06T10:05:00Z",
                        "app": {"id": 1, "slug": "github-actions"},
                        "run_attempt": 1
                    },
                    {
                        "id": 102,
                        "name": "lint",
                        "head_sha": head_sha,
                        "status": "completed",
                        "conclusion": "success",
                        "started_at": "2026-11-06T10:00:00Z",
                        "completed_at": "2026-11-06T10:02:00Z",
                        "app": {"id": 1, "slug": "github-actions"},
                        "run_attempt": 1
                    }
                ]
            })
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        verifier = GitHubVerifier(client=client)
        v_input = VerificationInput(
            task_id="task_1",
            pr_url="https://github.com/switch-org/switch-core/pull/42",
            expected_paths=["src/**", "tests/**"],
            allowed_authors=["alice"],
            policy_id="default_policy",
            policy_revision=1,
            policy_hash="dummy_hash",
            repo_full_name="switch-org/switch-core",
            required_checks=[{"name": "test"}, {"name": "lint"}]
        )

        result = await verifier.verify("att_1", 1, v_input)
        assert isinstance(result, VerifiedSnapshot)
        assert result.head_sha == head_sha
        assert result.author_login == "alice"
        assert len(result.selected_checks) == 2

@pytest.mark.asyncio
async def test_verifier_scope_violation():
    head_sha = "abc1234567890abcdef1234567890abcdef1234"
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/pulls/42/files" in url:
            return httpx.Response(200, json=[
                {"filename": "src/core.py", "status": "modified"},
                {"filename": "secret/creds.env", "status": "added"}
            ])
        elif "/pulls/42" in url:
            return httpx.Response(200, json={
                "number": 42,
                "user": {"login": "alice"},
                "head": {"sha": head_sha}
            })
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        verifier = GitHubVerifier(client=client)
        v_input = VerificationInput(
            task_id="task_1",
            pr_url="https://github.com/switch-org/switch-core/pull/42",
            expected_paths=["src/**"],
            allowed_authors=["alice"],
            policy_id="default_policy",
            policy_revision=1,
            policy_hash="dummy_hash",
            repo_full_name="switch-org/switch-core",
            required_checks=[]
        )
        result = await verifier.verify("att_1", 1, v_input)
        assert isinstance(result, PermanentFailure)
        assert result.error_type == "ScopeMismatch"

@pytest.mark.asyncio
async def test_verifier_author_mismatch():
    head_sha = "abc1234567890abcdef1234567890abcdef1234"
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "number": 42,
            "user": {"login": "mallory"},
            "head": {"sha": head_sha}
        })

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        verifier = GitHubVerifier(client=client)
        v_input = VerificationInput(
            task_id="task_1",
            pr_url="https://github.com/switch-org/switch-core/pull/42",
            expected_paths=["src/**"],
            allowed_authors=["alice"],
            policy_id="default_policy",
            policy_revision=1,
            policy_hash="dummy_hash",
            repo_full_name="switch-org/switch-core",
            required_checks=[]
        )
        result = await verifier.verify("att_1", 1, v_input)
        assert isinstance(result, PermanentFailure)
        assert result.error_type == "UnauthorizedAuthor"

@pytest.mark.asyncio
async def test_verifier_pending_check():
    head_sha = "abc1234567890abcdef1234567890abcdef1234"
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/pulls/42/files" in url:
            return httpx.Response(200, json=[{"filename": "src/core.py", "status": "modified"}])
        elif "/pulls/42" in url:
            return httpx.Response(200, json={"number": 42, "user": {"login": "alice"}, "head": {"sha": head_sha}})
        elif "/check-runs" in url:
            return httpx.Response(200, json={"check_runs": [
                {"id": 1, "name": "test", "head_sha": head_sha, "status": "in_progress", "conclusion": None, "started_at": "2026-11-06T10:00:00Z"}
            ]})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        verifier = GitHubVerifier(client=client)
        v_input = VerificationInput(
            task_id="task_1",
            pr_url="https://github.com/switch-org/switch-core/pull/42",
            expected_paths=["src/**"],
            allowed_authors=["alice"],
            policy_id="default_policy",
            policy_revision=1,
            policy_hash="dummy_hash",
            repo_full_name="switch-org/switch-core",
            required_checks=[{"name": "test"}]
        )
        result = await verifier.verify("att_1", 1, v_input)
        assert isinstance(result, RetryableFailure)
        assert result.error_type == "ChecksPending"

