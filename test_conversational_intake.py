"""
test_conversational_intake.py: Unit tests for conversational LLM intake and fast regex fallback.
"""

import pytest
import httpx
from main import parse_conversational_intent, _regex_intent_fallback, _heuristic_intent_fallback

@pytest.mark.asyncio
async def test_fast_regex_fallback():
    # 1. Create task
    res = await parse_conversational_intent("@Saarathi create Build JWT scope:src/auth/**,tests/auth/**", "soham")
    assert res["intent"] == "CREATE_TASK"
    assert "JWT" in res["task_title"]
    assert res["expected_scope"] == ["src/auth/**", "tests/auth/**"]

    # 2. Claim done with PR URL
    res = await parse_conversational_intent("@Saarathi done https://github.com/switch-org/switch-core/pull/10 for task task_123", "samarth")
    assert res["intent"] == "CLAIM_DONE"
    assert res["pr_url"] == "https://github.com/switch-org/switch-core/pull/10"
    assert res["task_id"] == "task_123"

    # 3. Block task
    res = await parse_conversational_intent("@Saarathi block task_123 reason:Waiting for review", "atharva")
    assert res["intent"] == "REPORT_BLOCKER"
    assert res["task_id"] == "task_123"
    assert "Waiting for review" in res["blocker_reason"]

    # 4. Unblock task
    res = await parse_conversational_intent("@Saarathi unblock task_123", "soham")
    assert res["intent"] == "CLEAR_BLOCKER"
    assert res["task_id"] == "task_123"

    # 5. Start task
    res = await parse_conversational_intent("@Saarathi start task_123", "parth")
    assert res["intent"] == "START_TASK"
    assert res["task_id"] == "task_123"


@pytest.mark.asyncio
async def test_conversational_intake_mocked_llm():
    # Simulate non-regex conversational message hitting LLM
    mock_llm_json = {
        "id": "chatcmpl-123",
        "choices": [
            {
                "message": {
                    "content": '{"intent": "CLAIM_DONE", "task_title": null, "owner": null, "expected_scope": null, "pr_url": "https://github.com/switch-org/switch-core/pull/99", "task_id": "task_abc", "blocker_reason": null}'
                }
            }
        ]
    }

    def mock_transport(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=mock_llm_json)

    transport = httpx.MockTransport(mock_transport)
    async with httpx.AsyncClient(transport=transport) as client:
        # Patch LLM_API_KEY for test
        import main
        orig_key = main.LLM_API_KEY
        main.LLM_API_KEY = "mock_key"
        try:
            res = await parse_conversational_intent(
                "@Saarathi hey team, I just opened PR https://github.com/switch-org/switch-core/pull/99 for task_abc, please verify!",
                "samarth",
                http_client=client,
            )
            assert res["intent"] == "CLAIM_DONE"
            assert res["pr_url"] == "https://github.com/switch-org/switch-core/pull/99"
            assert res["task_id"] == "task_abc"
        finally:
            main.LLM_API_KEY = orig_key


@pytest.mark.asyncio
async def test_claim_done_without_pr_url():
    # User claims done in natural language without providing any GitHub PR URL
    res = await parse_conversational_intent("@Saarathi done with the feature", "soham")
    assert res["intent"] == "CLAIM_DONE"
    assert res["pr_url"] is None

