"""Slack delivery adapter for durable Saarathi outbox messages."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx
from pydantic import BaseModel, ConfigDict, Field


class SlackReplyTarget(BaseModel):
    """Validated Slack destination supplied by the Switch-to-Slack bridge."""

    model_config = ConfigDict(extra="forbid")

    channel_id: str = Field(pattern=r"^[CGD][A-Z0-9]+$", min_length=2, max_length=32)
    thread_ts: Optional[str] = Field(default=None, pattern=r"^\d{10}\.\d{6}$")


class SlackDeliveryError(RuntimeError):
    """Slack delivery failure with retry classification."""

    def __init__(self, message: str, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


class SlackAdapter:
    """Post messages to Slack without embedding Slack logic in task services."""

    def __init__(
        self,
        token: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
        api_base: Optional[str] = None,
    ) -> None:
        self.token = token if token is not None else os.getenv("SLACK_BOT_TOKEN", "")
        self.api_base = (api_base or os.getenv("SLACK_API_BASE", "https://slack.com/api")).rstrip("/")
        self._external_client = client

    async def post_message(
        self,
        target: SlackReplyTarget,
        text: str,
        idempotency_key: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        if not self.token:
            raise SlackDeliveryError("SLACK_BOT_TOKEN is not configured", retryable=False)

        http = client or self._external_client or httpx.AsyncClient(timeout=10.0)
        own_client = client is None and self._external_client is None
        payload: Dict[str, Any] = {
            "channel": target.channel_id,
            "text": text,
            "client_msg_id": idempotency_key,
        }
        if target.thread_ts:
            payload["thread_ts"] = target.thread_ts

        try:
            response = await http.post(
                f"{self.api_base}/chat.postMessage",
                json=payload,
                headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            )
            if response.status_code >= 500 or response.status_code == 429:
                raise SlackDeliveryError(f"Slack API temporary failure ({response.status_code})")
            if response.status_code != 200:
                raise SlackDeliveryError(
                    f"Slack API returned HTTP {response.status_code}", retryable=False
                )
            try:
                body = response.json()
            except ValueError as exc:
                raise SlackDeliveryError("Slack API returned invalid JSON") from exc
            if not body.get("ok"):
                error = body.get("error", "unknown_error")
                retryable = error in {"ratelimited", "internal_error", "service_unavailable", "timeout"}
                raise SlackDeliveryError(f"Slack API error: {error}", retryable=retryable)
            return body
        except httpx.TimeoutException as exc:
            raise SlackDeliveryError("Slack API request timed out") from exc
        except httpx.HTTPError as exc:
            raise SlackDeliveryError("Slack API request failed") from exc
        finally:
            if own_client:
                await http.aclose()
