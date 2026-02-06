"""WebhookAuditSink — emit audit events via HTTP POST."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from typing import Any

import aiohttp

from callguard.audit import AuditEvent, RedactionPolicy

logger = logging.getLogger(__name__)

_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BASE_DELAY = 1.0


class WebhookAuditSink:
    """Emit audit events as JSON via HTTP POST with retry logic.

    Supports exponential backoff (1s, 2s, 4s) with up to 3 retries,
    optional RedactionPolicy, and fire-and-forget mode.
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        fire_and_forget: bool = False,
        redaction_policy: RedactionPolicy | None = None,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        base_delay: float = _DEFAULT_BASE_DELAY,
    ) -> None:
        self._url = url
        self._headers = {"Content-Type": "application/json", **(headers or {})}
        self._fire_and_forget = fire_and_forget
        self._redaction = redaction_policy
        self._max_retries = max_retries
        self._base_delay = base_delay

    def _serialize_event(self, event: AuditEvent) -> dict[str, Any]:
        """Convert an AuditEvent to a JSON-serializable dict."""
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        data["action"] = event.action.value
        if self._redaction:
            data["tool_args"] = self._redaction.redact_args(data.get("tool_args", {}))
            data = self._redaction.cap_payload(data)
        return data

    async def _send_with_retry(self, payload: dict[str, Any]) -> None:
        """POST payload with exponential backoff retry."""
        body = json.dumps(payload, default=str)
        last_error: Exception | None = None

        for attempt in range(self._max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self._url,
                        data=body,
                        headers=self._headers,
                    ) as resp:
                        resp.raise_for_status()
                        return
            except Exception as exc:
                last_error = exc
                if attempt < self._max_retries - 1:
                    delay = self._base_delay * (2**attempt)
                    logger.warning(
                        "Webhook POST to %s failed (attempt %d/%d): %s. Retrying in %.1fs.",
                        self._url,
                        attempt + 1,
                        self._max_retries,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)

        logger.error(
            "Webhook POST to %s failed after %d retries: %s",
            self._url,
            self._max_retries,
            last_error,
        )

    async def emit(self, event: AuditEvent) -> None:
        """Emit an audit event via HTTP POST."""
        payload = self._serialize_event(event)

        if self._fire_and_forget:
            asyncio.create_task(self._send_with_retry(payload))
        else:
            await self._send_with_retry(payload)
