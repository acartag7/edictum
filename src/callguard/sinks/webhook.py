"""WebhookAuditSink — emit audit events via HTTP POST."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from typing import Any

from callguard.audit import AuditEvent, RedactionPolicy
from callguard.sinks._base import HTTPSinkBase


class WebhookAuditSink(HTTPSinkBase):
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
        max_retries: int = 3,
        base_delay: float = 1.0,
    ) -> None:
        super().__init__(max_retries=max_retries, base_delay=base_delay)
        self._url = url
        self._headers = {"Content-Type": "application/json", **(headers or {})}
        self._fire_and_forget = fire_and_forget
        self._redaction = redaction_policy

    def _serialize_event(self, event: AuditEvent) -> dict[str, Any]:
        """Convert an AuditEvent to a JSON-serializable dict."""
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        data["action"] = event.action.value
        if self._redaction:
            data["tool_args"] = self._redaction.redact_args(data.get("tool_args", {}))
            data = self._redaction.cap_payload(data)
        return data

    async def emit(self, event: AuditEvent) -> None:
        """Emit an audit event via HTTP POST."""
        payload = self._serialize_event(event)
        body = json.dumps(payload, default=str)

        if self._fire_and_forget:
            asyncio.create_task(self._send_with_retry(self._url, body, self._headers))
        else:
            await self._send_with_retry(self._url, body, self._headers)
