"""SplunkHECSink — emit audit events to Splunk HTTP Event Collector."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from callguard.audit import AuditEvent, RedactionPolicy
from callguard.sinks._base import HTTPSinkBase


class SplunkHECSink(HTTPSinkBase):
    """Emit audit events to Splunk via HTTP Event Collector (HEC).

    Events are wrapped in the HEC format with configurable index and sourcetype.
    Authentication uses the ``Authorization: Splunk <token>`` header.
    """

    def __init__(
        self,
        url: str,
        token: str,
        index: str = "main",
        sourcetype: str = "callguard",
        redaction_policy: RedactionPolicy | None = None,
        max_retries: int = 3,
        base_delay: float = 1.0,
    ) -> None:
        super().__init__(max_retries=max_retries, base_delay=base_delay)
        self._url = url
        self._token = token
        self._index = index
        self._sourcetype = sourcetype
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

    def _wrap_hec(self, event_data: dict[str, Any]) -> dict[str, Any]:
        """Wrap event data in Splunk HEC envelope."""
        return {
            "event": event_data,
            "sourcetype": self._sourcetype,
            "index": self._index,
        }

    async def emit(self, event: AuditEvent) -> None:
        """Emit an audit event to Splunk HEC."""
        event_data = self._serialize_event(event)
        payload = self._wrap_hec(event_data)
        body = json.dumps(payload, default=str)

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Splunk {self._token}",
        }

        await self._send_with_retry(self._url, body, headers)
