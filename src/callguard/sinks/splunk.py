"""SplunkHECSink — emit audit events to Splunk HTTP Event Collector."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from typing import Any

import aiohttp

from callguard.audit import AuditEvent, RedactionPolicy

logger = logging.getLogger(__name__)


class SplunkHECSink:
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
    ) -> None:
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

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._url,
                    data=body,
                    headers=headers,
                ) as resp:
                    resp.raise_for_status()
        except Exception:
            logger.exception("Splunk HEC POST to %s failed", self._url)
