"""DatadogSink — emit audit events to Datadog Logs API."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from typing import Any

import aiohttp

from callguard.audit import AuditEvent, RedactionPolicy

logger = logging.getLogger(__name__)


class DatadogSink:
    """Emit audit events to the Datadog Logs API.

    Events are posted to ``https://http-intake.logs.{site}/api/v2/logs``
    with the ``DD-API-KEY`` header for authentication.
    """

    def __init__(
        self,
        api_key: str,
        site: str = "datadoghq.com",
        service: str = "callguard",
        source: str = "callguard",
        redaction_policy: RedactionPolicy | None = None,
    ) -> None:
        self._api_key = api_key
        self._site = site
        self._service = service
        self._source = source
        self._redaction = redaction_policy
        self._url = f"https://http-intake.logs.{site}/api/v2/logs"

    def _serialize_event(self, event: AuditEvent) -> dict[str, Any]:
        """Convert an AuditEvent to a JSON-serializable dict."""
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        data["action"] = event.action.value
        if self._redaction:
            data["tool_args"] = self._redaction.redact_args(data.get("tool_args", {}))
            data = self._redaction.cap_payload(data)
        return data

    def _build_payload(self, event_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Build Datadog Logs API payload."""
        return [
            {
                "ddsource": self._source,
                "ddtags": f"service:{self._service}",
                "service": self._service,
                "message": event_data,
            }
        ]

    async def emit(self, event: AuditEvent) -> None:
        """Emit an audit event to the Datadog Logs API."""
        event_data = self._serialize_event(event)
        payload = self._build_payload(event_data)
        body = json.dumps(payload, default=str)

        headers = {
            "Content-Type": "application/json",
            "DD-API-KEY": self._api_key,
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
            logger.exception("Datadog POST to %s failed", self._url)
