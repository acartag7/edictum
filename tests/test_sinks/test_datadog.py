"""Tests for DatadogSink."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from callguard.audit import AuditAction, AuditEvent, RedactionPolicy
from callguard.sinks.datadog import DatadogSink


@pytest.fixture
def event():
    return AuditEvent(
        action=AuditAction.CALL_DENIED,
        tool_name="Bash",
        tool_args={"command": "rm -rf /"},
        policy_version="sha256:abc123",
        policy_error=True,
    )


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    def raise_for_status(self):
        if self.status >= 400:
            raise Exception(f"HTTP {self.status}")


class _FakeSession:
    closed = False

    def __init__(self, response: _FakeResponse | None = None):
        self._response = response or _FakeResponse(200)
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return _FakeContextManager(self._response)


class _FakeContextManager:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *args):
        pass


class TestDatadogSink:
    async def test_emit_datadog_format(self, event):
        sink = DatadogSink(api_key="dd-api-key-123")
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        assert len(fake_session.calls) == 1
        body = json.loads(fake_session.calls[0]["data"])
        assert isinstance(body, list)
        assert len(body) == 1
        entry = body[0]
        assert entry["ddsource"] == "callguard"
        assert entry["service"] == "callguard"
        assert entry["ddtags"] == "service:callguard"
        assert entry["message"]["tool_name"] == "Bash"
        assert entry["message"]["action"] == "call_denied"
        assert entry["message"]["policy_version"] == "sha256:abc123"
        assert entry["message"]["policy_error"] is True

    async def test_api_key_header(self, event):
        sink = DatadogSink(api_key="dd-api-key-123")
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        headers = fake_session.calls[0]["headers"]
        assert headers["DD-API-KEY"] == "dd-api-key-123"
        assert headers["Content-Type"] == "application/json"

    async def test_custom_site(self, event):
        sink = DatadogSink(api_key="dd-api-key-123", site="datadoghq.eu")
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        url = fake_session.calls[0]["url"]
        assert "datadoghq.eu" in url

    async def test_default_url(self):
        sink = DatadogSink(api_key="key")
        assert sink._url == "https://http-intake.logs.datadoghq.com/api/v2/logs"

    async def test_custom_service_and_source(self, event):
        sink = DatadogSink(
            api_key="dd-api-key-123",
            service="my-agent",
            source="my-source",
        )
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        body = json.loads(fake_session.calls[0]["data"])
        entry = body[0]
        assert entry["ddsource"] == "my-source"
        assert entry["service"] == "my-agent"
        assert entry["ddtags"] == "service:my-agent"

    async def test_redaction_policy_applied(self):
        redaction = RedactionPolicy()
        sink = DatadogSink(api_key="dd-api-key-123", redaction_policy=redaction)
        event = AuditEvent(
            action=AuditAction.CALL_ALLOWED,
            tool_name="Read",
            tool_args={"api_key": "sk-supersecret1234567890abcdef"},
        )
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        body = json.loads(fake_session.calls[0]["data"])
        assert body[0]["message"]["tool_args"]["api_key"] == "[REDACTED]"

    async def test_http_error_does_not_raise(self, event):
        sink = DatadogSink(
            api_key="dd-api-key-123",
            max_retries=3,
            base_delay=0.01,
        )
        fake_session = _FakeSession(_FakeResponse(500))

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            # Should not raise — retries then logs error
            await sink.emit(event)

        assert len(fake_session.calls) == 3
