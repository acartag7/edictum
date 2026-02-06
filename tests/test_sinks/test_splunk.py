"""Tests for SplunkHECSink."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from callguard.audit import AuditAction, AuditEvent, RedactionPolicy
from callguard.sinks.splunk import SplunkHECSink


@pytest.fixture
def event():
    return AuditEvent(
        action=AuditAction.CALL_ALLOWED,
        tool_name="Read",
        tool_args={"file_path": "/tmp/test.txt"},
        policy_version="sha256:abc123",
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


class TestSplunkHECSink:
    async def test_emit_hec_format(self, event):
        sink = SplunkHECSink(
            url="https://splunk.example.com:8088/services/collector",
            token="my-hec-token",
        )
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        assert len(fake_session.calls) == 1
        body = json.loads(fake_session.calls[0]["data"])
        assert "event" in body
        assert body["sourcetype"] == "callguard"
        assert body["index"] == "main"
        assert body["event"]["tool_name"] == "Read"
        assert body["event"]["action"] == "call_allowed"
        assert body["event"]["policy_version"] == "sha256:abc123"

    async def test_token_auth_header(self, event):
        sink = SplunkHECSink(
            url="https://splunk.example.com:8088/services/collector",
            token="my-hec-token",
        )
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        headers = fake_session.calls[0]["headers"]
        assert headers["Authorization"] == "Splunk my-hec-token"
        assert headers["Content-Type"] == "application/json"

    async def test_custom_index_and_sourcetype(self, event):
        sink = SplunkHECSink(
            url="https://splunk.example.com:8088/services/collector",
            token="my-hec-token",
            index="security",
            sourcetype="callguard:audit",
        )
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        body = json.loads(fake_session.calls[0]["data"])
        assert body["index"] == "security"
        assert body["sourcetype"] == "callguard:audit"

    async def test_redaction_policy_applied(self):
        redaction = RedactionPolicy()
        sink = SplunkHECSink(
            url="https://splunk.example.com:8088/services/collector",
            token="my-hec-token",
            redaction_policy=redaction,
        )
        event = AuditEvent(
            action=AuditAction.CALL_ALLOWED,
            tool_name="Read",
            tool_args={"api_key": "sk-supersecret1234567890abcdef"},
        )
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        body = json.loads(fake_session.calls[0]["data"])
        assert body["event"]["tool_args"]["api_key"] == "[REDACTED]"

    async def test_http_error_does_not_raise(self, event):
        sink = SplunkHECSink(
            url="https://splunk.example.com:8088/services/collector",
            token="my-hec-token",
            max_retries=3,
            base_delay=0.01,
        )
        fake_session = _FakeSession(_FakeResponse(500))

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            # Should not raise — retries then logs error
            await sink.emit(event)

        assert len(fake_session.calls) == 3
