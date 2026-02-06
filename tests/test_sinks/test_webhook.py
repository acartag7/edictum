"""Tests for WebhookAuditSink."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import pytest

from callguard.audit import AuditAction, AuditEvent, RedactionPolicy
from callguard.sinks.webhook import WebhookAuditSink


@pytest.fixture
def event():
    return AuditEvent(
        action=AuditAction.CALL_ALLOWED,
        tool_name="Read",
        tool_args={"file_path": "/tmp/test.txt"},
        policy_version="sha256:abc123",
    )


class _FakeResponse:
    """Fake aiohttp response for testing."""

    def __init__(self, status: int = 200):
        self.status = status

    def raise_for_status(self):
        if self.status >= 400:
            raise Exception(f"HTTP {self.status}")


class _FakeSession:
    """Fake aiohttp.ClientSession that records calls."""

    closed = False

    def __init__(self, responses: list[_FakeResponse] | None = None):
        self._responses = responses or [_FakeResponse(200)]
        self._call_index = 0
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        resp = self._responses[min(self._call_index, len(self._responses) - 1)]
        self._call_index += 1
        return _FakeContextManager(resp)


class _FakeContextManager:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *args):
        pass


class TestWebhookAuditSink:
    async def test_emit_posts_json(self, event):
        sink = WebhookAuditSink(url="https://hooks.example.com/audit")
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        assert len(fake_session.calls) == 1
        body = json.loads(fake_session.calls[0]["data"])
        assert body["tool_name"] == "Read"
        assert body["action"] == "call_allowed"
        assert body["policy_version"] == "sha256:abc123"

    async def test_emit_sends_custom_headers(self, event):
        sink = WebhookAuditSink(
            url="https://hooks.example.com/audit",
            headers={"X-Custom": "myvalue"},
        )
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        headers = fake_session.calls[0]["headers"]
        assert headers["X-Custom"] == "myvalue"
        assert headers["Content-Type"] == "application/json"

    async def test_retry_on_failure(self, event):
        sink = WebhookAuditSink(
            url="https://hooks.example.com/audit",
            max_retries=3,
            base_delay=0.01,
        )
        responses = [_FakeResponse(500), _FakeResponse(500), _FakeResponse(200)]
        fake_session = _FakeSession(responses)

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        assert len(fake_session.calls) == 3

    async def test_all_retries_exhausted(self, event):
        sink = WebhookAuditSink(
            url="https://hooks.example.com/audit",
            max_retries=3,
            base_delay=0.01,
        )
        responses = [_FakeResponse(500), _FakeResponse(500), _FakeResponse(500)]
        fake_session = _FakeSession(responses)

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            # Should not raise — just logs the error
            await sink.emit(event)

        assert len(fake_session.calls) == 3

    async def test_redaction_policy_applied(self):
        redaction = RedactionPolicy()
        sink = WebhookAuditSink(
            url="https://hooks.example.com/audit",
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
        assert body["tool_args"]["api_key"] == "[REDACTED]"

    async def test_fire_and_forget(self, event):
        sink = WebhookAuditSink(
            url="https://hooks.example.com/audit",
            fire_and_forget=True,
        )
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)
            # Give the background task time to complete
            await asyncio.sleep(0.1)

        assert len(fake_session.calls) == 1

    async def test_serialization_includes_policy_fields(self):
        sink = WebhookAuditSink(url="https://hooks.example.com/audit")
        event = AuditEvent(
            action=AuditAction.CALL_DENIED,
            tool_name="Bash",
            policy_version="sha256:xyz789",
            policy_error=True,
        )
        fake_session = _FakeSession()

        with patch("callguard.sinks._base.aiohttp.ClientSession", return_value=fake_session):
            await sink.emit(event)

        body = json.loads(fake_session.calls[0]["data"])
        assert body["policy_version"] == "sha256:xyz789"
        assert body["policy_error"] is True
