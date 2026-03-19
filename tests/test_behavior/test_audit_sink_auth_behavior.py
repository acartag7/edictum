"""Behavior tests for ServerAuditSink auth error handling.

Proves that non-retryable HTTP errors (401, 403) are raised
immediately instead of silently buffered for retry.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from edictum.audit import AuditAction, AuditEvent
from edictum.server.audit_sink import ServerAuditSink
from edictum.server.client import EdictumServerError


def _make_client_mock():
    client = MagicMock()
    client.agent_id = "test-agent"
    client.env = "production"
    client.bundle_name = "default"
    return client


def _make_event():
    return AuditEvent(
        tool_name="TestTool",
        call_id="call-1",
        action=AuditAction.CALL_ALLOWED,
    )


class TestAuthErrorNotBuffered:
    """4xx client errors (except 429) must be raised, not buffered."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_401_raises_immediately(self):
        """HTTP 401 is raised, not silently buffered for retry."""
        client = _make_client_mock()
        client.post = AsyncMock(side_effect=EdictumServerError(401, "Unauthorized"))
        sink = ServerAuditSink(client, batch_size=100)

        # Manually add event to buffer and flush — 401 must raise, not buffer
        sink._buffer.append(sink._map_event(_make_event()))
        with pytest.raises(EdictumServerError, match="401"):
            await sink.flush()
        # Buffer must NOT be restored (event is lost, not retried)
        assert len(sink._buffer) == 0

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_403_raises_immediately(self):
        """HTTP 403 is raised, not silently buffered for retry."""
        client = _make_client_mock()
        client.post = AsyncMock(side_effect=EdictumServerError(403, "Forbidden"))
        sink = ServerAuditSink(client, batch_size=100)

        sink._buffer.append(sink._map_event(_make_event()))
        with pytest.raises(EdictumServerError, match="403"):
            await sink.flush()

    @pytest.mark.asyncio
    async def test_429_is_buffered_for_retry(self):
        """HTTP 429 (rate limit) should be buffered for retry, not raised."""
        client = _make_client_mock()
        client.post = AsyncMock(side_effect=EdictumServerError(429, "Too Many Requests"))
        sink = ServerAuditSink(client, batch_size=100)

        event_payload = sink._map_event(_make_event())
        sink._buffer.append(event_payload)
        # Should not raise — events buffered for retry
        await sink.flush()
        assert len(sink._buffer) == 1  # Event restored to buffer

    @pytest.mark.asyncio
    async def test_500_is_buffered_for_retry(self):
        """HTTP 500 should be buffered for retry."""
        client = _make_client_mock()
        client.post = AsyncMock(side_effect=EdictumServerError(500, "Internal Server Error"))
        sink = ServerAuditSink(client, batch_size=100)

        event_payload = sink._map_event(_make_event())
        sink._buffer.append(event_payload)
        await sink.flush()
        assert len(sink._buffer) == 1  # Event restored to buffer

    @pytest.mark.asyncio
    async def test_network_error_is_buffered_for_retry(self):
        """Network errors should be buffered for retry."""
        client = _make_client_mock()
        client.post = AsyncMock(side_effect=ConnectionError("Network unreachable"))
        sink = ServerAuditSink(client, batch_size=100)

        event_payload = sink._map_event(_make_event())
        sink._buffer.append(event_payload)
        await sink.flush()
        assert len(sink._buffer) == 1
