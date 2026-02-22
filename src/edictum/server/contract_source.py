"""SSE client for receiving contract bundle updates from edictum-server."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator

from edictum.server.client import EdictumServerClient

logger = logging.getLogger(__name__)


class ServerContractSource:
    """Receives contract bundle updates from edictum-server via SSE.

    Subscribes to /api/v1/stream and yields updated bundles.
    Implements auto-reconnect with exponential backoff.
    """

    def __init__(
        self,
        client: EdictumServerClient,
        *,
        reconnect_delay: float = 1.0,
        max_reconnect_delay: float = 60.0,
    ) -> None:
        self._client = client
        self._reconnect_delay = reconnect_delay
        self._max_reconnect_delay = max_reconnect_delay
        self._connected = False
        self._closed = False

    async def connect(self) -> None:
        """Mark the source as ready to receive events."""
        self._connected = True
        self._closed = False

    async def watch(self) -> AsyncIterator[dict]:
        """Yield contract bundles as they arrive via SSE.

        Auto-reconnects on disconnect with exponential backoff.
        """
        import httpx_sse

        delay = self._reconnect_delay

        while not self._closed:
            try:
                http_client = self._client._ensure_client()
                async with httpx_sse.aconnect_sse(
                    http_client,
                    "GET",
                    "/api/v1/stream",
                ) as event_source:
                    self._connected = True
                    delay = self._reconnect_delay

                    async for event in event_source.aiter_sse():
                        if self._closed:
                            return
                        if event.event == "contract_update":
                            try:
                                bundle = json.loads(event.data)
                                yield bundle
                            except json.JSONDecodeError:
                                logger.warning("Invalid JSON in SSE contract_update event")

            except Exception:
                if self._closed:
                    return
                logger.warning("SSE connection lost, reconnecting in %.1fs", delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._max_reconnect_delay)

    async def close(self) -> None:
        """Stop watching for updates."""
        self._closed = True
        self._connected = False
