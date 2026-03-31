"""SSE client for receiving rule bundle updates from edictum-server."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator

from edictum.server.client import _SAFE_IDENTIFIER_RE, EdictumServerClient, EdictumServerError

logger = logging.getLogger(__name__)

_STABLE_CONNECTION_SECS = 30.0


class ServerContractSource:
    """Receives ruleset updates from edictum-server via SSE.

    Subscribes to /v1/stream and yields updated rules.
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
        self._current_revision: str | None = None

    async def connect(self) -> None:
        """Mark the source as ready to receive events."""
        self._connected = True
        self._closed = False

    async def watch(self) -> AsyncIterator[dict]:
        """Yield rules as they arrive via SSE.

        Passes ``env``, ``bundle_name``, and ``policy_version`` as query
        params so the server can filter events and detect drift.
        Auto-reconnects on disconnect with exponential backoff.
        """
        import httpx
        import httpx_sse

        delay = self._reconnect_delay
        consecutive_failures = 0
        connected_at: float | None = None

        while not self._closed:
            try:
                http_client = self._client._ensure_client()
                params: dict[str, str] = {"env": self._client.env}
                if self._client.bundle_name:
                    params["bundle_name"] = self._client.bundle_name
                if self._current_revision:
                    params["policy_version"] = self._current_revision
                if self._client.tags:
                    params["tags"] = json.dumps(self._client.tags)

                async with httpx_sse.aconnect_sse(
                    http_client,
                    "GET",
                    "/v1/stream",
                    params=params,
                    # Separate connect timeout from stream idle timeout.
                    # The default client timeout (30s) applies to all phases —
                    # including read, which would kill SSE streams that are idle
                    # longer than 30s between events.
                    timeout=httpx.Timeout(connect=30.0, read=300.0, write=30.0, pool=30.0),
                ) as event_source:
                    self._connected = True
                    connected_at = time.monotonic()

                    async for event in event_source.aiter_sse():
                        if self._closed:
                            return
                        if event.event in {"contract_update", "ruleset_updated"}:
                            try:
                                bundle = json.loads(event.data)
                            except json.JSONDecodeError:
                                logger.warning("Invalid JSON in SSE %s event", event.event)
                                continue
                            if not isinstance(bundle, dict):
                                logger.warning("SSE %s payload is not an object", event.event)
                                continue
                            if event.event == "ruleset_updated":
                                ruleset_name = bundle.get("name")
                                if not isinstance(ruleset_name, str) or not _SAFE_IDENTIFIER_RE.match(ruleset_name):
                                    logger.warning("SSE ruleset_updated has invalid name: %r", ruleset_name)
                                    continue
                                current_name = self._client.bundle_name
                                if current_name is not None and ruleset_name != current_name:
                                    continue
                                try:
                                    bundle = await self._client.get(
                                        f"/v1/rulesets/{ruleset_name}/current",
                                        env=self._client.env,
                                    )
                                except (EdictumServerError, httpx.HTTPError, OSError) as exc:
                                    logger.warning("Failed to fetch ruleset %s after SSE update: %s", ruleset_name, exc)
                                    continue
                            revision = bundle.get("revision_hash")
                            if revision is None and "version" in bundle:
                                revision = str(bundle["version"])
                            if isinstance(revision, str):
                                self._current_revision = revision
                            yield bundle
                        elif event.event == "assignment_changed":
                            try:
                                data = json.loads(event.data)
                            except json.JSONDecodeError:
                                logger.warning("Invalid JSON in SSE assignment_changed event")
                                continue
                            if not isinstance(data, dict):
                                logger.warning("SSE assignment_changed payload is not an object")
                                continue
                            new_bundle = data.get("bundle_name")
                            if not isinstance(new_bundle, str) or not _SAFE_IDENTIFIER_RE.match(new_bundle):
                                logger.warning("SSE assignment_changed has invalid bundle_name: %r", new_bundle)
                                continue
                            if new_bundle != self._client.bundle_name:
                                logger.info(
                                    "Assignment changed: %s -> %s",
                                    self._client.bundle_name,
                                    new_bundle,
                                )
                                # Do NOT update self._client.bundle_name here.
                                # The watcher updates it after a successful reload.
                                # Updating early would cause deduplication to block
                                # retries if the fetch fails.
                                yield {"_assignment_changed": True, "bundle_name": new_bundle}

            except (httpx.TransportError, httpx.HTTPStatusError, OSError) as exc:
                if self._closed:
                    return

                self._connected = False

                if connected_at is not None:
                    elapsed = time.monotonic() - connected_at
                    if elapsed >= _STABLE_CONNECTION_SECS:
                        delay = self._reconnect_delay
                        consecutive_failures = 0
                    connected_at = None

                consecutive_failures += 1
                if consecutive_failures == 1:
                    logger.warning("SSE connection lost (%s), reconnecting in %.1fs", exc, delay)
                elif consecutive_failures <= 3:
                    logger.info(
                        "SSE reconnect attempt %d (%s), retrying in %.1fs",
                        consecutive_failures,
                        exc,
                        delay,
                    )
                else:
                    logger.debug(
                        "SSE reconnect attempt %d (%s), retrying in %.1fs",
                        consecutive_failures,
                        exc,
                        delay,
                    )

                await asyncio.sleep(delay)
                delay = min(delay * 2, self._max_reconnect_delay)
            else:
                # Stream ended cleanly — full reset so any subsequent
                # failure is treated as a new sequence.
                self._connected = False
                connected_at = None
                delay = self._reconnect_delay
                consecutive_failures = 0

    async def close(self) -> None:
        """Stop watching for updates."""
        self._closed = True
        self._connected = False
