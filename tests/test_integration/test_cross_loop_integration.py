"""Real-HTTP integration tests for cross-event-loop fix.

These reproduce the actual RuntimeError that occurs when httpx.AsyncClient
is shared across threads with different event loops. Requires a real HTTP
server with keep-alive (uvicorn) — MockTransport does NOT reproduce the bug.

Run with: pytest tests/test_integration/test_cross_loop_integration.py -v --run-integration
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from edictum.server.client import EdictumServerClient

# ---------------------------------------------------------------------------
# Test server fixture
# ---------------------------------------------------------------------------

try:
    import uvicorn
    from fastapi import FastAPI

    HAS_SERVER_DEPS = True
except ImportError:
    HAS_SERVER_DEPS = False

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HAS_SERVER_DEPS, reason="fastapi/uvicorn not installed"),
]


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/v1/sessions/{key}")
    async def get_session(key: str):
        return {"value": 1}

    @app.post("/api/v1/events")
    async def post_events(body: dict):
        return {"accepted": len(body.get("events", [])), "duplicates": 0}

    return app


@pytest.fixture(scope="module")
def server_url():
    """Start a uvicorn server on a random port, yield its URL."""
    app = _build_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)

    # uvicorn.Server.run() blocks, so run it in a daemon thread
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for the server to bind and expose its port
    deadline = time.monotonic() + 5
    port = None
    while time.monotonic() < deadline:
        if server.started and server.servers:
            sockets = server.servers[0].sockets
            if sockets:
                port = sockets[0].getsockname()[1]
                break
        time.sleep(0.05)

    if port is None:
        pytest.fail("Uvicorn server did not start within 5 seconds")

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=3)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(server_url: str) -> EdictumServerClient:
    return EdictumServerClient(server_url, "test-key", agent_id="agent-1")


def _run_in_thread(coro_factory):
    """Run an async function in a new thread via asyncio.run()."""
    result = None
    error = None

    def target():
        nonlocal result, error
        try:
            result = asyncio.run(coro_factory())
        except Exception as exc:
            error = exc

    t = threading.Thread(target=target)
    t.start()
    t.join(timeout=10)
    if error is not None:
        raise error
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCrossLoopIntegration:
    @pytest.mark.asyncio
    async def test_cross_thread_sequential_requests(self, server_url):
        """Main thread request + worker thread request both succeed."""
        client = _make_client(server_url)

        # Main thread request
        result = await client.get("/api/v1/health")
        assert result["status"] == "ok"

        # Worker thread request (new event loop via asyncio.run)
        async def worker():
            return await client.get("/api/v1/sessions/test-key")

        worker_result = _run_in_thread(worker)
        assert worker_result["value"] == 1

        await client.close()

    @pytest.mark.asyncio
    async def test_cross_thread_multiple_workers(self, server_url):
        """5 sequential worker threads making real HTTP requests all succeed."""
        client = _make_client(server_url)

        # Warm up main thread client
        await client.get("/api/v1/health")

        errors = []
        for i in range(5):

            async def worker(idx=i):
                resp = await client.get("/api/v1/sessions/test-key")
                assert resp["value"] == 1
                return idx

            try:
                _run_in_thread(worker)
            except Exception as exc:
                errors.append((i, exc))

        assert errors == [], f"Worker errors: {errors}"
        await client.close()

    @pytest.mark.asyncio
    async def test_cross_thread_post_requests(self, server_url):
        """Worker threads can POST to the server (audit sink pattern)."""
        client = _make_client(server_url)

        async def worker():
            return await client.post("/api/v1/events", {"events": [{"call_id": "test"}]})

        result = _run_in_thread(worker)
        assert result["accepted"] == 1

        await client.close()
