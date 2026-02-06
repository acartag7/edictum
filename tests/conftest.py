"""Shared test fixtures."""

from __future__ import annotations

import pytest

from callguard import CallGuard, create_envelope
from callguard.session import Session
from callguard.storage import MemoryBackend


class NullAuditSink:
    """Audit sink that discards all events (for tests)."""

    def __init__(self):
        self.events = []

    async def emit(self, event):
        self.events.append(event)


@pytest.fixture
def backend():
    return MemoryBackend()


@pytest.fixture
def session(backend):
    return Session("test-session", backend)


@pytest.fixture
def null_sink():
    return NullAuditSink()


@pytest.fixture
def guard(null_sink, backend):
    return CallGuard(
        environment="test",
        audit_sink=null_sink,
        backend=backend,
    )


@pytest.fixture
def envelope():
    return create_envelope("TestTool", {"key": "value"})


@pytest.fixture
def bash_envelope():
    return create_envelope("Bash", {"command": "ls -la"})


@pytest.fixture
def read_envelope():
    return create_envelope("Read", {"file_path": "/tmp/test.txt"})
