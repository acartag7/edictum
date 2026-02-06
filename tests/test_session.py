"""Tests for Session async counter operations."""

from __future__ import annotations

import pytest

from callguard.session import Session
from callguard.storage import MemoryBackend


@pytest.fixture
def session():
    return Session("test-sess", MemoryBackend())


class TestSession:
    async def test_increment_attempts(self, session):
        count = await session.increment_attempts()
        assert count == 1
        count = await session.increment_attempts()
        assert count == 2

    async def test_attempt_count_starts_at_zero(self, session):
        count = await session.attempt_count()
        assert count == 0

    async def test_attempt_count_after_increments(self, session):
        await session.increment_attempts()
        await session.increment_attempts()
        count = await session.attempt_count()
        assert count == 2

    async def test_record_execution_increments_counts(self, session):
        await session.record_execution("Bash", success=True)
        assert await session.execution_count() == 1
        assert await session.tool_execution_count("Bash") == 1

    async def test_per_tool_counts_independent(self, session):
        await session.record_execution("Bash", success=True)
        await session.record_execution("Read", success=True)
        await session.record_execution("Bash", success=True)
        assert await session.tool_execution_count("Bash") == 2
        assert await session.tool_execution_count("Read") == 1
        assert await session.execution_count() == 3

    async def test_consecutive_failures_increments(self, session):
        await session.record_execution("Bash", success=False)
        assert await session.consecutive_failures() == 1
        await session.record_execution("Bash", success=False)
        assert await session.consecutive_failures() == 2

    async def test_consecutive_failures_resets_on_success(self, session):
        await session.record_execution("Bash", success=False)
        await session.record_execution("Bash", success=False)
        assert await session.consecutive_failures() == 2
        await session.record_execution("Bash", success=True)
        assert await session.consecutive_failures() == 0

    async def test_session_id_property(self, session):
        assert session.session_id == "test-sess"

    async def test_key_scheme(self, session):
        """Verify the storage key scheme."""
        backend = session._backend
        await session.increment_attempts()
        # Verify the key exists in counters
        assert backend._counters.get("s:test-sess:attempts") == 1

        await session.record_execution("Bash", success=True)
        assert backend._counters.get("s:test-sess:execs") == 1
        assert backend._counters.get("s:test-sess:tool:Bash") == 1
