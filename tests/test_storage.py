"""Tests for MemoryBackend."""

from __future__ import annotations

import pytest

from callguard.storage import MemoryBackend


@pytest.fixture
def backend():
    return MemoryBackend()


class TestMemoryBackend:
    async def test_get_missing_key(self, backend):
        result = await backend.get("nonexistent")
        assert result is None

    async def test_set_and_get(self, backend):
        await backend.set("key1", "value1")
        result = await backend.get("key1")
        assert result == "value1"

    async def test_set_overwrites(self, backend):
        await backend.set("key1", "v1")
        await backend.set("key1", "v2")
        assert await backend.get("key1") == "v2"

    async def test_delete_existing(self, backend):
        await backend.set("key1", "value1")
        await backend.delete("key1")
        assert await backend.get("key1") is None

    async def test_delete_nonexistent(self, backend):
        await backend.delete("nonexistent")  # should not raise

    async def test_delete_removes_counter(self, backend):
        await backend.increment("counter1")
        await backend.delete("counter1")
        # After delete, counter should be gone
        result = await backend.increment("counter1")
        assert result == 1  # starts fresh

    async def test_increment_new_key(self, backend):
        result = await backend.increment("counter1")
        assert result == 1

    async def test_increment_existing(self, backend):
        await backend.increment("counter1")
        result = await backend.increment("counter1")
        assert result == 2

    async def test_increment_custom_amount(self, backend):
        result = await backend.increment("counter1", amount=5)
        assert result == 5
        result = await backend.increment("counter1", amount=3)
        assert result == 8

    async def test_counters_separate_from_data(self, backend):
        """Counters and data are stored separately."""
        await backend.set("key1", "value1")
        await backend.increment("key1", amount=10)
        # Data store still has the string
        assert await backend.get("key1") == "value1"
        # Counter store has the number
        assert backend._counters["key1"] == 10

    async def test_ttl_accepted_but_ignored(self, backend):
        """TTL is accepted but not enforced in MemoryBackend."""
        await backend.set("key1", "value1", ttl=60)
        assert await backend.get("key1") == "value1"
