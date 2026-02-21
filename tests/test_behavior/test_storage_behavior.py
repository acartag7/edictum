"""Behavior tests for StorageBackend and MemoryBackend.

Every accepted parameter must have an observable effect.
If a parameter is accepted but ignored, these tests fail.
"""

from __future__ import annotations

import inspect

import pytest

from edictum.storage import MemoryBackend


class TestMemoryBackendParameterEffects:
    """Every parameter accepted by MemoryBackend must have an observable effect."""

    async def test_ttl_parameter_is_not_silently_ignored(self):
        """If MemoryBackend.set() accepts ttl, it must either enforce it or reject it.

        Silently accepting and ignoring ttl is a correctness bug:
        users think time-windowed session limits work when they don't.
        """
        backend = MemoryBackend()
        sig = inspect.signature(backend.set)

        if "ttl" not in sig.parameters:
            pytest.skip("ttl parameter not in MemoryBackend.set() signature")

        # If ttl is accepted, it must DO something:
        # Option A: enforce TTL (key expires) — ideal
        # Option B: raise NotImplementedError — acceptable
        # Option C: silently ignore — BUG (this test catches it)
        try:
            await backend.set("key", "value", ttl=60)
        except (NotImplementedError, TypeError):
            # Option B: explicitly rejected — acceptable
            return

        # If we get here, ttl was accepted without error.
        # The value must show evidence of TTL awareness.
        result = await backend.get("key")
        if result is not None:
            pytest.fail(
                "MemoryBackend.set() accepts ttl parameter but does not enforce it "
                "and does not raise NotImplementedError. This silently breaks "
                "time-windowed session contracts. Either implement TTL expiry, "
                "raise NotImplementedError, or remove ttl from the signature."
            )

    async def test_increment_amount_parameter_has_effect(self):
        """increment(amount=N) must increase by N, not by 1."""
        backend = MemoryBackend()
        result = await backend.increment("counter", amount=5)
        assert result == 5, "amount parameter must affect the increment value"
        result = await backend.increment("counter", amount=3)
        assert result == 8, "subsequent increments must accumulate correctly"

    async def test_increment_default_amount_is_one(self):
        """increment() with no amount must default to 1."""
        backend = MemoryBackend()
        result = await backend.increment("counter")
        assert result == 1, "default increment amount must be 1"

    async def test_delete_removes_both_data_and_counters(self):
        """delete() must remove from both _data and _counters stores."""
        backend = MemoryBackend()
        await backend.set("data_key", "value")
        await backend.increment("counter_key")

        await backend.delete("data_key")
        await backend.delete("counter_key")

        assert await backend.get("data_key") is None
        assert await backend.get("counter_key") is None
