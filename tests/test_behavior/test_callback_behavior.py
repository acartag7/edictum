"""Behavior tests for callback invocation.

Callbacks must fire exactly once per event. No double-firing.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from edictum import Edictum, Verdict, postcondition
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def _make_warn_guard():
    """Create a guard with a postcondition that always warns."""

    @postcondition("TestTool")
    def detect_issue(envelope, result):
        return Verdict.fail("issue detected")

    return Edictum(
        environment="test",
        contracts=[detect_issue],
        audit_sink=NullAuditSink(),
        backend=MemoryBackend(),
    )


class TestCallbackInvocationCount:
    """on_postcondition_warn must fire exactly once per postcondition failure."""

    async def test_crewai_callback_fires_exactly_once(self):
        """CrewAI must call on_postcondition_warn exactly once, not twice."""
        from edictum.adapters.crewai import CrewAIAdapter

        guard = _make_warn_guard()
        callback = MagicMock()
        adapter = CrewAIAdapter(guard)
        adapter._on_postcondition_warn = callback

        before_ctx = SimpleNamespace(tool_name="TestTool", tool_input={}, agent=None, task=None)
        after_ctx = SimpleNamespace(
            tool_name="TestTool",
            tool_input={},
            tool_result="test output",
            agent=None,
            task=None,
        )

        await adapter._before_hook(before_ctx)
        await adapter._after_hook(after_ctx)

        assert callback.call_count == 1, (
            f"on_postcondition_warn called {callback.call_count} times, expected exactly 1. "
            "Check for double invocation in _after_hook and the outer register() wrapper."
        )

    async def test_openai_callback_fires_exactly_once(self):
        """OpenAI adapter callback must also fire exactly once."""
        from edictum.adapters.openai_agents import OpenAIAgentsAdapter

        guard = _make_warn_guard()
        callback = MagicMock()
        adapter = OpenAIAgentsAdapter(guard)
        adapter._on_postcondition_warn = callback

        await adapter._pre("TestTool", {}, "call-1")
        await adapter._post("call-1", "test output")

        assert callback.call_count == 1, f"OpenAI on_postcondition_warn called {callback.call_count} times, expected 1."


class TestCallbackArguments:
    """Callbacks must receive correct arguments."""

    async def test_callback_receives_result_and_findings(self):
        """on_postcondition_warn must receive (result, findings)."""
        from edictum.adapters.crewai import CrewAIAdapter

        guard = _make_warn_guard()
        callback = MagicMock()
        adapter = CrewAIAdapter(guard)
        adapter._on_postcondition_warn = callback

        before_ctx = SimpleNamespace(tool_name="TestTool", tool_input={}, agent=None, task=None)
        after_ctx = SimpleNamespace(
            tool_name="TestTool",
            tool_input={},
            tool_result="test output",
            agent=None,
            task=None,
        )

        await adapter._before_hook(before_ctx)
        await adapter._after_hook(after_ctx)

        assert callback.call_count >= 1
        args = callback.call_args
        assert len(args[0]) == 2, f"Callback received {len(args[0])} args, expected 2 (result, findings)"
