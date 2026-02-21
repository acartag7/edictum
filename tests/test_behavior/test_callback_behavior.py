"""Behavior tests for callback invocation.

Callbacks must fire exactly once per event. No double-firing.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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

    def test_crewai_register_wrapper_no_double_fire(self):
        """register() outer wrapper must not re-invoke the callback.

        The callback lives in _after_hook(). The register() closure must
        NOT call it a second time when translating PostCallResult for CrewAI.

        Uses lowercase tool name to match the register() normalization.
        """
        from edictum.adapters.crewai import CrewAIAdapter

        @postcondition("testtool")
        def detect_issue(envelope, result):
            return Verdict.fail("issue detected")

        guard = Edictum(
            environment="test",
            contracts=[detect_issue],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
        )
        callback = MagicMock()
        adapter = CrewAIAdapter(guard)

        # Mock CrewAI hook registration to capture the installed hooks
        captured = {}
        mock_tool_hooks = MagicMock()
        mock_tool_hooks.register_before_tool_call_hook = lambda h: captured.update(before=h)
        mock_tool_hooks.register_after_tool_call_hook = lambda h: captured.update(after=h)

        with patch.dict(
            sys.modules,
            {
                "crewai": MagicMock(),
                "crewai.hooks": MagicMock(),
                "crewai.hooks.tool_hooks": mock_tool_hooks,
            },
        ):
            adapter.register(on_postcondition_warn=callback)

        # Drive the hooks exactly as CrewAI would
        before_ctx = SimpleNamespace(tool_name="TestTool", tool_input={}, agent=None, task=None)
        captured["before"](before_ctx)

        after_ctx = SimpleNamespace(
            tool_name="TestTool",
            tool_input={},
            tool_result="test output",
            agent=None,
            task=None,
        )
        captured["after"](after_ctx)

        assert callback.call_count == 1, (
            f"on_postcondition_warn called {callback.call_count} times via register(), "
            "expected exactly 1. The register() wrapper must not duplicate the "
            "callback invocation from _after_hook()."
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


class TestCrewAIDenyReturnValue:
    """CrewAI _deny() must return the reason string, not a boolean."""

    async def test_deny_returns_reason_string(self):
        """_deny() must return 'DENIED: {reason}' so the agent sees why."""
        from edictum.adapters.crewai import CrewAIAdapter

        result = CrewAIAdapter._deny("budget exceeded")
        assert isinstance(result, str), f"_deny() returned {type(result).__name__}, expected str"
        assert "DENIED" in result, f"_deny() returned {result!r}, expected 'DENIED: ...'"
        assert "budget exceeded" in result, f"_deny() lost the reason. Got: {result!r}"

    async def test_deny_propagates_through_before_hook(self):
        """_before_hook() must return the denial reason string on deny."""
        from edictum import precondition
        from edictum.adapters.crewai import CrewAIAdapter

        @precondition("*")
        def block_all(envelope):
            return Verdict.fail("budget exceeded")

        guard = Edictum(
            environment="test",
            contracts=[block_all],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
        )
        adapter = CrewAIAdapter(guard)
        ctx = SimpleNamespace(tool_name="TestTool", tool_input={}, agent=None, task=None)
        result = await adapter._before_hook(ctx)

        assert isinstance(result, str), f"_before_hook returned {type(result).__name__} on deny, expected str"
        assert "budget exceeded" in result, f"Denial reason lost. Got: {result!r}"


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
