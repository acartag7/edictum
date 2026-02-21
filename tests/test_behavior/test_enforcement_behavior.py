"""Behavior tests for enforcement paths.

When the pipeline denies a tool call, the adapter must actually prevent execution.
Tests that deny decisions are enforced end-to-end, not silently swallowed.
"""

from __future__ import annotations

from types import SimpleNamespace

from edictum import Edictum, Verdict, postcondition, precondition
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def _make_deny_guard(**extra):
    @precondition("*")
    def always_deny(envelope):
        return Verdict.fail("contract violation: access denied")

    defaults = {
        "environment": "test",
        "contracts": [always_deny],
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(extra)
    return Edictum(**defaults)


class TestPreconditionDenyEnforcement:
    """Precondition deny must propagate through every adapter."""

    async def test_crewai_deny_returns_false(self):
        """CrewAI _before_hook must return False on deny."""
        from edictum.adapters.crewai import CrewAIAdapter

        guard = _make_deny_guard()
        adapter = CrewAIAdapter(guard)
        ctx = SimpleNamespace(tool_name="TestTool", tool_input={}, agent=None, task=None)
        result = await adapter._before_hook(ctx)
        assert result is False, "CrewAI must return False on deny (not None, which means allow)"

    async def test_openai_deny_returns_denied_string(self):
        """OpenAI _pre must return a DENIED: string on deny."""
        from edictum.adapters.openai_agents import OpenAIAgentsAdapter

        guard = _make_deny_guard()
        adapter = OpenAIAgentsAdapter(guard)
        result = await adapter._pre("TestTool", {}, "call-1")
        assert result is not None
        assert "DENIED" in result

    async def test_langchain_deny_blocks_execution(self):
        """LangChain must produce a denial response, not None."""
        from unittest.mock import MagicMock

        from edictum.adapters.langchain import LangChainAdapter

        guard = _make_deny_guard()
        adapter = LangChainAdapter(guard)
        request = MagicMock()
        request.tool_call = {"name": "TestTool", "args": {}, "id": "tc-1"}
        result = await adapter._pre_tool_call(request)
        assert result is not None, "LangChain must not return None on deny"


class TestPostconditionDenyEnforcement:
    """Postcondition effect=deny must not silently degrade to warn."""

    async def test_postcondition_deny_is_reflected_in_post_result(self):
        """When a postcondition has effect=deny, post result must indicate failure."""

        @postcondition("TestTool")
        def deny_output(envelope, result):
            return Verdict.fail("output contains violation")

        deny_output._edictum_effect = "deny"

        sink = NullAuditSink()
        guard = Edictum(
            environment="test",
            contracts=[deny_output],
            audit_sink=sink,
            backend=MemoryBackend(),
        )

        from edictum.adapters.openai_agents import OpenAIAgentsAdapter

        adapter = OpenAIAgentsAdapter(guard)

        # Pre must allow (no preconditions)
        await adapter._pre("TestTool", {}, "call-1")

        # Post must reflect the denial
        post_result = await adapter._post("call-1", "violation data")
        assert post_result is not None
        assert (
            post_result.postconditions_passed is False
        ), "Postcondition with effect=deny must report postconditions_passed=False"


class TestObserveModeEnforcement:
    """Observe mode must convert deny to allow, not silently skip contracts."""

    async def test_observe_mode_logs_would_deny(self):
        """In observe mode, denied calls must emit CALL_WOULD_DENY audit events."""
        sink = NullAuditSink()
        guard = _make_deny_guard(audit_sink=sink, mode="observe")

        from edictum.adapters.crewai import CrewAIAdapter

        adapter = CrewAIAdapter(guard)
        ctx = SimpleNamespace(tool_name="TestTool", tool_input={}, agent=None, task=None)
        result = await adapter._before_hook(ctx)

        # Observe mode: must allow
        assert result is None, "Observe mode must allow (return None)"

        # Must have logged would_deny
        would_deny_events = [e for e in sink.events if e.action == AuditAction.CALL_WOULD_DENY]
        assert len(would_deny_events) >= 1, "Observe mode must emit CALL_WOULD_DENY audit event"
