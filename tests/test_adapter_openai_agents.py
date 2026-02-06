"""Tests for OpenAIAgentsAdapter."""

from __future__ import annotations

from callguard import CallGuard, Verdict, precondition
from callguard.adapters.openai_agents import OpenAIAgentsAdapter
from callguard.audit import AuditAction
from callguard.storage import MemoryBackend
from tests.conftest import NullAuditSink


def make_guard(**kwargs):
    defaults = {
        "environment": "test",
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(kwargs)
    return CallGuard(**defaults)


class TestOpenAIAgentsAdapter:
    async def test_allow_returns_correct_format(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard, session_id="test-session")
        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={"key": "value"},
            call_id="call-1",
        )
        assert result is None  # None means allow

    async def test_deny_returns_correct_format(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("blocked")

        guard = make_guard(contracts=[always_deny])
        adapter = OpenAIAgentsAdapter(guard)
        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert result is not None
        assert result.startswith("DENIED:")
        assert "blocked" in result

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)

        # Pre creates pending
        await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert "call-1" in adapter._pending

        # Post clears pending
        await adapter._post(call_id="call-1", tool_response="ok")
        assert "call-1" not in adapter._pending

    async def test_deny_clears_pending(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("no")

        guard = make_guard(contracts=[always_deny])
        adapter = OpenAIAgentsAdapter(guard)

        await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert "call-1" not in adapter._pending

    async def test_post_without_pending_returns_empty(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)
        result = await adapter._post(call_id="unknown")
        assert result is None

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)

        await adapter._pre(tool_name="T", tool_input={}, call_id="call-1")
        await adapter._pre(tool_name="T", tool_input={}, call_id="call-2")
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("would be blocked")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", contracts=[always_deny], audit_sink=sink)
        adapter = OpenAIAgentsAdapter(guard)

        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        # Should allow through (None)
        assert result is None
        # Should have CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        # Pending should exist (tool will execute)
        assert "call-1" in adapter._pending

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = OpenAIAgentsAdapter(guard)

        await adapter._pre(tool_name="T", tool_input={}, call_id="call-1")
        await adapter._post(call_id="call-1", tool_response="ok")

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)

        assert adapter._check_tool_success(None) is True
        assert adapter._check_tool_success("ok") is True
        assert adapter._check_tool_success("Error: something failed") is False
        assert adapter._check_tool_success("fatal: not a git repo") is False

    async def test_public_api_returns_framework_native(self):
        """as_guardrails() returns a tuple of 2 callables (without importing framework)."""
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)

        # We cannot call as_guardrails() without the agents framework installed,
        # so we verify the method exists and the internal _pre/_post are callable
        assert callable(adapter._pre)
        assert callable(adapter._post)
        assert hasattr(adapter, "as_guardrails")

    async def test_session_id_default(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)
        assert adapter.session_id  # should be a UUID string

    async def test_deny_helper_format(self):
        result = OpenAIAgentsAdapter._deny("test reason")
        assert result == "DENIED: test reason"
