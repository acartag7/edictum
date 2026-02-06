"""Tests for CrewAIAdapter."""

from __future__ import annotations

from types import SimpleNamespace

from callguard import CallGuard, Verdict, precondition
from callguard.adapters.crewai import CrewAIAdapter
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


def _make_before_context(tool_name: str = "TestTool", tool_input: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        tool_name=tool_name,
        tool_input=tool_input or {},
        agent=None,
        task=None,
    )


def _make_after_context(
    tool_name: str = "TestTool",
    tool_input: dict | None = None,
    tool_result: str = "ok",
) -> SimpleNamespace:
    return SimpleNamespace(
        tool_name=tool_name,
        tool_input=tool_input or {},
        tool_result=tool_result,
        agent=None,
        task=None,
    )


class TestCrewAIAdapter:
    async def test_allow_returns_correct_format(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard, session_id="test-session")
        result = await adapter._before_hook(_make_before_context())
        assert result is None

    async def test_deny_returns_correct_format(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("blocked")

        sink = NullAuditSink()
        guard = make_guard(contracts=[always_deny], audit_sink=sink)
        adapter = CrewAIAdapter(guard)
        result = await adapter._before_hook(_make_before_context())
        assert result is False
        # Verify audit contains the reason
        deny_events = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
        assert len(deny_events) == 1
        assert deny_events[0].reason == "blocked"

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard)

        # Before hook stores pending
        await adapter._before_hook(_make_before_context())
        assert adapter._pending_envelope is not None
        assert adapter._pending_span is not None

        # After hook clears pending
        await adapter._after_hook(_make_after_context())
        assert adapter._pending_envelope is None
        assert adapter._pending_span is None

    async def test_deny_clears_pending(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("no")

        guard = make_guard(contracts=[always_deny])
        adapter = CrewAIAdapter(guard)

        await adapter._before_hook(_make_before_context())
        assert adapter._pending_envelope is None
        assert adapter._pending_span is None

    async def test_post_without_pending_returns_empty(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard)
        # After hook with no pending state is a no-op
        result = await adapter._after_hook(_make_after_context(tool_name="unknown"))
        assert result is None

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard)

        await adapter._before_hook(_make_before_context(tool_name="T1"))
        # Clear pending so next before can proceed cleanly
        await adapter._after_hook(_make_after_context(tool_name="T1"))
        await adapter._before_hook(_make_before_context(tool_name="T2"))
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("would be blocked")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", contracts=[always_deny], audit_sink=sink)
        adapter = CrewAIAdapter(guard)

        result = await adapter._before_hook(_make_before_context())
        # Should allow through (None)
        assert result is None
        # Should have CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        # Pending should exist (tool will execute)
        assert adapter._pending_envelope is not None

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = CrewAIAdapter(guard)

        await adapter._before_hook(_make_before_context(tool_name="T"))
        await adapter._after_hook(_make_after_context(tool_name="T"))

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard)

        assert adapter._check_tool_success(None) is True
        assert adapter._check_tool_success("ok") is True
        assert adapter._check_tool_success("Error: something failed") is False
        assert adapter._check_tool_success("fatal: not a git repo") is False

    async def test_public_api_returns_framework_native(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard)
        # register() requires crewai, but _before_hook/_after_hook are exposed
        assert callable(adapter._before_hook)
        assert callable(adapter._after_hook)
        assert callable(adapter.register)
