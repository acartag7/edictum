"""Tests for SemanticKernelAdapter."""

from __future__ import annotations

from callguard import CallGuard, Verdict, precondition
from callguard.adapters.semantic_kernel import SemanticKernelAdapter
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


class TestSemanticKernelAdapter:
    async def test_allow_returns_correct_format(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard, session_id="test-session")
        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={"key": "value"},
            call_id="call-1",
        )
        assert result == {}

    async def test_deny_returns_correct_format(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("blocked")

        guard = make_guard(contracts=[always_deny])
        adapter = SemanticKernelAdapter(guard)
        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert isinstance(result, str)
        assert "DENIED" in result
        assert "blocked" in result

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard)

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
        adapter = SemanticKernelAdapter(guard)

        await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert "call-1" not in adapter._pending

    async def test_post_without_pending_returns_empty(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard)
        result = await adapter._post(call_id="unknown")
        assert result == {}

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard)

        await adapter._pre(tool_name="T", tool_input={}, call_id="call-1")
        await adapter._pre(tool_name="T", tool_input={}, call_id="call-2")
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("would be blocked")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", contracts=[always_deny], audit_sink=sink)
        adapter = SemanticKernelAdapter(guard)

        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        # Should allow through (empty dict)
        assert result == {}
        # Should have CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        # Pending should exist (tool will execute)
        assert "call-1" in adapter._pending

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = SemanticKernelAdapter(guard)

        await adapter._pre(tool_name="T", tool_input={}, call_id="call-1")
        await adapter._post(call_id="call-1", tool_response="ok")

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard)

        assert adapter._check_tool_success(None) is True
        assert adapter._check_tool_success("ok") is True
        assert adapter._check_tool_success({"result": "good"}) is True
        assert adapter._check_tool_success({"is_error": True}) is False
        assert adapter._check_tool_success("Error: something failed") is False
        assert adapter._check_tool_success("fatal: not a git repo") is False

    async def test_public_api_returns_framework_native(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard)
        assert hasattr(adapter, "register")
        assert callable(adapter.register)
