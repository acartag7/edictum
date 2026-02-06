"""Tests for ClaudeAgentSDKAdapter."""

from __future__ import annotations

import pytest

from callguard import CallGuard, Verdict, precondition
from callguard.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
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


class TestClaudeAgentSDKAdapter:
    async def test_allow_returns_empty_dict(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard, session_id="test-session")
        result = await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={"key": "value"},
            tool_use_id="tu-1",
        )
        assert result == {}

    async def test_deny_returns_sdk_format(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("blocked")

        guard = make_guard(contracts=[always_deny])
        adapter = ClaudeAgentSDKAdapter(guard)
        result = await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={},
            tool_use_id="tu-1",
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert result["hookSpecificOutput"]["permissionDecisionReason"] == "blocked"
        assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)

        # Pre-tool-use stores pending
        await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={},
            tool_use_id="tu-1",
        )
        assert "tu-1" in adapter._pending

        # Post-tool-use clears pending
        await adapter._post_tool_use(tool_use_id="tu-1", tool_response="ok")
        assert "tu-1" not in adapter._pending

    async def test_deny_clears_pending(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("no")

        guard = make_guard(contracts=[always_deny])
        adapter = ClaudeAgentSDKAdapter(guard)

        await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={},
            tool_use_id="tu-1",
        )
        assert "tu-1" not in adapter._pending

    async def test_post_without_pending_returns_empty(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)
        result = await adapter._post_tool_use(tool_use_id="unknown")
        assert result == {}

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)

        await adapter._pre_tool_use(tool_name="T", tool_input={}, tool_use_id="tu-1")
        await adapter._pre_tool_use(tool_name="T", tool_input={}, tool_use_id="tu-2")
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("would be blocked")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", contracts=[always_deny], audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard)

        result = await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={},
            tool_use_id="tu-1",
        )
        # Should allow through (empty dict)
        assert result == {}
        # Should have CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        # Pending should exist (tool will execute)
        assert "tu-1" in adapter._pending

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)

        assert adapter._check_tool_success(None) is True
        assert adapter._check_tool_success("ok") is True
        assert adapter._check_tool_success({"result": "good"}) is True
        assert adapter._check_tool_success({"is_error": True}) is False
        assert adapter._check_tool_success("Error: something failed") is False
        assert adapter._check_tool_success("fatal: not a git repo") is False

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard)

        await adapter._pre_tool_use(tool_name="T", tool_input={}, tool_use_id="tu-1")
        await adapter._post_tool_use(tool_use_id="tu-1", tool_response="ok")

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_post_tool_warnings_in_output(self):
        from callguard.contracts import postcondition as postc

        @postc("TestTool")
        def bad_result(envelope, result):
            return Verdict.fail("Result was bad")

        guard = make_guard(contracts=[bad_result])
        adapter = ClaudeAgentSDKAdapter(guard)

        await adapter._pre_tool_use(tool_name="TestTool", tool_input={}, tool_use_id="tu-1")
        result = await adapter._post_tool_use(tool_use_id="tu-1", tool_response="bad")

        assert "hookSpecificOutput" in result
        assert "additionalContext" in result["hookSpecificOutput"]

    async def test_session_id_default(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)
        assert adapter.session_id  # should be a UUID string

    async def test_to_sdk_hooks(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks()
        assert "pre_tool_use" in hooks
        assert "post_tool_use" in hooks


class TestCallGuardRun:
    async def test_run_allows_and_returns(self):
        guard = make_guard()

        async def my_tool(key):
            return f"result: {key}"

        result = await guard.run("TestTool", {"key": "hello"}, my_tool)
        assert result == "result: hello"

    async def test_run_emits_full_audit_trail(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)

        async def my_tool(**kwargs):
            return "ok"

        await guard.run("TestTool", {}, my_tool)
        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_run_deny_raises(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("denied by precondition")

        guard = make_guard(contracts=[always_deny])

        async def my_tool(**kwargs):
            return "ok"

        from callguard import CallGuardDenied

        with pytest.raises(CallGuardDenied) as exc_info:
            await guard.run("TestTool", {}, my_tool)
        assert exc_info.value.reason == "denied by precondition"

    async def test_run_deny_emits_audit_no_execute(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("denied")

        sink = NullAuditSink()
        guard = make_guard(contracts=[always_deny], audit_sink=sink)

        async def my_tool(**kwargs):
            return "ok"

        from callguard import CallGuardDenied

        with pytest.raises(CallGuardDenied):
            await guard.run("TestTool", {}, my_tool)
        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_DENIED in actions
        # Denied means no execution audit
        assert AuditAction.CALL_EXECUTED not in actions
        assert AuditAction.CALL_ALLOWED not in actions

    async def test_run_tool_error_emits_call_failed(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)

        async def failing_tool(**kwargs):
            raise RuntimeError("boom")

        from callguard import CallGuardToolError

        with pytest.raises(CallGuardToolError):
            await guard.run("TestTool", {}, failing_tool)
        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_FAILED in actions

    async def test_run_observe_mode_full_trail(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("would deny")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", contracts=[always_deny], audit_sink=sink)

        async def my_tool(**kwargs):
            return "ok"

        result = await guard.run("TestTool", {}, my_tool)
        assert result == "ok"
        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_WOULD_DENY in actions
        assert AuditAction.CALL_EXECUTED in actions
