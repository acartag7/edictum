"""Behavior tests for LocalApprovalBackend redaction.

Proves that tool_args are redacted before printing to stdout.
"""

from __future__ import annotations

import pytest

from edictum.approval import LocalApprovalBackend


class TestLocalApprovalRedaction:
    """LocalApprovalBackend must redact sensitive args in stdout output."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sensitive_args_redacted_in_stdout(self, capsys):
        """tool_args containing api_key must be redacted in stdout."""
        backend = LocalApprovalBackend()
        await backend.request_approval(
            "dangerous_tool",
            {"api_key": "sk-secret123", "query": "SELECT 1"},
            "Approve this?",
        )
        captured = capsys.readouterr()
        assert "sk-secret123" not in captured.out
        assert "[REDACTED]" in captured.out
        # Non-sensitive args should still be visible
        assert "SELECT 1" in captured.out

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_password_redacted_in_stdout(self, capsys):
        """tool_args containing password must be redacted."""
        backend = LocalApprovalBackend()
        await backend.request_approval(
            "connect_db",
            {"password": "hunter2", "host": "localhost"},
            "Approve?",
        )
        captured = capsys.readouterr()
        assert "hunter2" not in captured.out
        assert "[REDACTED]" in captured.out
        assert "localhost" in captured.out
