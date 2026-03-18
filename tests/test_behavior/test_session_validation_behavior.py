"""Behavior tests for session_id and tool_name validation in Session.

Tests that invalid identifiers are rejected at construction and in
methods that use them as storage key components.
"""

from __future__ import annotations

import pytest

from edictum.session import Session
from edictum.storage import MemoryBackend


class TestSessionIdValidation:
    """Session rejects session_ids that could cause storage key injection."""

    def test_valid_session_id_accepted(self):
        """Normal alphanumeric session_id is accepted."""
        session = Session("my-session-123", MemoryBackend())
        assert session.session_id == "my-session-123"

    @pytest.mark.security
    def test_empty_session_id_rejected(self):
        """Empty string is rejected."""
        with pytest.raises(ValueError, match="Invalid session_id"):
            Session("", MemoryBackend())

    @pytest.mark.security
    def test_colon_in_session_id_rejected(self):
        """Colons are storage key delimiters — allowing them enables key collision."""
        with pytest.raises(ValueError, match="Invalid session_id"):
            Session("real-session:execs", MemoryBackend())

    @pytest.mark.security
    def test_null_byte_in_session_id_rejected(self):
        """Null bytes cause truncation in C-backed storage."""
        with pytest.raises(ValueError, match="Invalid session_id"):
            Session("sess\x00injected", MemoryBackend())

    @pytest.mark.security
    def test_newline_in_session_id_rejected(self):
        """Control characters are rejected."""
        with pytest.raises(ValueError, match="Invalid session_id"):
            Session("sess\ninjected", MemoryBackend())

    @pytest.mark.security
    def test_path_separator_in_session_id_rejected(self):
        """Path separators are rejected."""
        with pytest.raises(ValueError, match="Invalid session_id"):
            Session("sess/injected", MemoryBackend())

    @pytest.mark.security
    def test_backslash_in_session_id_rejected(self):
        with pytest.raises(ValueError, match="Invalid session_id"):
            Session("sess\\injected", MemoryBackend())

    @pytest.mark.security
    def test_del_in_session_id_rejected(self):
        """DEL (0x7F) control character is rejected."""
        with pytest.raises(ValueError, match="Invalid session_id"):
            Session("sess\x7finjected", MemoryBackend())


class TestToolNameValidationInSession:
    """Session methods that accept tool_name validate it."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_record_execution_rejects_invalid_tool_name(self):
        session = Session("valid-session", MemoryBackend())
        with pytest.raises(ValueError, match="Invalid tool_name"):
            await session.record_execution("tool\x00name", True)

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_tool_execution_count_rejects_invalid_tool_name(self):
        session = Session("valid-session", MemoryBackend())
        with pytest.raises(ValueError, match="Invalid tool_name"):
            await session.tool_execution_count("tool/name")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_batch_get_counters_rejects_invalid_tool_name(self):
        session = Session("valid-session", MemoryBackend())
        with pytest.raises(ValueError, match="Invalid tool_name"):
            await session.batch_get_counters(include_tool="tool\x00name")
