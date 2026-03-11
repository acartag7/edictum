"""Behavior tests for tool_name validation in create_envelope().

Security tests verify that backslash (Windows path separator) is rejected
alongside forward slash, preventing ambiguous session keys and audit entries.
"""

from __future__ import annotations

import pytest

from edictum import create_envelope


class TestToolNameBackslashRejection:
    """Backslash in tool_name must be rejected (path separator on Windows)."""

    @pytest.mark.security
    def test_single_backslash_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("evil\\tool", {})

    @pytest.mark.security
    def test_backslash_path_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("path\\to\\tool", {})

    @pytest.mark.security
    def test_forward_slash_still_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("evil/tool", {})

    @pytest.mark.security
    def test_null_byte_still_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("evil\x00tool", {})

    def test_valid_names_accepted(self):
        """Normal tool names with hyphens, underscores, dots are fine."""
        for name in ("Bash", "my-tool", "my_tool", "tool.v2", "ReadFile"):
            env = create_envelope(name, {})
            assert env.tool_name == name
