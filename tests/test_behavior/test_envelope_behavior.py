"""Behavior tests for create_envelope tool_name validation.

Verifies that ALL ASCII control characters (0x00-0x1f, 0x7f) are rejected,
not just NUL and newline.
"""

from __future__ import annotations

import pytest

from edictum.envelope import create_envelope


@pytest.mark.security
class TestToolNameControlCharRejection:
    """Security: create_envelope rejects all ASCII control characters in tool_name."""

    def test_carriage_return_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("tool\rname", {})

    def test_tab_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("tool\tname", {})

    def test_del_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("tool\x7fname", {})

    def test_soh_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("tool\x01name", {})

    def test_null_byte_still_rejected(self):
        """Regression: NUL byte rejection must survive the refactor."""
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("tool\x00name", {})

    def test_newline_still_rejected(self):
        """Regression: newline rejection must survive the refactor."""
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("tool\nname", {})

    def test_path_separator_still_rejected(self):
        """Regression: forward slash rejection must survive the refactor."""
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("path/to/tool", {})

    def test_empty_string_still_rejected(self):
        """Regression: empty tool_name rejection must survive the refactor."""
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("", {})


@pytest.mark.security
class TestToolNameValidNamesAccepted:
    """Valid tool names must pass validation after the control-char fix."""

    def test_simple_name(self):
        envelope = create_envelope("Bash", {})
        assert envelope.tool_name == "Bash"

    def test_hyphenated_name(self):
        envelope = create_envelope("my-tool", {})
        assert envelope.tool_name == "my-tool"

    def test_underscored_name(self):
        envelope = create_envelope("my_tool", {})
        assert envelope.tool_name == "my_tool"

    def test_dotted_version_name(self):
        envelope = create_envelope("Tool.v2", {})
        assert envelope.tool_name == "Tool.v2"

    def test_colon_namespace(self):
        envelope = create_envelope("ns:tool", {})
        assert envelope.tool_name == "ns:tool"

    def test_unicode_name(self):
        envelope = create_envelope("tool_\u00e9", {})
        assert envelope.tool_name == "tool_\u00e9"
