"""Tests for Cline format handler."""

from __future__ import annotations

import json

from edictum.gate.formats.cline import CLINE_TOOL_MAP, ClineFormat


class TestClineParse:
    def setup_method(self) -> None:
        self.fmt = ClineFormat()

    def test_parse_stdin_basic(self) -> None:
        data = {
            "type": "PreToolUse",
            "tool": "execute_command",
            "params": {"command": "ls"},
            "cwd": "/project",
        }
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Bash"
        assert tool_input == {"command": "ls"}
        assert cwd == "/project"

    def test_tool_mapping_execute_command(self) -> None:
        assert CLINE_TOOL_MAP["execute_command"] == "Bash"

    def test_tool_mapping_read_file(self) -> None:
        assert CLINE_TOOL_MAP["read_file"] == "Read"

    def test_tool_mapping_write_to_file(self) -> None:
        assert CLINE_TOOL_MAP["write_to_file"] == "Write"

    def test_tool_mapping_replace_in_file(self) -> None:
        assert CLINE_TOOL_MAP["replace_in_file"] == "Edit"

    def test_tool_mapping_unknown(self) -> None:
        data = {"tool": "some_unknown_tool", "params": {}, "cwd": "/project"}
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "some_unknown_tool"


class TestClineOutput:
    def setup_method(self) -> None:
        self.fmt = ClineFormat()

    def test_format_allow(self) -> None:
        stdout, code = self.fmt.format_output("allow", None, None, 5)
        assert json.loads(stdout) == {}
        assert code == 0

    def test_format_deny(self) -> None:
        stdout, code = self.fmt.format_output("deny", "test-contract", "Not allowed", 5)
        result = json.loads(stdout)
        assert result["cancel"] is True
        assert "test-contract" in result["errorMessage"]
        assert "Not allowed" in result["errorMessage"]
