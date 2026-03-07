"""Tests for OpenCode format handler."""

from __future__ import annotations

import json

from edictum.gate.formats.opencode import OPENCODE_TOOL_MAP, OpenCodeFormat


class TestOpenCodeParse:
    def setup_method(self) -> None:
        self.fmt = OpenCodeFormat()

    def test_parse_stdin_basic(self) -> None:
        data = {
            "tool": "bash",
            "input": {"command": "ls"},
            "sessionId": "abc123",
            "workingDirectory": "/project",
        }
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Bash"
        assert tool_input == {"command": "ls"}
        assert cwd == "/project"

    def test_tool_mapping_bash(self) -> None:
        assert OPENCODE_TOOL_MAP["bash"] == "Bash"

    def test_tool_mapping_shell(self) -> None:
        assert OPENCODE_TOOL_MAP["shell"] == "Bash"

    def test_working_directory_extraction(self) -> None:
        data = {"tool": "read", "input": {}, "workingDirectory": "/custom/dir"}
        _, _, cwd = self.fmt.parse_stdin(data)
        assert cwd == "/custom/dir"


class TestOpenCodeOutput:
    def setup_method(self) -> None:
        self.fmt = OpenCodeFormat()

    def test_format_allow(self) -> None:
        stdout, code = self.fmt.format_output("allow", None, None, 5)
        result = json.loads(stdout)
        assert result["allow"] is True
        assert code == 0

    def test_format_deny(self) -> None:
        stdout, code = self.fmt.format_output("deny", "test-contract", "Not allowed", 5)
        result = json.loads(stdout)
        assert result["allow"] is False
        assert "test-contract" in result["reason"]
        assert "Not allowed" in result["reason"]
