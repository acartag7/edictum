"""Cline format handler — PreToolUse hook stdin/stdout."""

from __future__ import annotations

import json
import os

CLINE_TOOL_MAP: dict[str, str] = {
    "execute_command": "Bash",
    "read_file": "Read",
    "write_to_file": "Write",
    "replace_in_file": "Edit",
    "search_files": "Grep",
    "list_files": "Glob",
    "browser_action": "WebFetch",
    "use_mcp_tool": "mcp",
}


class ClineFormat:
    """Parse Cline PreToolUse hook stdin, format output."""

    def parse_stdin(self, data: dict) -> tuple[str, dict, str]:
        """Extract tool_name, tool_input, cwd from Cline stdin.

        Cline uses 'tool' and 'params' keys, with different tool names.
        """
        raw_tool = data.get("tool", "")
        tool_name = CLINE_TOOL_MAP.get(raw_tool, raw_tool)
        tool_input = data.get("params", {})
        cwd = data.get("cwd", os.getcwd())
        return tool_name, tool_input, cwd

    def format_output(
        self, verdict: str, contract_id: str | None, reason: str | None, evaluated: int
    ) -> tuple[str, int]:
        """Format verdict for Cline.

        Allow: empty JSON.
        Deny: {"cancel": true, "errorMessage": "..."}.
        """
        if verdict != "deny":
            return json.dumps({}), 0

        error_msg = ""
        if contract_id and reason:
            error_msg = f"Contract '{contract_id}': {reason}"
        elif reason:
            error_msg = reason
        elif contract_id:
            error_msg = f"Denied by contract '{contract_id}'"

        output = {
            "cancel": True,
            "errorMessage": error_msg,
        }
        return json.dumps(output), 0
