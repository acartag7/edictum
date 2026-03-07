"""OpenCode format handler — tool.execute.before plugin stdin/stdout."""

from __future__ import annotations

import json
import os

OPENCODE_TOOL_MAP: dict[str, str] = {
    "bash": "Bash",
    "shell": "Bash",
    "read": "Read",
    "write": "Write",
    "patch": "Edit",
    "glob": "Glob",
    "grep": "Grep",
    "browser": "WebFetch",
}


class OpenCodeFormat:
    """Parse OpenCode tool.execute.before plugin stdin, format output."""

    def parse_stdin(self, data: dict) -> tuple[str, dict, str]:
        """Extract tool_name, tool_input, cwd from OpenCode stdin.

        OpenCode uses 'tool' and 'input' keys with lowercase tool names.
        """
        raw_tool = data.get("tool", "")
        tool_name = OPENCODE_TOOL_MAP.get(raw_tool, raw_tool)
        tool_input = data.get("input", {})
        cwd = data.get("workingDirectory", os.getcwd())
        return tool_name, tool_input, cwd

    def format_output(
        self, verdict: str, contract_id: str | None, reason: str | None, evaluated: int
    ) -> tuple[str, int]:
        """Format verdict for OpenCode.

        Allow: {"allow": true}.
        Deny: {"allow": false, "reason": "..."}.
        """
        if verdict != "deny":
            return json.dumps({"allow": True}), 0

        deny_reason = ""
        if contract_id and reason:
            deny_reason = f"Contract '{contract_id}': {reason}"
        elif reason:
            deny_reason = reason
        elif contract_id:
            deny_reason = f"Denied by contract '{contract_id}'"

        output = {
            "allow": False,
            "reason": deny_reason,
        }
        return json.dumps(output), 0
