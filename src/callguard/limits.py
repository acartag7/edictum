"""Operation Limits — tool call and attempt caps."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OperationLimits:
    """Operation limits for an agent session.

    Two counter types:
    - max_attempts: caps ALL PreToolUse events (including denied)
    - max_tool_calls: caps EXECUTIONS only (PostToolUse)

    Both are checked. Whichever fires first wins.
    """

    max_attempts: int = 500
    max_tool_calls: int = 200
    max_calls_per_tool: dict[str, int] = field(default_factory=dict)
