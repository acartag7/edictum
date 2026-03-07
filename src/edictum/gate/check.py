"""Gate check — stdin -> ToolEnvelope -> evaluate -> stdout."""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

CATEGORY_MAP: dict[str, str] = {
    "Bash": "shell",
    "Read": "file.read",
    "Write": "file.write",
    "Edit": "file.edit",
    "Glob": "file.search",
    "Grep": "file.search",
    "WebFetch": "browser",
    "WebSearch": "browser",
    "NotebookEdit": "notebook",
    "Task": "task",
}

# Tools subject to scope enforcement (writes/edits outside cwd)
_SCOPE_TOOLS = frozenset({"Write", "Edit"})

# Max stdin size (10 MB)
_MAX_STDIN_SIZE = 10 * 1024 * 1024


def resolve_category(tool_name: str) -> str:
    """Map a tool name to its category string."""
    if tool_name in CATEGORY_MAP:
        return CATEGORY_MAP[tool_name]
    if tool_name.startswith("mcp__"):
        return "mcp"
    return "unknown"


def _check_scope(file_path: str | None, cwd: str) -> tuple[bool, str]:
    """Check if file_path is within cwd. Returns (is_within, reason)."""
    if not file_path:
        return True, ""
    try:
        real = os.path.realpath(file_path)
        real_cwd = os.path.realpath(cwd)
        if real == real_cwd or real.startswith(real_cwd + os.sep):
            return True, ""
        return False, f"Denied: file path '{file_path}' is outside the project directory"
    except (OSError, ValueError):
        return False, f"Denied: cannot resolve file path '{file_path}'"


def _validate_stdin(data: Any) -> tuple[str, dict, str] | tuple[None, None, str]:
    """Validate basic stdin structure. Returns (tool_name, tool_input, error)."""
    if not isinstance(data, dict):
        return None, None, "stdin must be a JSON object"

    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input")

    if not tool_name or not isinstance(tool_name, str):
        return None, None, "missing or invalid tool_name"

    if tool_input is not None and not isinstance(tool_input, dict):
        return None, None, "tool_input must be a JSON object"

    return tool_name, tool_input or {}, ""


def run_check(
    stdin_data: str,
    format_name: str,
    config: Any,
    cwd: str,
) -> tuple[str, int]:
    """Core gate check: parse stdin, evaluate contracts, return (stdout_json, exit_code).

    Args:
        stdin_data: Raw JSON string from stdin.
        format_name: Output format name (claude-code, cline, opencode, raw).
        config: GateConfig instance.
        cwd: Working directory for scope enforcement.

    Returns:
        Tuple of (JSON string for stdout, exit code).
    """
    from edictum.gate.formats import get_format

    start = time.perf_counter_ns()
    format_handler = get_format(format_name)

    try:
        return _run_check_inner(stdin_data, format_handler, config, cwd, start)
    except Exception as exc:
        # Fail-closed by default
        if getattr(config, "fail_open", False):
            return format_handler.format_output("allow", None, None, 0)
        reason = f"Gate internal error: {exc}"
        return format_handler.format_output("deny", None, reason, 0)


def _run_check_inner(
    stdin_data: str,
    format_handler: Any,
    config: Any,
    cwd: str,
    start: int,
) -> tuple[str, int]:
    """Inner check logic, separated so exceptions propagate to run_check."""
    # Size check
    if len(stdin_data) > _MAX_STDIN_SIZE:
        return format_handler.format_output("deny", None, "Denied: stdin payload too large", 0)

    # Parse JSON
    try:
        parsed = json.loads(stdin_data)
    except (json.JSONDecodeError, ValueError):
        return format_handler.format_output("deny", None, "Denied: invalid JSON in stdin", 0)

    if not isinstance(parsed, dict):
        return format_handler.format_output("deny", None, "Denied: stdin must be a JSON object", 0)

    # Parse format-specific fields
    try:
        tool_name, tool_input, parsed_cwd = format_handler.parse_stdin(parsed)
    except Exception:
        return format_handler.format_output("deny", None, "Denied: failed to parse stdin", 0)

    effective_cwd = parsed_cwd or cwd

    # Validate tool_name
    if not tool_name or not isinstance(tool_name, str):
        return format_handler.format_output("deny", None, "Denied: missing or invalid tool_name", 0)

    # Reject control characters in tool_name
    if any(ord(c) < 32 or c == "\x7f" for c in tool_name):
        return format_handler.format_output("deny", None, "Denied: invalid characters in tool_name", 0)

    if not isinstance(tool_input, dict):
        return format_handler.format_output("deny", None, "Denied: tool_input must be a JSON object", 0)

    # Resolve category
    category = resolve_category(tool_name)

    # Load and evaluate contracts
    from edictum import Edictum, EdictumConfigError

    contract_paths = list(getattr(config, "contracts", ()))
    fail_open = getattr(config, "fail_open", False)

    if not contract_paths:
        if fail_open:
            return format_handler.format_output("allow", None, None, 0)
        return format_handler.format_output("deny", None, "Denied: no contract paths configured", 0)

    # Filter to existing paths
    existing_paths = [p for p in contract_paths if os.path.exists(p)]
    if not existing_paths:
        if fail_open:
            return format_handler.format_output("allow", None, None, 0)
        return format_handler.format_output("deny", None, "Denied: no contract files found", 0)

    try:
        guard = Edictum.from_yaml(*existing_paths)
    except (EdictumConfigError, Exception):
        if getattr(config, "fail_open", False):
            return format_handler.format_output("allow", None, None, 0)
        return format_handler.format_output("deny", None, "Denied: failed to load contracts", 0)

    # Evaluate
    result = guard.evaluate(tool_name, tool_input)

    verdict = result.verdict  # "allow", "deny", or "warn"
    if verdict == "warn":
        verdict = "allow"  # Gate is binary: allow or deny

    contract_id = None
    reason = None
    if result.contracts:
        for c in result.contracts:
            if not c.passed and not c.observed:
                contract_id = c.contract_id
                reason = c.message
                break

    # Scope enforcement (programmatic, not YAML)
    if verdict == "allow" and tool_name in _SCOPE_TOOLS:
        file_path = tool_input.get("file_path") or tool_input.get("filePath") or tool_input.get("path")
        is_within, scope_reason = _check_scope(file_path, effective_cwd)
        if not is_within:
            verdict = "deny"
            contract_id = "gate-scope-enforcement"
            reason = scope_reason

    duration_ms = (time.perf_counter_ns() - start) // 1_000_000
    evaluated_count = result.contracts_evaluated

    # Write audit event (sync, non-blocking on failure)
    _write_audit(
        config,
        tool_name,
        tool_input,
        category,
        verdict,
        contract_id,
        reason,
        effective_cwd,
        duration_ms,
        evaluated_count,
        format_handler.__class__.__name__,
    )

    return format_handler.format_output(verdict, contract_id, reason, evaluated_count)


def _write_audit(
    config: Any,
    tool_name: str,
    tool_input: dict,
    category: str,
    verdict: str,
    contract_id: str | None,
    reason: str | None,
    cwd: str,
    duration_ms: int,
    contracts_evaluated: int,
    assistant: str,
) -> None:
    """Write audit event to WAL if audit is enabled. Never raises."""
    try:
        audit_config = getattr(config, "audit", None)
        if audit_config is None or not getattr(audit_config, "enabled", True):
            return

        from edictum.gate.audit_buffer import AuditBuffer, build_audit_event

        redaction_config = getattr(config, "redaction", None)
        buffer = AuditBuffer(audit_config, redaction_config)
        event = build_audit_event(
            tool_name=tool_name,
            tool_input=tool_input,
            category=category,
            verdict=verdict,
            contract_id=contract_id,
            reason=reason,
            cwd=cwd,
            duration_ms=duration_ms,
            contracts_evaluated=contracts_evaluated,
            assistant=assistant,
        )
        buffer.write(event)
    except Exception:
        pass  # Audit failure must never block the gate check


def main() -> None:
    """Entry point for `python -m edictum.gate`."""
    import argparse

    parser = argparse.ArgumentParser(description="Edictum Gate check")
    parser.add_argument(
        "--format",
        dest="format_name",
        default="claude-code",
        choices=["claude-code", "cline", "opencode", "raw"],
        help="Output format (default: claude-code)",
    )
    parser.add_argument("--contracts", dest="contracts_path", default=None, help="Override contract path")
    args = parser.parse_args()

    from edictum.gate.config import GateConfig, load_gate_config

    config = load_gate_config()

    if args.contracts_path:
        config = GateConfig(
            contracts=(args.contracts_path,),
            console=config.console,
            audit=config.audit,
            redaction=config.redaction,
            cache=config.cache,
            fail_open=config.fail_open,
        )

    stdin_data = sys.stdin.read()
    cwd = os.getcwd()

    stdout_json, exit_code = run_check(stdin_data, args.format_name, config, cwd)
    sys.stdout.write(stdout_json)
    sys.stdout.write("\n")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
