"""Edictum CLI — validate, check, diff, and replay contract bundles."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

try:
    from rich.console import Console
    from rich.markup import escape

    _console = Console(highlight=False)
    _err_console = Console(stderr=True, highlight=False)
except ImportError:
    raise ImportError("The CLI requires click and rich. " "Install them with: pip install edictum[cli]")

from edictum import EdictumConfigError
from edictum.envelope import Principal, ToolEnvelope, create_envelope
from edictum.yaml_engine.loader import load_bundle

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_and_compile(path: str) -> tuple[dict, str, Any]:
    """Load a YAML bundle, return (bundle_data, bundle_hash, compiled).

    Raises EdictumConfigError on invalid bundles.
    """
    from edictum.yaml_engine.compiler import compile_contracts

    bundle_data, bundle_hash = load_bundle(path)
    compiled = compile_contracts(bundle_data)
    return bundle_data, str(bundle_hash), compiled


def _build_envelope(
    tool_name: str,
    tool_args: dict,
    environment: str = "production",
    principal: Principal | None = None,
) -> ToolEnvelope:
    """Build a synthetic ToolEnvelope for dry-run evaluation."""
    return create_envelope(
        tool_name=tool_name,
        tool_input=tool_args,
        environment=environment,
        principal=principal,
    )


def _evaluate_preconditions(
    compiled: Any,
    envelope: ToolEnvelope,
) -> tuple[str, str | None, str | None, list[dict]]:
    """Evaluate compiled preconditions against an envelope.

    Returns (verdict, rule_id, message, evaluated_records).
    verdict is "denied" or "allowed".
    """
    evaluated: list[dict] = []

    for fn in compiled.preconditions:
        tool_filter = getattr(fn, "_edictum_tool", "*")
        if tool_filter != "*" and tool_filter != envelope.tool_name:
            continue

        verdict = fn(envelope)
        record = {
            "id": getattr(fn, "_edictum_id", "unknown"),
            "passed": verdict.passed,
            "message": verdict.message,
        }
        if verdict.metadata:
            record["metadata"] = verdict.metadata
        evaluated.append(record)

        if not verdict.passed:
            return "denied", record["id"], verdict.message, evaluated

    return "allowed", None, None, evaluated


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Edictum — Runtime contracts for AI agents."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@cli.command()
def version() -> None:
    """Show the installed edictum version."""
    from edictum import __version__

    click.echo(f"edictum {__version__}")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("files", nargs=-1, required=True, type=click.Path())
def validate(files: tuple[str, ...]) -> None:
    """Validate one or more contract bundle files."""
    has_errors = False

    for file_path in files:
        path = Path(file_path)
        if not path.exists():
            _err_console.print(f"[red]  {escape(str(path))} — file not found[/red]")
            has_errors = True
            continue

        try:
            bundle_data, _ = load_bundle(file_path)
        except EdictumConfigError as e:
            _err_console.print(f"[red]  {escape(path.name)} — {escape(str(e))}[/red]")
            has_errors = True
            continue
        except Exception as e:
            _err_console.print(f"[red]  {escape(path.name)} — {escape(str(e))}[/red]")
            has_errors = True
            continue

        contracts = bundle_data.get("contracts", [])
        counts: dict[str, int] = {}
        for c in contracts:
            ct = c.get("type", "unknown")
            counts[ct] = counts.get(ct, 0) + 1

        total = sum(counts.values())
        breakdown = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        _console.print(f"[green]  {escape(path.name)}[/green] — {total} contracts ({breakdown})")

    sys.exit(1 if has_errors else 0)


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--tool", required=True, help="Tool name to check.")
@click.option("--args", "tool_args", required=True, help="Tool arguments as JSON.")
@click.option("--environment", default="production", help="Environment name.")
@click.option("--principal-role", default=None, help="Principal role.")
@click.option("--principal-user", default=None, help="Principal user ID.")
@click.option("--principal-ticket", default=None, help="Principal ticket ref.")
def check(
    file: str,
    tool: str,
    tool_args: str,
    environment: str,
    principal_role: str | None,
    principal_user: str | None,
    principal_ticket: str | None,
) -> None:
    """Dry-run a tool call against contracts."""
    # Parse JSON args
    try:
        parsed_args = json.loads(tool_args)
    except json.JSONDecodeError as e:
        _err_console.print(f"[red]Invalid JSON in --args: {escape(str(e))}[/red]")
        sys.exit(2)

    # Load contracts
    try:
        _, _, compiled = _load_and_compile(file)
    except EdictumConfigError as e:
        _err_console.print(f"[red]Failed to load contracts: {escape(str(e))}[/red]")
        sys.exit(1)

    # Build principal
    principal = None
    if principal_role or principal_user or principal_ticket:
        principal = Principal(
            user_id=principal_user,
            role=principal_role,
            ticket_ref=principal_ticket,
        )

    # Build envelope
    envelope = _build_envelope(tool, parsed_args, environment, principal)

    # Evaluate
    verdict, rule_id, message, evaluated = _evaluate_preconditions(compiled, envelope)

    n_evaluated = len(evaluated)

    if verdict == "denied":
        _console.print(f"[red bold]DENIED[/red bold] by rule [yellow]{escape(rule_id or '')}[/yellow]")
        _console.print(f"  Message: {escape(message or '')}")
        # Show tags if available
        deny_record = evaluated[-1] if evaluated else {}
        tags = deny_record.get("metadata", {}).get("tags", [])
        if tags:
            _console.print(f"  Tags: {', '.join(str(t) for t in tags)}")
        _console.print(f"  Rules evaluated: {n_evaluated}")
        sys.exit(1)
    else:
        _console.print("[green bold]ALLOWED[/green bold]")
        _console.print(f"  Rules evaluated: {n_evaluated} contract(s)")
        sys.exit(0)


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def _contracts_by_id(bundle: dict) -> dict[str, dict]:
    """Index contracts by their id."""
    return {c["id"]: c for c in bundle.get("contracts", [])}


@cli.command()
@click.argument("old_file", type=click.Path(exists=True))
@click.argument("new_file", type=click.Path(exists=True))
def diff(old_file: str, new_file: str) -> None:
    """Compare two contract bundles and show changes."""
    try:
        old_bundle, _, _ = _load_and_compile(old_file)
    except EdictumConfigError as e:
        _err_console.print(f"[red]Failed to load old bundle: {escape(str(e))}[/red]")
        sys.exit(1)

    try:
        new_bundle, _, _ = _load_and_compile(new_file)
    except EdictumConfigError as e:
        _err_console.print(f"[red]Failed to load new bundle: {escape(str(e))}[/red]")
        sys.exit(1)

    old_contracts = _contracts_by_id(old_bundle)
    new_contracts = _contracts_by_id(new_bundle)

    old_ids = set(old_contracts.keys())
    new_ids = set(new_contracts.keys())

    added = sorted(new_ids - old_ids)
    removed = sorted(old_ids - new_ids)
    common = sorted(old_ids & new_ids)

    changed: list[str] = []
    unchanged: list[str] = []

    for cid in common:
        if old_contracts[cid] != new_contracts[cid]:
            changed.append(cid)
        else:
            unchanged.append(cid)

    has_changes = bool(added or removed or changed)

    if added:
        _console.print("[green bold]Added:[/green bold]")
        for cid in added:
            c = new_contracts[cid]
            _console.print(f"  + {cid} (type: {c.get('type', '?')})")

    if removed:
        _console.print("[red bold]Removed:[/red bold]")
        for cid in removed:
            c = old_contracts[cid]
            _console.print(f"  - {cid} (type: {c.get('type', '?')})")

    if changed:
        _console.print("[yellow bold]Changed:[/yellow bold]")
        for cid in changed:
            _console.print(f"  ~ {cid}")

    if unchanged and not has_changes:
        _console.print("[dim]No changes detected. Bundles are identical.[/dim]")

    # Summary
    parts = []
    if added:
        parts.append(f"{len(added)} added")
    if removed:
        parts.append(f"{len(removed)} removed")
    if changed:
        parts.append(f"{len(changed)} changed")
    if unchanged:
        parts.append(f"{len(unchanged)} unchanged")
    if parts:
        _console.print(f"\nSummary: {', '.join(parts)}")

    sys.exit(1 if has_changes else 0)


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--audit-log", required=True, type=click.Path(exists=True), help="JSONL audit log.")
@click.option("--output", default=None, type=click.Path(), help="Write detailed report as JSONL.")
def replay(file: str, audit_log: str, output: str | None) -> None:
    """Replay an audit log against contracts and detect verdict changes."""
    # Load contracts
    try:
        _, _, compiled = _load_and_compile(file)
    except EdictumConfigError as e:
        _err_console.print(f"[red]Failed to load contracts: {escape(str(e))}[/red]")
        sys.exit(1)

    # Read audit log
    log_path = Path(audit_log)
    raw = log_path.read_text().strip()
    lines = raw.split("\n") if raw else []

    total = 0
    changes = 0
    skipped = 0
    report_lines: list[dict] = []

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            _err_console.print(f"[yellow]Warning: skipped invalid JSON on line {i}[/yellow]")
            skipped += 1
            continue

        total += 1
        original_action = event.get("action", "unknown")
        tool_name = event.get("tool_name", "unknown")
        tool_args = event.get("tool_args", {})
        environment = event.get("environment", "production")

        # Reconstruct principal
        principal = None
        p_data = event.get("principal")
        if p_data and isinstance(p_data, dict):
            principal = Principal(
                user_id=p_data.get("user_id"),
                role=p_data.get("role"),
                ticket_ref=p_data.get("ticket_ref"),
                claims=p_data.get("claims", {}),
            )

        # Build envelope and evaluate
        envelope = _build_envelope(tool_name, tool_args, environment, principal)
        new_verdict, rule_id, message, evaluated = _evaluate_preconditions(compiled, envelope)

        # Map to action strings for comparison
        new_action = "call_denied" if new_verdict == "denied" else "call_allowed"
        changed = original_action != new_action

        if changed:
            changes += 1

        report_entry = {
            "tool_name": tool_name,
            "tool_args": tool_args,
            "environment": environment,
            "original_action": original_action,
            "new_verdict": new_verdict,
            "changed": changed,
        }
        if rule_id:
            report_entry["denied_by"] = rule_id
            report_entry["message"] = message
        report_lines.append(report_entry)

    # Write output file if requested
    if output:
        with open(output, "w") as f:
            for entry in report_lines:
                f.write(json.dumps(entry) + "\n")

    # Summary
    _console.print(f"\nReplayed {total} events, {changes} would change")
    if skipped:
        _console.print(f"  ({skipped} lines skipped due to invalid JSON)")

    if changes:
        _console.print("\n[yellow]Changed verdicts:[/yellow]")
        for entry in report_lines:
            if entry["changed"]:
                _console.print(f"  {entry['tool_name']}: " f"{entry['original_action']} -> {entry['new_verdict']}")
                if entry.get("denied_by"):
                    _console.print(f"    Rule: {entry['denied_by']}")
    else:
        _console.print("[green]No changes detected.[/green]")

    sys.exit(1 if changes else 0)


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------


@cli.command("test")
@click.argument("file", type=click.Path(exists=True))
@click.option("--cases", required=True, type=click.Path(exists=True), help="YAML file with test cases.")
def test_cmd(file: str, cases: str) -> None:
    """Test contracts against YAML test cases (preconditions only).

    Evaluates each test case against the contract bundle and reports
    pass/fail results. Postcondition testing is not supported — this
    command evaluates preconditions only since postconditions require
    actual tool output.

    Exit code 0: all cases pass.
    Exit code 1: one or more cases fail.
    """
    import yaml

    # Load contracts
    try:
        _, _, compiled = _load_and_compile(file)
    except EdictumConfigError as e:
        _err_console.print(f"[red]Failed to load contracts: {escape(str(e))}[/red]")
        sys.exit(1)

    # Load test cases
    try:
        with open(cases) as f:
            cases_data = yaml.safe_load(f)
    except Exception as e:
        _err_console.print(f"[red]Failed to load test cases: {escape(str(e))}[/red]")
        sys.exit(1)

    if not isinstance(cases_data, dict) or "cases" not in cases_data:
        _err_console.print("[red]Test cases file must contain a 'cases' list.[/red]")
        sys.exit(1)

    test_cases = cases_data["cases"]
    if not isinstance(test_cases, list):
        _err_console.print("[red]'cases' must be a list.[/red]")
        sys.exit(1)

    passed = 0
    failed = 0
    total = len(test_cases)

    valid_expects = {"allow", "deny"}

    for i, tc in enumerate(test_cases):
        tc_id = tc.get("id", f"case-{i + 1}")

        # Validate required fields
        missing = [f for f in ("tool", "expect") if f not in tc]
        if missing:
            _err_console.print(f"[red]  {escape(tc_id)}: missing required field(s): {', '.join(missing)}[/red]")
            sys.exit(2)

        tool = tc["tool"]
        args = tc.get("args", {})
        expect = tc["expect"].lower()

        if expect not in valid_expects:
            _err_console.print(
                f"[red]  {escape(tc_id)}: invalid expect value '{escape(tc['expect'])}' "
                f"(must be one of: {', '.join(sorted(valid_expects))})[/red]"
            )
            sys.exit(2)

        match_contract = tc.get("match_contract")

        # Build principal
        principal = None
        principal_data = tc.get("principal")
        if principal_data and isinstance(principal_data, dict):
            principal = Principal(
                role=principal_data.get("role"),
                user_id=principal_data.get("user_id"),
                ticket_ref=principal_data.get("ticket_ref"),
                claims=principal_data.get("claims", {}),
            )

        # Build envelope and evaluate
        envelope = _build_envelope(tool, args, principal=principal)
        verdict, rule_id, message, evaluated = _evaluate_preconditions(compiled, envelope)

        # Map verdict to expected format
        actual = "deny" if verdict == "denied" else "allow"

        # Check match_contract
        contract_match_ok = True
        if match_contract and actual == "deny":
            contract_match_ok = rule_id == match_contract

        if actual == expect and contract_match_ok:
            passed += 1
            detail = f"{tool} {json.dumps(args)}"
            verdict_label = "DENIED" if actual == "deny" else "ALLOWED"
            contract_info = f" ({rule_id})" if rule_id else ""
            _console.print(f"[green]  {escape(tc_id)}:[/green] {escape(detail)} -> {verdict_label}{contract_info}")
        else:
            failed += 1
            detail = f"{tool} {json.dumps(args)}"
            actual_label = "DENIED" if actual == "deny" else "ALLOWED"
            expected_label = expect.upper()
            if not contract_match_ok:
                _console.print(
                    f"[red]  {escape(tc_id)}:[/red] {escape(detail)} -> "
                    f"expected contract {escape(match_contract)}, got {escape(rule_id or 'none')}"
                )
            else:
                _console.print(
                    f"[red]  {escape(tc_id)}:[/red] {escape(detail)} -> "
                    f"expected {expected_label}, got {actual_label}"
                )

    # Summary
    _console.print(f"\n{passed}/{total} passed, {failed} failed")
    sys.exit(1 if failed else 0)
