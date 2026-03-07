"""Gate CLI subcommands — edictum gate *."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import click

try:
    from rich.console import Console
    from rich.markup import escape

    _console = Console(highlight=False)
    _err_console = Console(stderr=True, highlight=False)
except ImportError:
    raise ImportError("The CLI requires click and rich. Install with: pip install edictum[cli]")


@click.group()
def gate() -> None:
    """Coding assistant governance via hook interception."""


@gate.command("init")
@click.option("--server", default=None, help="Console server URL.")
@click.option("--api-key", default=None, help="Console API key.")
def gate_init(server: str | None, api_key: str | None) -> None:
    """Initialize gate configuration for the current machine."""
    from edictum.gate.config import DEFAULT_GATE_DIR

    gate_dir = DEFAULT_GATE_DIR
    config_path = gate_dir / "gate.yaml"

    if config_path.exists():
        if not click.confirm(f"{config_path} already exists. Overwrite?"):
            _console.print("[yellow]Aborted.[/yellow]")
            return

    # Create directory structure
    (gate_dir / "contracts").mkdir(parents=True, exist_ok=True)
    (gate_dir / "audit").mkdir(parents=True, exist_ok=True)
    (gate_dir / "cache").mkdir(parents=True, exist_ok=True)

    # Copy base contract template
    template_src = Path(__file__).parent.parent / "yaml_engine" / "templates" / "coding-assistant-base.yaml"
    template_dst = gate_dir / "contracts" / "base.yaml"
    if template_src.exists():
        shutil.copy2(str(template_src), str(template_dst))
        _console.print(f"  [green]Created[/green] {template_dst}")
    else:
        # Write minimal inline contract bundle
        minimal = (
            "apiVersion: edictum/v1\nkind: ContractBundle\n\n"
            "metadata:\n  name: base\n  description: Base gate contracts\n\n"
            "defaults:\n  mode: enforce\n\ncontracts: []\n"
        )
        template_dst.write_text(minimal)
        _console.print(f"  [yellow]Created[/yellow] {template_dst} (minimal — template not found)")

    # Write gate.yaml
    config_lines = [
        "# Edictum Gate configuration",
        "contracts:",
        f"  - {template_dst}",
        "",
    ]

    if server:
        config_lines.extend(
            [
                "console:",
                f"  url: {server}",
                f"  api_key: {api_key or ''}",
                '  agent_id: "${hostname}-${user}"',
                "",
            ]
        )

    config_lines.extend(
        [
            "audit:",
            "  enabled: true",
            f"  buffer_path: {gate_dir / 'audit' / 'wal.jsonl'}",
            "  flush_interval_seconds: 10",
            "  max_buffer_size_mb: 50",
            "",
            "redaction:",
            "  enabled: true",
            "  patterns:",
            "    - 'sk_live_\\w+'",
            "    - 'AKIA\\w{16}'",
            "    - 'ghp_\\w{36}'",
            "    - '-----BEGIN .* PRIVATE KEY-----'",
            "  replacement: '<REDACTED>'",
            "",
            "cache:",
            "  hash_mtime: true",
            "  ttl_seconds: 300",
            "",
            "fail_open: false",
        ]
    )

    config_path.write_text("\n".join(config_lines) + "\n")
    _console.print(f"  [green]Created[/green] {config_path}")
    _console.print(
        "\n[bold]Gate initialized.[/bold] " "Run [cyan]edictum gate install <assistant>[/cyan] to register hooks."
    )


@gate.command("check")
@click.option(
    "--format",
    "format_name",
    default="claude-code",
    type=click.Choice(["claude-code", "cline", "opencode", "raw"]),
    help="Output format (default: claude-code).",
)
@click.option("--contracts", "contracts_path", default=None, type=click.Path(), help="Override contract path.")
@click.option("--json", "json_flag", is_flag=True, default=False, help="Force JSON output.")
def gate_check(format_name: str, contracts_path: str | None, json_flag: bool) -> None:
    """Evaluate a tool call from stdin against contracts."""
    from edictum.gate.check import run_check
    from edictum.gate.config import GateConfig, load_gate_config

    config = load_gate_config()

    if contracts_path:
        config = GateConfig(
            contracts=(contracts_path,),
            console=config.console,
            audit=config.audit,
            redaction=config.redaction,
            cache=config.cache,
            fail_open=config.fail_open,
        )

    stdin_data = sys.stdin.read()
    cwd = os.getcwd()

    stdout_json, exit_code = run_check(stdin_data, format_name, config, cwd)
    sys.stdout.write(stdout_json)
    sys.stdout.write("\n")
    sys.exit(exit_code)


@gate.command("install")
@click.argument("assistant", type=click.Choice(["claude-code", "cline", "opencode"]))
def gate_install(assistant: str) -> None:
    """Register the gate hook with a coding assistant."""
    from edictum.gate.install import INSTALLER_REGISTRY

    installer, _ = INSTALLER_REGISTRY[assistant]
    result = installer()
    _console.print(result)


@gate.command("uninstall")
@click.argument("assistant", type=click.Choice(["claude-code", "cline", "opencode"]))
def gate_uninstall(assistant: str) -> None:
    """Remove the gate hook from a coding assistant."""
    from edictum.gate.install import INSTALLER_REGISTRY

    _, uninstaller = INSTALLER_REGISTRY[assistant]
    result = uninstaller()
    _console.print(result)


@gate.command("status")
def gate_status() -> None:
    """Show current gate configuration and health."""
    from edictum import __version__
    from edictum.gate.config import load_gate_config

    config = load_gate_config()

    _console.print(f"[bold]Edictum Gate[/bold] v{__version__}")

    # Contracts
    for cp in config.contracts:
        p = Path(cp)
        if p.exists():
            import hashlib

            h = hashlib.sha256(p.read_bytes()).hexdigest()[:12]
            try:
                from edictum.yaml_engine.loader import load_bundle

                bundle, _ = load_bundle(cp)
                count = len(bundle.get("contracts", []))
                _console.print(f"  Contracts: {cp} ({count} contracts, SHA256: {h}...)")
            except Exception:
                _console.print(f"  Contracts: {cp} (SHA256: {h}...)")
        else:
            _console.print(f"  Contracts: [red]{cp} (not found)[/red]")

    # Console
    if config.console and config.console.url:
        _console.print(f"  Console:   {config.console.url}")
    else:
        _console.print("  Console:   not configured")

    # Audit
    wal = Path(config.audit.buffer_path)
    if wal.exists():
        size = wal.stat().st_size
        line_count = sum(1 for _ in open(wal))
        _console.print(f"  Audit:     {line_count} events buffered ({size} bytes)")
    else:
        _console.print("  Audit:     no events")

    # Installed assistants
    home = Path.home()
    installed = []
    settings = home / ".claude" / "settings.json"
    if settings.exists():
        try:
            data = json.loads(settings.read_text())
            for entry in data.get("hooks", {}).get("PreToolUse", []):
                for h in entry.get("hooks", []):
                    if isinstance(h, dict) and "edictum gate check" in h.get("command", ""):
                        installed.append("claude-code")
                        break
        except Exception:
            pass

    cline_hook = home / "Documents" / "Cline" / "Rules" / "Hooks" / "edictum-gate.sh"
    if cline_hook.exists():
        installed.append("cline")

    opencode_plugin = home / ".opencode" / "plugins" / "edictum-gate.ts"
    if opencode_plugin.exists():
        installed.append("opencode")

    if installed:
        _console.print(f"  Installed: {', '.join(installed)}")
    else:
        _console.print("  Installed: none")


@gate.command("audit")
@click.option("--limit", default=20, help="Number of recent events to show.")
@click.option("--tool", default=None, help="Filter by tool name.")
@click.option("--verdict", default=None, type=click.Choice(["allow", "deny"]), help="Filter by verdict.")
def gate_audit(limit: int, tool: str | None, verdict: str | None) -> None:
    """Show recent audit events from the local write-ahead log."""
    from edictum.gate.audit_buffer import AuditBuffer
    from edictum.gate.config import load_gate_config

    config = load_gate_config()
    buffer = AuditBuffer(config.audit, config.redaction)
    events = buffer.read_recent(limit=limit, tool=tool, verdict=verdict)

    if not events:
        _console.print("[dim]No audit events found.[/dim]")
        return

    try:
        from rich.table import Table

        table = Table(show_header=True)
        table.add_column("Time", style="dim", width=20)
        table.add_column("Tool")
        table.add_column("Verdict")
        table.add_column("Contract")
        table.add_column("Args Preview", max_width=40)

        for e in events:
            ts = e.get("timestamp", "")[:19]
            v = e.get("verdict", "")
            verdict_styled = f"[red]{v}[/red]" if v == "deny" else f"[green]{v}[/green]"
            table.add_row(
                ts,
                e.get("tool_name", ""),
                verdict_styled,
                e.get("contract_id", "") or "",
                escape(e.get("args_preview", "")[:40]),
            )
        _console.print(table)
    except ImportError:
        for e in events:
            _console.print(json.dumps(e))


@gate.command("sync")
def gate_sync() -> None:
    """Force-sync contracts from Console."""
    from edictum.gate.config import load_gate_config

    config = load_gate_config()
    if not config.console or not config.console.url:
        _err_console.print("[red]Console not configured. Run: edictum gate init --server URL[/red]")
        sys.exit(1)

    try:
        from edictum.gate.audit_buffer import AuditBuffer

        buffer = AuditBuffer(config.audit, config.redaction)
        sent = buffer.flush_to_console(config.console)
        _console.print(f"Flushed {sent} audit events to Console")
    except ImportError:
        _err_console.print(
            "[red]Console sync requires edictum[server]. " "Install with: pip install edictum[server,gate][/red]"
        )
        sys.exit(1)
