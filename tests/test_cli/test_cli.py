"""CallGuard CLI — Stream D implementation spec and tests.

This file serves two purposes:
1. Documents the exact CLI behavior (read the docstrings)
2. Provides the test suite the agent should make pass

Dependencies: click>=8.0, rich>=13.0 (under [cli] optional extra)
Entry point: callguard (via pyproject.toml [project.scripts])

Architecture:
- callguard/cli/__init__.py — empty
- callguard/cli/main.py — click group + 4 commands
- Each command is a thin wrapper around library functions
- Exit codes: 0 = success, 1 = validation/policy error, 2 = usage error

Run with: pytest tests/test_cli/ -v
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner


# ---------------------------------------------------------------------------
# Test fixtures — YAML bundles
# ---------------------------------------------------------------------------

VALID_BUNDLE = """\
apiVersion: callguard/v1
kind: ContractBundle

metadata:
  name: test-bundle
  description: "Valid test bundle."

defaults:
  mode: enforce

contracts:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' blocked."
      tags: [secrets]

  - id: bash-safety
    type: pre
    tool: bash
    when:
      args.command:
        matches: '\\brm\\s+-rf\\b'
    then:
      effect: deny
      message: "Destructive command blocked."
      tags: [safety]

  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      effect: warn
      message: "PII detected."
      tags: [pii]

  - id: session-cap
    type: session
    limits:
      max_tool_calls: 50
    then:
      effect: deny
      message: "Session limit reached."
      tags: [rate-limit]
"""

INVALID_WRONG_EFFECT = """\
apiVersion: callguard/v1
kind: ContractBundle

metadata:
  name: bad-effect

defaults:
  mode: enforce

contracts:
  - id: bad-rule
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm" }
    then:
      effect: warn
      message: "Wrong effect for pre."
"""

INVALID_DUPLICATE_ID = """\
apiVersion: callguard/v1
kind: ContractBundle

metadata:
  name: dupe-ids

defaults:
  mode: enforce

contracts:
  - id: same-id
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm" }
    then:
      effect: deny
      message: "First rule."

  - id: same-id
    type: pre
    tool: read_file
    when:
      args.path: { contains: ".env" }
    then:
      effect: deny
      message: "Duplicate."
"""

INVALID_BAD_REGEX = """\
apiVersion: callguard/v1
kind: ContractBundle

metadata:
  name: bad-regex

defaults:
  mode: enforce

contracts:
  - id: bad-regex-rule
    type: pre
    tool: bash
    when:
      args.command:
        matches: '[invalid(regex'
    then:
      effect: deny
      message: "Bad regex."
"""

INVALID_YAML_SYNTAX = """\
apiVersion: callguard/v1
kind: ContractBundle
metadata:
  name: broken
defaults:
  mode: enforce
contracts:
  - id: rule1
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm"
    then:
      effect: deny
      message: "Broken YAML."
"""

INVALID_MISSING_WHEN = """\
apiVersion: callguard/v1
kind: ContractBundle

metadata:
  name: no-when

defaults:
  mode: enforce

contracts:
  - id: no-when-rule
    type: pre
    tool: bash
    then:
      effect: deny
      message: "Missing when."
"""

BUNDLE_V2 = """\
apiVersion: callguard/v1
kind: ContractBundle

metadata:
  name: test-bundle-v2
  description: "Updated bundle."

defaults:
  mode: enforce

contracts:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", ".pem"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' blocked."
      tags: [secrets]

  - id: require-ticket
    type: pre
    tool: deploy_service
    when:
      principal.ticket_ref: { exists: false }
    then:
      effect: deny
      message: "Ticket required."
      tags: [compliance]

  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      effect: warn
      message: "PII detected."
      tags: [pii]

  - id: session-cap
    type: session
    limits:
      max_tool_calls: 100
    then:
      effect: deny
      message: "Session limit reached."
      tags: [rate-limit]
"""


def write_file(content: str, suffix: str = ".yaml") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# Import the CLI — agent implements this
# ---------------------------------------------------------------------------

# The agent should create callguard/cli/main.py with a click group:
#
#   import click
#
#   @click.group()
#   def cli():
#       """CallGuard — Runtime contracts for AI agents."""
#       pass
#
#   @cli.command()
#   @click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
#   def validate(files): ...
#
#   @cli.command()
#   @click.argument("file", type=click.Path(exists=True))
#   @click.option("--tool", required=True)
#   @click.option("--args", "tool_args", required=True)
#   @click.option("--environment", default="production")
#   @click.option("--principal-role", default=None)
#   @click.option("--principal-user", default=None)
#   @click.option("--principal-ticket", default=None)
#   def check(file, tool, tool_args, environment, principal_role, principal_user, principal_ticket): ...
#
#   @cli.command()
#   @click.argument("old_file", type=click.Path(exists=True))
#   @click.argument("new_file", type=click.Path(exists=True))
#   def diff(old_file, new_file): ...
#
#   @cli.command()
#   @click.argument("file", type=click.Path(exists=True))
#   @click.option("--audit-log", required=True, type=click.Path(exists=True))
#   @click.option("--output", default=None, type=click.Path())
#   def replay(file, audit_log, output): ...
#
# Entry point in pyproject.toml:
#   [project.scripts]
#   callguard = "callguard.cli.main:cli"


# This import will fail until the agent creates the module.
# The agent should make it work.
from callguard.cli.main import cli


# ---------------------------------------------------------------------------
# 1. callguard validate
# ---------------------------------------------------------------------------


class TestValidateCommand:
    """
    SPEC: callguard validate <file.yaml> [file2.yaml ...]

    Validates one or more contract bundle files.
    For each file:
    - Parse YAML (report syntax errors)
    - Validate against JSON Schema (report structural errors)
    - Check unique contract IDs
    - Compile all regexes and report invalid ones
    - Report contract summary (count by type)

    Exit code 0: all files valid
    Exit code 1: any file has errors

    Output format:
    ✓ contracts.yaml — 4 contracts (2 pre, 1 post, 1 session)
    ✗ bad.yaml:14 — error description
    """

    def test_valid_bundle(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 0
        assert "4 contract" in result.output
        # Should show type breakdown
        assert "pre" in result.output
        assert "post" in result.output
        assert "session" in result.output

    def test_multiple_valid_files(self):
        path1 = write_file(VALID_BUNDLE)
        path2 = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path1, path2])
        assert result.exit_code == 0

    def test_invalid_effect_reports_error(self):
        path = write_file(INVALID_WRONG_EFFECT)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 1
        # Should mention what's wrong
        assert "effect" in result.output.lower() or "warn" in result.output.lower()

    def test_duplicate_id_reports_error(self):
        path = write_file(INVALID_DUPLICATE_ID)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 1
        assert "same-id" in result.output or "duplicate" in result.output.lower()

    def test_bad_regex_reports_error(self):
        path = write_file(INVALID_BAD_REGEX)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 1
        assert "regex" in result.output.lower() or "pattern" in result.output.lower()

    def test_yaml_syntax_error(self):
        path = write_file(INVALID_YAML_SYNTAX)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 1
        # Should indicate it's a parse error
        assert "yaml" in result.output.lower() or "parse" in result.output.lower() or "syntax" in result.output.lower()

    def test_missing_when_reports_error(self):
        path = write_file(INVALID_MISSING_WHEN)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 1

    def test_nonexistent_file(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", "/nonexistent/file.yaml"])
        assert result.exit_code != 0

    def test_mixed_valid_and_invalid(self):
        """If one file is valid and another invalid, exit code should be 1."""
        valid_path = write_file(VALID_BUNDLE)
        invalid_path = write_file(INVALID_WRONG_EFFECT)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", valid_path, invalid_path])
        assert result.exit_code == 1
        # But valid file should still show success
        assert "4 contract" in result.output


# ---------------------------------------------------------------------------
# 2. callguard check
# ---------------------------------------------------------------------------


class TestCheckCommand:
    """
    SPEC: callguard check <file.yaml> --tool <name> --args '<json>'
                          [--environment <env>]
                          [--principal-role <role>]
                          [--principal-user <user>]
                          [--principal-ticket <ticket>]

    Dry-run: create a synthetic envelope and evaluate it against the contracts.
    Show which rules matched, which passed, which would deny/warn.

    Exit code 0: tool call would be ALLOWED
    Exit code 1: tool call would be DENIED

    Output should show:
    - Verdict (ALLOWED / DENIED)
    - Which rule denied (if denied): id, message, tags
    - How many rules were evaluated
    """

    def test_denied_sensitive_read(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", path,
            "--tool", "read_file",
            "--args", '{"path": "/app/.env"}',
        ])
        assert result.exit_code == 1
        assert "denied" in result.output.lower() or "DENIED" in result.output
        assert "block-env-reads" in result.output

    def test_allowed_safe_read(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", path,
            "--tool", "read_file",
            "--args", '{"path": "README.md"}',
        ])
        assert result.exit_code == 0
        assert "allowed" in result.output.lower() or "ALLOWED" in result.output

    def test_denied_destructive_bash(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", path,
            "--tool", "bash",
            "--args", '{"command": "rm -rf /tmp/data"}',
        ])
        assert result.exit_code == 1
        assert "bash-safety" in result.output

    def test_allowed_safe_bash(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", path,
            "--tool", "bash",
            "--args", '{"command": "ls -la"}',
        ])
        assert result.exit_code == 0

    def test_check_with_principal_role(self):
        path = write_file(BUNDLE_V2)
        runner = CliRunner()
        # BUNDLE_V2 has require-ticket which checks principal.ticket_ref exists: false
        # Providing a ticket should pass
        result = runner.invoke(cli, [
            "check", path,
            "--tool", "deploy_service",
            "--args", '{"service": "api"}',
            "--principal-role", "sre",
            "--principal-ticket", "JIRA-123",
        ])
        assert result.exit_code == 0

    def test_check_without_ticket_denied(self):
        path = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", path,
            "--tool", "deploy_service",
            "--args", '{"service": "api"}',
            "--principal-role", "sre",
            # no ticket
        ])
        assert result.exit_code == 1
        assert "require-ticket" in result.output or "ticket" in result.output.lower()

    def test_check_with_environment(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", path,
            "--tool", "read_file",
            "--args", '{"path": "safe.txt"}',
            "--environment", "staging",
        ])
        assert result.exit_code == 0

    def test_check_invalid_json_args(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", path,
            "--tool", "read_file",
            "--args", "not valid json",
        ])
        assert result.exit_code == 2 or result.exit_code == 1
        assert "json" in result.output.lower() or "invalid" in result.output.lower()

    def test_check_shows_evaluated_count(self):
        """Output should indicate how many rules were evaluated."""
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", path,
            "--tool", "read_file",
            "--args", '{"path": "safe.txt"}',
        ])
        assert result.exit_code == 0
        # Should mention number of rules evaluated
        assert "rule" in result.output.lower() or "contract" in result.output.lower()

    def test_unrelated_tool_passes(self):
        """Tool not targeted by any pre contract should pass."""
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", path,
            "--tool", "send_email",
            "--args", '{"to": "test@test.com"}',
        ])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# 3. callguard diff
# ---------------------------------------------------------------------------


class TestDiffCommand:
    """
    SPEC: callguard diff <old.yaml> <new.yaml>

    Compare two contract bundles and show what changed.
    Output categories:
    - Added: contracts in new but not in old (by id)
    - Removed: contracts in old but not in new (by id)
    - Changed: contracts with same id but different content
    - Unchanged: contracts identical in both

    Exit code 0: no changes (bundles identical)
    Exit code 1: changes detected

    This is designed for PR reviews and CI gates.
    """

    def test_identical_bundles(self):
        path1 = write_file(VALID_BUNDLE)
        path2 = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", path1, path2])
        assert result.exit_code == 0
        assert "no change" in result.output.lower() or "identical" in result.output.lower()

    def test_added_contract(self):
        """BUNDLE_V2 adds 'require-ticket' that's not in VALID_BUNDLE."""
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new])
        assert result.exit_code == 1
        assert "require-ticket" in result.output
        assert "add" in result.output.lower()

    def test_removed_contract(self):
        """Reverse: VALID_BUNDLE has 'bash-safety' that's not in BUNDLE_V2."""
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new])
        assert result.exit_code == 1
        assert "bash-safety" in result.output
        assert "remove" in result.output.lower()

    def test_changed_contract(self):
        """'block-env-reads' exists in both but BUNDLE_V2 adds '.pem' to contains_any."""
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new])
        assert result.exit_code == 1
        assert "block-env-reads" in result.output
        assert "change" in result.output.lower() or "modif" in result.output.lower()

    def test_changed_session_limits(self):
        """session-cap changes max_tool_calls from 50 to 100."""
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new])
        assert "session-cap" in result.output

    def test_diff_shows_summary(self):
        """Should show a summary line like '1 added, 1 removed, 2 changed, 1 unchanged'."""
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new])
        # Should have some kind of summary
        output_lower = result.output.lower()
        assert ("added" in output_lower or "removed" in output_lower or "changed" in output_lower)

    def test_diff_invalid_file(self):
        valid = write_file(VALID_BUNDLE)
        invalid = write_file(INVALID_WRONG_EFFECT)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", valid, invalid])
        # Should fail gracefully — can't diff an invalid bundle
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# 4. callguard replay
# ---------------------------------------------------------------------------


class TestReplayCommand:
    """
    SPEC: callguard replay <file.yaml> --audit-log <events.jsonl>
                           [--output <report.jsonl>]

    Replay an audit log against a (potentially different) contract bundle.
    For each event in the log:
    - Reconstruct the envelope (tool_name, tool_args, environment, principal)
    - Evaluate against the provided contracts
    - Compare: would the new contracts produce a different verdict?

    Output:
    - Summary: N events replayed, M would change
    - Changed events: old verdict → new verdict, which rule, why
    - If --output specified, write detailed report as JSONL

    Exit code 0: no changes (new contracts produce same verdicts)
    Exit code 1: changes detected

    Use case: "If we deploy this new contract bundle, which past tool calls
    would have been affected?"
    """

    @pytest.fixture
    def audit_log(self) -> str:
        """Create a sample audit log with events that match/don't match contracts."""
        events = [
            # Event 1: read_file on .env — was allowed (no contracts before)
            {
                "action": "call_allowed",
                "tool_name": "read_file",
                "tool_args": {"path": "/app/.env"},
                "environment": "production",
                "principal": {"user_id": "dev-1", "role": "developer"},
            },
            # Event 2: read_file on README — was allowed
            {
                "action": "call_allowed",
                "tool_name": "read_file",
                "tool_args": {"path": "README.md"},
                "environment": "production",
                "principal": {"user_id": "dev-1", "role": "developer"},
            },
            # Event 3: bash rm -rf — was allowed (no contracts before)
            {
                "action": "call_allowed",
                "tool_name": "bash",
                "tool_args": {"command": "rm -rf /tmp/cache"},
                "environment": "production",
                "principal": {"user_id": "dev-1", "role": "developer"},
            },
            # Event 4: safe bash — was allowed
            {
                "action": "call_allowed",
                "tool_name": "bash",
                "tool_args": {"command": "ls -la"},
                "environment": "production",
                "principal": {"user_id": "dev-1", "role": "developer"},
            },
            # Event 5: was denied by some old rule — should stay denied or change
            {
                "action": "call_denied",
                "tool_name": "deploy_service",
                "tool_args": {"service": "api"},
                "environment": "production",
                "principal": {"user_id": "dev-1", "role": "developer"},
            },
        ]
        path = write_file(
            "\n".join(json.dumps(e) for e in events),
            suffix=".jsonl",
        )
        return path

    def test_replay_detects_changes(self, audit_log):
        """Events 1 and 3 were allowed but would now be denied by VALID_BUNDLE."""
        contracts = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", contracts, "--audit-log", audit_log])
        assert result.exit_code == 1  # changes detected
        # Should report that some events would change
        assert "change" in result.output.lower() or "would" in result.output.lower()
        # Should mention the count
        assert "5" in result.output or "event" in result.output.lower()

    def test_replay_with_output_file(self, audit_log):
        contracts = write_file(VALID_BUNDLE)
        output_path = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name
        runner = CliRunner()
        result = runner.invoke(cli, [
            "replay", contracts,
            "--audit-log", audit_log,
            "--output", output_path,
        ])
        # Output file should be created with details
        output = Path(output_path)
        assert output.exists()
        lines = output.read_text().strip().split("\n")
        assert len(lines) >= 1
        # Each line should be valid JSON
        for line in lines:
            data = json.loads(line)
            assert "tool_name" in data
            assert "original_action" in data or "new_verdict" in data

    def test_replay_no_changes(self):
        """If the audit log only has events that match current contracts, no changes."""
        events = [
            {
                "action": "call_allowed",
                "tool_name": "send_email",
                "tool_args": {"to": "test@test.com"},
                "environment": "production",
                "principal": {"user_id": "dev-1"},
            },
        ]
        log_path = write_file(
            "\n".join(json.dumps(e) for e in events),
            suffix=".jsonl",
        )
        contracts = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", contracts, "--audit-log", log_path])
        assert result.exit_code == 0
        assert "no change" in result.output.lower() or "0" in result.output

    def test_replay_empty_log(self):
        log_path = write_file("", suffix=".jsonl")
        contracts = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", contracts, "--audit-log", log_path])
        assert result.exit_code == 0
        assert "0" in result.output

    def test_replay_invalid_contracts(self, audit_log):
        """Replay with invalid contracts should fail gracefully."""
        contracts = write_file(INVALID_WRONG_EFFECT)
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", contracts, "--audit-log", audit_log])
        assert result.exit_code != 0

    def test_replay_malformed_log_line(self):
        """Malformed JSONL lines should be skipped with a warning, not crash."""
        log_content = '{"action":"call_allowed","tool_name":"bash","tool_args":{"command":"ls"}}\nnot json\n{"action":"call_allowed","tool_name":"bash","tool_args":{"command":"pwd"}}'
        log_path = write_file(log_content, suffix=".jsonl")
        contracts = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", contracts, "--audit-log", log_path])
        # Should process 2 valid events and warn about 1 bad line
        assert "skip" in result.output.lower() or "warn" in result.output.lower() or "invalid" in result.output.lower()


# ---------------------------------------------------------------------------
# 5. General CLI behavior
# ---------------------------------------------------------------------------


class TestCLIGeneral:
    """Cross-cutting CLI concerns."""

    def test_help_text(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "validate" in result.output
        assert "check" in result.output
        assert "diff" in result.output
        assert "replay" in result.output

    def test_validate_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", "--help"])
        assert result.exit_code == 0

    def test_check_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--help"])
        assert result.exit_code == 0

    def test_check_missing_required_args(self):
        """check without --tool should fail."""
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["check", path])
        assert result.exit_code != 0

    def test_no_command(self):
        runner = CliRunner()
        result = runner.invoke(cli, [])
        assert result.exit_code == 0
        # Should show help/usage
        assert "Usage" in result.output or "validate" in result.output
