"""Tests for redaction in gate audit events."""

from __future__ import annotations

import json
from pathlib import Path

from edictum.gate.audit_buffer import GateAuditEvent, build_audit_event
from edictum.gate.config import RedactionConfig


def _make_event(**kwargs) -> GateAuditEvent:
    defaults = {
        "timestamp": "2026-03-01T00:00:00+00:00",
        "session_id": "",
        "agent_id": "",
        "assistant": "claude-code",
        "tool_name": "Bash",
        "tool_category": "shell",
        "args_preview": "{}",
        "verdict": "allow",
        "contract_id": None,
        "reason": None,
        "cwd": "/project",
        "duration_ms": 2,
        "contracts_evaluated": 5,
    }
    defaults.update(kwargs)
    return GateAuditEvent(**defaults)


class TestRedactionBeforeWal:
    def test_redaction_before_wal_write(self, tmp_path: Path) -> None:
        """Secrets are redacted in args_preview before building the event."""
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"command": "export TOKEN=sk_live_abc123def456"},
            category="shell",
            verdict="allow",
            contract_id=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            contracts_evaluated=5,
            assistant="claude-code",
            redaction_config=RedactionConfig(
                patterns=("sk_live_\\w+",),
                replacement="<REDACTED>",
            ),
        )
        assert "sk_live_" not in event.args_preview
        assert "<REDACTED>" in event.args_preview

    def test_redaction_aws_key(self) -> None:
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"key": "AKIAIOSFODNN7EXAMPLE"},
            category="shell",
            verdict="allow",
            contract_id=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            contracts_evaluated=5,
            assistant="claude-code",
            redaction_config=RedactionConfig(
                patterns=("AKIA\\w{16}",),
                replacement="<REDACTED>",
            ),
        )
        assert "AKIA" not in event.args_preview

    def test_redaction_github_token(self) -> None:
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
            category="shell",
            verdict="allow",
            contract_id=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            contracts_evaluated=5,
            assistant="claude-code",
            redaction_config=RedactionConfig(
                patterns=("ghp_\\w{36}",),
                replacement="<REDACTED>",
            ),
        )
        assert "ghp_" not in event.args_preview

    def test_redaction_custom_pattern(self) -> None:
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"data": "my_custom_secret_12345"},
            category="shell",
            verdict="allow",
            contract_id=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            contracts_evaluated=5,
            assistant="claude-code",
            redaction_config=RedactionConfig(
                patterns=("my_custom_secret_\\d+",),
                replacement="<REDACTED>",
            ),
        )
        assert "my_custom_secret_" not in event.args_preview

    def test_redaction_preserves_structure(self) -> None:
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"command": "ls", "safe_field": "hello"},
            category="shell",
            verdict="allow",
            contract_id=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            contracts_evaluated=5,
            assistant="claude-code",
        )
        parsed = json.loads(event.args_preview)
        assert parsed["command"] == "ls"
        assert parsed["safe_field"] == "hello"

    def test_redaction_policy_from_config(self) -> None:
        from edictum.gate.audit_buffer import _build_redaction_policy

        config = RedactionConfig(
            patterns=("secret_\\d+",),
            replacement="***",
        )
        policy = _build_redaction_policy(config)
        result = policy.redact_args({"value": "secret_12345"})
        # The custom pattern is a regex substitution on string values
        assert isinstance(result, dict)
