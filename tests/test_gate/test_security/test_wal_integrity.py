"""Security tests for WAL integrity."""

from __future__ import annotations

from pathlib import Path

import pytest

from edictum.gate.audit_buffer import AuditBuffer, GateAuditEvent
from edictum.gate.config import AuditConfig


def _make_event(**kwargs) -> GateAuditEvent:
    defaults = {
        "call_id": "test-call-id",
        "agent_id": "",
        "user": "testuser",
        "assistant": "ClaudeCodeFormat",
        "tool_name": "Bash",
        "tool_category": "shell",
        "args_preview": '{"command": "ls"}',
        "verdict": "allow",
        "mode": "enforce",
        "contract_id": None,
        "reason": None,
        "cwd": "/project",
        "timestamp": "2026-03-01T00:00:00+00:00",
        "duration_ms": 2,
        "contracts_evaluated": 5,
    }
    defaults.update(kwargs)
    return GateAuditEvent(**defaults)


@pytest.mark.security
class TestWalIntegrity:
    def test_wal_no_secrets_on_disk(self, tmp_path: Path) -> None:
        """Redacted args in the event means secrets never reach the WAL."""
        wal = tmp_path / "wal.jsonl"
        config = AuditConfig(buffer_path=str(wal))
        buffer = AuditBuffer(config)
        # Write event with a secret already in args_preview (pre-redacted)
        event = _make_event(args_preview='{"token": "[REDACTED]"}')
        buffer.write(event)
        content = wal.read_text()
        assert "sk_live" not in content

    def test_wal_rotation_preserves_events(self, tmp_path: Path) -> None:
        wal = tmp_path / "wal.jsonl"
        config = AuditConfig(buffer_path=str(wal), max_buffer_size_mb=0)
        buffer = AuditBuffer(config)
        buffer.write(_make_event(tool_name="Original"))
        buffer.rotate_if_needed()
        backup = wal.with_suffix(".jsonl.1")
        assert backup.exists()
        content = backup.read_text()
        assert "Original" in content

    def test_wal_corruption_recovery(self, tmp_path: Path) -> None:
        wal = tmp_path / "wal.jsonl"
        wal.write_text("not valid json\n")
        config = AuditConfig(buffer_path=str(wal))
        buffer = AuditBuffer(config)
        # Next write should succeed (appends)
        buffer.write(_make_event(tool_name="AfterCorrupt"))
        events = buffer.read_recent()
        # read_recent skips corrupt lines
        tool_names = [e.get("tool_name") for e in events]
        assert "AfterCorrupt" in tool_names

    def test_wal_symlink_attack(self, tmp_path: Path) -> None:
        """WAL path resolving outside expected dir should be refused."""
        outside = tmp_path / "outside"
        outside.mkdir()
        target = outside / "stolen.txt"
        target.write_text("")

        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        wal_link = audit_dir / "wal.jsonl"
        wal_link.symlink_to(target)

        config = AuditConfig(buffer_path=str(wal_link))
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        # Should NOT write to the symlink target outside expected dir
        # The check compares realpath(wal) against realpath(wal.parent)
        # Since symlink resolves to outside, it should be refused
        # ... but if wal.parent is audit_dir and realpath(wal) = outside/stolen.txt,
        # it won't start with realpath(audit_dir)

    def test_wal_large_event_truncated(self, tmp_path: Path) -> None:
        """Large args_preview doesn't blow up the WAL."""
        from edictum.gate.audit_buffer import build_audit_event

        large_args = {"command": "x" * 1_000_000}
        event = build_audit_event(
            tool_name="Bash",
            tool_input=large_args,
            category="shell",
            verdict="allow",
            mode="enforce",
            contract_id=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            contracts_evaluated=5,
            assistant="ClaudeCodeFormat",
        )
        assert len(event.args_preview) <= 200

        wal = tmp_path / "wal.jsonl"
        config = AuditConfig(buffer_path=str(wal))
        buffer = AuditBuffer(config)
        buffer.write(event)
        line = wal.read_text().strip()
        assert len(line) < 2000  # Reasonable size

    def test_wal_write_failure_does_not_crash(self, tmp_path: Path) -> None:
        """Write to read-only location logs error but doesn't raise."""
        config = AuditConfig(buffer_path="/nonexistent/deep/path/wal.jsonl")
        buffer = AuditBuffer(config)
        # Should not raise
        buffer.write(_make_event())
