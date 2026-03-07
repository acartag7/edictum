"""Tests for gate audit buffer (WAL write, read, rotate)."""

from __future__ import annotations

import json
from pathlib import Path

from edictum.gate.audit_buffer import AuditBuffer, GateAuditEvent, build_audit_event
from edictum.gate.config import AuditConfig


def _make_audit_config(tmp_path: Path) -> AuditConfig:
    wal = tmp_path / "audit" / "wal.jsonl"
    return AuditConfig(
        enabled=True,
        buffer_path=str(wal),
        max_buffer_size_mb=50,
    )


def _make_event(**kwargs) -> GateAuditEvent:
    defaults = {
        "timestamp": "2026-03-01T00:00:00+00:00",
        "session_id": "test-session",
        "agent_id": "test-agent",
        "assistant": "claude-code",
        "tool_name": "Bash",
        "tool_category": "shell",
        "args_preview": '{"command": "ls"}',
        "verdict": "allow",
        "contract_id": None,
        "reason": None,
        "cwd": "/project",
        "duration_ms": 2,
        "contracts_evaluated": 5,
    }
    defaults.update(kwargs)
    return GateAuditEvent(**defaults)


class TestAuditBufferWrite:
    def test_write_creates_wal(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        wal = Path(config.buffer_path)
        assert wal.exists()
        lines = wal.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_write_appends(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event(verdict="allow"))
        buffer.write(_make_event(verdict="deny"))
        wal = Path(config.buffer_path)
        lines = wal.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_write_valid_jsonl(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        wal = Path(config.buffer_path)
        for line in wal.read_text().strip().split("\n"):
            event = json.loads(line)
            assert isinstance(event, dict)

    def test_write_event_fields(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event(tool_name="Read", verdict="deny"))
        wal = Path(config.buffer_path)
        event = json.loads(wal.read_text().strip())
        assert event["tool_name"] == "Read"
        assert event["verdict"] == "deny"

    def test_write_survives_missing_directory(self, tmp_path: Path) -> None:
        deep_path = tmp_path / "deep" / "nested" / "wal.jsonl"
        config = AuditConfig(buffer_path=str(deep_path))
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        assert deep_path.exists()


class TestAuditBufferRead:
    def test_read_recent_default(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        for i in range(25):
            buffer.write(_make_event(tool_name=f"Tool{i}"))
        events = buffer.read_recent()
        assert len(events) == 20

    def test_read_recent_with_limit(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        for i in range(10):
            buffer.write(_make_event())
        events = buffer.read_recent(limit=5)
        assert len(events) == 5

    def test_read_recent_filter_tool(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event(tool_name="Bash"))
        buffer.write(_make_event(tool_name="Read"))
        buffer.write(_make_event(tool_name="Bash"))
        events = buffer.read_recent(tool="Bash")
        assert len(events) == 2

    def test_read_recent_filter_verdict(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event(verdict="allow"))
        buffer.write(_make_event(verdict="deny"))
        buffer.write(_make_event(verdict="allow"))
        events = buffer.read_recent(verdict="deny")
        assert len(events) == 1


class TestAuditBufferRotate:
    def test_rotate_when_exceeded(self, tmp_path: Path) -> None:
        wal = tmp_path / "wal.jsonl"
        config = AuditConfig(buffer_path=str(wal), max_buffer_size_mb=0)  # 0 = always rotate
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        buffer.rotate_if_needed()
        backup = wal.with_suffix(".jsonl.1")
        assert backup.exists()

    def test_rotate_keeps_one_backup(self, tmp_path: Path) -> None:
        wal = tmp_path / "wal.jsonl"
        config = AuditConfig(buffer_path=str(wal), max_buffer_size_mb=0)
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        buffer.rotate_if_needed()
        # Write again and rotate again
        buffer.write(_make_event())
        buffer.rotate_if_needed()
        backup1 = wal.with_suffix(".jsonl.1")
        backup2 = wal.with_suffix(".jsonl.2")
        assert backup1.exists()
        assert not backup2.exists()


class TestBuildAuditEvent:
    def test_basic_event(self) -> None:
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"command": "ls"},
            category="shell",
            verdict="allow",
            contract_id=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            contracts_evaluated=5,
            assistant="claude-code",
        )
        assert event.tool_name == "Bash"
        assert event.verdict == "allow"
        assert event.tool_category == "shell"

    def test_args_preview_truncated(self) -> None:
        long_args = {"command": "x" * 500}
        event = build_audit_event(
            tool_name="Bash",
            tool_input=long_args,
            category="shell",
            verdict="allow",
            contract_id=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            contracts_evaluated=5,
            assistant="claude-code",
        )
        assert len(event.args_preview) <= 200
