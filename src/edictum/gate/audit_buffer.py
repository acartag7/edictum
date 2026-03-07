"""Gate audit buffer — WAL write + batch flush to Console."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from edictum.audit import RedactionPolicy


@dataclass(frozen=True)
class GateAuditEvent:
    """Gate-specific audit event for JSONL WAL."""

    timestamp: str
    session_id: str
    agent_id: str
    assistant: str
    tool_name: str
    tool_category: str
    args_preview: str
    verdict: str
    contract_id: str | None
    reason: str | None
    cwd: str
    duration_ms: int
    contracts_evaluated: int


def _build_redaction_policy(config: Any) -> RedactionPolicy:
    """Build RedactionPolicy from gate RedactionConfig."""
    if config is None:
        return RedactionPolicy()
    patterns = getattr(config, "patterns", ())
    replacement = getattr(config, "replacement", "<REDACTED>")
    custom_patterns = [(p, replacement) for p in patterns] if patterns else []
    return RedactionPolicy(custom_patterns=custom_patterns)


def build_audit_event(
    *,
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
    session_id: str = "",
    agent_id: str = "",
    redaction_config: Any = None,
) -> GateAuditEvent:
    """Build a GateAuditEvent with redacted args preview."""
    import re

    policy = _build_redaction_policy(redaction_config)
    redacted_args = policy.redact_args(tool_input)
    args_str = json.dumps(redacted_args, default=str)

    # Apply gate-specific regex patterns to the serialized string
    if redaction_config is not None:
        patterns = getattr(redaction_config, "patterns", ())
        replacement = getattr(redaction_config, "replacement", "<REDACTED>")
        for pattern in patterns:
            try:
                args_str = re.sub(pattern, replacement, args_str)
            except re.error:
                pass

    if len(args_str) > 200:
        args_str = args_str[:197] + "..."

    return GateAuditEvent(
        timestamp=datetime.now(UTC).isoformat(),
        session_id=session_id,
        agent_id=agent_id,
        assistant=assistant,
        tool_name=tool_name,
        tool_category=category,
        args_preview=args_str,
        verdict=verdict,
        contract_id=contract_id,
        reason=reason,
        cwd=cwd,
        duration_ms=duration_ms,
        contracts_evaluated=contracts_evaluated,
    )


class AuditBuffer:
    """Write-ahead log for gate audit events.

    Events are redacted BEFORE writing to the WAL. Secrets never hit disk.
    """

    def __init__(self, audit_config: Any, redaction_config: Any = None) -> None:
        self._buffer_path = Path(getattr(audit_config, "buffer_path", ""))
        self._max_size_mb = getattr(audit_config, "max_buffer_size_mb", 50)
        self._redaction_config = redaction_config

    def write(self, event: GateAuditEvent) -> None:
        """Append event to WAL. Sync, fast (<5ms target)."""
        try:
            # Ensure directory exists
            self._buffer_path.parent.mkdir(parents=True, exist_ok=True)

            # Safety: refuse to write if WAL path resolves to a symlink target outside expected dir
            real_path = os.path.realpath(self._buffer_path)
            expected_parent = os.path.realpath(self._buffer_path.parent)
            if not real_path.startswith(expected_parent):
                print("Gate audit: WAL path resolves outside expected directory", file=sys.stderr)
                return

            line = json.dumps(asdict(event), default=str) + "\n"
            with open(real_path, "a") as f:
                f.write(line)
        except Exception as exc:
            # Never crash the gate check
            print(f"Gate audit write error: {exc}", file=sys.stderr)

    def rotate_if_needed(self) -> None:
        """Rotate WAL if it exceeds max_buffer_size_mb."""
        try:
            if not self._buffer_path.exists():
                return
            size_mb = self._buffer_path.stat().st_size / (1024 * 1024)
            if size_mb < self._max_size_mb:
                return

            backup = self._buffer_path.with_suffix(".jsonl.1")
            # Remove older backup if exists
            old_backup = self._buffer_path.with_suffix(".jsonl.2")
            if old_backup.exists():
                old_backup.unlink()
            # Rotate current to .1
            if backup.exists():
                backup.unlink()
            os.replace(str(self._buffer_path), str(backup))
        except Exception as exc:
            print(f"Gate audit rotate error: {exc}", file=sys.stderr)

    def read_recent(self, limit: int = 20, tool: str | None = None, verdict: str | None = None) -> list[dict]:
        """Read recent events from WAL with optional filters."""
        if not self._buffer_path.exists():
            return []

        events: list[dict] = []
        try:
            with open(self._buffer_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if tool and event.get("tool_name") != tool:
                        continue
                    if verdict and event.get("verdict") != verdict:
                        continue
                    events.append(event)
        except OSError:
            return []

        return events[-limit:]

    def flush_to_console(self, console_config: Any) -> int:
        """Batch POST buffered events to Console. Returns count sent."""
        try:
            import edictum.server.client  # noqa: F401
        except ImportError:
            raise ImportError(
                "Console flush requires edictum[server]. " "Install with: pip install edictum[server,gate]"
            )

        if not self._buffer_path.exists():
            return 0

        lines = self._buffer_path.read_text().strip().split("\n")
        events = []
        for line in lines:
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if not events:
            return 0

        url = getattr(console_config, "url", "")
        api_key = getattr(console_config, "api_key", "")
        if not url:
            return 0

        import httpx

        client = httpx.Client(
            base_url=url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30,
        )
        try:
            response = client.post("/api/v1/events", json={"events": events})
            response.raise_for_status()
        except Exception as exc:
            print(f"Gate audit flush error: {exc}", file=sys.stderr)
            return 0
        finally:
            client.close()

        # Truncate WAL on success
        try:
            self._buffer_path.write_text("")
        except OSError:
            pass

        return len(events)
