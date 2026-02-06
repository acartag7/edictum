"""Structured Event Log with Redaction."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AuditSink(Protocol):
    """Protocol for audit event consumers."""

    async def emit(self, event: Any) -> None: ...


class AuditAction(StrEnum):
    CALL_DENIED = "call_denied"
    CALL_WOULD_DENY = "call_would_deny"
    CALL_ALLOWED = "call_allowed"
    CALL_EXECUTED = "call_executed"
    CALL_FAILED = "call_failed"
    POSTCONDITION_WARNING = "postcondition_warning"


@dataclass
class AuditEvent:
    schema_version: str = "0.0.1"

    # Identity
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    run_id: str = ""
    call_id: str = ""
    call_index: int = 0
    parent_call_id: str | None = None

    # Tool
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    side_effect: str = ""
    environment: str = ""

    # Principal
    principal: dict | None = None

    # Governance decision
    action: AuditAction = AuditAction.CALL_DENIED
    decision_source: str | None = None
    decision_name: str | None = None
    reason: str | None = None
    hooks_evaluated: list[dict] = field(default_factory=list)
    contracts_evaluated: list[dict] = field(default_factory=list)

    # Execution (post only)
    tool_success: bool | None = None
    postconditions_passed: bool | None = None
    duration_ms: int = 0
    error: str | None = None
    result_summary: str | None = None

    # Counters
    session_attempt_count: int = 0
    session_execution_count: int = 0

    # Mode
    mode: str = "enforce"


class RedactionPolicy:
    """Redact sensitive data from audit events.

    Recurses into dicts AND lists. Normalizes keys to lowercase.
    Caps total payload size. Detects common secret patterns in values.
    """

    DEFAULT_SENSITIVE_KEYS: set[str] = {
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "api-key",
        "authorization",
        "auth",
        "credentials",
        "private_key",
        "privatekey",
        "access_token",
        "refresh_token",
        "client_secret",
        "connection_string",
        "database_url",
        "db_password",
        "ssh_key",
        "passphrase",
    }

    BASH_REDACTION_PATTERNS: list[tuple[str, str]] = [
        (r"(export\s+\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*=)\S+", r"\1[REDACTED]"),
        (r"(-p\s*|--password[= ])\S+", r"\1[REDACTED]"),
        (r"(://\w+:)\S+(@)", r"\1[REDACTED]\2"),
    ]

    SECRET_VALUE_PATTERNS = [
        r"^(sk-[a-zA-Z0-9]{20,})",
        r"^(AKIA[A-Z0-9]{16})",
        r"^(eyJ[a-zA-Z0-9_-]{20,}\.)",
        r"^(ghp_[a-zA-Z0-9]{36})",
        r"^(xox[bpas]-[a-zA-Z0-9-]{10,})",
    ]

    MAX_PAYLOAD_SIZE = 32_768

    def __init__(
        self,
        sensitive_keys: set[str] | None = None,
        custom_patterns: list[tuple[str, str]] | None = None,
        detect_secret_values: bool = True,
    ):
        base_keys = sensitive_keys or self.DEFAULT_SENSITIVE_KEYS
        self._keys = {k.lower() for k in base_keys}
        self._patterns = (custom_patterns or []) + self.BASH_REDACTION_PATTERNS
        self._detect_values = detect_secret_values

    def redact_args(self, args: Any) -> Any:
        """Recursively redact sensitive data from tool arguments."""
        if isinstance(args, dict):
            return {
                key: "[REDACTED]" if self._is_sensitive_key(key) else self.redact_args(value)
                for key, value in args.items()
            }
        elif isinstance(args, (list, tuple)):
            return [self.redact_args(item) for item in args]
        elif isinstance(args, str):
            if self._detect_values and self._looks_like_secret(args):
                return "[REDACTED]"
            if len(args) > 1000:
                return args[:997] + "..."
            return args
        return args

    def _is_sensitive_key(self, key: str) -> bool:
        k = key.lower()
        return k in self._keys or any(s in k for s in ("token", "key", "secret", "password", "credential"))

    def _looks_like_secret(self, value: str) -> bool:
        for pattern in self.SECRET_VALUE_PATTERNS:
            if re.match(pattern, value):
                return True
        return False

    def redact_bash_command(self, command: str) -> str:
        result = command
        for pattern, replacement in self._patterns:
            result = re.sub(pattern, replacement, result)
        return result

    def redact_result(self, result: str, max_length: int = 500) -> str:
        redacted = result
        for pattern, replacement in self._patterns:
            redacted = re.sub(pattern, replacement, redacted)
        if len(redacted) > max_length:
            redacted = redacted[: max_length - 3] + "..."
        return redacted

    def cap_payload(self, data: dict) -> dict:
        """Cap total serialized size of audit payload."""
        serialized = json.dumps(data, default=str)
        if len(serialized) > self.MAX_PAYLOAD_SIZE:
            data["_truncated"] = True
            data.pop("result_summary", None)
            data.pop("tool_args", None)
            data["tool_args"] = {"_redacted": "payload exceeded 32KB"}
        return data


class StdoutAuditSink:
    """Emit audit events as JSON to stdout."""

    def __init__(self, redaction: RedactionPolicy | None = None):
        self._redaction = redaction or RedactionPolicy()

    async def emit(self, event: AuditEvent) -> None:
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        data["action"] = event.action.value
        data = self._redaction.cap_payload(data)
        print(json.dumps(data, default=str))


class FileAuditSink:
    """Emit audit events as JSON lines to a file."""

    def __init__(self, path: str | Path, redaction: RedactionPolicy | None = None):
        self._path = Path(path)
        self._redaction = redaction or RedactionPolicy()

    async def emit(self, event: AuditEvent) -> None:
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        data["action"] = event.action.value
        data = self._redaction.cap_payload(data)
        line = json.dumps(data, default=str) + "\n"
        with open(self._path, "a") as f:
            f.write(line)
