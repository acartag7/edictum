"""Edictum — Runtime safety for AI agents."""

from __future__ import annotations

from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("edictum")
except Exception:  # pragma: no cover — editable installs, test envs
    __version__ = "0.0.0-dev"

from edictum._exceptions import EdictumConfigError, EdictumDenied, EdictumToolError
from edictum._factory import TemplateInfo
from edictum._guard import Edictum
from edictum._server_factory import _ASSIGNMENT_TIMEOUT_SECS
from edictum.approval import (
    ApprovalBackend,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    LocalApprovalBackend,
)
from edictum.audit import (
    AuditAction,
    AuditEvent,
    AuditSink,
    CollectingAuditSink,
    CompositeSink,
    FileAuditSink,
    MarkEvictedError,
    RedactionPolicy,
    StdoutAuditSink,
)
from edictum.builtins import deny_sensitive_reads
from edictum.contracts import Verdict, postcondition, precondition, session_contract
from edictum.envelope import (
    BashClassifier,
    Principal,
    SideEffect,
    ToolEnvelope,
    ToolRegistry,
    create_envelope,
)
from edictum.evaluation import ContractResult, EvaluationResult
from edictum.findings import Finding, PostCallResult
from edictum.hooks import HookDecision, HookResult
from edictum.limits import OperationLimits
from edictum.otel import configure_otel, has_otel
from edictum.pipeline import GovernancePipeline, PostDecision, PreDecision
from edictum.session import Session
from edictum.storage import MemoryBackend, StorageBackend
from edictum.telemetry import GovernanceTelemetry
from edictum.types import HookRegistration
from edictum.yaml_engine.composer import CompositionReport

__all__ = [
    "__version__",
    "_ASSIGNMENT_TIMEOUT_SECS",
    "ApprovalBackend",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStatus",
    "LocalApprovalBackend",
    "Edictum",
    "EdictumConfigError",
    "EdictumDenied",
    "EdictumToolError",
    "SideEffect",
    "Principal",
    "ToolEnvelope",
    "create_envelope",
    "ToolRegistry",
    "BashClassifier",
    "HookDecision",
    "HookRegistration",
    "HookResult",
    "Verdict",
    "precondition",
    "postcondition",
    "session_contract",
    "OperationLimits",
    "Session",
    "StorageBackend",
    "MemoryBackend",
    "AuditAction",
    "AuditEvent",
    "AuditSink",
    "CollectingAuditSink",
    "CompositeSink",
    "FileAuditSink",
    "MarkEvictedError",
    "StdoutAuditSink",
    "RedactionPolicy",
    "GovernanceTelemetry",
    "GovernancePipeline",
    "PreDecision",
    "PostDecision",
    "deny_sensitive_reads",
    "configure_otel",
    "has_otel",
    "Finding",
    "PostCallResult",
    "EvaluationResult",
    "ContractResult",
    "CompositionReport",
    "TemplateInfo",
]
