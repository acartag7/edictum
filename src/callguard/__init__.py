"""CallGuard — Runtime safety for AI agents."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from typing import Any

from callguard.audit import (
    AuditAction,
    AuditEvent,
    AuditSink,
    FileAuditSink,
    RedactionPolicy,
    StdoutAuditSink,
)
from callguard.builtins import deny_sensitive_reads
from callguard.contracts import Verdict, postcondition, precondition, session_contract
from callguard.envelope import (
    BashClassifier,
    Principal,
    SideEffect,
    ToolEnvelope,
    ToolRegistry,
    create_envelope,
)
from callguard.hooks import HookDecision, HookResult
from callguard.limits import OperationLimits
from callguard.pipeline import GovernancePipeline, PostDecision, PreDecision
from callguard.session import Session
from callguard.storage import MemoryBackend, StorageBackend
from callguard.telemetry import GovernanceTelemetry
from callguard.types import HookRegistration

__all__ = [
    "CallGuard",
    "CallGuardDenied",
    "CallGuardToolError",
    "SideEffect",
    "Principal",
    "ToolEnvelope",
    "create_envelope",
    "ToolRegistry",
    "BashClassifier",
    "HookDecision",
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
    "StdoutAuditSink",
    "FileAuditSink",
    "RedactionPolicy",
    "GovernanceTelemetry",
    "GovernancePipeline",
    "PreDecision",
    "PostDecision",
    "deny_sensitive_reads",
]


class CallGuard:
    """Main configuration and entrypoint.

    Two usage modes:
    1. With Claude Agent SDK: use ClaudeAgentSDKAdapter
    2. Framework-agnostic: use guard.run() directly
    """

    def __init__(
        self,
        *,
        environment: str = "production",
        mode: str = "enforce",
        limits: OperationLimits | None = None,
        tools: dict[str, dict] | None = None,
        contracts: list | None = None,
        hooks: list | None = None,
        audit_sink: AuditSink | None = None,
        redaction: RedactionPolicy | None = None,
        backend: StorageBackend | None = None,
    ):
        self.environment = environment
        self.mode = mode
        self.limits = limits or OperationLimits()
        self.backend = backend or MemoryBackend()
        self.redaction = redaction or RedactionPolicy()
        self.audit_sink = audit_sink or StdoutAuditSink(self.redaction)
        self.telemetry = GovernanceTelemetry()

        # Build tool registry
        self.tool_registry = ToolRegistry()
        if tools:
            for name, config in tools.items():
                self.tool_registry.register(
                    name,
                    side_effect=SideEffect(config.get("side_effect", "irreversible")),
                    idempotent=config.get("idempotent", False),
                )

        # Organize contracts and hooks by type
        self._preconditions: list = []
        self._postconditions: list = []
        self._session_contracts: list = []
        self._before_hooks: list[HookRegistration] = []
        self._after_hooks: list[HookRegistration] = []

        for item in contracts or []:
            self._register_contract(item)
        for item in hooks or []:
            self._register_hook(item)

    def _register_contract(self, item: Any) -> None:
        contract_type = getattr(item, "_callguard_type", None)
        if contract_type == "precondition":
            self._preconditions.append(item)
        elif contract_type == "postcondition":
            self._postconditions.append(item)
        elif contract_type == "session_contract":
            self._session_contracts.append(item)

    def _register_hook(self, item: Any) -> None:
        if isinstance(item, HookRegistration):
            if item.phase == "before":
                self._before_hooks.append(item)
            else:
                self._after_hooks.append(item)

    def get_hooks(self, phase: str, envelope: ToolEnvelope) -> list[HookRegistration]:
        hooks = self._before_hooks if phase == "before" else self._after_hooks
        return [h for h in hooks if h.tool == "*" or h.tool == envelope.tool_name]

    def get_preconditions(self, envelope: ToolEnvelope) -> list:
        result = []
        for p in self._preconditions:
            tool = getattr(p, "_callguard_tool", "*")
            when = getattr(p, "_callguard_when", None)
            if tool != "*" and tool != envelope.tool_name:
                continue
            if when and not when(envelope):
                continue
            result.append(p)
        return result

    def get_postconditions(self, envelope: ToolEnvelope) -> list:
        result = []
        for p in self._postconditions:
            tool = getattr(p, "_callguard_tool", "*")
            when = getattr(p, "_callguard_when", None)
            if tool != "*" and tool != envelope.tool_name:
                continue
            if when and not when(envelope):
                continue
            result.append(p)
        return result

    def get_session_contracts(self) -> list:
        return self._session_contracts

    async def run(
        self,
        tool_name: str,
        args: dict[str, Any],
        tool_callable: Callable,
        *,
        session_id: str | None = None,
        **envelope_kwargs,
    ) -> Any:
        """Framework-agnostic entrypoint."""
        session_id = session_id or str(uuid.uuid4())
        session = Session(session_id, self.backend)
        pipeline = GovernancePipeline(self)

        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=args,
            run_id=session_id,
            environment=self.environment,
            registry=self.tool_registry,
            **envelope_kwargs,
        )

        # Increment attempts
        await session.increment_attempts()

        # Pre-execute
        pre = await pipeline.pre_execute(envelope, session)

        if pre.action == "deny":
            audit_action = AuditAction.CALL_WOULD_DENY if self.mode == "observe" else AuditAction.CALL_DENIED
            await self._emit_run_pre_audit(envelope, session, audit_action, pre)
            if self.mode == "enforce":
                raise CallGuardDenied(
                    reason=pre.reason,
                    decision_source=pre.decision_source,
                    decision_name=pre.decision_name,
                )
            # observe mode: fall through to execute
        else:
            await self._emit_run_pre_audit(envelope, session, AuditAction.CALL_ALLOWED, pre)

        # Execute tool
        try:
            result = tool_callable(**args)
            if asyncio.iscoroutine(result):
                result = await result
            tool_success = True
        except Exception as e:
            result = str(e)
            tool_success = False

        # Post-execute
        post = await pipeline.post_execute(envelope, result, tool_success)
        await session.record_execution(tool_name, success=tool_success)

        # Emit post-execute audit
        post_action = AuditAction.CALL_EXECUTED if tool_success else AuditAction.CALL_FAILED
        await self.audit_sink.emit(
            AuditEvent(
                action=post_action,
                run_id=envelope.run_id,
                call_id=envelope.call_id,
                tool_name=envelope.tool_name,
                tool_args=self.redaction.redact_args(envelope.args),
                side_effect=envelope.side_effect.value,
                environment=envelope.environment,
                tool_success=tool_success,
                postconditions_passed=post.postconditions_passed,
                contracts_evaluated=post.contracts_evaluated,
                session_attempt_count=await session.attempt_count(),
                session_execution_count=await session.execution_count(),
                mode=self.mode,
            )
        )

        if not tool_success:
            raise CallGuardToolError(result)

        return result

    async def _emit_run_pre_audit(
        self, envelope, session, action: AuditAction, pre: PreDecision
    ) -> None:
        await self.audit_sink.emit(
            AuditEvent(
                action=action,
                run_id=envelope.run_id,
                call_id=envelope.call_id,
                tool_name=envelope.tool_name,
                tool_args=self.redaction.redact_args(envelope.args),
                side_effect=envelope.side_effect.value,
                environment=envelope.environment,
                decision_source=pre.decision_source,
                decision_name=pre.decision_name,
                reason=pre.reason,
                hooks_evaluated=pre.hooks_evaluated,
                contracts_evaluated=pre.contracts_evaluated,
                session_attempt_count=await session.attempt_count(),
                session_execution_count=await session.execution_count(),
                mode=self.mode,
            )
        )


class CallGuardDenied(Exception):  # noqa: N818
    """Raised when guard.run() denies a tool call in enforce mode."""

    def __init__(self, reason, decision_source=None, decision_name=None):
        self.reason = reason
        self.decision_source = decision_source
        self.decision_name = decision_name
        super().__init__(reason)


class CallGuardToolError(Exception):
    """Raised when the governed tool itself fails."""

    pass
