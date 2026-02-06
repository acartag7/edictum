"""CrewAI adapter -- global before/after hook integration."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from callguard.audit import AuditAction, AuditEvent
from callguard.envelope import create_envelope
from callguard.pipeline import GovernancePipeline
from callguard.session import Session

if TYPE_CHECKING:
    from callguard import CallGuard


class CrewAIAdapter:
    """Translate CallGuard pipeline decisions into CrewAI hook format.

    The adapter does NOT contain governance logic -- that lives in
    GovernancePipeline. The adapter only:
    1. Creates envelopes from CrewAI hook context
    2. Manages pending state (envelope + span) between before/after hooks
    3. Translates PreDecision/PostDecision into CrewAI hook responses
    4. Handles observe mode (deny -> allow conversion)

    CrewAI is sequential, so a single-pending slot correlates before/after.
    """

    def __init__(self, guard: CallGuard, session_id: str | None = None):
        self._guard = guard
        self._pipeline = GovernancePipeline(guard)
        self._session_id = session_id or str(uuid.uuid4())
        self._session = Session(self._session_id, guard.backend)
        self._call_index = 0
        self._pending_envelope: Any | None = None
        self._pending_span: Any | None = None

    @property
    def session_id(self) -> str:
        return self._session_id

    def register(self) -> None:
        """Register global before/after tool-call hooks with CrewAI.

        Imports CrewAI decorators lazily to avoid hard dependency.
        The handlers are stored as _before_hook/_after_hook for direct
        test access without requiring the CrewAI framework.
        """
        from crewai.hooks import after_tool_call, before_tool_call  # noqa: F811

        before_tool_call(self._before_hook)
        after_tool_call(self._after_hook)

    async def _before_hook(self, context: Any) -> bool | None:
        """Handle a before-tool-call event from CrewAI.

        Returns None to allow, False to deny.
        """
        tool_name: str = context.tool_name
        tool_input: dict = context.tool_input

        # Create envelope
        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=tool_input,
            run_id=self._session_id,
            call_index=self._call_index,
            environment=self._guard.environment,
            registry=self._guard.tool_registry,
        )
        self._call_index += 1

        # Increment attempts BEFORE governance
        await self._session.increment_attempts()

        # Start OTel span
        span = self._guard.telemetry.start_tool_span(envelope)

        # Run pipeline
        decision = await self._pipeline.pre_execute(envelope, self._session)

        # Handle observe mode: convert deny to allow with warning
        if self._guard.mode == "observe" and decision.action == "deny":
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_WOULD_DENY)
            span.set_attribute("governance.action", "would_deny")
            span.set_attribute("governance.would_deny_reason", decision.reason)
            self._pending_envelope = envelope
            self._pending_span = span
            return None  # allow through

        # Handle deny
        if decision.action == "deny":
            await self._emit_audit_pre(envelope, decision)
            self._guard.telemetry.record_denial(envelope, decision.reason)
            span.set_attribute("governance.action", "denied")
            span.end()
            self._pending_envelope = None
            self._pending_span = None
            return self._deny(decision.reason)

        # Handle allow
        await self._emit_audit_pre(envelope, decision)
        span.set_attribute("governance.action", "allowed")
        self._pending_envelope = envelope
        self._pending_span = span
        return None

    async def _after_hook(self, context: Any) -> None:
        """Handle an after-tool-call event from CrewAI."""
        # Use single-pending slot (sequential execution model)
        envelope = self._pending_envelope
        span = self._pending_span

        if envelope is None or span is None:
            return

        # Clear pending state
        self._pending_envelope = None
        self._pending_span = None

        # Derive tool_success from context
        tool_result = getattr(context, "tool_result", None)
        tool_success = self._check_tool_success(tool_result)

        # Run pipeline
        post_decision = await self._pipeline.post_execute(envelope, tool_result, tool_success)

        # Record in session
        await self._session.record_execution(envelope.tool_name, success=tool_success)

        # Emit audit
        action = AuditAction.CALL_EXECUTED if tool_success else AuditAction.CALL_FAILED
        await self._guard.audit_sink.emit(
            AuditEvent(
                action=action,
                run_id=envelope.run_id,
                call_id=envelope.call_id,
                call_index=envelope.call_index,
                tool_name=envelope.tool_name,
                tool_args=self._guard.redaction.redact_args(envelope.args),
                side_effect=envelope.side_effect.value,
                environment=envelope.environment,
                tool_success=tool_success,
                postconditions_passed=post_decision.postconditions_passed,
                contracts_evaluated=post_decision.contracts_evaluated,
                session_attempt_count=await self._session.attempt_count(),
                session_execution_count=await self._session.execution_count(),
                mode=self._guard.mode,
            )
        )

        # End span
        span.set_attribute("governance.tool_success", tool_success)
        span.set_attribute("governance.postconditions_passed", post_decision.postconditions_passed)
        span.end()

    async def _emit_audit_pre(self, envelope: Any, decision: Any, audit_action: AuditAction | None = None) -> None:
        if audit_action is None:
            audit_action = AuditAction.CALL_DENIED if decision.action == "deny" else AuditAction.CALL_ALLOWED

        await self._guard.audit_sink.emit(
            AuditEvent(
                action=audit_action,
                run_id=envelope.run_id,
                call_id=envelope.call_id,
                call_index=envelope.call_index,
                tool_name=envelope.tool_name,
                tool_args=self._guard.redaction.redact_args(envelope.args),
                side_effect=envelope.side_effect.value,
                environment=envelope.environment,
                decision_source=decision.decision_source,
                decision_name=decision.decision_name,
                reason=decision.reason,
                hooks_evaluated=decision.hooks_evaluated,
                contracts_evaluated=decision.contracts_evaluated,
                session_attempt_count=await self._session.attempt_count(),
                session_execution_count=await self._session.execution_count(),
                mode=self._guard.mode,
            )
        )

    def _check_tool_success(self, tool_result: Any) -> bool:
        if tool_result is None:
            return True
        if isinstance(tool_result, str):
            if tool_result.startswith("Error:") or tool_result.startswith("fatal:"):
                return False
        return True

    @staticmethod
    def _deny(reason: str) -> bool:
        """Return CrewAI's deny signal (False)."""
        return False
