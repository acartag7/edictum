"""Semantic Kernel adapter — kernel filter for tool call governance."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from callguard.audit import AuditAction, AuditEvent
from callguard.envelope import create_envelope
from callguard.pipeline import GovernancePipeline
from callguard.session import Session

if TYPE_CHECKING:
    from callguard import CallGuard


class SemanticKernelAdapter:
    """Translate CallGuard pipeline decisions into Semantic Kernel filter format.

    The adapter does NOT contain governance logic -- that lives in
    GovernancePipeline. The adapter only:
    1. Creates envelopes from SK AutoFunctionInvocationContext
    2. Manages pending state (envelope + span) between pre/post
    3. Translates PreDecision/PostDecision into SK filter output
    4. Handles observe mode (deny -> allow conversion)
    """

    def __init__(self, guard: CallGuard, session_id: str | None = None):
        self._guard = guard
        self._pipeline = GovernancePipeline(guard)
        self._session_id = session_id or str(uuid.uuid4())
        self._session = Session(self._session_id, guard.backend)
        self._call_index = 0
        self._pending: dict[str, tuple[Any, Any]] = {}

    @property
    def session_id(self) -> str:
        return self._session_id

    def register(self, kernel: Any) -> None:
        """Register AUTO_FUNCTION_INVOCATION filter on the kernel.

        Usage::

            from semantic_kernel.kernel import Kernel

            kernel = Kernel()
            guard = CallGuard(...)
            adapter = SemanticKernelAdapter(guard)
            adapter.register(kernel)
        """
        from semantic_kernel.filters import FilterTypes

        adapter = self

        @kernel.filter(FilterTypes.AUTO_FUNCTION_INVOCATION)
        async def callguard_filter(context, next):  # noqa: N807
            call_id = str(uuid.uuid4())
            tool_name = context.function.name
            tool_input = dict(context.arguments) if context.arguments else {}

            pre_result = await adapter._pre(tool_name, tool_input, call_id)

            if isinstance(pre_result, str):
                # Denied — set result and don't call next
                context.function_result = pre_result
                context.terminate = True
                return

            # Allowed — call next to execute
            await next(context)

            # Post-execute with function result
            tool_response = context.function_result
            await adapter._post(call_id, tool_response)

    async def _pre(self, tool_name: str, tool_input: dict, call_id: str) -> dict | str:
        """Pre-execution governance. Returns {} to allow or denial string to deny."""
        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=tool_input,
            run_id=self._session_id,
            call_index=self._call_index,
            tool_use_id=call_id,
            environment=self._guard.environment,
            registry=self._guard.tool_registry,
        )
        self._call_index += 1

        await self._session.increment_attempts()

        span = self._guard.telemetry.start_tool_span(envelope)

        decision = await self._pipeline.pre_execute(envelope, self._session)

        # Observe mode: convert deny to allow with WOULD_DENY audit
        if self._guard.mode == "observe" and decision.action == "deny":
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_WOULD_DENY)
            span.set_attribute("governance.action", "would_deny")
            span.set_attribute("governance.would_deny_reason", decision.reason)
            self._pending[call_id] = (envelope, span)
            return {}  # allow through

        # Deny
        if decision.action == "deny":
            await self._emit_audit_pre(envelope, decision)
            self._guard.telemetry.record_denial(envelope, decision.reason)
            span.set_attribute("governance.action", "denied")
            span.end()
            self._pending.pop(call_id, None)
            return self._deny(decision.reason)

        # Allow
        await self._emit_audit_pre(envelope, decision)
        span.set_attribute("governance.action", "allowed")
        self._pending[call_id] = (envelope, span)
        return {}

    async def _post(self, call_id: str, tool_response: Any = None) -> dict:
        """Post-execution governance."""
        pending = self._pending.pop(call_id, None)
        if not pending:
            return {}

        envelope, span = pending

        tool_success = self._check_tool_success(tool_response)

        post_decision = await self._pipeline.post_execute(envelope, tool_response, tool_success)

        await self._session.record_execution(envelope.tool_name, success=tool_success)

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

        span.set_attribute("governance.tool_success", tool_success)
        span.set_attribute("governance.postconditions_passed", post_decision.postconditions_passed)
        span.end()

        return {}

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

    def _check_tool_success(self, tool_response: Any) -> bool:
        if tool_response is None:
            return True
        if isinstance(tool_response, dict):
            if tool_response.get("is_error"):
                return False
        if isinstance(tool_response, str):
            if tool_response.startswith("Error:") or tool_response.startswith("fatal:"):
                return False
        # Check for SK FunctionResult with error metadata
        error_meta = getattr(tool_response, "metadata", None)
        if isinstance(error_meta, dict) and error_meta.get("error"):
            return False
        return True

    def _deny(self, reason: str) -> str:
        """Return a denial string to set as function_result."""
        return f"DENIED: {reason}"
