"""OpenAI Agents SDK adapter — per-tool input/output guardrail integration."""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, Any

from callguard.audit import AuditAction, AuditEvent
from callguard.envelope import create_envelope
from callguard.pipeline import GovernancePipeline
from callguard.session import Session

if TYPE_CHECKING:
    from callguard import CallGuard


class OpenAIAgentsAdapter:
    """Translate CallGuard pipeline decisions into OpenAI Agents SDK guardrail format.

    The adapter does NOT contain governance logic -- that lives in
    GovernancePipeline. The adapter only:
    1. Creates envelopes from SDK guardrail data
    2. Manages pending state (envelope + span) between input/output guardrails
    3. Translates PreDecision/PostDecision into guardrail output format
    4. Handles observe mode (deny -> allow conversion)

    Input and output guardrails are separate functions with no shared tool_use_id.
    Correlation uses tool_name as the pending key since the SDK is typically
    single-threaded per agent run.
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

    def as_guardrails(self) -> tuple[Any, Any]:
        """Return (input_guardrail, output_guardrail) for OpenAI Agents SDK.

        Usage::

            from agents import tool_input_guardrail, tool_output_guardrail

            guard = CallGuard(...)
            adapter = OpenAIAgentsAdapter(guard)
            input_gr, output_gr = adapter.as_guardrails()
            # Pass to Agent(input_guardrails=[input_gr], output_guardrails=[output_gr])
        """
        from agents import (
            ToolGuardrailFunctionOutput,
            tool_input_guardrail,
            tool_output_guardrail,
        )

        adapter = self

        @tool_input_guardrail
        async def callguard_input_guardrail(context, agent, data):
            tool_name = data.context.tool_name
            try:
                tool_arguments = json.loads(data.context.tool_arguments)
            except (json.JSONDecodeError, TypeError):
                tool_arguments = {}

            call_id = str(uuid.uuid4())
            result = await adapter._pre(tool_name, tool_arguments, call_id)
            if result is not None:
                return ToolGuardrailFunctionOutput.reject_content(result)
            return ToolGuardrailFunctionOutput.allow()

        @tool_output_guardrail
        async def callguard_output_guardrail(context, agent, data):
            tool_output = str(data.output) if data.output is not None else ""
            # Correlate output to pending input via insertion-order (FIFO).
            # next(iter(_pending)) grabs the oldest entry — correct for
            # sequential execution but would need a proper correlation key
            # (e.g. tool_use_id) if the SDK ever runs guardrails in parallel.
            if adapter._pending:
                call_id = next(iter(adapter._pending))
                await adapter._post(call_id, tool_output)
            return ToolGuardrailFunctionOutput.allow()

        return callguard_input_guardrail, callguard_output_guardrail

    async def _pre(self, tool_name: str, tool_input: dict, call_id: str) -> str | None:
        """Run pre-execution governance. Returns denial reason string or None to allow.

        Exposed for direct testing without framework imports.
        """
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
            self._pending[call_id] = (envelope, span)
            return None  # allow through

        # Handle deny
        if decision.action == "deny":
            await self._emit_audit_pre(envelope, decision)
            self._guard.telemetry.record_denial(envelope, decision.reason)
            span.set_attribute("governance.action", "denied")
            span.end()
            self._pending.pop(call_id, None)
            return f"DENIED: {decision.reason}"

        # Handle allow
        await self._emit_audit_pre(envelope, decision)
        span.set_attribute("governance.action", "allowed")
        self._pending[call_id] = (envelope, span)
        return None

    async def _post(self, call_id: str, tool_response: Any = None) -> None:
        """Run post-execution governance.

        Exposed for direct testing without framework imports.
        """
        pending = self._pending.pop(call_id, None)
        if not pending:
            return

        envelope, span = pending

        # Derive tool_success from response
        tool_success = self._check_tool_success(tool_response)

        # Run pipeline
        post_decision = await self._pipeline.post_execute(envelope, tool_response, tool_success)

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

    def _check_tool_success(self, tool_response: Any) -> bool:
        if tool_response is None:
            return True
        if isinstance(tool_response, str):
            if tool_response.startswith("Error:") or tool_response.startswith("fatal:"):
                return False
        return True

    @staticmethod
    def _deny(reason: str) -> str:
        """Return the denial content string."""
        return f"DENIED: {reason}"
