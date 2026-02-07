"""OpenAI Agents SDK adapter — per-tool input/output guardrail integration."""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from edictum.audit import AuditAction, AuditEvent
from edictum.envelope import Principal, create_envelope
from edictum.findings import Finding, PostCallResult, build_findings
from edictum.pipeline import GovernancePipeline
from edictum.session import Session

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from edictum import Edictum


class OpenAIAgentsAdapter:
    """Translate Edictum pipeline decisions into OpenAI Agents SDK guardrail format.

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

    def __init__(
        self,
        guard: Edictum,
        session_id: str | None = None,
        principal: Principal | None = None,
    ):
        self._guard = guard
        self._pipeline = GovernancePipeline(guard)
        self._session_id = session_id or str(uuid.uuid4())
        self._session = Session(self._session_id, guard.backend)
        self._call_index = 0
        self._pending: dict[str, tuple[Any, Any]] = {}
        self._principal = principal

    @property
    def session_id(self) -> str:
        return self._session_id

    def as_guardrails(
        self,
        on_postcondition_warn: Callable[[Any, list[Finding]], Any] | None = None,
    ) -> tuple[Any, Any]:
        """Return (input_guardrail, output_guardrail) for OpenAI Agents SDK.

        Args:
            on_postcondition_warn: Optional callback invoked when postconditions
                detect issues. Receives (original_result, findings) and is called
                for side effects.

        Usage::

            from agents import tool_input_guardrail, tool_output_guardrail

            guard = Edictum(...)
            adapter = OpenAIAgentsAdapter(guard)
            input_gr, output_gr = adapter.as_guardrails()
            # Pass to Agent(input_guardrails=[input_gr], output_guardrails=[output_gr])
        """
        self._on_postcondition_warn = on_postcondition_warn

        from agents import (
            ToolGuardrailFunctionOutput,
            tool_input_guardrail,
            tool_output_guardrail,
        )

        adapter = self

        @tool_input_guardrail
        async def edictum_input_guardrail(context, agent, data):
            tool_name = data.context.tool_name
            try:
                tool_arguments = json.loads(data.context.tool_arguments)
            except (json.JSONDecodeError, TypeError):
                tool_arguments = {}

            # Use tool_use_id from SDK context if available, else generate one
            call_id = getattr(data.context, "tool_use_id", None) or str(uuid.uuid4())
            result = await adapter._pre(tool_name, tool_arguments, call_id)
            if result is not None:
                return ToolGuardrailFunctionOutput.reject_content(result)
            return ToolGuardrailFunctionOutput.allow()

        @tool_output_guardrail
        async def edictum_output_guardrail(context, agent, data):
            tool_output = str(data.output) if data.output is not None else ""
            # Try to correlate via tool_use_id from SDK context first.
            # Fall back to FIFO (insertion-order) for sequential execution.
            call_id = getattr(data, "tool_use_id", None)
            post_result = None
            if call_id and call_id in adapter._pending:
                post_result = await adapter._post(call_id, tool_output)
            elif adapter._pending:
                call_id = next(iter(adapter._pending))
                post_result = await adapter._post(call_id, tool_output)

            if post_result and not post_result.postconditions_passed and adapter._on_postcondition_warn:
                try:
                    adapter._on_postcondition_warn(post_result.result, post_result.findings)
                except Exception:
                    logger.exception("on_postcondition_warn callback raised")

            return ToolGuardrailFunctionOutput.allow()

        return edictum_input_guardrail, edictum_output_guardrail

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
            principal=self._principal,
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

        # Handle per-rule observed denials
        if decision.observed:
            for cr in decision.contracts_evaluated:
                if cr.get("observed") and not cr.get("passed"):
                    await self._guard.audit_sink.emit(
                        AuditEvent(
                            action=AuditAction.CALL_WOULD_DENY,
                            run_id=envelope.run_id,
                            call_id=envelope.call_id,
                            call_index=envelope.call_index,
                            tool_name=envelope.tool_name,
                            tool_args=self._guard.redaction.redact_args(envelope.args),
                            side_effect=envelope.side_effect.value,
                            environment=envelope.environment,
                            principal=asdict(envelope.principal) if envelope.principal else None,
                            decision_source="precondition",
                            decision_name=cr["name"],
                            reason=cr["message"],
                            mode="observe",
                            policy_version=self._guard.policy_version,
                            policy_error=decision.policy_error,
                        )
                    )

        # Handle allow
        await self._emit_audit_pre(envelope, decision)
        span.set_attribute("governance.action", "allowed")
        self._pending[call_id] = (envelope, span)
        return None

    async def _post(self, call_id: str, tool_response: Any = None) -> PostCallResult:
        """Run post-execution governance. Returns PostCallResult with findings.

        Exposed for direct testing without framework imports.
        """
        pending = self._pending.pop(call_id, None)
        if not pending:
            return PostCallResult(result=tool_response)

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
                principal=asdict(envelope.principal) if envelope.principal else None,
                tool_success=tool_success,
                postconditions_passed=post_decision.postconditions_passed,
                contracts_evaluated=post_decision.contracts_evaluated,
                session_attempt_count=await self._session.attempt_count(),
                session_execution_count=await self._session.execution_count(),
                mode=self._guard.mode,
                policy_version=self._guard.policy_version,
                policy_error=post_decision.policy_error,
            )
        )

        # End span
        span.set_attribute("governance.tool_success", tool_success)
        span.set_attribute("governance.postconditions_passed", post_decision.postconditions_passed)
        span.end()

        findings = build_findings(post_decision)
        return PostCallResult(
            result=tool_response,
            postconditions_passed=post_decision.postconditions_passed,
            findings=findings,
        )

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
                principal=asdict(envelope.principal) if envelope.principal else None,
                decision_source=decision.decision_source,
                decision_name=decision.decision_name,
                reason=decision.reason,
                hooks_evaluated=decision.hooks_evaluated,
                contracts_evaluated=decision.contracts_evaluated,
                session_attempt_count=await self._session.attempt_count(),
                session_execution_count=await self._session.execution_count(),
                mode=self._guard.mode,
                policy_version=self._guard.policy_version,
                policy_error=decision.policy_error,
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
        return True

    @staticmethod
    def _deny(reason: str) -> str:
        """Return the denial content string."""
        return f"DENIED: {reason}"
