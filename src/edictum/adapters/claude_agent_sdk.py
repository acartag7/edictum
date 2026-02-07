"""Claude Agent SDK adapter — thin translation layer."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from edictum.audit import AuditAction, AuditEvent
from edictum.envelope import Principal, create_envelope
from edictum.findings import Finding, build_findings
from edictum.pipeline import GovernancePipeline
from edictum.session import Session

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from edictum import Edictum


class ClaudeAgentSDKAdapter:
    """Translate Edictum pipeline decisions into Claude SDK hook format.

    The adapter does NOT contain governance logic -- that lives in
    GovernancePipeline. The adapter only:
    1. Creates envelopes from SDK input
    2. Manages pending state (envelope + span) between Pre/Post
    3. Translates PreDecision/PostDecision into SDK hook output format
    4. Handles observe mode (deny -> allow conversion)
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

    def to_sdk_hooks(
        self,
        on_postcondition_warn: Callable[[Any, list[Finding]], Any] | None = None,
    ) -> dict:
        """Return SDK hook dict with optional postcondition callback.

        Args:
            on_postcondition_warn: Optional callback invoked when postconditions
                detect issues. Receives (original_result, findings) and is called
                for side effects.
        """
        self._on_postcondition_warn = on_postcondition_warn
        return {
            "pre_tool_use": self._pre_tool_use,
            "post_tool_use": self._post_tool_use,
        }

    async def _pre_tool_use(self, tool_name: str, tool_input: dict, tool_use_id: str, **kwargs) -> dict:
        # Create envelope
        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=tool_input,
            run_id=self._session_id,
            call_index=self._call_index,
            tool_use_id=tool_use_id,
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
            self._pending[tool_use_id] = (envelope, span)
            return {}  # allow through

        # Handle deny
        if decision.action == "deny":
            await self._emit_audit_pre(envelope, decision)
            self._guard.telemetry.record_denial(envelope, decision.reason)
            span.set_attribute("governance.action", "denied")
            span.end()
            self._pending.pop(tool_use_id, None)
            return self._deny(decision.reason)

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
        self._pending[tool_use_id] = (envelope, span)
        return {}

    async def _post_tool_use(self, tool_use_id: str, tool_response: Any = None, **kwargs) -> dict:
        pending = self._pending.pop(tool_use_id, None)
        if not pending:
            return {}

        envelope, span = pending

        # Derive tool_success from SDK response
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

        # Build findings and call callback
        findings = build_findings(post_decision)
        on_warn = getattr(self, "_on_postcondition_warn", None)
        if not post_decision.postconditions_passed and findings and on_warn:
            try:
                on_warn(tool_response, findings)
            except Exception:
                logger.exception("on_postcondition_warn callback raised")

        # Return warnings as additionalContext
        if post_decision.warnings:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": "\n".join(post_decision.warnings),
                }
            }
        return {}

    async def _emit_audit_pre(self, envelope, decision, audit_action=None):
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

    def _check_tool_success(self, tool_response) -> bool:
        if tool_response is None:
            return True
        if isinstance(tool_response, dict):
            if tool_response.get("is_error"):
                return False
        if isinstance(tool_response, str):
            if tool_response.startswith("Error:") or tool_response.startswith("fatal:"):
                return False
        return True

    def _deny(self, reason):
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
