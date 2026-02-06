"""LangChain adapter — wrap-around middleware for tool call governance."""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Any

from callguard.audit import AuditAction, AuditEvent
from callguard.envelope import create_envelope
from callguard.pipeline import GovernancePipeline
from callguard.session import Session

if TYPE_CHECKING:
    from callguard import CallGuard


class LangChainAdapter:
    """Translate CallGuard pipeline decisions into LangChain middleware format.

    The adapter does NOT contain governance logic -- that lives in
    GovernancePipeline. The adapter only:
    1. Creates envelopes from LangChain ToolCallRequest
    2. Manages pending state (envelope + span) between pre/post
    3. Translates PreDecision/PostDecision into LangChain output format
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

    def as_middleware(self) -> Any:
        """Return a @wrap_tool_call decorated function for LangChain.

        Usage::

            from langchain.agents.middleware import wrap_tool_call

            guard = CallGuard(...)
            adapter = LangChainAdapter(guard)
            middleware = adapter.as_middleware()
            # Pass to agent as tool_call_middleware=[middleware]
        """
        from langchain.agents.middleware import wrap_tool_call

        adapter = self

        @wrap_tool_call
        def callguard_middleware(request, handler):
            loop = asyncio.get_event_loop()
            pre_result = loop.run_until_complete(adapter._pre_tool_call(request))
            if pre_result is not None:
                return pre_result

            result = handler(request)

            loop.run_until_complete(adapter._post_tool_call(request, result))
            return result

        return callguard_middleware

    async def _pre_tool_call(self, request: Any) -> Any | None:
        """Run pre-execution governance. Returns denial ToolMessage or None to allow."""
        tool_name = request.tool_call["name"]
        tool_args = request.tool_call["args"]
        tool_call_id = request.tool_call["id"]

        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=tool_args,
            run_id=self._session_id,
            call_index=self._call_index,
            tool_use_id=tool_call_id,
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
            self._pending[tool_call_id] = (envelope, span)
            return None  # allow through

        # Deny
        if decision.action == "deny":
            await self._emit_audit_pre(envelope, decision)
            self._guard.telemetry.record_denial(envelope, decision.reason)
            span.set_attribute("governance.action", "denied")
            span.end()
            self._pending.pop(tool_call_id, None)
            return self._deny(decision.reason, tool_call_id)

        # Allow
        await self._emit_audit_pre(envelope, decision)
        span.set_attribute("governance.action", "allowed")
        self._pending[tool_call_id] = (envelope, span)
        return None

    async def _post_tool_call(self, request: Any, result: Any) -> None:
        """Run post-execution governance."""
        tool_call_id = request.tool_call["id"]
        pending = self._pending.pop(tool_call_id, None)
        if not pending:
            return

        envelope, span = pending

        tool_success = self._check_tool_success(result)

        post_decision = await self._pipeline.post_execute(envelope, result, tool_success)

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

    def _check_tool_success(self, result: Any) -> bool:
        if result is None:
            return True
        # Check for LangChain ToolMessage with error content
        content = getattr(result, "content", None)
        if isinstance(content, str):
            if content.startswith("Error:") or content.startswith("fatal:"):
                return False
        if isinstance(result, dict):
            if result.get("is_error"):
                return False
        if isinstance(result, str):
            if result.startswith("Error:") or result.startswith("fatal:"):
                return False
        return True

    def _deny(self, reason: str, tool_call_id: str) -> Any:
        """Return a LangChain ToolMessage denial."""
        try:
            from langchain.messages import ToolMessage
        except ImportError:
            from dataclasses import dataclass as _dc

            @_dc
            class ToolMessage:  # type: ignore[no-redef]
                content: str
                tool_call_id: str

        return ToolMessage(content=f"DENIED: {reason}", tool_call_id=tool_call_id)
