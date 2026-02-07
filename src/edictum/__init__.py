"""Edictum — Runtime safety for AI agents."""

from __future__ import annotations

from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("edictum")
except Exception:  # pragma: no cover — editable installs, test envs
    __version__ = "0.0.0-dev"

import asyncio
import json
import uuid
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from edictum.audit import (
    AuditAction,
    AuditEvent,
    AuditSink,
    FileAuditSink,
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
from edictum.hooks import HookDecision, HookResult
from edictum.limits import OperationLimits
from edictum.otel import configure_otel, get_tracer, has_otel
from edictum.pipeline import GovernancePipeline, PostDecision, PreDecision
from edictum.session import Session
from edictum.storage import MemoryBackend, StorageBackend
from edictum.telemetry import GovernanceTelemetry
from edictum.types import HookRegistration

__all__ = [
    "__version__",
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
    "configure_otel",
    "has_otel",
]


class Edictum:
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
        policy_version: str | None = None,
    ):
        self.environment = environment
        self.mode = mode
        self.limits = limits or OperationLimits()
        self.backend = backend or MemoryBackend()
        self.redaction = redaction or RedactionPolicy()
        self.audit_sink = audit_sink or StdoutAuditSink(self.redaction)
        self.telemetry = GovernanceTelemetry()
        self._gov_tracer = get_tracer("edictum.governance")
        self.policy_version = policy_version

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

        # Persistent session for accumulating limits across run() calls
        self._session_id = str(uuid.uuid4())

        for item in contracts or []:
            self._register_contract(item)
        for item in hooks or []:
            self._register_hook(item)

    @classmethod
    def from_yaml(
        cls,
        path: str | Path,
        *,
        mode: str | None = None,
        audit_sink: AuditSink | None = None,
        redaction: RedactionPolicy | None = None,
        backend: StorageBackend | None = None,
        environment: str = "production",
    ) -> Edictum:
        """Create a Edictum instance from a YAML contract bundle.

        Args:
            path: Path to a YAML contract file.
            mode: Override the bundle's default mode (enforce/observe).
            audit_sink: Custom audit sink.
            redaction: Custom redaction policy.
            backend: Custom storage backend.
            environment: Environment name for envelope context.

        Returns:
            Configured Edictum instance.

        Raises:
            EdictumConfigError: If the YAML is invalid.
        """
        from edictum.yaml_engine.compiler import compile_contracts
        from edictum.yaml_engine.loader import load_bundle

        bundle_data, bundle_hash = load_bundle(path)
        compiled = compile_contracts(bundle_data)

        # Handle observability config
        obs_config = bundle_data.get("observability", {})
        otel_config = obs_config.get("otel", {})
        if otel_config.get("enabled"):
            from edictum.otel import configure_otel

            configure_otel(
                service_name=otel_config.get("service_name", "edictum-agent"),
                endpoint=otel_config.get("endpoint", "http://localhost:4317"),
                protocol=otel_config.get("protocol", "grpc"),
                resource_attributes=otel_config.get("resource_attributes"),
            )

        # Auto-configure audit sink from observability block if not explicitly provided
        if audit_sink is None:
            obs_file = obs_config.get("file")
            obs_stdout = obs_config.get("stdout", True)
            if obs_file:
                audit_sink = FileAuditSink(obs_file, redaction)
            elif obs_stdout is False:

                class _NullSink:
                    async def emit(self, event):
                        pass

                audit_sink = _NullSink()

        effective_mode = mode or compiled.default_mode
        all_contracts = compiled.preconditions + compiled.postconditions + compiled.session_contracts

        return cls(
            environment=environment,
            mode=effective_mode,
            limits=compiled.limits,
            contracts=all_contracts,
            audit_sink=audit_sink,
            redaction=redaction,
            backend=backend,
            policy_version=str(bundle_hash),
        )

    @classmethod
    def from_template(
        cls,
        name: str,
        *,
        mode: str | None = None,
        audit_sink: AuditSink | None = None,
        redaction: RedactionPolicy | None = None,
        backend: StorageBackend | None = None,
        environment: str = "production",
    ) -> Edictum:
        """Create a Edictum instance from a built-in template.

        Args:
            name: Template name (e.g., "file-agent", "research-agent", "devops-agent").

        Returns:
            Configured Edictum instance.

        Raises:
            EdictumConfigError: If the template does not exist.
        """
        templates_dir = Path(__file__).parent / "yaml_engine" / "templates"
        template_path = templates_dir / f"{name}.yaml"
        if not template_path.exists():
            raise EdictumConfigError(
                f"Template '{name}' not found. Available: {', '.join(p.stem for p in templates_dir.glob('*.yaml'))}"
            )
        return cls.from_yaml(
            template_path,
            mode=mode,
            audit_sink=audit_sink,
            redaction=redaction,
            backend=backend,
            environment=environment,
        )

    def _register_contract(self, item: Any) -> None:
        contract_type = getattr(item, "_edictum_type", None)
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
            tool = getattr(p, "_edictum_tool", "*")
            when = getattr(p, "_edictum_when", None)
            if tool != "*" and tool != envelope.tool_name:
                continue
            if when and not when(envelope):
                continue
            result.append(p)
        return result

    def get_postconditions(self, envelope: ToolEnvelope) -> list:
        result = []
        for p in self._postconditions:
            tool = getattr(p, "_edictum_tool", "*")
            when = getattr(p, "_edictum_when", None)
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
        session_id = session_id or self._session_id
        session = Session(session_id, self.backend)
        pipeline = GovernancePipeline(self)

        # Allow per-call environment override; fall back to guard-level default
        env = envelope_kwargs.pop("environment", self.environment)

        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=args,
            run_id=session_id,
            environment=env,
            registry=self.tool_registry,
            **envelope_kwargs,
        )

        # Increment attempts
        await session.increment_attempts()

        # Start OTel span
        span = self.telemetry.start_tool_span(envelope)
        if self.policy_version:
            span.set_attribute("edictum.policy_version", self.policy_version)

        # Pre-execute
        pre = await pipeline.pre_execute(envelope, session)

        # Determine if this is a real deny or just per-rule observed denials
        real_deny = pre.action == "deny" and not pre.observed

        if real_deny:
            audit_action = AuditAction.CALL_WOULD_DENY if self.mode == "observe" else AuditAction.CALL_DENIED
            await self._emit_run_pre_audit(envelope, session, audit_action, pre)
            self.telemetry.record_denial(envelope, pre.reason)
            if self.mode == "enforce":
                span.set_attribute("governance.action", "denied")
                span.set_attribute("governance.reason", pre.reason or "")
                span.end()
                raise EdictumDenied(
                    reason=pre.reason,
                    decision_source=pre.decision_source,
                    decision_name=pre.decision_name,
                )
            # observe mode: fall through to execute
            span.set_attribute("governance.action", "would_deny")
            span.set_attribute("governance.would_deny_reason", pre.reason or "")
        else:
            # Emit CALL_WOULD_DENY for any per-rule observed denials
            for cr in pre.contracts_evaluated:
                if cr.get("observed") and not cr.get("passed"):
                    observed_event = AuditEvent(
                        action=AuditAction.CALL_WOULD_DENY,
                        run_id=envelope.run_id,
                        call_id=envelope.call_id,
                        tool_name=envelope.tool_name,
                        tool_args=self.redaction.redact_args(envelope.args),
                        side_effect=envelope.side_effect.value,
                        environment=envelope.environment,
                        principal=asdict(envelope.principal) if envelope.principal else None,
                        decision_source="precondition",
                        decision_name=cr["name"],
                        reason=cr["message"],
                        mode="observe",
                        policy_version=self.policy_version,
                        policy_error=pre.policy_error,
                    )
                    await self.audit_sink.emit(observed_event)
                    self._emit_otel_governance_span(observed_event)
            await self._emit_run_pre_audit(envelope, session, AuditAction.CALL_ALLOWED, pre)
            self.telemetry.record_allowed(envelope)
            span.set_attribute("governance.action", "allowed")

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
        post_event = AuditEvent(
            action=post_action,
            run_id=envelope.run_id,
            call_id=envelope.call_id,
            tool_name=envelope.tool_name,
            tool_args=self.redaction.redact_args(envelope.args),
            side_effect=envelope.side_effect.value,
            environment=envelope.environment,
            principal=asdict(envelope.principal) if envelope.principal else None,
            tool_success=tool_success,
            postconditions_passed=post.postconditions_passed,
            contracts_evaluated=post.contracts_evaluated,
            session_attempt_count=await session.attempt_count(),
            session_execution_count=await session.execution_count(),
            mode=self.mode,
            policy_version=self.policy_version,
            policy_error=post.policy_error,
        )
        await self.audit_sink.emit(post_event)
        self._emit_otel_governance_span(post_event)

        span.set_attribute("governance.tool_success", tool_success)
        span.set_attribute("governance.postconditions_passed", post.postconditions_passed)
        span.end()

        if not tool_success:
            raise EdictumToolError(result)

        return result

    async def _emit_run_pre_audit(self, envelope, session, action: AuditAction, pre: PreDecision) -> None:
        event = AuditEvent(
            action=action,
            run_id=envelope.run_id,
            call_id=envelope.call_id,
            tool_name=envelope.tool_name,
            tool_args=self.redaction.redact_args(envelope.args),
            side_effect=envelope.side_effect.value,
            environment=envelope.environment,
            principal=asdict(envelope.principal) if envelope.principal else None,
            decision_source=pre.decision_source,
            decision_name=pre.decision_name,
            reason=pre.reason,
            hooks_evaluated=pre.hooks_evaluated,
            contracts_evaluated=pre.contracts_evaluated,
            session_attempt_count=await session.attempt_count(),
            session_execution_count=await session.execution_count(),
            mode=self.mode,
            policy_version=self.policy_version,
            policy_error=pre.policy_error,
        )
        await self.audit_sink.emit(event)
        self._emit_otel_governance_span(event)

    def _emit_otel_governance_span(self, audit_event: AuditEvent) -> None:
        """Emit an OTel span with governance attributes from an AuditEvent."""
        if not has_otel():
            return

        from opentelemetry.trace import StatusCode

        with self._gov_tracer.start_as_current_span("edictum.evaluate") as span:
            span.set_attribute("edictum.tool.name", audit_event.tool_name)
            span.set_attribute("edictum.verdict", audit_event.action.value)
            span.set_attribute("edictum.verdict.reason", audit_event.reason or "")
            span.set_attribute("edictum.decision.source", audit_event.decision_source or "")
            span.set_attribute("edictum.decision.name", audit_event.decision_name or "")
            span.set_attribute("edictum.side_effect", audit_event.side_effect)
            span.set_attribute("edictum.environment", audit_event.environment)
            span.set_attribute("edictum.mode", audit_event.mode)
            span.set_attribute("edictum.session.attempt_count", audit_event.session_attempt_count or 0)
            span.set_attribute("edictum.session.execution_count", audit_event.session_execution_count or 0)

            tool_args_str = json.dumps(audit_event.tool_args, default=str) if audit_event.tool_args else "{}"
            span.set_attribute("edictum.tool.args", tool_args_str)

            if audit_event.principal:
                for key in ("role", "team", "ticket_ref", "user_id", "org_id"):
                    val = audit_event.principal.get(key)
                    if val:
                        span.set_attribute(f"edictum.principal.{key}", val)

            if audit_event.policy_version:
                span.set_attribute("edictum.policy_version", audit_event.policy_version)
            if audit_event.policy_error:
                span.set_attribute("edictum.policy_error", True)

            if audit_event.action.value in ("call_denied",):
                span.set_status(StatusCode.ERROR, audit_event.reason or "denied")
            else:
                span.set_status(StatusCode.OK)


class EdictumDenied(Exception):  # noqa: N818
    """Raised when guard.run() denies a tool call in enforce mode."""

    def __init__(self, reason, decision_source=None, decision_name=None):
        self.reason = reason
        self.decision_source = decision_source
        self.decision_name = decision_name
        super().__init__(reason)


class EdictumConfigError(Exception):
    """Raised for configuration/load-time errors (invalid YAML, schema failures, etc.)."""

    pass


class EdictumToolError(Exception):
    """Raised when the governed tool itself fails."""

    pass
