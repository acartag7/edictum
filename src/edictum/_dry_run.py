"""Dry-run evaluation logic for Edictum.evaluate() and evaluate_batch()."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from edictum.envelope import Principal, create_envelope
from edictum.evaluation import ContractResult, EvaluationResult

if TYPE_CHECKING:
    from edictum._guard import Edictum


def _evaluate(
    self: Edictum,
    tool_name: str,
    args: dict[str, Any],
    *,
    principal: Principal | None = None,
    output: str | None = None,
    environment: str | None = None,
) -> EvaluationResult:
    """Dry-run evaluation of a tool call against all matching contracts.

    Unlike run(), this never executes the tool and evaluates all
    matching contracts exhaustively (no short-circuit on first deny).
    Session contracts are skipped (no session state in dry-run).
    """
    env = environment or self.environment
    envelope = create_envelope(
        tool_name=tool_name,
        tool_input=args,
        environment=env,
        principal=principal,
        registry=self.tool_registry,
    )

    contracts: list[ContractResult] = []
    deny_reasons: list[str] = []
    warn_reasons: list[str] = []

    # Evaluate all matching preconditions (exhaustive, no short-circuit)
    for contract in self.get_preconditions(envelope):
        contract_id = getattr(contract, "_edictum_id", None) or getattr(contract, "__name__", "unknown")
        try:
            verdict = contract(envelope)
        except Exception as exc:
            contract_result = ContractResult(
                contract_id=contract_id,
                contract_type="precondition",
                passed=False,
                message=f"Precondition error: {exc}",
                policy_error=True,
            )
            contracts.append(contract_result)
            deny_reasons.append(contract_result.message)
            continue

        tags = verdict.metadata.get("tags", []) if verdict.metadata else []
        is_observed = getattr(contract, "_edictum_mode", None) == "observe" and not verdict.passed
        pe = verdict.metadata.get("policy_error", False) if verdict.metadata else False

        contract_result = ContractResult(
            contract_id=contract_id,
            contract_type="precondition",
            passed=verdict.passed,
            message=verdict.message,
            tags=tags,
            observed=is_observed,
            policy_error=pe,
        )
        contracts.append(contract_result)

        if not verdict.passed and not is_observed:
            deny_reasons.append(verdict.message or "")

    # Evaluate sandbox contracts (exhaustive, no short-circuit)
    for contract in self.get_sandbox_contracts(envelope):
        contract_id = getattr(contract, "_edictum_id", None) or getattr(contract, "__name__", "unknown")
        try:
            verdict = contract(envelope)
        except Exception as exc:
            contract_result = ContractResult(
                contract_id=contract_id,
                contract_type="sandbox",
                passed=False,
                message=f"Sandbox error: {exc}",
                policy_error=True,
            )
            contracts.append(contract_result)
            deny_reasons.append(contract_result.message)
            continue

        tags = verdict.metadata.get("tags", []) if verdict.metadata else []
        is_observed = getattr(contract, "_edictum_mode", None) == "observe" and not verdict.passed
        pe = verdict.metadata.get("policy_error", False) if verdict.metadata else False

        contract_result = ContractResult(
            contract_id=contract_id,
            contract_type="sandbox",
            passed=verdict.passed,
            message=verdict.message,
            tags=tags,
            observed=is_observed,
            policy_error=pe,
        )
        contracts.append(contract_result)

        if not verdict.passed and not is_observed:
            deny_reasons.append(verdict.message or "")

    # Evaluate postconditions only when output is provided
    if output is not None:
        for contract in self.get_postconditions(envelope):
            contract_id = getattr(contract, "_edictum_id", None) or getattr(contract, "__name__", "unknown")
            try:
                verdict = contract(envelope, output)
            except Exception as exc:
                contract_result = ContractResult(
                    contract_id=contract_id,
                    contract_type="postcondition",
                    passed=False,
                    message=f"Postcondition error: {exc}",
                    policy_error=True,
                )
                contracts.append(contract_result)
                warn_reasons.append(contract_result.message)
                continue

            tags = verdict.metadata.get("tags", []) if verdict.metadata else []
            is_observed = getattr(contract, "_edictum_mode", None) == "observe" and not verdict.passed
            pe = verdict.metadata.get("policy_error", False) if verdict.metadata else False
            effect = getattr(contract, "_edictum_effect", "warn")

            contract_result = ContractResult(
                contract_id=contract_id,
                contract_type="postcondition",
                passed=verdict.passed,
                message=verdict.message,
                tags=tags,
                observed=is_observed,
                effect=effect,
                policy_error=pe,
            )
            contracts.append(contract_result)

            if not verdict.passed and not is_observed:
                warn_reasons.append(verdict.message or "")

    # Compute verdict
    if deny_reasons:
        verdict_str = "deny"
    elif warn_reasons:
        verdict_str = "warn"
    else:
        verdict_str = "allow"

    return EvaluationResult(
        verdict=verdict_str,
        tool_name=tool_name,
        contracts=contracts,
        deny_reasons=deny_reasons,
        warn_reasons=warn_reasons,
        contracts_evaluated=len(contracts),
        policy_error=any(r.policy_error for r in contracts),
    )


def _evaluate_batch(self: Edictum, calls: list[dict[str, Any]]) -> list[EvaluationResult]:
    """Evaluate a batch of tool calls. Thin wrapper over evaluate()."""
    results: list[EvaluationResult] = []
    for call in calls:
        tool = call["tool"]
        args = call.get("args", {})

        # Convert principal dict to Principal object
        principal = None
        principal_data = call.get("principal")
        if principal_data and isinstance(principal_data, dict):
            principal = Principal(
                role=principal_data.get("role"),
                user_id=principal_data.get("user_id"),
                ticket_ref=principal_data.get("ticket_ref"),
                claims=principal_data.get("claims", {}),
            )

        # Normalize output
        output = call.get("output")
        if isinstance(output, dict):
            output = json.dumps(output)

        environment = call.get("environment")

        results.append(
            self.evaluate(
                tool,
                args,
                principal=principal,
                output=output,
                environment=environment,
            )
        )
    return results
