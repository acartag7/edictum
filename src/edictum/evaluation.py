"""Evaluation result dataclasses for dry-run contract evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ContractResult:
    """Result of evaluating a single contract."""

    contract_id: str
    contract_type: str  # "precondition" | "postcondition"
    passed: bool
    message: str | None = None
    tags: list[str] = field(default_factory=list)
    observed: bool = False
    effect: str = "warn"
    policy_error: bool = False


@dataclass(frozen=True)
class EvaluationResult:
    """Result of dry-run evaluation of a tool call against contracts."""

    verdict: str  # "allow" | "deny" | "warn"
    tool_name: str
    contracts: list[ContractResult] = field(default_factory=list)
    deny_reasons: list[str] = field(default_factory=list)
    warn_reasons: list[str] = field(default_factory=list)
    contracts_evaluated: int = 0
    policy_error: bool = False
