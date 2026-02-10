"""Evaluation result dataclasses for dry-run contract evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleResult:
    """Result of evaluating a single contract rule."""

    rule_id: str
    rule_type: str  # "precondition" | "postcondition"
    passed: bool
    message: str | None = None
    tags: list[str] = field(default_factory=list)
    observed: bool = False
    policy_error: bool = False


@dataclass(frozen=True)
class EvaluationResult:
    """Result of dry-run evaluation of a tool call against contracts."""

    verdict: str  # "allow" | "deny" | "warn"
    tool_name: str
    rules: list[RuleResult] = field(default_factory=list)
    deny_reasons: list[str] = field(default_factory=list)
    warn_reasons: list[str] = field(default_factory=list)
    rules_evaluated: int = 0
    policy_error: bool = False
