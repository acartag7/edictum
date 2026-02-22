"""Shared types for Edictum internals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class HookRegistration:
    """Registration for a hook callback."""

    phase: str  # "before" | "after"
    tool: str  # tool name or "*" for all
    callback: Any
    when: Any | None = None


@dataclass
class ToolConfig:
    """Internal tool configuration."""

    name: str
    side_effect: Any
    idempotent: bool = False
