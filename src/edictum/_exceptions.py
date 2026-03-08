"""Exception classes for Edictum."""

from __future__ import annotations


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
