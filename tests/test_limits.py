"""Tests for OperationLimits."""

from __future__ import annotations

from callguard.limits import OperationLimits


class TestOperationLimits:
    def test_defaults(self):
        limits = OperationLimits()
        assert limits.max_attempts == 500
        assert limits.max_tool_calls == 200
        assert limits.max_calls_per_tool == {}

    def test_custom_values(self):
        limits = OperationLimits(
            max_attempts=100,
            max_tool_calls=50,
            max_calls_per_tool={"Bash": 10, "Write": 5},
        )
        assert limits.max_attempts == 100
        assert limits.max_tool_calls == 50
        assert limits.max_calls_per_tool == {"Bash": 10, "Write": 5}

    def test_per_tool_empty_by_default(self):
        limits = OperationLimits()
        assert "Bash" not in limits.max_calls_per_tool
