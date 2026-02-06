"""OpenTelemetry integration — graceful no-op if absent."""

from __future__ import annotations

from typing import Any

try:
    from opentelemetry import metrics, trace

    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False


class _NoOpSpan:
    """Dummy span when OTel is not available."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def set_attribute(self, key, value):
        pass

    def set_status(self, status):
        pass

    def add_event(self, name, attributes=None):
        pass

    def end(self):
        pass


class GovernanceTelemetry:
    """OTel integration. No-op if opentelemetry not installed.

    Install: pip install callguard[otel]
    """

    def __init__(self):
        if _HAS_OTEL:
            self._tracer = trace.get_tracer("callguard")
            self._meter = metrics.get_meter("callguard")
            self._setup_metrics()
        else:
            self._tracer = None
            self._meter = None

    def _setup_metrics(self):
        if not self._meter:
            return
        self._denied_counter = self._meter.create_counter(
            "callguard.calls.denied",
            description="Number of denied tool calls",
        )
        self._allowed_counter = self._meter.create_counter(
            "callguard.calls.allowed",
            description="Number of allowed tool calls",
        )

    def start_tool_span(self, envelope: Any) -> Any:
        """Start span. Returns _NoOpSpan if OTel not available."""
        if not self._tracer:
            return _NoOpSpan()
        return self._tracer.start_span(
            f"tool.execute {envelope.tool_name}",
            attributes={
                "tool.name": envelope.tool_name,
                "tool.side_effect": envelope.side_effect.value,
                "tool.call_index": envelope.call_index,
                "governance.environment": envelope.environment,
                "governance.run_id": envelope.run_id,
            },
        )

    def record_denial(self, envelope: Any, reason: str | None = None) -> None:
        if _HAS_OTEL and self._meter:
            self._denied_counter.add(1, {"tool.name": envelope.tool_name})

    def record_allowed(self, envelope: Any) -> None:
        if _HAS_OTEL and self._meter:
            self._allowed_counter.add(1, {"tool.name": envelope.tool_name})
