"""Tests for GovernanceTelemetry and _NoOpSpan."""

from __future__ import annotations

from callguard.envelope import create_envelope
from callguard.telemetry import _HAS_OTEL, GovernanceTelemetry, _NoOpSpan


class TestNoOpSpan:
    def test_context_manager(self):
        span = _NoOpSpan()
        with span as s:
            assert s is span

    def test_set_attribute(self):
        span = _NoOpSpan()
        span.set_attribute("key", "value")  # should not raise

    def test_set_status(self):
        span = _NoOpSpan()
        span.set_status("ok")  # should not raise

    def test_add_event(self):
        span = _NoOpSpan()
        span.add_event("test", attributes={"key": "val"})  # should not raise

    def test_end(self):
        span = _NoOpSpan()
        span.end()  # should not raise


class TestGovernanceTelemetry:
    def test_start_tool_span_returns_span(self):
        telemetry = GovernanceTelemetry()
        envelope = create_envelope("TestTool", {})
        span = telemetry.start_tool_span(envelope)
        if _HAS_OTEL:
            # When OTel is installed, returns a real span
            assert hasattr(span, "set_attribute")
            assert hasattr(span, "end")
        else:
            assert isinstance(span, _NoOpSpan)
        # Either way, span should support the interface
        span.set_attribute("test", "value")
        span.end()

    def test_record_denial_does_not_raise(self):
        telemetry = GovernanceTelemetry()
        envelope = create_envelope("TestTool", {})
        telemetry.record_denial(envelope, "test reason")

    def test_record_allowed_does_not_raise(self):
        telemetry = GovernanceTelemetry()
        envelope = create_envelope("TestTool", {})
        telemetry.record_allowed(envelope)
