"""Behavior tests for edictum.otel — configure_otel() parameter effects."""

from __future__ import annotations

import unittest.mock as mock

import pytest

try:
    import opentelemetry  # noqa: F401

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False


def _reset_otel_provider():
    """Reset the global OTel tracer provider so tests can install their own."""
    from opentelemetry import trace
    from opentelemetry.util._once import Once

    trace._TRACER_PROVIDER_SET_ONCE = Once()
    trace._TRACER_PROVIDER = trace._PROXY_TRACER_PROVIDER


@pytest.mark.skipif(not HAS_OTEL, reason="OpenTelemetry not installed")
class TestConfigureOtelInsecure:
    """insecure parameter controls TLS on gRPC OTLPSpanExporter."""

    def test_grpc_insecure_true_by_default(self):
        """Default insecure=True preserves backward compatibility."""
        from edictum.otel import configure_otel

        _reset_otel_provider()

        with mock.patch("edictum.otel.OTLPSpanExporter") as mock_grpc:
            mock_grpc.return_value = mock.MagicMock()
            configure_otel(endpoint="http://localhost:4317")
            mock_grpc.assert_called_once_with(endpoint="http://localhost:4317", insecure=True)

    def test_grpc_insecure_false_enables_tls(self):
        """insecure=False passes through to gRPC exporter for TLS."""
        from edictum.otel import configure_otel

        _reset_otel_provider()

        with mock.patch("edictum.otel.OTLPSpanExporter") as mock_grpc:
            mock_grpc.return_value = mock.MagicMock()
            configure_otel(
                endpoint="https://collector.prod:4317",
                insecure=False,
            )
            mock_grpc.assert_called_once_with(endpoint="https://collector.prod:4317", insecure=False)

    def test_insecure_does_not_affect_http_exporter(self):
        """HTTP exporter does not receive insecure kwarg (TLS via URL scheme)."""
        from edictum.otel import configure_otel

        _reset_otel_provider()

        with mock.patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter") as mock_http:
            mock_http.return_value = mock.MagicMock()
            configure_otel(
                protocol="http",
                endpoint="https://collector.prod:4318/v1/traces",
                insecure=False,
            )
            # HTTP exporter uses URL scheme for TLS, not insecure flag
            mock_http.assert_called_once_with(endpoint="https://collector.prod:4318/v1/traces")
