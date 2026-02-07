"""Edictum OpenTelemetry integration.

Emits governance-specific spans for every contract evaluation.
Gracefully degrades to no-op if OpenTelemetry is not installed.

Install: pip install edictum[otel]
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False


def has_otel() -> bool:
    """Check if OpenTelemetry is available."""
    return _HAS_OTEL


def configure_otel(
    *,
    service_name: str = "edictum-agent",
    endpoint: str = "http://localhost:4317",
    protocol: str = "grpc",
    resource_attributes: dict[str, str] | None = None,
    edictum_version: str | None = None,
) -> None:
    """Configure OpenTelemetry for Edictum.

    Call this once at startup to enable OTel span emission.
    If OTel is not installed, this is a no-op.

    Standard OTel env vars override these settings:
    - OTEL_EXPORTER_OTLP_ENDPOINT overrides endpoint
    - OTEL_SERVICE_NAME overrides service_name
    - OTEL_RESOURCE_ATTRIBUTES merged with resource_attributes
    """
    if not _HAS_OTEL:
        return

    attrs: dict[str, str] = {
        "service.name": service_name,
    }
    if edictum_version:
        attrs["edictum.version"] = edictum_version
    if resource_attributes:
        attrs.update(resource_attributes)

    resource = Resource.create(attrs)
    provider = TracerProvider(resource=resource)

    actual_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)

    if protocol == "grpc":
        exporter = OTLPSpanExporter(endpoint=actual_endpoint, insecure=True)
    else:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as HTTPExporter

        exporter = HTTPExporter(endpoint=actual_endpoint)

    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)


def get_tracer(name: str = "edictum") -> Any:
    """Get an OTel tracer. Returns no-op if OTel not installed."""
    if not _HAS_OTEL:
        return _NoOpTracer()
    return trace.get_tracer(name)


class _NoOpSpan:
    """Dummy span when OTel is not available."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any, description: str | None = None) -> None:
        pass

    def add_event(self, name: str, attributes: dict | None = None) -> None:
        pass

    def end(self) -> None:
        pass

    def get_span_context(self) -> None:
        return None


class _NoOpTracer:
    """Dummy tracer when OTel is not available."""

    def start_span(self, name: str, **kwargs: Any) -> _NoOpSpan:
        return _NoOpSpan()

    def start_as_current_span(self, name: str, **kwargs: Any) -> contextlib._GeneratorContextManager:
        @contextlib.contextmanager
        def _noop_ctx():
            yield _NoOpSpan()

        return _noop_ctx()
