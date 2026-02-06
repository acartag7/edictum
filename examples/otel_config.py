"""Optional OpenTelemetry configuration for CallGuard demos."""

from __future__ import annotations


def setup_otel(service_name: str = "callguard-demo") -> None:
    """Configure OTel tracing if opentelemetry-sdk is installed."""
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(provider)
        print(f"[otel] Tracing enabled for {service_name}")
    except ImportError:
        print("[otel] opentelemetry-sdk not installed, tracing disabled. Install with: pip install callguard[otel]")
