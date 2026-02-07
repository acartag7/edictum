# OpenTelemetry Integration

Edictum instruments the governance pipeline with OpenTelemetry spans and metrics.
When `opentelemetry` is not installed, all instrumentation degrades to silent no-ops
with zero overhead.

## Installation

```bash
pip install edictum[otel]
```

This installs the `opentelemetry-api` and `opentelemetry-sdk` packages. You will
also need an exporter for your backend (e.g. `opentelemetry-exporter-otlp` for OTLP,
`opentelemetry-exporter-jaeger` for Jaeger).

---

## What Gets Instrumented

`GovernanceTelemetry` creates an OTel tracer named `"edictum"` and a meter named
`"edictum"`. These produce spans and counters that track every tool call through
the governance pipeline.

### Spans

Each tool call produces one span:

```
tool.execute {tool_name}
```

For example, a call to the `Bash` tool produces a span named
`tool.execute Bash`. The span begins when Edictum starts evaluating the
envelope and ends after post-execution checks complete (or after denial, if
the call is blocked).

### Span Attributes

Attributes are set at different lifecycle stages.

**Set at span creation (pre-execution):**

| Attribute | Type | Description |
|-----------|------|-------------|
| `tool.name` | `string` | Name of the tool |
| `tool.side_effect` | `string` | Side-effect classification: `pure`, `read`, `write`, `irreversible` |
| `tool.call_index` | `int` | Sequential call number within the run |
| `governance.environment` | `string` | Deployment environment |
| `governance.run_id` | `string` | Unique run identifier |

**Set during governance evaluation:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `governance.action` | `string` | Decision outcome: `allowed`, `denied`, `would_deny` |
| `governance.reason` | `string` | Denial reason (only set when denied) |
| `edictum.policy_version` | `string` | SHA-256 hash of the active YAML contract file |

**Set after tool execution (post-execution):**

| Attribute | Type | Description |
|-----------|------|-------------|
| `governance.tool_success` | `bool` | Whether the tool call succeeded |
| `governance.postconditions_passed` | `bool` | Whether all postconditions passed |

---

## Metrics

Two counters are registered under the `edictum` meter:

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `edictum.calls.denied` | Counter | `tool.name` | Incremented each time a tool call is denied |
| `edictum.calls.allowed` | Counter | `tool.name` | Incremented each time a tool call is allowed |

These counters let you build dashboards that answer questions like:

- What percentage of tool calls are being denied?
- Which tools trigger the most denials?
- How does denial rate change after a contract update?

---

## Quick Setup with `configure_otel()`

The simplest way to enable OTel is the `configure_otel()` helper from the
`edictum.otel` module. Call it once at startup:

```python
from edictum.otel import configure_otel
from edictum import Edictum

configure_otel(
    service_name="my-agent",
    endpoint="http://localhost:4317",
)

guard = Edictum(...)
# Governance spans are now emitted to the configured OTLP endpoint
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `service_name` | `str` | `"edictum-agent"` | OTel service name resource attribute |
| `endpoint` | `str` | `"http://localhost:4317"` | OTLP collector endpoint |
| `protocol` | `str` | `"grpc"` | Transport protocol: `"grpc"`, `"http"`, or `"http/protobuf"`. Any non-`"grpc"` value selects the HTTP exporter. When HTTP is selected and `endpoint` is the default, it auto-adjusts to `http://localhost:4318/v1/traces`. |
| `resource_attributes` | `dict \| None` | `None` | Additional OTel resource attributes |
| `edictum_version` | `str \| None` | `None` | Edictum version tag |
| `force` | `bool` | `False` | Replace an existing TracerProvider. By default, `configure_otel()` is a no-op if a provider is already set. |

If a `TracerProvider` is already configured (e.g. by the host application or
another SDK), `configure_otel()` is a no-op. This prevents Edictum from
clobbering an existing OTel setup. Pass `force=True` to override.

Standard OTel environment variables take precedence over function arguments:

| Env Var | Overrides |
|---------|-----------|
| `OTEL_SERVICE_NAME` | `service_name` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `endpoint` |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `protocol` |
| `OTEL_RESOURCE_ATTRIBUTES` | Merged with `resource_attributes` (env wins on conflict) |

Configure via environment variables if you prefer:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317"
export OTEL_SERVICE_NAME="my-agent"
```

---

## Advanced Setup with OTLP Exporter

For full control over tracer and meter providers (e.g., custom exporters,
metric readers, or resource attributes), configure them directly:

```python
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

# Traces
tracer_provider = TracerProvider()
tracer_provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4317"))
)
trace.set_tracer_provider(tracer_provider)

# Metrics
metric_reader = PeriodicExportingMetricReader(
    OTLPMetricExporter(endpoint="http://localhost:4317"),
    export_interval_millis=10_000,
)
meter_provider = MeterProvider(metric_readers=[metric_reader])
metrics.set_meter_provider(meter_provider)

# Now import and use Edictum — telemetry activates automatically
from edictum import Edictum

guard = Edictum(...)
# GovernanceTelemetry picks up the global tracer and meter providers
```

---

## Graceful No-Op Behavior

If `opentelemetry` is not installed, `GovernanceTelemetry` operates as a complete
no-op:

- `start_tool_span()` returns an internal `_NoOpSpan` object that silently
  accepts all attribute and event calls
- `record_denial()` and `record_allowed()` do nothing
- No exceptions are raised
- No performance cost beyond a single `_HAS_OTEL` boolean check per call

This means you can leave telemetry wired into your pipeline configuration
unconditionally. When deploying to an environment without OTel, there is no need
to change code or configuration -- Edictum simply skips all instrumentation.

```python
from edictum.telemetry import GovernanceTelemetry

telemetry = GovernanceTelemetry()

# Without opentelemetry installed:
span = telemetry.start_tool_span(envelope)      # returns _NoOpSpan
span.set_attribute("governance.action", "allowed")  # silently ignored
span.end()                                        # silently ignored
telemetry.record_allowed(envelope)                # silently ignored
```

---

## Correlating with Application Traces

Edictum spans participate in the standard OTel context propagation. If your
application already creates spans (e.g. for an HTTP request or an agent loop
iteration), Edictum spans appear as children of whatever span is active when
the governance pipeline runs. This gives you a single trace that shows:

```
HTTP POST /agent/run                        [your app]
  └─ agent.loop.iteration                   [your app]
      └─ tool.execute Bash                  [edictum]
          governance.action = "allowed"
          governance.tool_success = true
```

No additional configuration is required for this to work. The standard OTel
context propagation handles span parenting automatically.
