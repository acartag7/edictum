# Observability Setup

Edictum instruments the pipeline with OpenTelemetry spans, metrics, and structured audit logs. This guide covers what gets emitted, how to configure backends, and what to monitor.

---

## What Edictum Emits

### Spans

Each tool call produces one span named `tool.execute {tool_name}`.

Key span attributes:

| Attribute | Type | Description |
|-----------|------|-------------|
| `edictum.tool.name` | string | Name of the tool |
| `edictum.verdict` | string | `allowed`, `denied`, or `would_deny` |
| `edictum.decision.name` | string | Contract ID that fired (if denied) |
| `edictum.principal.role` | string | Principal role from the adapter |
| `edictum.mode` | string | `enforce` or `observe` |
| `edictum.policy_version` | string | SHA-256 hash of the active YAML file |

Denied calls set the span status to ERROR with the denial reason.

### Counters

Two counters are registered under the `edictum` meter:

| Metric | Labels | Description |
|--------|--------|-------------|
| `edictum.calls.allowed` | `tool.name` | Incremented on each allowed tool call |
| `edictum.calls.denied` | `tool.name` | Incremented on each denied tool call |

---

## Setup: Grafana Cloud

Set environment variables to send traces and metrics to Grafana Cloud:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otlp-gateway-prod-us-east-0.grafana.net/otlp"
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic <base64-encoded-instance-id:api-key>"
export OTEL_SERVICE_NAME="my-agent"
```

Then configure Edictum with OTel:

```python
from edictum.otel import configure_otel

configure_otel(
    service_name="my-agent",
    endpoint="https://otlp-gateway-prod-us-east-0.grafana.net/otlp",
)
```

Standard OTel environment variables take precedence over function arguments, so you can configure purely via env vars if preferred.

---

## Setup: Local Development

For local development, use a docker-compose stack with the OpenTelemetry Collector, Tempo, and Grafana. The [edictum-demo](https://github.com/acartag7/edictum-demo) repository includes a ready-to-use `docker-compose.yaml` and dashboard JSON.

Point Edictum at the local collector:

```python
from edictum.otel import configure_otel

configure_otel(
    service_name="my-agent",
    endpoint="http://localhost:4317",
)
```

---

## YAML Observability Config

Edictum supports an `observability` block at the top level of your contract bundle for configuring audit output:

```yaml
observability:
  otel:
    enabled: true
    service_name: my-agent
    endpoint: http://localhost:4317
  file: audit.jsonl
  stdout: true
```

| Field | Description |
|-------|-------------|
| `otel.enabled` | Enable OpenTelemetry instrumentation |
| `otel.service_name` | OTel service name resource attribute |
| `otel.endpoint` | OTLP collector endpoint |
| `file` | Path to write JSONL audit events |
| `stdout` | Print audit events to stdout |

---

## What to Monitor

### Denial rate

Track the ratio of denied to total tool calls. A spike in denials may indicate:

- A misconfigured contract (false positives)
- An agent behaving unexpectedly (attempting denied actions repeatedly)
- A legitimate contract change that needs communication to users

### PII detection frequency

Monitor postcondition warnings with `pii` tags. Frequent PII detections may indicate:

- Tools returning sensitive data that should be filtered upstream
- Missing input validation in external services
- Need for stricter preconditions to prevent the calls in the first place

### Session limit hits

Track `session` contract denials. Frequent session limit hits suggest:

- Agents stuck in loops (retry-after-deny patterns)
- Limits set too low for the task complexity
- Need for better agent instructions to prevent excessive tool use

### Observe mode shadow denials

In observe mode, track `CALL_WOULD_DENY` events to validate new contracts before enforcement. A high shadow-denial rate on a new contract may mean it needs tuning before going to enforce mode.

---

## Dashboard and Demo

The [edictum-demo](https://github.com/acartag7/edictum-demo) repository includes:

- A `docker-compose.yaml` with OTel Collector, Tempo, and Grafana pre-configured
- Grafana dashboard JSON for visualizing denial rates, tool call volumes, and PII detection
- Example agents that produce enforcement telemetry

For full details on span attributes, metric names, and advanced OTel configuration, see the [Telemetry Reference](../audit/telemetry.md).
