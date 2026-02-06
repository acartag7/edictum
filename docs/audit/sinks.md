# Audit Sinks

Every governance decision in CallGuard produces an `AuditEvent`. Audit sinks consume
these events and route them to storage, monitoring, or alerting systems.

## The AuditSink Protocol

Any class that implements the `AuditSink` protocol can receive audit events. The
protocol requires a single async method:

```python
from callguard.audit import AuditSink

class MyCustomSink:
    async def emit(self, event: AuditEvent) -> None:
        # process the event
        ...
```

CallGuard checks conformance at runtime via `@runtime_checkable`, so there is no need
to inherit from a base class. Implement `emit` and you are done.

Register a sink when constructing your `CallGuard` instance:

```python
from callguard import CallGuard
from callguard.audit import FileAuditSink

guard = CallGuard(
    audit_sink=FileAuditSink("/var/log/callguard/events.jsonl"),
)
```

If no `audit_sink` is provided, a `StdoutAuditSink` is used by default.

---

## AuditEvent Fields

Every audit event contains the following fields:

### Identity

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `str` | Event schema version (currently `"0.3.0"`) |
| `timestamp` | `datetime` | UTC timestamp of the event |
| `run_id` | `str` | Unique ID for the agent run |
| `call_id` | `str` | Unique ID for this specific tool call |
| `call_index` | `int` | Sequential call number within the run |
| `parent_call_id` | `str \| None` | Parent call ID for nested invocations |

### Tool

| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | `str` | Name of the tool being called |
| `tool_args` | `dict` | Arguments passed to the tool |
| `side_effect` | `str` | Side-effect classification: `pure`, `read`, `write`, `irreversible` |
| `environment` | `str` | Deployment environment (e.g. `production`, `staging`) |

### Principal

| Field | Type | Description |
|-------|------|-------------|
| `principal` | `dict \| None` | Identity context: `user_id`, `service_id`, `org_id`, `role`, `ticket_ref`, `claims` |

### Governance Decision

| Field | Type | Description |
|-------|------|-------------|
| `action` | `AuditAction` | One of: `call_denied`, `call_would_deny`, `call_allowed`, `call_executed`, `call_failed` |
| `decision_source` | `str \| None` | What produced the decision: `hook`, `precondition`, `session_contract`, `attempt_limit`, `operation_limit` |
| `decision_name` | `str \| None` | Name of the specific hook or contract |
| `reason` | `str \| None` | Human-readable denial reason |
| `hooks_evaluated` | `list[dict]` | Each hook with its name, result, and reason |
| `contracts_evaluated` | `list[dict]` | Each contract with name, type, passed, and message |

### Execution

| Field | Type | Description |
|-------|------|-------------|
| `tool_success` | `bool \| None` | Whether the tool call succeeded (set after execution) |
| `postconditions_passed` | `bool \| None` | Whether all postconditions passed |
| `duration_ms` | `int` | Tool execution time in milliseconds |
| `error` | `str \| None` | Error message if the tool failed |
| `result_summary` | `str \| None` | Truncated summary of the tool result |

### Counters

| Field | Type | Description |
|-------|------|-------------|
| `session_attempt_count` | `int` | Total attempts in this session (including denials) |
| `session_execution_count` | `int` | Total executions in this session |

### Policy

| Field | Type | Description |
|-------|------|-------------|
| `policy_version` | `str \| None` | SHA-256 hash of the YAML contract file |
| `policy_error` | `bool` | `True` if there was an error loading contracts |
| `mode` | `str` | `enforce` or `observe` |

---

## Built-in Sinks

### StdoutAuditSink

Prints each event as a single JSON line to stdout. Useful for development and for
piping into log aggregators.

```python
from callguard.audit import StdoutAuditSink, RedactionPolicy

sink = StdoutAuditSink(redaction=RedactionPolicy())
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `redaction` | `RedactionPolicy \| None` | `RedactionPolicy()` | Redaction policy (always applied; defaults to standard policy) |

### FileAuditSink

Appends each event as a JSON line to a file. Creates the file if it does not exist.
Suitable for local audit logs and offline analysis.

```python
from callguard.audit import FileAuditSink, RedactionPolicy

sink = FileAuditSink(
    path="/var/log/callguard/events.jsonl",
    redaction=RedactionPolicy(),
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `str \| Path` | (required) | File path for the JSONL output |
| `redaction` | `RedactionPolicy \| None` | `RedactionPolicy()` | Redaction policy |

### WebhookAuditSink

Posts each event as JSON via HTTP POST. Supports exponential-backoff retries
(delays of 1s, 2s, 4s by default) and a fire-and-forget mode that dispatches
via `asyncio.create_task` without blocking the governance pipeline.

```bash
pip install callguard[sinks]  # adds aiohttp dependency
```

```python
from callguard.audit import RedactionPolicy
from callguard.sinks.webhook import WebhookAuditSink

sink = WebhookAuditSink(
    url="https://hooks.example.com/callguard",
    headers={"Authorization": "Bearer <token>"},
    fire_and_forget=False,
    redaction_policy=RedactionPolicy(),
    max_retries=3,
    base_delay=1.0,
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `str` | (required) | Webhook endpoint URL |
| `headers` | `dict \| None` | `None` | Additional HTTP headers (`Content-Type: application/json` is always set) |
| `fire_and_forget` | `bool` | `False` | If `True`, emit returns immediately and delivery happens in a background task |
| `redaction_policy` | `RedactionPolicy \| None` | `None` | Redaction policy applied before sending |
| `max_retries` | `int` | `3` | Maximum number of delivery attempts |
| `base_delay` | `float` | `1.0` | Base delay in seconds for exponential backoff |

!!! warning "Fire-and-forget risk"

    When `fire_and_forget=True`, events are dispatched via `asyncio.create_task` without
    blocking the governance pipeline. **Events may be silently dropped after retry
    exhaustion.** The sink logs a warning but does not raise. For production deployments,
    use `fire_and_forget=False` (the default) to ensure delivery errors surface.

### SplunkHECSink

Sends events to Splunk via the HTTP Event Collector. Each event is wrapped in
the HEC envelope format with a configurable `index` and `sourcetype`.
Authentication uses the `Authorization: Splunk <token>` header.

```bash
pip install callguard[sinks]
```

```python
from callguard.audit import RedactionPolicy
from callguard.sinks.splunk import SplunkHECSink

sink = SplunkHECSink(
    url="https://splunk.example.com:8088/services/collector",
    token="your-hec-token",
    index="ai_governance",
    sourcetype="callguard",
    redaction_policy=RedactionPolicy(),
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `str` | (required) | Splunk HEC endpoint URL |
| `token` | `str` | (required) | HEC authentication token |
| `index` | `str` | `"main"` | Splunk index to write to |
| `sourcetype` | `str` | `"callguard"` | Sourcetype for the events |
| `redaction_policy` | `RedactionPolicy \| None` | `None` | Redaction policy applied before sending |

The HEC payload sent to Splunk looks like:

```json
{
  "event": { "...audit event fields..." },
  "sourcetype": "callguard",
  "index": "ai_governance"
}
```

### DatadogSink

Sends events to the Datadog Logs API. Events are posted to
`https://http-intake.logs.{site}/api/v2/logs` with the `DD-API-KEY` header.

```bash
pip install callguard[sinks]
```

```python
from callguard.audit import RedactionPolicy
from callguard.sinks.datadog import DatadogSink

sink = DatadogSink(
    api_key="your-datadog-api-key",
    site="datadoghq.com",
    service="callguard",
    source="callguard",
    redaction_policy=RedactionPolicy(),
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str` | (required) | Datadog API key |
| `site` | `str` | `"datadoghq.com"` | Datadog site (`datadoghq.com`, `datadoghq.eu`, `us3.datadoghq.com`, etc.) |
| `service` | `str` | `"callguard"` | Service name tag |
| `source` | `str` | `"callguard"` | Source tag for Datadog pipelines |
| `redaction_policy` | `RedactionPolicy \| None` | `None` | Redaction policy applied before sending |

The Datadog payload format:

```json
[
  {
    "ddsource": "callguard",
    "ddtags": "service:callguard",
    "service": "callguard",
    "message": { "...audit event fields..." }
  }
]
```

---

## HTTP Sink Session Management

All HTTP sinks (`WebhookAuditSink`, `SplunkHECSink`, `DatadogSink`) share a lazy
aiohttp session that is created on first `emit()` and reused across calls. Call
`close()` when shutting down to release the connection pool:

```python
sink = WebhookAuditSink(url="https://hooks.example.com/callguard")

# ... use the sink ...

await sink.close()
```

If `close()` is not called, the underlying connection pool will be released when the
process exits, but Python may emit `ResourceWarning` about unclosed sessions.

---

## Redaction Policy

All sinks support automatic redaction of sensitive data via `RedactionPolicy`. If
no explicit policy is provided, `StdoutAuditSink` and `FileAuditSink` create a
default policy automatically. The network sinks (`Webhook`, `Splunk`, `Datadog`)
apply redaction only when you pass a `redaction_policy`.

### Sensitive Key Detection

Keys are normalized to lowercase and matched against a built-in set:

`password`, `secret`, `token`, `api_key`, `apikey`, `api-key`, `authorization`,
`auth`, `credentials`, `private_key`, `privatekey`, `access_token`,
`refresh_token`, `client_secret`, `connection_string`, `database_url`,
`db_password`, `ssh_key`, `passphrase`

Additionally, any key containing `token`, `key`, `secret`, `password`, or
`credential` as a substring is treated as sensitive.

### Secret Value Pattern Detection

Values are checked against patterns for common secret formats, regardless of the
key name:

| Pattern | Example |
|---------|---------|
| `sk-*` | OpenAI API keys |
| `AKIA*` | AWS access key IDs |
| `eyJ*` | JWT tokens |
| `ghp_*` | GitHub personal access tokens |
| `xox[bpas]-*` | Slack tokens |

### Bash Command Redaction

Bash commands in `tool_args` are scrubbed for inline secrets:

- `export SECRET_KEY=abc123` becomes `export SECRET_KEY=[REDACTED]`
- `-p mypassword` becomes `-p [REDACTED]`
- `https://user:pass@host` becomes `https://user:[REDACTED]@host`

### Payload Size Cap

Payloads exceeding 32 KB are truncated. The `tool_args` and `result_summary` fields
are replaced with a marker indicating the cap was hit. This prevents audit sinks from
dropping events due to oversized payloads.

### Custom Redaction

```python
from callguard.audit import RedactionPolicy

policy = RedactionPolicy(
    sensitive_keys={"my_custom_key", "internal_token"},  # merged with defaults via substring matching
    custom_patterns=[
        (r"(MY_PREFIX_)\S+", r"\1[REDACTED]"),           # custom regex substitutions
    ],
    detect_secret_values=True,                            # enable/disable value pattern detection
)
```

---

## Custom Sinks

Implement the `AuditSink` protocol to route events to any destination:

```python
import json
from callguard.audit import AuditEvent, RedactionPolicy

class KafkaAuditSink:
    """Send audit events to a Kafka topic."""

    def __init__(self, producer, topic: str, redaction: RedactionPolicy | None = None):
        self._producer = producer
        self._topic = topic
        self._redaction = redaction or RedactionPolicy()

    async def emit(self, event: AuditEvent) -> None:
        from dataclasses import asdict
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        data["action"] = event.action.value
        data = self._redaction.cap_payload(data)
        await self._producer.send(
            self._topic,
            json.dumps(data, default=str).encode(),
        )
```

Then register it:

```python
guard = CallGuard(
    audit_sink=KafkaAuditSink(producer, "callguard-events"),
)
```

The `AuditSink` protocol is `@runtime_checkable`, so CallGuard validates your
sink at registration time. If `emit` is missing or has the wrong signature,
you get an immediate `TypeError` rather than a silent failure at event time.
