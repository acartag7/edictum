# Claude Agent SDK Adapter

The `ClaudeAgentSDKAdapter` enforces contracts on tool calls made through
Anthropic's Claude Agent SDK. It produces a hooks dict with `pre_tool_use` and
`post_tool_use` async functions.

## Installation

```bash
pip install edictum[yaml]
```

No additional framework dependencies are needed beyond the YAML engine.

## Integration

```python
from edictum import Edictum, Principal
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = ClaudeAgentSDKAdapter(
    guard=guard,
    session_id="session-001",
    principal=Principal(user_id="deploy-bot", role="ci"),
)

hooks = adapter.to_sdk_hooks()
# hooks == {"pre_tool_use": <async fn>, "post_tool_use": <async fn>}

# Pass hooks to your Claude agent/client setup:
#   client = Claude(
#       model="claude-sonnet-4-20250514",
#       tools=[...],
#       hooks=hooks,
#   )
#   response = await client.run("Deploy the staging environment")
```

The `to_sdk_hooks()` method returns a dict. Pass it when creating your Claude
client or agent. The SDK calls `pre_tool_use` before each tool call and
`post_tool_use` after.

## Loading Contracts

Contracts can be loaded from a YAML file, a built-in template, or defined in
Python:

```python
# From a YAML contract bundle
guard = Edictum.from_yaml("contracts.yaml")

# From a built-in template
guard = Edictum.from_template("file-agent")

# From Python contracts
from edictum import deny_sensitive_reads
guard = Edictum(contracts=[deny_sensitive_reads()])
```

## Hook Behavior

### Pre-hook (`pre_tool_use`)

```python
async def pre_tool_use(tool_name: str, tool_input: dict, tool_use_id: str, **kwargs) -> dict
```

**On allow**, the hook returns an empty dict `{}`. The SDK proceeds with tool
execution.

**On deny**, the hook returns a denial dict:

```python
{
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "File /etc/shadow is in the sensitive path denylist",
    }
}
```

The SDK receives this and stops the tool call without executing it.

### Post-hook (`post_tool_use`)

The post-hook runs after tool execution to evaluate postconditions:

```python
async def post_tool_use(tool_use_id: str, tool_response: Any = None, **kwargs) -> dict
```

If postconditions produce findings, they are returned as additional context:

```python
{
    "hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": "Write operation modified 47 files (threshold: 20)",
    }
}
```

If no findings are raised, the post-hook returns `{}`.

## Known Limitations

- **Side-effect only**: The hook cannot replace the tool result. PII detection
  produces findings that are logged and returned as additional context, but the
  original tool output still reaches the model.

- **No result transformation**: Unlike wrap-around adapters (LangChain, Agno),
  the `on_postcondition_warn` callback return value is ignored. Use the callback
  for side effects only (logging, alerting).

## Observe Mode

Deploy contracts without enforcement to see what would be denied:

```python
guard = Edictum.from_yaml("contracts.yaml", mode="observe")
adapter = ClaudeAgentSDKAdapter(guard=guard)
```

In observe mode, calls that would be denied are instead allowed through. The
adapter emits `CALL_WOULD_DENY` audit events so you can see what would have been
denied. This is useful for validating contracts in production before switching
to `mode="enforce"`.

The pre-hook returns `{}` (allow) even for denied calls, and the OTel span
records `edictum.verdict = "would_deny"` with the reason.

## Audit and Observability

By default, audit events are printed to stdout as JSON. You can direct them to a
file for local development, or enable OpenTelemetry to route spans to any
observability backend (Datadog, Splunk, Grafana, Jaeger):

```python
from edictum import Edictum
from edictum.audit import FileAuditSink, RedactionPolicy
from edictum.otel import configure_otel

# Local file sink for audit logs
redaction = RedactionPolicy()
sink = FileAuditSink("audit.jsonl", redaction=redaction)

# OTel for production observability
configure_otel(service_name="my-agent", endpoint="http://localhost:4317")

guard = Edictum.from_yaml(
    "contracts.yaml",
    audit_sink=sink,
    redaction=redaction,
)

adapter = ClaudeAgentSDKAdapter(guard=guard)
```

Every tool call -- whether allowed, denied, or observed -- produces a structured
`AuditEvent` written to `audit.jsonl` as a JSON line, and an `edictum.*` OTel
span routed to the configured collector. Sensitive fields (tokens, passwords,
API keys) are automatically redacted by the `RedactionPolicy`.

## Session Tracking

The adapter tracks per-session state automatically:

- **`session_id`** groups tool calls into a session. If you omit it, a UUID is
  generated. Access it via `adapter.session_id`.
- **Attempt count** increments before every contract evaluation (even denied calls).
- **Execution count** increments only when a tool actually runs.
- **Call index** is a monotonic counter within the adapter instance.

Session-level limits in your contracts (e.g., max 50 tool calls) are enforced
through these counters.
