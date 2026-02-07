# Postcondition Findings

When a postcondition contract detects an issue in tool output (PII, secrets, policy violations),
Edictum produces structured **findings** that your application can act on.

## The Pattern: Detect -> Remediate

Edictum separates detection from remediation:

- **Contracts detect** -- YAML postconditions evaluate tool output, produce findings
- **Your code remediates** -- a callback transforms the result before the LLM sees it

```python
from edictum import Edictum
from edictum.adapters.langchain import LangChainAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = LangChainAdapter(guard)

# Without remediation -- findings are logged, result unchanged
wrapper = adapter.as_tool_wrapper()

# With remediation -- callback transforms result when postconditions warn
wrapper = adapter.as_tool_wrapper(
    on_postcondition_warn=lambda result, findings: redact_pii(result, findings)
)
```

## Finding Object

Each finding contains:

| Field | Type | Description |
|-------|------|-------------|
| `type` | str | Category: `pii_detected`, `secret_detected`, `limit_exceeded`, `policy_violation` |
| `contract_id` | str | Which contract produced this finding |
| `field` | str | Which selector triggered it. Defaults to `"output"` for postconditions; contracts can provide a more specific value via `Verdict.fail("msg", field="output.text")` |
| `message` | str | Human-readable description |
| `metadata` | dict | Extra context (optional) |

```python
Finding(
    type="pii_detected",
    contract_id="pii-in-any-output",
    field="output.text",
    message="SSN pattern detected in tool output",
    metadata={"match_count": 2},
)
```

Findings are **frozen** (immutable) -- they cannot be modified after creation.

## PostCallResult

The adapter's post-tool-call returns a `PostCallResult`:

```python
PostCallResult(
    result="raw tool output with SSN 123-45-6789",
    postconditions_passed=False,
    findings=[Finding(type="pii_detected", ...)],
)
```

When `postconditions_passed` is `True`, the `findings` list is empty and the callback is not invoked.

## Remediation Examples

### Surgical PII redaction

```python
import re

def redact_pii(result, findings):
    """Replace PII patterns while keeping useful data intact."""
    text = str(result)
    for f in findings:
        if f.type == "pii_detected":
            text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '***-**-****', text)
            text = re.sub(r'Name:\s*\w+\s+\w+', 'Name: [REDACTED]', text)
    return text

wrapper = adapter.as_tool_wrapper(on_postcondition_warn=redact_pii)
```

### Full replacement

```python
def replace_on_warn(result, findings):
    """Replace entire result with warning message."""
    messages = [f.message for f in findings]
    return f"[REDACTED] Postcondition warnings: {'; '.join(messages)}"

wrapper = adapter.as_tool_wrapper(on_postcondition_warn=replace_on_warn)
```

### Log and pass through

```python
import logging
logger = logging.getLogger("my_agent")

def log_findings(result, findings):
    """Log findings but return result unchanged."""
    for f in findings:
        logger.warning(f"[{f.contract_id}] {f.type}: {f.message}")
    return result  # unchanged

wrapper = adapter.as_tool_wrapper(on_postcondition_warn=log_findings)
```

### Route by finding type

```python
def route_by_type(result, findings):
    """Different remediation per finding type."""
    text = str(result)
    for f in findings:
        if f.type == "pii_detected":
            text = redact_pii_patterns(text)
        elif f.type == "secret_detected":
            text = "[BLOCKED] Secret detected in tool output"
            break  # full block on secrets
    return text

wrapper = adapter.as_tool_wrapper(on_postcondition_warn=route_by_type)
```

## How It Works With Observe / Enforce

| Mode | Postcondition warns | Callback invoked | Result transformed |
|------|-------------------|-----------------|-------------------|
| **observe** | Logged as `would_warn` | Yes (if provided) | Yes |
| **enforce** | Logged as `postcondition_warning` | Yes (if provided) | Yes |

The callback fires in both modes when postconditions produce findings.
Postconditions with `effect: warn` always allow the tool call to complete --
the callback controls what the LLM sees in the result.

## Callback Semantics by Adapter

The callback behavior differs depending on whether the adapter controls tool execution:

| Adapter | Pattern | Callback return value |
|---------|---------|----------------------|
| **LangChain** | Wrap-around | **Replaces** tool result — the LLM sees the callback return value |
| **Agno** | Wrap-around | **Replaces** tool result |
| **Semantic Kernel** | Filter | **Replaces** `context.function_result` |
| **CrewAI** | Hook | Side-effect only — return value ignored (framework controls result) |
| **Claude Agent SDK** | Hook | Side-effect only — return value ignored |
| **OpenAI Agents SDK** | Guardrail | Side-effect only — return value ignored |

For **wrap-around** adapters, write callbacks that return the transformed result:

```python
def redact(result, findings):
    return mask_pii(result)  # returned value replaces the original
```

For **hook-based** adapters, write callbacks that perform side effects (logging, alerting):

```python
def log_and_alert(result, findings):
    logger.warning("PII detected: %s", findings)
    alert_service.notify(findings)
    # return value is ignored
```

If the callback raises an exception, it is caught and logged. The original
tool result is returned unchanged to avoid breaking execution.

## Framework-Specific Callback Behavior

The `on_postcondition_warn` callback signature is consistent across all adapters:
`(result, findings) -> result`. However, what `result` is and whether the
transformed result reaches the LLM depends on the framework:

| Framework | `result` type | Transformation respected | PII interception |
|-----------|--------------|-------------------------|-----------------|
| LangChain | `ToolMessage` | Yes — mutate `.content` | Full |
| Agno | `str` | Yes — return new string | Full |
| Semantic Kernel | `str` (wrapped in `FunctionResult`) | Yes | Full |
| OpenAI Agents | `str` | No — allow/reject only | Logged only |
| CrewAI | `str` | Partial (undocumented) | Partial |
| Claude Agent SDK | `Any` | No — side-effect only | Logged only |

For regulated environments requiring PII interception, use LangChain, Agno,
or Semantic Kernel.

## Relationship to Contracts

Contracts stay declarative. They **detect**, they don't **remediate**.

```yaml
# This contract DETECTS PII in tool output
- id: pii-in-any-output
  type: post
  tool: "*"
  when:
    output.text:
      matches_any: ["\\b\\d{3}-\\d{2}-\\d{4}\\b", "\\bUSR-\\d+\\b"]
  then:
    effect: warn
    message: "PII pattern detected in tool output"
```

The contract says "this output contains PII." Your `on_postcondition_warn`
callback decides what to do about it -- redact, replace, log, or ignore.

This separation means:

- Compliance teams write contracts (YAML, auditable, versioned)
- Engineering teams write remediation (code, testable, framework-specific)
- Neither needs to understand the other's domain
