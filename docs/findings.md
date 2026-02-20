# Postcondition Findings

When a postcondition contract detects an issue in tool output (PII, secrets, contract violations),
Edictum produces structured **findings** that your application can act on.

## The Pattern: Detect -> Remediate

Postconditions detect issues in tool output. What happens next depends on the declared `effect`:

- **`effect: warn`** (default) -- the contract produces findings and your `on_postcondition_warn` callback remediates
- **`effect: redact`** -- the pipeline automatically replaces matched patterns with `[REDACTED]` (READ/PURE tools only)
- **`effect: deny`** -- the pipeline suppresses the entire output (READ/PURE tools only)

For `warn`, your code handles remediation. For `redact` and `deny`, the pipeline handles it automatically. In all cases, findings are still produced and the callback is still invoked if provided. Claude SDK and OpenAI Agents native hooks cannot substitute results -- see [adapter limitations](guides/adapter-comparison.md#known-limitations).

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
            text = "[DENIED] Secret detected in tool output"
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
| **CrewAI** | Hook | **Replaces** tool result — callback return value replaces the original |
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
| CrewAI | `str` | Yes — via register() callback | Via callback |
| Claude Agent SDK | `Any` | No — side-effect only | Logged only |

For regulated environments requiring PII interception, use LangChain, Agno,
or Semantic Kernel.

## Relationship to Contracts

Contracts are declarative. With `effect: warn`, they **detect** and your code **remediates**. With `effect: redact` or `effect: deny`, the pipeline handles common remediation automatically.

```yaml
# Detect and warn -- your callback remediates
- id: pii-in-any-output
  type: post
  tool: "*"
  when:
    output.text:
      matches_any: ["\\b\\d{3}-\\d{2}-\\d{4}\\b", "\\bUSR-\\d+\\b"]
  then:
    effect: warn
    message: "PII pattern detected in tool output"

# Detect and redact -- pipeline handles it
- id: secrets-in-output
  type: post
  tool: "*"
  when:
    output.text:
      matches_any: ['sk-prod-[a-z0-9]{8}', 'AKIA-PROD-[A-Z]{12}']
  then:
    effect: redact
    message: "Secrets detected and redacted."
```

For `warn`, the contract says "this output contains PII" and your `on_postcondition_warn` callback decides what to do. For `redact`, the pipeline removes the matched patterns automatically. For `deny`, the pipeline suppresses the entire output.

This separation means:

- Compliance teams write contracts (YAML, auditable, versioned)
- Engineering teams write remediation for `warn` effects (code, testable, framework-specific)
- `redact` and `deny` effects require no application code -- the pipeline handles enforcement
