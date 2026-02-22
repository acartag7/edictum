# Postcondition Design

Postconditions evaluate *after* the tool has already executed. Their behavior depends on two factors: the declared **effect** and the tool's **side-effect classification**.

---

## When to use this

Read this when you need to enforce contracts on tool output -- choosing between the `warn`, `redact`, and `deny` effects, understanding why effects fall back to `warn` for write/irreversible tools, or designing the detect-remediate pattern where compliance teams write YAML postconditions and engineering teams write `on_postcondition_warn` callbacks. For precondition design, see [Writing contracts](writing-contracts.md). For the callback API by adapter, see the individual [adapter guides](../adapters/langchain.md).

---

## Three Effects

Postconditions support three effects:

| Effect | What it does | When it applies |
|--------|-------------|-----------------|
| `warn` | Produces a finding. The tool result is unchanged. | All tools. |
| `redact` | Replaces matched patterns in the output with `[REDACTED]`. | READ/PURE tools only. Falls back to `warn` for WRITE/IRREVERSIBLE. |
| `deny` | Suppresses the entire output with `[OUTPUT SUPPRESSED]`. | READ/PURE tools only. Falls back to `warn` for WRITE/IRREVERSIBLE. |

## Why Side Effects Matter

The side-effect constraint is deliberate. For tools that only read data (`SideEffect.READ` or `SideEffect.PURE`), the output can be safely redacted or suppressed because the tool has no lasting effect. Nothing happened in the real world -- we are only controlling what the agent sees.

For tools that write or mutate state (`SideEffect.WRITE` or `SideEffect.IRREVERSIBLE`), the file was already written, the API was already called, the database row was already inserted. Hiding the result at this point only removes context the agent needs. The action happened regardless. Effects fall back to `warn` so the agent retains awareness of what occurred.

### Classifying Tools

For `redact` and `deny` to work, Edictum needs to know each tool's side effect. Without classification, all tools default to `irreversible` and effects fall back to `warn`.

Declare tool classifications in the `tools:` section of your contract bundle:

```yaml
tools:
  read_config:
    side_effect: read
  search_db:
    side_effect: pure
  deploy_service:
    side_effect: irreversible
```

Or pass them as a parameter to `from_yaml()`:

```python
guard = Edictum.from_yaml(
    "contracts.yaml",
    tools={"read_config": {"side_effect": "read"}},
)
```

Both sources are merged (parameter wins on conflict). See the [YAML reference](../contracts/yaml-reference.md#tool-classifications) for the full schema.

---

## Choosing an Effect

**Use `warn`** (default) when you want detection without enforcement. Your `on_postcondition_warn` callback decides what to do -- redact, replace, log, or ignore.

**Use `redact`** when the output contains structured sensitive tokens (API keys, SSNs, patient IDs) embedded in otherwise useful data. The pipeline uses the `when` clause's regex patterns to find and replace only the sensitive tokens:

```yaml
- id: secrets-in-output
  type: post
  tool: "*"
  when:
    output.text:
      matches_any:
        - 'sk-prod-[a-z0-9]{8}'
        - 'AKIA-PROD-[A-Z]{12}'
  then:
    effect: redact
    message: "Secrets detected and redacted."
    tags: [secrets]
```

**Use `deny`** when the entire output is sensitive content where partial redaction still leaks information (accommodation records, privileged legal documents, medical info):

```yaml
- id: accommodation-confidential
  type: post
  tool: "*"
  when:
    output.text:
      matches: '\b(504\s*Plan|IEP|accommodation)\b'
  then:
    effect: deny
    message: "Accommodation info cannot be returned."
    tags: [ferpa]
```

---

## The Detect-Remediate Pattern

For `effect: warn`, Edictum separates detection from remediation:

1. **Contracts detect** -- a YAML postcondition evaluates tool output and produces findings.
2. **Your code remediates** -- an `on_postcondition_warn` callback transforms the result before the LLM sees it.

```yaml
# Contract: DETECT PII in output
- id: pii-in-output
  type: post
  tool: "*"
  when:
    output.text:
      matches_any:
        - '\b\d{3}-\d{2}-\d{4}\b'
        - '\bName:\s+\w+\s+\w+\b'
  then:
    effect: warn
    message: "PII pattern detected in tool output."
    tags: [pii, compliance]
```

Use single-quoted strings for regex in YAML. Double-quoted strings interpret `\b` as a backspace character instead of a regex word boundary.

```python
# Callback: REMEDIATE by redacting PII
import re

def redact_pii(result, findings):
    text = str(result)
    for f in findings:
        if f.type == "pii_detected":
            text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '***-**-****', text)
            text = re.sub(r'Name:\s*\w+\s+\w+', 'Name: [REDACTED]', text)
    return text

wrapper = adapter.as_tool_wrapper(on_postcondition_warn=redact_pii)
```

This separation has organizational benefits:

- **Compliance teams write contracts** -- YAML, auditable, version-controlled. No code required.
- **Engineering teams write remediation** -- Python callbacks, testable, framework-specific. No contract knowledge required.
- Neither team needs to understand the other's domain.

With `effect: redact` and `effect: deny`, the pipeline handles common remediation patterns automatically -- no callback needed. The callback approach remains available for `warn` and for custom remediation logic beyond what the built-in effects provide.

---

## Design Rationale

### Why not deny all postconditions?

For WRITE/IRREVERSIBLE tools, denying after execution is theater. The action happened. A "deny" response only prevents the agent from seeing the result, creating a false sense of safety while the damage is already done. This is why effects fall back to `warn` for these tools.

### Why not let contracts remediate?

Contracts should be declarative, not imperative. The `redact` and `deny` effects are intentionally simple: `redact` uses the same patterns from the `when` clause (no new syntax), and `deny` suppresses entirely (no partial logic). Complex remediation (custom replacement text, conditional logic, external service calls) belongs in `on_postcondition_warn` callbacks where it can be tested and debugged with standard engineering tools.

---

## Callback Capabilities by Adapter

Whether the `on_postcondition_warn` callback can replace the tool result depends on the adapter pattern:

| Adapter | Pattern | Callback replaces result | Built-in redact/deny |
|---------|---------|--------------------------|---------------------|
| LangChain | Wrap-around | Yes | Yes |
| Agno | Wrap-around | Yes | Yes |
| Semantic Kernel | Filter | Yes | Yes |
| CrewAI | Hook | Side-effect only | Side-effect only |
| Claude SDK | Native hook | Side-effect only | Side-effect only |
| OpenAI Agents | Native guardrail | Side-effect only | Side-effect only |

For **wrap-around** adapters (LangChain, Agno, Semantic Kernel), both `on_postcondition_warn` callbacks and built-in `redact`/`deny` effects work fully. The LLM sees the modified result.

For **native hook** adapters (CrewAI, Claude SDK, OpenAI Agents), the framework controls the result flow and the hook cannot substitute it. Built-in `redact`/`deny` effects set the `PostCallResult.result` field (available to wrapper consumers and callbacks) but cannot intercept the result before the framework passes it to the model. A warning is logged at adapter construction time when postconditions declare `redact` or `deny` effects with these adapters.

If your environment requires PII interception (not just detection), use LangChain, Agno, or Semantic Kernel.

---

## Summary

Postconditions detect and, for READ/PURE tools, can enforce. `warn` produces findings for your code to act on. `redact` removes sensitive tokens. `deny` suppresses the entire output. WRITE/IRREVERSIBLE tools always get `warn` because the action already happened.
