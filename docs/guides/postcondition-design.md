# Why Postconditions Warn, Not Deny

Edictum postconditions can only `warn`, never `deny`. This is a deliberate design decision, not a limitation. This guide explains the reasoning and shows how to handle postcondition findings in practice.

---

## The Design Decision

Postconditions evaluate *after* the tool has already executed. The file was already written. The API was already called. The database row was already inserted.

Denying at this point is theater -- it hides the result from the agent while the side effect persists in the real world. The action happened. A "deny" response only prevents the agent from seeing the result, which is worse than useless: it creates a false sense of safety while the damage is already done.

This is why setting `effect: deny` on a postcondition is a validation error:

```yaml
# This will fail validation at load time
- id: bad-post
  type: post
  tool: "*"
  when:
    output.text:
      contains: "SSN"
  then:
    effect: deny   # validation error: postconditions cannot deny
    message: "..."
```

---

## The Detect-Remediate Pattern

Edictum separates detection from remediation:

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
- **Engineering teams write remediation** -- Python callbacks, testable, framework-specific. No policy knowledge required.
- Neither team needs to understand the other's domain.

---

## Alternatives Considered

### Deny and rollback

Rejected. Rollback is domain-specific and cannot be generalized. Undoing a file write is different from undoing an API call, which is different from undoing a database insert. Some actions have no rollback at all (sending an email, posting to a public API). A governance library cannot implement rollback for arbitrary tools.

### Deny and log

Rejected. This prevents the agent from seeing the result but does not undo the action. The side effect persists while the agent loses context about what happened. This creates a confusing state where the action occurred but the agent does not know about it.

### Let contracts remediate

Rejected. Contracts should be declarative, not imperative. A YAML contract that says "replace SSNs with asterisks" is no longer a policy declaration -- it is code masquerading as configuration. Remediation logic belongs in code where it can be tested, debugged, and reviewed with standard engineering tools.

---

## Callback Capabilities by Adapter

Whether the callback can actually replace the tool result depends on the adapter pattern:

| Adapter | Pattern | Callback replaces result |
|---------|---------|--------------------------|
| LangChain | Wrap-around | Yes |
| Agno | Wrap-around | Yes |
| Semantic Kernel | Filter | Yes |
| CrewAI | Hook | Yes (callback return replaces result) |
| Claude SDK | Hook | Side-effect only |
| OpenAI Agents | Guardrail | Side-effect only |

For **wrap-around** and **hook** adapters that support result replacement (LangChain, Agno, Semantic Kernel, CrewAI), the callback return value replaces the tool result. The LLM sees the redacted version:

```python
def redact(result, findings):
    return mask_pii(result)  # returned value replaces the original
```

For **hook-based** adapters where the SDK controls the result flow (Claude SDK, OpenAI Agents), the return value is ignored. Use the callback for side effects like logging or alerting:

```python
def log_and_alert(result, findings):
    logger.warning("PII detected: %s", findings)
    alert_service.notify(findings)
    # return value is ignored
```

If your environment requires PII interception (not just detection), use LangChain, CrewAI, Agno, or Semantic Kernel.

---

## Summary

Postconditions detect. Your code remediates. This separation keeps contracts declarative, remediation testable, and the overall system honest about what actually happened.
