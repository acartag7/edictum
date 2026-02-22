# Contracts

A contract is a check that Edictum evaluates on every tool call. Contracts are written in YAML and compiled to deterministic checks -- the LLM cannot bypass them.

There are three contract types: **preconditions** check before execution, **postconditions** check after, and **session contracts** track state across multiple calls.

## When to use this

**Your agent must never access certain files or endpoints.** A precondition (`type: pre`) checks arguments before the tool runs. If `args.path` contains `.env`, the call is denied and the tool never executes. Use preconditions for hard boundaries on dangerous inputs.

**You need to scan tool output for sensitive data.** A postcondition (`type: post`) inspects the tool's response after execution. It can produce findings with `effect: warn`, replace matched patterns with `[REDACTED]` using `effect: redact`, or suppress the entire output with `effect: deny` -- but only for READ/PURE tools. Use postconditions when the risk is in what the tool returns, not what it receives.

**Your agent runs in long sessions and you need to cap total tool usage.** A session contract (`type: session`) tracks cumulative state -- total calls, total attempts, per-tool limits. When a limit is hit, the call is denied. Use session contracts to stop runaway agents and enforce budget constraints.

**You need all three types together.** A fintech agent that cannot access credentials (precondition), must redact SSNs from query results (postcondition), and is limited to 50 database calls per session (session contract). Load all three in one contract bundle via `Edictum.from_yaml("contracts.yaml")`.

For the full YAML syntax, see [YAML reference](../contracts/yaml-reference.md). For the evaluation order between contract types, see [how it works](how-it-works.md).

## Preconditions

Preconditions evaluate **before** the tool runs. If the condition matches, the call is denied and the tool never executes.

```yaml
- id: block-dotenv
  type: pre
  tool: read_file
  when:
    args.path: { contains: ".env" }
  then:
    effect: deny
    message: "Read of sensitive file denied: {args.path}"
```

This contract fires when `read_file` is called with a `path` argument containing `".env"`. The effect is always `deny` -- preconditions exist to stop dangerous calls.

Key properties:

- `type: pre` marks this as a precondition.
- `tool` targets a specific tool name, or `"*"` for all tools.
- `when` is the condition tree. See [operators](../contracts/operators.md) for the full list.
- `effect: deny` is the only valid effect for preconditions.

## Postconditions

Postconditions evaluate **after** the tool runs. They inspect the tool's output and produce findings.

```yaml
- id: pii-in-output
  type: post
  tool: "*"
  when:
    output.text:
      matches_any:
        - '\b\d{3}-\d{2}-\d{4}\b'
        - '\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b'
  then:
    effect: warn
    message: "PII pattern detected in output. Redact before using."
```

This contract scans every tool's output for SSN and IBAN patterns. When a pattern matches, it produces a finding that your application can act on -- redact the output, log it, or alert a human.

Key properties:

- `type: post` marks this as a postcondition.
- `output.text` is available only in postconditions. It contains the stringified tool response.
- `effect` can be `warn`, `redact`, or `deny`. `warn` produces findings. `redact` replaces matched patterns with `[REDACTED]` for READ/PURE tools. `deny` suppresses the entire output for READ/PURE tools. WRITE/IRREVERSIBLE tools always fall back to `warn`. See [postcondition effects](../contracts/yaml-reference.md#postcondition-effects).
- Findings are structured objects with type, contract ID, field, and message. See [findings](../findings.md).

## Session Contracts

Session contracts track cumulative state across all tool calls within a session. They enforce limits on total calls, total attempts, and per-tool counts.

```yaml
- id: session-limits
  type: session
  limits:
    max_tool_calls: 50
    max_attempts: 120
    max_calls_per_tool:
      deploy_service: 3
      send_notification: 10
  then:
    effect: deny
    message: "Session limit reached. Summarize progress and stop."
```

This contract caps the session at 50 successful tool executions, 120 total attempts (including denied calls), and per-tool limits on `deploy_service` and `send_notification`.

Key properties:

- `type: session` marks this as a session contract.
- Session contracts have no `tool` or `when` fields. They apply to all tools.
- `max_attempts` counts denied calls too, catching agents stuck in retry loops.
- `effect: deny` is the only valid effect for session contracts.

## The `when` / `then` Structure

Every precondition and postcondition has a `when` block (the condition) and a `then` block (the action).

**`when`** is an expression tree that evaluates against the tool call's arguments, principal, environment, and output. It supports boolean combinators (`all`, `any`, `not`) and 15 operators (equality, membership, string matching, regex, numeric comparisons).

```yaml
when:
  all:
    - environment: { equals: production }
    - principal.role: { not_in: [admin, sre] }
    - principal.ticket_ref: { exists: false }
```

This condition matches when all three sub-conditions are true: the environment is production, the principal's role is not admin or sre, and no ticket reference is attached.

**`then`** defines the action when the condition matches:

```yaml
then:
  effect: deny
  message: "Production changes require admin/sre role and a ticket."
  tags: [change-control, production]
  metadata:
    severity: high
```

- `effect` -- `deny` (preconditions, session) or `warn`/`redact`/`deny` (postconditions).
- `message` -- sent to the agent and recorded in the audit event. Supports `{placeholder}` expansion from the envelope context.
- `tags` -- optional classification labels for filtering in audit systems.
- `metadata` -- optional key-value pairs stamped into the audit event.

## Enforce vs. Observe

Each contract can run in one of two modes:

- **`mode: enforce`** -- the contract actively denies tool calls (preconditions) or produces findings (postconditions). This is the default.
- **`mode: observe`** -- the contract evaluates but does not deny. Preconditions that would fire emit `CALL_WOULD_DENY` audit events instead. The tool call proceeds.

Set the default for all contracts in the bundle:

```yaml
defaults:
  mode: enforce
```

Override per-contract when you want to shadow-test a new contract:

```yaml
- id: experimental-api-check
  type: pre
  mode: observe
  tool: call_api
  when:
    args.endpoint: { contains: "/v1/expensive" }
  then:
    effect: deny
    message: "Expensive API call detected (observe mode)."
```

For a full walkthrough of the observe-to-enforce workflow, see [observe mode](observe-mode.md).

## Contract Bundle Structure

Contracts live in a YAML file called a **contract bundle**. Every bundle starts with four required fields:

```yaml
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: my-agent-contracts
defaults:
  mode: enforce
contracts:
  - id: block-dotenv
    type: pre
    # ...
```

Load a bundle in Python:

```python
from edictum import Edictum

guard = Edictum.from_yaml("contracts.yaml")
```

The bundle is hashed (SHA-256) at load time. The hash is stamped as `policy_version` on every audit event, linking each governance decision to the exact contract file that produced it.

## Next Steps

- [YAML reference](../contracts/yaml-reference.md) -- full contract syntax and schema
- [Operators](../contracts/operators.md) -- all 15 operators with examples
- [How it works](how-it-works.md) -- the pipeline that evaluates contracts
- [Principals](principals.md) -- identity context in contract conditions
