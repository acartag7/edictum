# How It Works

Every tool call your agent makes passes through Edictum's pipeline before it executes. The pipeline evaluates YAML contracts against the call's arguments, principal, and session state. If any contract fails, the call is denied and never reaches the tool. This is a hard boundary -- the LLM cannot reason its way past it.

```
Agent decides to call tool
        |
  +--------------+
  |   Edictum    |
  |   Pipeline   |
  +--------------+
  | Preconditions | <-- YAML contracts checked BEFORE execution
  | Session limits|
  | Principal     |
  +------+-------+
         | ALLOW / DENY
         v
    Tool executes (only if allowed)
         |
  +--------------+
  |Postconditions| <-- Output checked AFTER execution
  | Audit event  | --> OTel / stdout
  +--------------+
```

## A Denied Call: Step by Step

An agent tries to read `.env` using the `read_file` tool. Here is what happens:

**1. Agent decides to call `read_file` with `{"path": ".env"}`.**

The framework adapter intercepts the call and builds a `ToolEnvelope` -- a frozen snapshot of the tool name, arguments, and principal.

**2. Edictum evaluates preconditions.**

The pipeline checks the contract bundle. This contract matches:

```yaml
- id: block-dotenv
  type: pre
  tool: read_file
  when:
    args.path: { contains: ".env" }
  then:
    effect: deny
    message: "Blocked read of sensitive file: {args.path}"
```

The `args.path` value is `".env"`. The `contains` operator finds `".env"` in the string. The contract fires.

**3. The call is denied.**

The pipeline returns a `PreDecision` with `action: "deny"`. The tool function never executes. The agent receives the denial message: `"Blocked read of sensitive file: .env"`.

**4. An audit event is emitted.**

An `AuditEvent` with `action: CALL_DENIED` is written to all configured sinks (stdout, file, OpenTelemetry). The event records the tool name, arguments, principal, which contract fired, and the policy version hash.

The `.env` file was never read. The agent sees the denial and can try a different approach.

## An Allowed Call: Step by Step

The same agent calls `read_file` with `{"path": "config.txt"}`.

**1. Agent decides to call `read_file` with `{"path": "config.txt"}`.**

The adapter intercepts and builds the envelope.

**2. Edictum evaluates preconditions.**

The `block-dotenv` contract checks `args.path` for `".env"`. The value is `"config.txt"` -- no match. All other preconditions pass. Session limits are within bounds.

**3. The call is allowed.**

The pipeline returns `PreDecision` with `action: "allow"`. The tool function executes and returns the file contents.

**4. Edictum evaluates postconditions.**

The pipeline checks the tool's output against postcondition contracts. For example, a PII detection contract scans the output for SSN patterns. If a pattern matches, the contract produces a [finding](../findings.md) (a structured warning). Findings never deny -- the tool already ran.

**5. An audit event is emitted.**

An `AuditEvent` with `action: CALL_EXECUTED` is written. It includes the tool name, arguments, whether postconditions passed, any findings, and the policy version hash.

## Why This Is Deterministic

Contracts are code evaluated against arguments. The expression grammar supports string matching, regex, numeric comparisons, and membership checks -- all evaluated by Python at runtime, outside the LLM.

A precondition like `args.path: { contains: ".env" }` will always deny when the path contains `.env`. It does not matter what the LLM was told in its system prompt, how long the conversation has been, or how creatively the agent argues. The check runs in Python, not in the model.

This is the difference between a prompt instruction ("do not read .env files") and a contract. The prompt is a suggestion. The contract is enforcement.

## What Happens at Each Stage

| Stage | When | Can Deny? | Output |
|-------|------|-----------|--------|
| Preconditions | Before tool executes | Yes | `CALL_DENIED` or pass |
| Session limits | Before tool executes | Yes | `CALL_DENIED` if limit exceeded |
| Tool execution | Only if all preconditions pass | -- | Tool's return value |
| Postconditions | After tool executes | No -- produces findings | `CALL_EXECUTED` with warnings |
| Audit | After every evaluation | -- | Structured event to all sinks |

## Next Steps

- [Contracts](contracts.md) -- the three contract types and how to write them
- [Principals](principals.md) -- attaching identity context to tool calls
- [Observe mode](observe-mode.md) -- shadow-testing contracts before enforcement
- [YAML reference](../contracts/yaml-reference.md) -- full contract syntax
