# Architecture

Edictum is a single pipeline that every adapter calls. Contracts written in YAML compile to the same runtime objects as Python-defined contracts. The pipeline is deterministic -- same input, same decision, every time.

---

## Pipeline Overview

Every tool call passes through one pipeline, regardless of which framework adapter triggers it.

```
Agent decides to call tool
        |
  +-----+---------+
  |    Edictum     |
  |    Pipeline    |
  +----------------+
  | Preconditions  | <-- YAML contracts checked BEFORE execution
  | Session limits |
  | Principal      |
  +-------+--------+
          | ALLOW / DENY
          v
    Tool executes (only if allowed)
          v
  +----------------+
  | Postconditions | <-- Output checked AFTER execution
  | Audit event    | --> OTel / stdout
  +----------------+
```

If any precondition fails, the tool call is denied. The tool never executes. There is no "soft deny" -- either every check passes or the call does not happen.

---

## Pre-Execution Detail

`GovernancePipeline.pre_execute()` runs five checks in order. The first failure short-circuits -- remaining checks are skipped.

```
ToolEnvelope --> pre_execute(envelope, session)
                    |
                    +-- 1. Check attempt limit (max_attempts)
                    |      Counts ALL attempts, including denied ones.
                    |      Catches retry loops before they waste resources.
                    |
                    +-- 2. Run before-hooks
                    |      Each hook returns allow or deny.
                    |      First denial short-circuits.
                    |      Hooks have optional `when` predicates for filtering.
                    |
                    +-- 3. Evaluate preconditions
                    |      Each returns Verdict.pass_() or .fail(msg).
                    |      In observe mode, failures are recorded but do not deny.
                    |      In enforce mode, first failure short-circuits.
                    |
                    +-- 4. Evaluate session contracts
                    |      Session contracts receive the Session object.
                    |      Used for cross-turn limits and stateful contracts.
                    |      First failure short-circuits.
                    |
                    +-- 5. Check execution limits
                           max_tool_calls: total executions across all tools.
                           max_calls_per_tool: per-tool execution cap.
                           Counts only successful past executions, not attempts.

                    --> PreDecision(action="allow"|"deny", reason, decision_source, ...)
```

If the `PreDecision.action` is `"allow"`, the adapter lets the tool execute.

---

## Post-Execution Detail

Once a tool has executed, Edictum checks its output. Postconditions produce findings (warnings), never denials -- the tool already ran and may have caused side effects.

```
(tool_response, tool_success) --> post_execute(envelope, response, success)
                                      |
                                      +-- 1. Evaluate postconditions
                                      |      Each returns Verdict.pass_() or .fail(msg).
                                      |      Failures produce warnings, NEVER deny.
                                      |      For pure/read tools: suggest retry.
                                      |      For write/irreversible: warn only.
                                      |
                                      +-- 2. Run after-hooks
                                             Fire-and-forget observation hooks.
                                             Cannot modify the result.

                                      --> PostDecision(tool_success, postconditions_passed, warnings)
```

The pipeline warns the agent and lets it decide how to proceed. This is deliberate -- denying after execution would be misleading.

---

## YAML Compilation

YAML contract bundles go through a three-stage compilation that produces the same runtime objects as hand-written Python contracts.

```
YAML file
  |
  +-- loader.py
  |     Parse YAML text
  |     Validate against JSON Schema (edictum-v1.schema.json)
  |     Compute SHA-256 hash (becomes policy_version in audit events)
  |     Return structured contract definitions
  |
  +-- compiler.py
  |     Convert each definition into @precondition / @postcondition /
  |       @session_contract decorated callables
  |     Compile regex match patterns
  |     Build OperationLimits from session limits section
  |     Return list of contract objects + OperationLimits
  |
  +-- Result: identical objects to Python-defined contracts
        Registered in Edictum the same way
        Executed by the same pipeline
```

There is no separate "YAML execution path." A precondition compiled from YAML and a precondition written as a Python function are indistinguishable to the pipeline. They produce the same `Verdict` objects, appear in the same `contracts_evaluated` audit records, and are subject to the same observe-mode behavior.

---

## Adapter Pattern

Adapters are thin translation layers between framework-specific hook APIs and the pipeline. Each adapter:

1. Intercepts the framework's tool-call lifecycle event
2. Builds a `ToolEnvelope` via `create_envelope()`
3. Calls `pipeline.pre_execute()` and translates the `PreDecision` into the framework's expected format
4. If allowed, lets the tool execute
5. Calls `pipeline.post_execute()` and forwards any findings

| Adapter | Framework | Integration Method |
|---------|-----------|-------------------|
| `LangChainAdapter` | LangChain | `as_middleware()`, `as_tool_wrapper()` |
| `CrewAIAdapter` | CrewAI | `register()` -- global hooks |
| `AgnoAdapter` | Agno | `as_tool_hook()` -- wrap-around hook |
| `SemanticKernelAdapter` | Semantic Kernel | `register(kernel)` -- auto-invocation filter |
| `OpenAIAgentsAdapter` | OpenAI Agents | `as_guardrails()` -- input/output guardrails |
| `ClaudeAgentSDKAdapter` | Claude Agent SDK | `to_sdk_hooks()` -- pre/post tool use hooks |

Adapters never contain enforcement logic. They translate formats. If you need to add a new rule, add a contract or hook -- not adapter code.

---

## Design Decisions

### Envelope Immutability

`ToolEnvelope` is a frozen dataclass. Once created, no field can be modified.

This is enforced at two levels: `@dataclass(frozen=True)` raises `FrozenInstanceError` on assignment, and `create_envelope()` deep-copies `args` and `metadata` via `json.loads(json.dumps(...))` so the caller cannot mutate the original dicts.

Always create envelopes through `create_envelope()`, never by constructing `ToolEnvelope(...)` directly. The `Principal` dataclass is also frozen.

### Session and Storage Model

Sessions track execution state across multiple tool calls within an agent run.

| Counter | Semantics |
|---------|-----------|
| `attempts` | Incremented on every `pre_execute` call, including denials |
| `execs` | Incremented only when a tool actually executes |
| `tool:{name}` | Per-tool execution count |
| `consec_fail` | Consecutive failures; resets on success |

All counter operations go through the `StorageBackend` protocol:

```python
class StorageBackend(Protocol):
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl: int | None = None) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def increment(self, key: str, amount: float = 1) -> float: ...
```

`increment()` must be atomic. This is the fundamental requirement for correctness under concurrent access.

`MemoryBackend` stores counters in a Python dict -- one process, one agent. This covers the vast majority of use cases: a single agent process enforcing session limits on its own tool calls. For multi-agent coordination across processes, the Edictum Server (planned) handles centralized session tracking. See the [roadmap](roadmap.md).

### Operation Limits

`OperationLimits` defines three cap types:

| Limit | Default | Counts |
|-------|---------|--------|
| `max_attempts` | 500 | All `pre_execute` calls (including denials) |
| `max_tool_calls` | 200 | Successful executions only |
| `max_calls_per_tool` | `{}` | Per-tool execution count |

`max_attempts` fires first because it counts denied calls too. An agent stuck in a denial loop hits the attempt cap without ever incrementing the execution counter. The denial message tells the agent to stop and reassess rather than keep retrying.

### Error Handling: Fail-Closed

Edictum follows a fail-closed default with explicit opt-in to permissive behavior:

- **Unregistered tools** default to `SideEffect.IRREVERSIBLE` (most restrictive classification)
- **Contract evaluation errors** deny the tool call rather than silently allowing it
- **Observe mode** is opt-in per-contract or per-pipeline, never the default
- **Postconditions** warn rather than deny, because the tool has already executed

Audit events record `policy_error: true` when contract loading fails, ensuring that broken contract bundles are visible in monitoring even when the system falls back to a safe default.

---

## Where It's Heading

Edictum is currently an in-process library -- contracts are loaded and enforced within the same process as the agent. This covers single-agent deployments and most production use cases today.

The next step is a central policy server where multiple agents pull contracts on startup, with versioning and hot-reload. This enables multi-agent coordination: one set of contracts governing an entire fleet of agents, with a governance dashboard showing denial rates and contract drift across the organization. See the [roadmap](roadmap.md) for details.

### The Boundary Principle

The split between OSS core and enterprise follows one rule: **evaluation engine = OSS, infrastructure = enterprise.**

- The pipeline that takes a tool call and returns allow/deny/warn is OSS
- Anything that requires persistence beyond local files, networking, or coordination is enterprise
- PIIDetector protocol is OSS -- users can write their own detector. Implementations (regex, Presidio) are enterprise
- Stdout + File (.jsonl) sinks ship in OSS for dev and local audit. Network destinations (Webhook, Splunk, Datadog) are enterprise
- OTel instrumentation (emitting spans) is OSS. Dashboards and alerting are enterprise
- Session (MemoryBackend) is OSS for single-process. Multi-process coordination via Edictum Server is enterprise

---

<details>
<summary>Source Layout</summary>

```
src/edictum/
  __init__.py              Edictum facade (registers contracts, hooks, sinks)

  envelope.py              ToolEnvelope, Principal, ToolRegistry, BashClassifier
  contracts.py             @precondition, @postcondition, @session_contract, Verdict
  pipeline.py              GovernancePipeline -- PreDecision, PostDecision
  hooks.py                 HookResult, HookDecision (allow/deny)
  session.py               Session (atomic counters via StorageBackend)
  storage.py               StorageBackend protocol, MemoryBackend
  limits.py                OperationLimits (max_attempts, max_tool_calls, per-tool)
  audit.py                 AuditEvent, AuditAction, AuditSink, RedactionPolicy
  telemetry.py             GovernanceTelemetry (OTel spans + metrics, no-op fallback)
  builtins.py              deny_sensitive_reads() built-in precondition

  yaml_engine/
    loader.py              Parse YAML, validate against JSON Schema, SHA-256 hash
    evaluator.py           Condition evaluation (match, principal checks, etc.)
    compiler.py            YAML contracts -> @precondition/@postcondition objects

  otel.py                  configure_otel(), has_otel(), get_tracer() (OTel spans)

  cli/
    main.py                Click CLI entry point (validate, check, diff, replay, test)

  adapters/
    langchain.py           LangChain tool-calling middleware
    crewai.py              CrewAI before/after hooks
    agno.py                Agno async hook wrapper
    semantic_kernel.py     Semantic Kernel filter pattern
    openai_agents.py       OpenAI Agents guardrails
    claude_agent_sdk.py    Anthropic Claude Agent SDK hooks
```

</details>
