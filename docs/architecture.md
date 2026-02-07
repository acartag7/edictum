# Architecture

Edictum enforces runtime contracts on AI agent tool calls. This page describes
how the system is structured, how data flows through it, and the reasoning behind
the key design decisions.

## Module Overview

```
src/edictum/
  __init__.py              Edictum facade (registers contracts, hooks, sinks)

  envelope.py              ToolEnvelope, Principal, ToolRegistry, BashClassifier
  contracts.py             @precondition, @postcondition, @session_contract, Verdict
  pipeline.py              GovernancePipeline — PreDecision, PostDecision
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
    main.py                Click CLI entry point (validate, check, diff, replay)

  adapters/
    langchain.py           LangChain tool-calling middleware
    crewai.py              CrewAI before/after hooks
    agno.py                Agno async hook wrapper
    semantic_kernel.py     Semantic Kernel filter pattern
    openai_agents.py       OpenAI Agents guardrails
    claude_agent_sdk.py    Anthropic Claude Agent SDK hooks
```

---

## Pipeline Flow

`GovernancePipeline` is the single source of truth for all governance logic. Every
adapter calls the same pipeline methods, ensuring that Python-defined contracts and
YAML-compiled contracts follow identical execution paths.

### Pre-Execution: `GovernancePipeline.pre_execute()`

```
ToolEnvelope ──> pre_execute(envelope, session)
                    │
                    ├── 1. Check attempt limit (max_attempts)
                    │      Catches retry loops before they waste resources.
                    │      Counts ALL attempts, including previously denied ones.
                    │
                    ├── 2. Run before-hooks
                    │      Each hook returns HookDecision.allow() or .deny(reason).
                    │      First denial short-circuits: remaining hooks are skipped.
                    │      Hooks have optional `when` predicates for filtering.
                    │
                    ├── 3. Evaluate preconditions
                    │      Each precondition returns Verdict.pass_() or .fail(msg).
                    │      In observe mode, failures are recorded but do not deny.
                    │      First failure in enforce mode short-circuits.
                    │
                    ├── 4. Evaluate session contracts
                    │      Session contracts receive the Session object (async counters).
                    │      Used for cross-turn limits and stateful policies.
                    │      First failure short-circuits.
                    │
                    └── 5. Check execution limits
                           max_tool_calls: total executions across all tools.
                           max_calls_per_tool: per-tool execution cap.
                           Counts only successful past executions, not attempts.

                    ──> PreDecision(action="allow"|"deny", reason, decision_source, ...)
```

If the `PreDecision.action` is `"allow"`, the adapter lets the tool execute.

### Post-Execution: `GovernancePipeline.post_execute()`

```
(tool_response, tool_success) ──> post_execute(envelope, response, success)
                                      │
                                      ├── 1. Evaluate postconditions
                                      │      Each returns Verdict.pass_() or .fail(msg).
                                      │      Failures produce warnings, NEVER block.
                                      │      For pure/read tools: suggest retry.
                                      │      For write/irreversible: warn only.
                                      │
                                      └── 2. Run after-hooks
                                             Fire-and-forget observation hooks.
                                             Cannot modify the result.

                                      ──> PostDecision(tool_success, postconditions_passed, warnings)
```

Postconditions are observe-only by design. Once a tool has executed (especially one
with side effects), it is too late to deny. The pipeline warns the agent and lets it
decide how to proceed.

---

## YAML Compilation

YAML contract files go through a three-stage pipeline that produces the same runtime
objects as hand-written Python contracts.

```
YAML file
  │
  ├── loader.py
  │     Parse YAML text
  │     Validate against JSON Schema (edictum-v1.schema.json)
  │     Compute SHA-256 hash (becomes policy_version in audit events)
  │     Return structured contract definitions
  │
  ├── compiler.py
  │     Convert each definition into @precondition / @postcondition /
  │       @session_contract decorated callables
  │     Compile regex match patterns
  │     Build OperationLimits from session limits section
  │     Return list of contract objects + OperationLimits
  │
  └── Result: identical objects to Python-defined contracts
        Registered in Edictum the same way
        Executed by the same GovernancePipeline
```

This design means there is no separate "YAML execution path." A precondition
compiled from YAML and a precondition written as a Python function are
indistinguishable to the pipeline. They produce the same `Verdict` objects, appear
in the same `contracts_evaluated` audit records, and are subject to the same
observe-mode behavior.

---

## Adapter Pattern

Adapters are thin translation layers between framework-specific hook APIs and the
`GovernancePipeline`. Each adapter:

1. Intercepts the framework's tool-call lifecycle event
2. Builds a `ToolEnvelope` via `create_envelope()`
3. Calls `pipeline.pre_execute()` and translates the `PreDecision` into the
   framework's expected format (e.g. a denial ToolMessage for LangChain, `False`
   return for CrewAI)
4. If allowed, lets the tool execute
5. Calls `pipeline.post_execute()` and forwards any warnings

The six supported adapters:

| Adapter | Framework | Pre Hook | Post Hook |
|---------|-----------|----------|-----------|
| `langchain.py` | LangChain | `_pre_tool_call(request)` | `_post_tool_call(request, result)` |
| `crewai.py` | CrewAI | `_before_hook(ctx)` returns `False` to deny | `_after_hook(ctx)` |
| `agno.py` | Agno | `_hook_async(name, callable, args)` | wraps around execution |
| `semantic_kernel.py` | Semantic Kernel | `_pre(name, args, call_id)` returns `{}`/`"DENIED"` | `_post(call_id, result)` |
| `openai_agents.py` | OpenAI Agents | `_pre(name, args, call_id)` returns `None`/`"DENIED"` | `_post(call_id, result)` |
| `claude_agent_sdk.py` | Claude Agent SDK | `_pre_tool_use(name, input, id)` returns `{}` or deny dict | `_post_tool_use(id, resp)` |

Adapters never contain governance logic. They translate formats. If you need to add
a new rule, add a contract or hook -- not adapter code.

---

## Envelope Immutability

`ToolEnvelope` is a frozen dataclass. Once created, no field can be modified. This is
enforced at two levels:

1. **`@dataclass(frozen=True)`** -- Python raises `FrozenInstanceError` on assignment
2. **`create_envelope()` factory** -- deep-copies `args` and `metadata` via
   `json.loads(json.dumps(...))` so the caller cannot mutate the original dicts

Always create envelopes through `create_envelope()`, never by constructing
`ToolEnvelope(...)` directly.

The `Principal` dataclass is also frozen. The `claims` dict inside it has an immutable
*reference* (you cannot reassign `principal.claims`), though the dict contents are
technically mutable. Callers should treat `claims` as read-only after construction.

---

## Session and Storage Model

Sessions track execution state across multiple tool calls within an agent run.

**Session counters:**

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

`increment()` must be atomic. This is the fundamental requirement for correctness
under concurrent access.

**Built-in backend:**

`MemoryBackend` stores counters in a Python dict. It is not concurrency-safe and
loses state on restart. This is intentional -- it exists for development and testing.
Production deployments should implement `StorageBackend` against Redis, DynamoDB,
or another backend with atomic increment support.

---

## Operation Limits

`OperationLimits` defines three cap types:

| Limit | Default | Counts |
|-------|---------|--------|
| `max_attempts` | 500 | All `pre_execute` calls (including denials) |
| `max_tool_calls` | 200 | Successful executions only |
| `max_calls_per_tool` | `{}` | Per-tool execution count |

`max_attempts` fires first because it counts denied calls too. An agent stuck
in a denial loop hits the attempt cap without ever incrementing the execution
counter. The denial message is designed to be agent-readable: it tells the agent
to stop and reassess rather than keep retrying.

---

## Error Handling Philosophy

Edictum follows a "fail-closed" default with explicit opt-in to permissive
behavior:

- **Unregistered tools** default to `SideEffect.IRREVERSIBLE` (most restrictive
  classification)
- **Contract evaluation errors** deny the call rather than silently allowing it
- **Observe mode** is opt-in per-contract or per-pipeline, never the default
- **Postconditions** warn rather than deny, because the tool has already executed
  and denying after the fact would be misleading

Audit events record `policy_error: true` when contract loading fails, ensuring
that broken policy files are visible in monitoring even when the system falls back
to a safe default.
