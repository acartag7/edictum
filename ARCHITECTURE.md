# CallGuard Architecture

> Runtime safety for AI agents. Stop agents before they break things.

## What It Does

CallGuard sits between an agent's decision to call a tool and actual execution. It enforces contracts, hooks, audit trails, and operation limits. When a rule is violated, it tells the agent **why** so it can self-correct.

## Package Structure

```
src/callguard/
├── __init__.py          # CallGuard class, guard.run(), exceptions, re-exports
├── envelope.py          # ToolEnvelope (frozen), SideEffect, ToolRegistry, BashClassifier
├── hooks.py             # HookDecision (ALLOW/DENY)
├── contracts.py         # Verdict, @precondition, @postcondition, @session_contract
├── limits.py            # OperationLimits (attempt + execution + per-tool caps)
├── pipeline.py          # GovernancePipeline — single source of governance logic
├── session.py           # Session (atomic counters via StorageBackend)
├── storage.py           # StorageBackend protocol + MemoryBackend
├── audit.py             # AuditEvent, RedactionPolicy, Stdout/File sinks
├── telemetry.py         # OpenTelemetry (graceful no-op if absent)
├── builtins.py          # deny_sensitive_reads()
├── types.py             # Internal types (HookRegistration, ToolConfig)
└── adapters/
    └── claude_agent_sdk.py  # Claude Agent SDK adapter (thin translation layer)
```

## The Flow

Every tool call passes through:

```
Agent decides to call tool
    │
    ▼
Adapter creates ToolEnvelope (deep-copied, classified)
Increments attempt_count (BEFORE governance)
    │
    ▼
Pipeline.pre_execute() — 5 steps:
    1. Attempt limit (>= max_attempts?)
    2. Before hooks (user-defined, can DENY)
    3. Preconditions (contract checks, can DENY)
    4. Session contracts (cross-turn state, can DENY)
    5. Execution limits (>= max_tool_calls? per-tool?)
    │
    ├── DENY → audit event → tell agent why → agent self-corrects
    │
    └── ALLOW → tool executes
                    │
                    ▼
            Pipeline.post_execute():
                1. Postconditions (observe-only, warnings)
                2. After hooks
                3. Session record (exec count, consecutive failures)
                    │
                    ▼
                Audit event (CALL_EXECUTED or CALL_FAILED)
```

## Key Design Decisions

**Pipeline owns ALL governance logic.** Adapters are thin translation layers. Adding a second adapter doesn't fork governance behavior.

**Two counter types:**
- `max_attempts` — caps ALL PreToolUse events (including denied). Catches denial loops.
- `max_tool_calls` — caps executions only (PostToolUse). Caps total work done.

**Postconditions are observe-only** in v0.0.1. They emit warnings, never block. For pure/read tools: suggest retry. For write/irreversible: warn only.

**Observe mode** (`mode="observe"`): full pipeline runs, audit emits `CALL_WOULD_DENY`, but tool executes anyway. For shadow deployment.

**Zero runtime deps.** OpenTelemetry via optional `callguard[otel]`.

**Redaction at write time.** Destructive by design — no recovery. Sensitive keys, secret value patterns (OpenAI/AWS/JWT/GitHub/Slack), 32KB payload cap.

**BashClassifier is a heuristic, not a security boundary.** Conservative READ allowlist + shell operator detection. Defense in depth with `deny_sensitive_reads()`.

## Two Usage Modes

**1. Framework-agnostic:**
```python
guard = CallGuard(contracts=[deny_sensitive_reads()])
result = await guard.run("Bash", {"command": "ls"}, my_bash_fn)
```

**2. Claude Agent SDK adapter:**
```python
adapter = ClaudeAgentSDKAdapter(guard, session_id="session-1")
hooks = adapter.to_sdk_hooks()
```

## What This Is NOT

- Not prompt injection defense
- Not content safety filtering
- Not network egress control
- Not a security boundary for Bash
- Not concurrency-safe across workers (MemoryBackend is single-process)
