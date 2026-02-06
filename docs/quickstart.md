# Quickstart

## Installation

```bash
pip install callguard
```

For OpenTelemetry integration:

```bash
pip install callguard[otel]
```

Requires Python 3.11+. Zero runtime dependencies.

## Framework-Agnostic Usage (guard.run)

`guard.run()` is the simplest way to govern a tool call. It runs the full governance pipeline, executes the tool if allowed, and raises `CallGuardDenied` if blocked.

```python
import asyncio
from callguard import (
    CallGuard,
    CallGuardDenied,
    CallGuardToolError,
    Verdict,
    deny_sensitive_reads,
    precondition,
)


# A custom precondition: block Bash commands starting with "rm"
@precondition("Bash")
def no_destructive_commands(envelope):
    if envelope.bash_command and envelope.bash_command.strip().startswith("rm"):
        return Verdict.fail(
            "Destructive command blocked. Use a safer alternative or "
            "request explicit approval before deleting files."
        )
    return Verdict.pass_()


guard = CallGuard(
    contracts=[
        deny_sensitive_reads(),
        no_destructive_commands,
    ],
)


async def run_bash(command):
    """Mock tool — in production this would execute a shell command."""
    return f"executed: {command}"


async def main():
    # Allowed: normal command
    result = await guard.run("Bash", {"command": "ls -la"}, run_bash)
    print(result)  # "executed: ls -la"

    # Denied: destructive command
    try:
        await guard.run("Bash", {"command": "rm -rf /tmp/data"}, run_bash)
    except CallGuardDenied as e:
        print(f"Denied: {e.reason}")
        print(f"Source: {e.decision_source}")  # "precondition"

    # Denied: sensitive path
    try:
        await guard.run(
            "Read",
            {"file_path": "/home/user/.ssh/id_rsa"},
            lambda file_path: open(file_path).read(),
        )
    except CallGuardDenied as e:
        print(f"Denied: {e.reason}")


asyncio.run(main())
```

### Observe Mode

Observe mode runs the full pipeline but never blocks. Denials are logged as `CALL_WOULD_DENY` instead of `CALL_DENIED`. Use this for shadow deployment -- see what *would* break before enforcing rules.

```python
import asyncio
from callguard import CallGuard, Verdict, deny_sensitive_reads, precondition
from callguard.audit import FileAuditSink


guard = CallGuard(
    mode="observe",
    contracts=[deny_sensitive_reads()],
    audit_sink=FileAuditSink("audit.jsonl"),
)


async def run_bash(command):
    return f"executed: {command}"


async def main():
    # This would be denied in enforce mode, but observe mode allows it through.
    # The audit log records CALL_WOULD_DENY so you can review violations.
    result = await guard.run("Bash", {"command": "cat ~/.ssh/id_rsa"}, run_bash)
    print(result)  # "executed: cat ~/.ssh/id_rsa"


asyncio.run(main())
```

## Claude Agent SDK Adapter

The adapter translates CallGuard decisions into the Claude Agent SDK hook format. It's a thin layer -- all governance logic lives in the pipeline.

```python
from callguard import CallGuard, deny_sensitive_reads, OperationLimits
from callguard.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter

guard = CallGuard(
    contracts=[deny_sensitive_reads()],
    limits=OperationLimits(max_tool_calls=100),
)

adapter = ClaudeAgentSDKAdapter(guard, session_id="session-abc")
hooks = adapter.to_sdk_hooks()
# hooks = {"pre_tool_use": <async fn>, "post_tool_use": <async fn>}

# Pass hooks to the Claude Agent SDK:
# agent = Agent(hooks=hooks)
```

The adapter manages pending state between pre and post hooks, tracks call indices, and emits audit events for every tool call. Each adapter instance owns a `Session` with atomic counters for attempt and execution tracking.

## Writing Contracts

### Preconditions

Preconditions run before execution. They receive a `ToolEnvelope` and return a `Verdict`. If the verdict fails, the tool call is denied and the agent receives the failure message.

```python
from callguard import Verdict, precondition


# Target a specific tool
@precondition("Bash")
def require_safe_prefix(envelope):
    allowed = ["ls", "cat", "git status", "git diff", "pwd"]
    cmd = (envelope.bash_command or "").strip()
    if not any(cmd == p or cmd.startswith(p + " ") for p in allowed):
        return Verdict.fail(
            f"Command '{cmd}' is not in the safe prefix list. "
            "Use one of: ls, cat, git status, git diff, pwd."
        )
    return Verdict.pass_()


# Target all tools with a wildcard
@precondition("*")
def block_production(envelope):
    if envelope.environment == "production":
        return Verdict.fail("Tool calls are disabled in production.")
    return Verdict.pass_()
```

### Postconditions

Postconditions run after execution. In v0.0.1, they are observe-only -- they emit warnings but never block. The warning message adapts to the tool's side-effect classification:

- **Pure/Read tools:** warning suggests retrying.
- **Write/Irreversible tools:** warning says "assess before proceeding" (no retry coaching for something that already mutated state).

```python
from callguard import Verdict
from callguard.contracts import postcondition


@postcondition("Bash")
def check_exit_status(envelope, result):
    if isinstance(result, str) and "Error:" in result:
        return Verdict.fail(
            f"Bash command returned an error: {result[:200]}"
        )
    return Verdict.pass_()
```

### Session Contracts

Session contracts check cross-turn state using persisted atomic counters. They must be async because session methods are async.

```python
from callguard import Verdict
from callguard.contracts import session_contract


@session_contract
async def limit_bash_calls(session):
    bash_count = await session.tool_execution_count("Bash")
    if bash_count >= 50:
        return Verdict.fail(
            "Bash execution limit reached (50). Summarize progress "
            "and use non-Bash tools to continue."
        )
    return Verdict.pass_()
```

## Writing Hooks

Hooks are lower-level than contracts. A before-hook receives the `ToolEnvelope` and returns a `HookDecision`. Hooks run before preconditions in the pipeline.

```python
from callguard import CallGuard
from callguard.hooks import HookDecision
from callguard.types import HookRegistration


def log_and_allow(envelope):
    print(f"[hook] tool={envelope.tool_name} args={envelope.args}")
    return HookDecision.allow()


def deny_after_hours(envelope):
    from datetime import datetime, timezone
    hour = datetime.now(timezone.utc).hour
    if hour < 6 or hour > 22:
        return HookDecision.deny("Tool calls blocked outside business hours (06-22 UTC).")
    return HookDecision.allow()


guard = CallGuard(
    hooks=[
        HookRegistration(phase="before", tool="*", callback=log_and_allow),
        HookRegistration(phase="before", tool="Bash", callback=deny_after_hours),
    ],
)
```

After-hooks observe the result. They receive `(envelope, result)` and don't return a decision.

```python
def audit_after(envelope, result):
    print(f"[after] {envelope.tool_name} completed")


guard = CallGuard(
    hooks=[
        HookRegistration(phase="after", tool="*", callback=audit_after),
    ],
)
```

## Audit & Redaction

Every tool call emits a structured `AuditEvent` to a configurable sink. Two built-in sinks are provided:

```python
from callguard import CallGuard
from callguard.audit import FileAuditSink, RedactionPolicy, StdoutAuditSink

# JSON to stdout (default)
guard = CallGuard(audit_sink=StdoutAuditSink())

# JSON lines to a file
guard = CallGuard(audit_sink=FileAuditSink("audit.jsonl"))
```

### Redaction

`RedactionPolicy` strips sensitive data at write time. Redaction is destructive -- there is no recovery path.

What gets auto-redacted:

- **Sensitive keys:** any dict key containing `token`, `key`, `secret`, `password`, or `credential` (plus a full default set).
- **Secret value patterns:** OpenAI keys (`sk-...`), AWS access keys (`AKIA...`), JWTs (`eyJ...`), GitHub tokens (`ghp_...`), Slack tokens (`xox...`).
- **Bash credentials:** `export SECRET_KEY=...`, `-p password`, URL credentials (`://user:pass@`).
- **Payload cap:** audit events exceeding 32KB are truncated.

Custom configuration:

```python
from callguard import CallGuard
from callguard.audit import FileAuditSink, RedactionPolicy

redaction = RedactionPolicy(
    sensitive_keys={"my_internal_token", "database_url", "password"},
)

guard = CallGuard(
    audit_sink=FileAuditSink("audit.jsonl", redaction=redaction),
    redaction=redaction,
)
```

### Custom Sink

Implement the `AuditSink` protocol -- a single async `emit(event)` method:

```python
class MyAuditSink:
    async def emit(self, event):
        # event is an AuditEvent dataclass
        print(f"{event.action}: {event.tool_name}")
```

## Operation Limits

Operation limits cap how many tool calls an agent can make in a session. Two counter types serve different purposes:

- **`max_attempts`** caps all governance evaluations, including denied ones. This catches denial loops where an agent keeps retrying the same blocked call.
- **`max_tool_calls`** caps only successful executions. This caps total work done.
- **`max_calls_per_tool`** caps individual tools independently.

```python
from callguard import CallGuard, OperationLimits

guard = CallGuard(
    limits=OperationLimits(
        max_attempts=100,
        max_tool_calls=50,
        max_calls_per_tool={"Bash": 20, "Write": 10},
    ),
)
```

When a limit fires, the denial message tells the agent to stop and reassess rather than retry.

## Observe Mode

Set `mode="observe"` to run the full governance pipeline without blocking anything. The pipeline evaluates all rules, emits audit events, but converts denials to `CALL_WOULD_DENY` and allows the tool through.

Use this for:

- **Shadow deployment.** Deploy CallGuard alongside your agent, collect audit logs, and tune rules before switching to enforce mode.
- **Rule development.** Write new preconditions and see what they'd block without disrupting the agent.
- **Compliance auditing.** Record every tool call with governance evaluation results, even if you don't want to block anything yet.

The audit trail distinguishes three states:

| Audit Action | Meaning |
|---|---|
| `CALL_ALLOWED` | Pipeline passed, tool executed |
| `CALL_DENIED` | Pipeline denied, tool did not execute (enforce mode) |
| `CALL_WOULD_DENY` | Pipeline denied, tool executed anyway (observe mode) |

## What's Next

- [Architecture overview](../ARCHITECTURE.md) for the full module structure and design decisions.
- v0.1 roadmap: retry-with-feedback, human approval gates, Redis storage backend.
