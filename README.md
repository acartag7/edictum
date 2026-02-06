# CallGuard

[![PyPI](https://img.shields.io/pypi/v/callguard)](https://pypi.org/project/callguard/)
[![Python](https://img.shields.io/pypi/pyversions/callguard)](https://pypi.org/project/callguard/)
[![License](https://img.shields.io/pypi/l/callguard)](LICENSE)

**Runtime safety for AI agents.** Stop agents before they break things.

Nothing sits between an AI agent deciding to call `rm -rf /` and it happening. CallGuard is that layer. It intercepts every tool call, enforces contracts and operation limits, logs a structured audit trail, and returns actionable error messages so agents self-correct instead of failing silently. Zero runtime dependencies. Drop it in front of any tool-calling agent.

## Why CallGuard

- **Audit trail for every tool call.** Structured JSON events with automatic redaction of secrets (OpenAI keys, AWS credentials, JWTs, GitHub tokens). Know exactly what your agent did, when, and why it was allowed or denied.
- **Agents self-correct from actionable denials.** When CallGuard blocks a tool call, it tells the agent *why* with a specific, instructive message. The agent adjusts its approach instead of retrying blindly.
- **Observe mode for shadow deployment.** Run the full governance pipeline without blocking anything. Audit events log `CALL_WOULD_DENY` so you can tune rules before enforcing them in production.
- **Zero runtime dependencies.** Pure Python 3.11+. OpenTelemetry support via optional `callguard[otel]`.

## Install

```bash
pip install callguard            # core only
pip install callguard[all]       # all 6 framework adapters + OTel
pip install callguard[langchain] # individual adapter extras
```

Requires Python 3.11+. Zero runtime dependencies for the core package.

## Quickstart

```python
import asyncio
from callguard import CallGuard, CallGuardDenied, deny_sensitive_reads

guard = CallGuard(contracts=[deny_sensitive_reads()])

async def read_file(file_path):
    return open(file_path).read()

async def main():
    # This succeeds
    result = await guard.run("Read", {"file_path": "/tmp/notes.txt"}, read_file)

    # This raises CallGuardDenied
    try:
        await guard.run("Read", {"file_path": "/home/user/.ssh/id_rsa"}, read_file)
    except CallGuardDenied as e:
        print(e.reason)
        # "Access to sensitive path blocked: /home/user/.ssh/id_rsa.
        #  This file may contain secrets or credentials."

asyncio.run(main())
```

See [docs/quickstart.md](docs/quickstart.md) for custom contracts, hooks, and audit configuration.

## Framework Adapters

CallGuard ships thin adapters for 6 agent frameworks. Each adapter translates between the framework's hook/middleware interface and the shared governance pipeline — no forked logic.

| Framework | Adapter | Hook Pattern |
|-----------|---------|-------------|
| LangChain | `LangChainAdapter` | `_pre_tool_call` / `_post_tool_call` |
| CrewAI | `CrewAIAdapter` | `_before_hook` / `_after_hook` |
| Agno | `AgnoAdapter` | `_hook_async` (wrap-around) |
| Semantic Kernel | `SemanticKernelAdapter` | `_pre` / `_post` (filter) |
| OpenAI Agents SDK | `OpenAIAgentsAdapter` | `_pre` / `_post` (guardrails) |
| Claude Agent SDK | `ClaudeAgentSDKAdapter` | `_pre_tool_use` / `_post_tool_use` |

```python
from callguard import CallGuard
from callguard.adapters.langchain import LangChainAdapter

guard = CallGuard(contracts=[...])
adapter = LangChainAdapter(guard, session_id="session-1")
```

Live demos for all 6 adapters are in [examples/](examples/).

## Live Demos

Every demo runs the same scenario: an LLM agent is told to read, clean up, and organize files in `/tmp/messy_files/`. The workspace contains trap files (`.env` with AWS keys, `credentials.json`) and the agent is tempted to `rm -rf` and move files to the wrong directory.

|                        | Without CallGuard     | With CallGuard               |
|------------------------|-----------------------|------------------------------|
| `.env` with AWS keys   | Agent reads + dumps   | **DENIED** — sensitive file   |
| `credentials.json`     | Agent reads + dumps   | **DENIED** — sensitive file   |
| `rm -rf /tmp/messy_files/` | Executes, files gone | **DENIED** — destructive cmd |
| `cat .env` via bash    | Executes, keys leak   | **DENIED** — sensitive bash   |
| Move to wrong dir      | Executes              | **DENIED** — must use `/tmp/organized/` |
| 50+ tool calls         | Unlimited             | **Capped** at 25             |
| Audit trail            | None                  | Structured JSONL             |
| Code diff              | -                     | ~10 lines added              |

### What the Contracts Enforce

1. **block_sensitive_reads** — Denies `read_file` on `.env`, `.secret`, `credentials`, `id_rsa`, `.pem`, `.key`
2. **block_destructive_commands** — Denies `bash` commands containing `rm -rf`, `rm -r`, `rmdir`, `dd if=`, etc.
3. **block_sensitive_bash** — Denies `bash` commands that reference sensitive file patterns
4. **require_organized_target** — `move_file` destinations must start with `/tmp/organized/`
5. **session_limit(25)** — Caps total tool calls at 25 per session

### Metrics (Tokens + Timing)

Sample run (Feb 2026):

| Demo | Mode | Calls | Denied | Tokens | LLM Time |
|------|------|------:|-------:|-------:|---------:|
| LangChain | no guard | 17 | 0 | 2,782 | 14.1s |
| LangChain | **guard** | 17 | **4** | 2,819 | 13.1s |
| CrewAI | no guard | 17 | 0 | 2,768 | 11.0s |
| CrewAI | **guard** | 17 | **4** | 2,649 | 22.3s |
| Agno | no guard | 17 | 0 | 2,858 | 11.6s |
| Agno | **guard** | 17 | **4** | 2,818 | 12.6s |
| Semantic Kernel | no guard | 17 | 0 | 2,855 | 12.3s |
| Semantic Kernel | **guard** | 17 | **4** | 2,767 | 12.8s |
| OpenAI Agents | no guard | 17 | 0 | 2,655 | 12.7s |
| OpenAI Agents | **guard** | 17 | **4** | 2,821 | 12.7s |
| Claude SDK | no guard | 20 | 0 | 55,703 | 42.9s |
| Claude SDK | **guard** | 21 | **6** | 52,868 | 37.5s |

GPT-4o-mini demos average ~2,800 tokens per run. Claude Haiku 4.5 (via OpenRouter) uses more tokens due to verbose tool-use patterns.

See [examples/](examples/) for setup instructions and quick start commands.

## Key Concepts

Every tool call is wrapped in a **ToolEnvelope** -- a frozen, deep-copied snapshot of the invocation (tool name, args, side-effect classification, environment). Envelopes are immutable. Nothing downstream can tamper with the original args.

**Contracts** define governance rules. A `@precondition` runs before execution and can deny the call. A `@postcondition` runs after and emits warnings (observe-only -- they emit warnings but never block). A `@session_contract` checks cross-turn state like total execution counts. All return a `Verdict`: either `Verdict.pass_()` or `Verdict.fail("actionable message")`.

**Hooks** are lower-level interception points. A before-hook receives the envelope and returns `HookDecision.allow()` or `HookDecision.deny("reason")`. After-hooks observe the result. Hooks run before contracts in the pipeline. Use contracts for most policy; use hooks when you need framework-specific interception or custom envelope shaping.

The **GovernancePipeline** evaluates five steps in order: attempt limit, before-hooks, preconditions, session contracts, execution limits. First denial wins. If everything passes, the tool executes, then postconditions and after-hooks run.

CallGuard tracks **two counter types**. `max_attempts` caps all governance evaluations, including denied ones -- this catches denial loops where an agent keeps retrying the same blocked call. `max_tool_calls` caps only successful executions. Both fire independently.

In **observe mode**, the full pipeline runs and audit events are emitted, but denials are converted to `CALL_WOULD_DENY` and the tool executes anyway. Use this for shadow deployment: see what *would* break before you enforce it.

**Audit and redaction** happen at write time. Every tool call emits a structured `AuditEvent` to a configurable sink (stdout, file, or custom). `RedactionPolicy` strips sensitive keys, detects secret value patterns, redacts bash credentials, and caps payloads at 32KB. Redaction is destructive by design -- no recovery path.

## What This Is NOT

- Not prompt injection defense.
- Not content safety filtering.
- Not network egress control.
- Not a security boundary for Bash. (`BashClassifier` is a heuristic, not a sandbox.)
- Not concurrency-safe across workers. (`MemoryBackend` is single-process.)

## Links

- [Quickstart Guide](docs/quickstart.md)
- [Adapter Usage Guide](docs/adapters.md) — code snippets for all 6 frameworks
- [Architecture](ARCHITECTURE.md)
- [Examples](examples/) — live demos for all 6 adapters
- [License](LICENSE) (MIT)
