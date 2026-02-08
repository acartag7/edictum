# Edictum

Edictum enforces contracts on AI agent tool calls. Before your agent reads a file, queries a database, or calls an API -- Edictum checks the call against YAML contracts and denies it if it violates policy. The agent cannot bypass it.

## The Problem

AI agents call tools with real-world side effects. An agent with `run_command` can delete files. An agent with `send_email` can impersonate your organization. The standard defense is prompt engineering: "Do not read .env files."

Prompts are suggestions the LLM can ignore. A long conversation, a creative jailbreak, or a model update can bypass any instruction embedded in a system prompt. There is no hard boundary between "the agent decides to act" and "the action executes."

## The Solution

Edictum sits at the decision-to-action seam. The agent decides to call a tool. Before that call executes, Edictum checks it against contracts. This is a hard boundary, not a suggestion.

**Without Edictum** -- the agent reads your secrets:

```python
# Agent decides to read .env
result = await read_file(".env")
# => "OPENAI_API_KEY=sk-abc123..."
```

**With Edictum** -- the call is denied before it executes:

```python
from edictum import Edictum, EdictumDenied

guard = Edictum.from_yaml("contracts.yaml")

try:
    result = await guard.run("read_file", {"path": ".env"}, read_file)
except EdictumDenied as e:
    print(e.reason)
    # => "Blocked read of sensitive file: .env"
```

**The contract that makes it happen** -- `contracts.yaml`:

```yaml
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: file-safety
defaults:
  mode: enforce
contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      any:
        - args.path: { contains: ".env" }
        - args.path: { contains: ".pem" }
        - args.path: { matches: ".*id_rsa$" }
    then:
      effect: deny
      message: "Blocked read of sensitive file: {args.path}"
```

Contracts are YAML. Enforcement is deterministic. The LLM cannot talk its way past a contract.

## How It Works

1. **Write contracts in YAML.** Preconditions deny dangerous calls before execution. Postconditions check tool output after execution. Session limits cap total calls and retries.

2. **Attach to your agent framework.** One adapter line. Same contracts across all six supported frameworks -- LangChain, OpenAI Agents, CrewAI, Agno, Semantic Kernel, and Claude SDK.

3. **Every tool call passes through the pipeline.** Agent decides to call a tool. Edictum evaluates preconditions, session limits, and principal context. If any contract fails, the call is denied and never executes.

4. **Full audit trail.** Every evaluation -- allowed, denied, or observed -- produces a structured audit event with automatic secret redaction. Route to stdout, OpenTelemetry, or your existing observability stack.

## Install

```bash
pip install edictum[yaml]
```

Requires Python 3.11+. Current version: **v0.5.3**. See the [quickstart](quickstart.md) to write your first contract and deny a dangerous call in five minutes.

## Framework Support

Edictum integrates with six agent frameworks. Same YAML contracts, same enforcement, different adapter patterns:

| Framework | Adapter | Integration |
|-----------|---------|-------------|
| LangChain | `LangChainAdapter` | `as_tool_wrapper()` / `as_middleware()` |
| OpenAI Agents SDK | `OpenAIAgentsAdapter` | `as_guardrails()` |
| CrewAI | `CrewAIAdapter` | `register()` |
| Agno | `AgnoAdapter` | `as_tool_hook()` |
| Semantic Kernel | `SemanticKernelAdapter` | `register(kernel)` |
| Claude Agent SDK | `ClaudeAgentSDKAdapter` | `to_sdk_hooks()` |

See the [adapter overview](adapters/overview.md) for setup guides and known limitations.

## What's Coming

Edictum is production-usable today as an in-process library. The roadmap extends it to fleet-scale enforcement:

- **PII detection** -- Pluggable detectors for postcondition contracts (regex built-in, Presidio ML/NER for enterprise)
- **Production audit sinks** -- File, Webhook, Splunk HEC, and Datadog sinks for compliance-grade audit trails
- **Central policy server** -- Agents pull contracts on startup, with versioning, hot-reload, and a dashboard for denial-rate visibility and contract drift

See the [roadmap](roadmap.md) for the full plan.

## Next Steps

- [Quickstart](quickstart.md) -- Install, write a contract, and deny your first dangerous call
- [How It Works](concepts/how-it-works.md) -- The pipeline, adapters, and what happens on every tool call
- [Contracts](concepts/contracts.md) -- Preconditions, postconditions, session limits, and observe mode
- [YAML Reference](contracts/yaml-reference.md) -- Full schema for `edictum/v1` contract bundles
- [Adapters](adapters/overview.md) -- Integration guides for all six frameworks
