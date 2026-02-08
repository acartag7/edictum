# Why Edictum?

## The Problem

AI agents that call tools have real side effects. An agent with `run_command` can delete files. An agent with `query_database` can exfiltrate customer records. An agent with `send_email` can impersonate your company.

The standard mitigation is prompt engineering: "Do not read .env files. Do not run destructive commands." This works until it doesn't -- a sufficiently long conversation, a creative jailbreak, or a model update can bypass any instruction embedded in a system prompt.

## Prompt Engineering vs. Contracts

| | Prompt engineering | Edictum contracts |
|---|---|---|
| Enforcement | Probabilistic (LLM interprets instruction) | Deterministic (code evaluates condition) |
| Bypass resistance | Vulnerable to jailbreaks, long contexts, model updates | Cannot be bypassed by the LLM -- runs outside the model |
| Auditability | No structured record of what was blocked | Every evaluation produces a structured `AuditEvent` |
| Portability | Rewrite prompts per model/framework | Same YAML contract works across 6 frameworks |
| Observe mode | Not possible | Shadow-test rules against live traffic before enforcing |
| Versioning | Prompt diffs are unstructured text | Contract bundles are hashed; audit events link to exact policy version |

Prompt engineering remains useful for guiding agent behavior. Edictum handles the hard boundary: when a tool call must be denied regardless of what the LLM thinks.

## Tested and Measured

### Governance overhead

Edictum's pipeline adds **54.3 microseconds** per tool call. On a typical LLM round-trip of 764ms, that is **0.01%** overhead. Governance is not a latency concern.

### Adversarial testing

We tested contracts against two models across 4 adversarial scenarios (prompt injection, indirect injection, multi-turn escalation, encoded payloads):

| Model | Cost (per 1M tokens) | Scenarios tested | Blocked |
|---|---|---|---|
| GPT-4.1 | $2 input / $8 output | 4 | 4/4 |
| DeepSeek v3.2 | $0.25 input / $0.38 output | 4 | 4/4 |

DeepSeek was more aggressive than GPT-4.1 -- it attempted PII exfiltration via `send_email` that GPT-4.1 self-censored. Both were blocked by the same contracts.

The key finding: governance is model-agnostic. The same YAML contract blocks the same dangerous call regardless of which LLM is driving the agent.

## Adapter Comparison

Each adapter maps the framework's native hook pattern into Edictum's governance pipeline. The mechanisms differ, but the contracts are identical.

| Framework | Can Redact Before LLM | Deny Mechanism | Cost (same task) |
|---|---|---|---|
| LangChain | Yes (wrapper transforms `ToolMessage`) | Return `"DENIED: reason"` as `ToolMessage` | $0.025 |
| OpenAI Agents | No (output guardrail is side-effect only) | Raise `GuardrailTripwireTriggered` | $0.018 |
| CrewAI | Yes (`after_hook` returns redacted string) | `before_hook` returns `False` | $0.040 |
| Agno | Yes (hook wraps execution) | Hook returns denial string | N/A (no token metrics) |
| Semantic Kernel | Yes (filter modifies `FunctionResult`) | Filter sets cancel + error result | $0.008 |
| Claude Agent SDK | No (hook is side-effect only) | Hook returns deny dict | N/A |

## What Edictum Governs

Edictum governs **tool calls** -- the structured function invocations that an agent makes through its framework. Every tool call passes through the governance pipeline before execution.

Edictum does **not** govern free-text LLM responses. If an agent generates harmful text without calling a tool, that is outside Edictum's scope. Use content filters and output guardrails for that.

## What's Deliberately Out of Scope

- **Authentication and authorization** -- Edictum accepts a `Principal` for contract evaluation but does not authenticate users or manage sessions. Plug in your own auth layer.
- **Tamper-proof audit storage** -- Built-in sinks write to stdout and local files. For compliance-grade immutable storage, route OpenTelemetry spans to your existing backend (Datadog, Splunk, Grafana).
- **ML-based PII detection** -- Postconditions use regex patterns for PII matching. For entity-level NER or ML classifiers, run them in your `on_postcondition_warn` callback.
- **Natural language to contract compilation** -- Contracts are written in YAML by humans. There is no LLM-in-the-loop that converts prose to rules.
