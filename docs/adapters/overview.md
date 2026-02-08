# Adapter Overview

Edictum ships six framework adapters. Adapters are thin translation layers --
they convert framework-specific hook events into Edictum envelopes and translate
enforcement decisions back into the format each framework expects. All allow/deny
logic lives in the pipeline, not in the adapters.

This means you get identical enforcement semantics regardless of which framework
you use. Switching frameworks requires changing only the adapter wiring, not
your contracts.

## The Common Pattern

Every adapter follows the same three-step setup:

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter  # or any adapter

# 1. Load contracts
guard = Edictum.from_yaml("contracts.yaml")

# 2. Create the adapter
adapter = LangChainAdapter(
    guard=guard,
    session_id="my-session-123",       # optional -- auto UUID if omitted
    principal=Principal(user_id="alice", role="analyst"),  # optional
)

# 3. Get the framework-specific hook and wire it in
wrapper = adapter.as_tool_wrapper()
```

## Quick Comparison

| Framework | Adapter Class | Integration Method | Returns |
|-----------|--------------|-------------------|---------|
| Claude Agent SDK | `ClaudeAgentSDKAdapter` | `to_sdk_hooks()` | `dict` with `pre_tool_use` and `post_tool_use` async functions |
| LangChain | `LangChainAdapter` | `as_tool_wrapper()` | Wrapper function for `ToolNode` |
| CrewAI | `CrewAIAdapter` | `register()` | Registers global before/after hooks |
| Agno | `AgnoAdapter` | `as_tool_hook()` | Wrap-around function |
| Semantic Kernel | `SemanticKernelAdapter` | `register(kernel)` | Registers `AUTO_FUNCTION_INVOCATION` filter on kernel |
| OpenAI Agents SDK | `OpenAIAgentsAdapter` | `as_guardrails()` | `(input_guardrail, output_guardrail)` tuple |

## Capabilities

| Framework | Can Redact Before LLM | Deny Mechanism |
|-----------|----------------------|----------------|
| LangChain | Yes | Return "DENIED: reason" as ToolMessage |
| CrewAI | Yes (callback return replaces result) | before_hook returns False |
| Agno | Yes (hook wraps execution) | Hook returns denial string |
| Semantic Kernel | Yes (filter modifies FunctionResult) | Filter sets terminate + error |
| Claude SDK | No (side-effect only) | Returns deny dict to SDK |
| OpenAI Agents | No (side-effect only) | `reject_content(reason)` |

For regulated environments requiring PII interception (not just detection), use
LangChain, CrewAI, Agno, or Semantic Kernel.

## Common Constructor

All adapters share the same constructor signature:

```python
adapter = SomeAdapter(
    guard=guard,                    # required -- the Edictum instance
    session_id="my-session-123",    # optional -- auto-generated UUID if omitted
    principal=principal,            # optional -- identity context for audit
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `guard` | `Edictum` | required | The Edictum instance holding contracts, limits, and sinks |
| `session_id` | `str \| None` | auto UUID | Groups related tool calls into a session for limit tracking |
| `principal` | `Principal \| None` | `None` | Identity context attached to every audit event in this session |

## Common Features

### Observe Mode

Every adapter supports observe mode. When the guard is created with
`mode="observe"`, denials are logged as `CALL_WOULD_DENY` audit events but the
tool call is allowed to proceed:

```python
guard = Edictum.from_yaml("contracts.yaml", mode="observe")
adapter = SomeAdapter(guard=guard)
```

This lets you deploy contracts in production to validate enforcement behavior
before switching to `mode="enforce"`.

### Audit Sinks

Route audit events to a file with automatic redaction:

```python
from edictum.audit import FileAuditSink, RedactionPolicy

redaction = RedactionPolicy()
sink = FileAuditSink("audit.jsonl", redaction=redaction)

guard = Edictum.from_yaml(
    "contracts.yaml",
    audit_sink=sink,
    redaction=redaction,
)
```

### Principal Context

Attach identity information to every audit event:

```python
from edictum import Principal

principal = Principal(
    user_id="alice",
    role="sre",
    ticket_ref="JIRA-1234",
    claims={"department": "platform"},
)

adapter = SomeAdapter(guard=guard, principal=principal)
```

## Choosing an Adapter

Pick the adapter that matches your agent framework:

- **Claude Agent SDK** -- Building with Anthropic's agent SDK. Hook-based
  enforcement via `pre_tool_use` / `post_tool_use`.
- **LangChain** -- Using LangChain agents with `ToolNode`. Wrap tool calls
  via `as_tool_wrapper()`.
- **CrewAI** -- Using CrewAI crews. Global before/after hooks applied to every
  tool call across all agents in the crew.
- **Agno** -- Using the Agno framework. A `tool_hooks` compatible function that
  wraps tool execution.
- **Semantic Kernel** -- Using Microsoft Semantic Kernel. Registers an
  auto-function-invocation filter on the kernel.
- **OpenAI Agents SDK** -- Using the OpenAI Agents SDK. Per-tool guardrails via
  `tool_input_guardrails` / `tool_output_guardrails`.

If your framework is not listed, use `Edictum.run()` directly -- it provides
the same pipeline without any adapter:

```python
result = await guard.run(
    tool_name="read_file",
    args={"path": "/etc/passwd"},
    tool_callable=my_read_file_fn,
)
```

## Installation Extras

Each adapter has an optional dependency group:

```bash
pip install edictum[langchain]        # LangChain adapter
pip install edictum[crewai]           # CrewAI adapter
pip install edictum[agno]             # Agno adapter
pip install edictum[semantic-kernel]  # Semantic Kernel adapter
pip install edictum[openai-agents]    # OpenAI Agents SDK adapter
pip install edictum[yaml]             # YAML contract engine (no framework deps)
pip install edictum[all]              # Everything
```

The Claude Agent SDK adapter has no extra dependencies beyond `edictum[yaml]`.
