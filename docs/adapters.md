# Framework Adapters

Edictum integrates with 6 agent frameworks. The same YAML contracts produce
the same governance decisions across all of them.

## Quick Comparison

| Feature | LangChain | OpenAI Agents | Agno | Semantic Kernel | CrewAI | Claude Agent SDK |
|---------|-----------|---------------|------|-----------------|--------|-----------------|
| PII redaction | True interception | Logged only* | True interception | True interception | Partial** | Logged only |
| Deny tool calls | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `on_postcondition_warn` | ✓ (transforms result) | ✓ (logged, cannot transform) | ✓ (transforms result) | ✓ (transforms result) | ✓ (partial, undocumented) | ✓ (side-effect only) |
| Multiple adapters/process | ✓ | ✓ | ✓ | ✓ (per kernel) | ✗ (global hooks) | ✓ |
| Tool name normalization | Not needed | Not needed | Not needed | Handled internally | Required*** | Not needed |
| Token tracking | Reliable | Reliable | Not available | Under-reports | Reliable | N/A |
| Relative token cost | 1x | 1.1x | N/A | 0.3–0.5x | ~3x | N/A |
| Integration complexity | Low | Medium | Low | Medium–High | High | Low |

\* OpenAI Agents output guardrails can allow or reject but cannot transform the result.
PII is detected and logged in the audit trail, but the LLM sees the raw output.

\** CrewAI's `after_tool_call` hook can return a replacement string, but this behavior
is underdocumented and may change in future versions.

\*** CrewAI uses human-readable tool names ("Search Documents") while contracts
use snake_case ("search_documents"). The adapter normalizes automatically.

## Choosing a Framework

**For regulated environments requiring PII interception:**
LangChain, Agno, or Semantic Kernel. These frameworks allow the
`on_postcondition_warn` callback to transform tool output before the LLM sees it.

**For simplest integration:**
LangChain (zero workarounds) or Agno (zero workarounds, but no token tracking).

**For cost-sensitive deployments:**
Semantic Kernel batches tool calls internally, resulting in fewer LLM round-trips
and 50–70% lower token usage. However, integration requires careful handling of
chat history and TOOL role messages.

**For CrewAI users:**
Edictum works with CrewAI but requires the most workarounds. Hooks are global
(one adapter per process), tool names need normalization, and denial messages
are generic (specific reasons are in the audit trail only). Token cost is ~3x
other frameworks due to CrewAI's verbose prompt construction.

## LangChain + LangGraph

**Status: Reference implementation. Cleanest integration.**

### Setup

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter
from langgraph.prebuilt import ToolNode

guard = Edictum.from_yaml("contracts.yaml")
principal = Principal(role="analyst", ticket_ref="TICKET-123")
adapter = LangChainAdapter(guard, principal=principal)

# Without remediation
tool_node = ToolNode(tools=tools, wrap_tool_call=adapter.as_tool_wrapper())

# With PII redaction
tool_node = ToolNode(
    tools=tools,
    wrap_tool_call=adapter.as_tool_wrapper(
        on_postcondition_warn=redact_pii
    ),
)
```

### How it works

The adapter wraps each tool call: pre-check → execute → post-check → optional remediation.
This is the wrap-around pattern — the adapter controls tool execution and can transform
the result before the LLM sees it.

- `on_postcondition_warn` receives `(result: ToolMessage, findings: list[Finding])`
- Mutate `result.content` directly for surgical redaction
- The LLM never sees unredacted content

### Token tracking

```python
# Token usage is on AIMessage.usage_metadata — iterate ALL AI messages
# (intermediate tool-calling messages carry tokens too)
for msg in result["messages"]:
    if hasattr(msg, "usage_metadata") and msg.usage_metadata:
        total_tokens += msg.usage_metadata.get("total_tokens", 0)
```

### Known limitations

None. This is the gold standard integration.

---

## OpenAI Agents SDK

### Setup

```python
from edictum import Edictum, Principal
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
from agents import function_tool, Agent, Runner

guard = Edictum.from_yaml("contracts.yaml")
principal = Principal(role="analyst")
adapter = OpenAIAgentsAdapter(guard, principal=principal)

input_gr, output_gr = adapter.as_guardrails()

@function_tool(tool_input_guardrails=[input_gr], tool_output_guardrails=[output_gr])
def read_database(dataset: str, query: str = "") -> str:
    ...

agent = Agent(name="Research Agent", tools=[read_database])
result = await Runner.run(agent, task)
```

### How it works

The adapter produces `ToolInputGuardrail` and `ToolOutputGuardrail` objects.
These go on individual tools via `@function_tool(tool_input_guardrails=...)`,
NOT on `Agent(input_guardrails=...)` (which expects a different type).

- Input guardrail: evaluates preconditions, returns allow or reject
- Output guardrail: evaluates postconditions, returns allow or reject
- Cannot transform results — SDK guardrails are binary (allow/reject)

### PII redaction limitation

The output guardrail detects PII via postconditions and logs it to the audit trail,
but cannot redact the tool result before the LLM sees it. The SDK's output
guardrail returns allow or reject — reject drops the entire result rather than
redacting specific fields.

If PII interception is required, use LangChain, Agno, or Semantic Kernel instead.

### Catching denials

```python
try:
    result = await Runner.run(agent, task)
except Exception as e:
    if "Tripwire" in type(e).__name__:
        # Guardrail rejection — check audit trail for details
        ...
```

### Known limitations

- Output guardrails cannot transform results (framework limitation)
- `Runner.run_sync()` fails inside `asyncio.run()` — use `await Runner.run()` instead
- `openai>=2.0` required — conflicts with `semantic-kernel` in same environment

---

## Agno

### Setup

```python
from edictum import Edictum, Principal
from edictum.adapters.agno import AgnoAdapter
from agno.agent import Agent
from agno.models.openai import OpenAIChat

guard = Edictum.from_yaml("contracts.yaml")
principal = Principal(role="analyst")
adapter = AgnoAdapter(guard, principal=principal)

hook = adapter.as_tool_hook(on_postcondition_warn=redact_pii)
agent = Agent(model=OpenAIChat(id="gpt-4.1"), tools=[...], tool_hooks=[hook])
```

### How it works

Similar to LangChain — the hook wraps tool execution with pre/post checks.
`on_postcondition_warn` receives `(result: str, findings: list[Finding])`.

### Known limitations

- No token metrics. `response.metrics` exists but does not reliably contain
  token counts. The API for metrics is underdocumented and key names vary between versions.
- Agno's `agent.run()` is synchronous; the adapter bridges async Edictum calls
  via `ThreadPoolExecutor`.

---

## Semantic Kernel

### Setup

```python
from edictum import Edictum, Principal
from edictum.adapters.semantic_kernel import SemanticKernelAdapter

guard = Edictum.from_yaml("contracts.yaml")
principal = Principal(role="analyst")
adapter = SemanticKernelAdapter(guard, principal=principal)

adapter.register(kernel, on_postcondition_warn=redact_pii)

# Manual chat loop required:
while True:
    result = await chat_service.get_chat_message_content(
        chat_history, settings, kernel=kernel
    )
    # IMPORTANT: Skip TOOL role messages to avoid chat history corruption
    if result.role != AuthorRole.TOOL:
        chat_history.add_message(result)
    if no_more_function_calls(result):
        break
```

### Chat history and TOOL role messages

When Edictum denies a tool call, SK still adds a `FunctionResultContent` (the denial
message) to chat history. On the next API call, the provider sees a `tool` role message
without a matching `tool_calls` assistant message and rejects it.

Always filter TOOL role messages when adding to chat history manually:

```python
if result.role != AuthorRole.TOOL:
    chat_history.add_message(result)
```

### Token tracking

SK batches tool call execution internally. `get_chat_message_content()` may process
multiple tool calls in one round-trip, so `llm_calls` count is lower than actual
API calls and per-call token counts may be incomplete.

### Known limitations

- Chat history TOOL role filtering required (see above)
- Token tracking under-reports due to batching
- Pydantic version sensitivity: SK 1.39+ requires `pydantic<2.12`
- Lowest token cost (~0.3–0.5x) due to internal batching

---

## CrewAI

### Setup

```python
from edictum import Edictum, Principal
from edictum.adapters.crewai import CrewAIAdapter

guard = Edictum.from_yaml("contracts.yaml")
principal = Principal(role="analyst")
adapter = CrewAIAdapter(guard, principal=principal)

adapter.register(on_postcondition_warn=redact_pii)
```

### Tool name normalization

CrewAI uses human-readable tool names ("Search Documents") while contracts
use snake_case ("search_documents"). The adapter normalizes automatically.

If you define tools with custom names, ensure the normalized form matches
your contract `tool:` field:

```python
# Tool name: "Search Documents" → normalized: "search_documents"
# Contract must use: tool: search_documents
```

### Known limitations

- Global hooks. Hooks are registered per process. Only one adapter can be active.
  Multiple adapters = last one wins.
- Generic denial messages. When a tool call is denied, CrewAI shows
  "Tool execution blocked by hook" without the governance reason. The specific
  reason is in the audit trail.
- Most expensive. ~3x token usage compared to other frameworks. CrewAI repeats
  the full agent role, backstory, and task description in every prompt.
- Tracing prompt. CrewAI prompts "Would you like to view your execution traces?"
  with a 20s timeout after every run. Set `CREWAI_TELEMETRY_OPT_OUT=1` to suppress.

---

## Claude Agent SDK

### Setup

```python
from claude_agent_sdk import Agent
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter

adapter = ClaudeAgentSDKAdapter(guard, session_id="session-claude")
hooks = adapter.to_sdk_hooks()

agent = Agent(
    model="claude-haiku-4-5",
    tools=[...],
    hooks=hooks,
)
```

`to_sdk_hooks()` returns `{"pre_tool_use": ..., "post_tool_use": ...}`. Denied calls return a dict with `permissionDecision: "deny"` and the reason.

**Postcondition remediation** (v0.5.1+):

```python
hooks = adapter.to_sdk_hooks(
    on_postcondition_warn=lambda result, findings: log_findings(result, findings)
)
```

---

## Governance Consistency Across Frameworks

The same YAML contracts produce the same governance decisions regardless of framework:

| Contract | LangChain | OpenAI Agents | Agno | SK | CrewAI | Claude SDK |
|----------|-----------|---------------|------|----|--------|-----------|
| block-sensitive-reads (deny) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| require-ticket-ref (deny without ticket) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| pii-in-any-output (postcondition warn) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Governance is deterministic. Framework behavior around denied calls and
postcondition remediation varies — see comparison table above.
