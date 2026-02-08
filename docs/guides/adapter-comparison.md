# Framework Adapter Comparison

Edictum ships six framework adapters. This guide helps you choose the right one and understand the tradeoffs.

---

## Quick Comparison

| Framework | Integration Method | Can Redact Before LLM | Deny Mechanism | Cost (same task) |
|-----------|-------------------|----------------------|----------------|-----------------|
| LangChain | `as_tool_wrapper()` | Yes | Return "DENIED: reason" as ToolMessage | $0.025 |
| OpenAI Agents | `as_guardrails()` | No (side-effect only) | `reject_content(reason)` | $0.018 |
| CrewAI | `register()` | Yes (callback return replaces result) | before_hook returns False | $0.040 |
| Agno | `as_tool_hook()` | Yes (hook wraps execution) | Hook returns denial string | N/A |
| Semantic Kernel | `register(kernel)` | Yes (filter modifies FunctionResult) | Filter sets cancel + error | $0.008 |
| Claude SDK | `to_sdk_hooks()` | No (side-effect only) | Returns deny dict to SDK | N/A |

Cost column reflects benchmarks from [edictum-demo](https://github.com/acartag7/edictum-demo) using each framework's default model. N/A indicates no published benchmark data.

---

## Which Adapter Should I Use?

- **Need full PII interception?** -- Use LangChain, CrewAI, Agno, or Semantic Kernel. These adapters can replace the tool result before the LLM sees it.
- **Cheapest per-task cost?** -- Semantic Kernel ($0.008 per task in benchmarks).
- **Simplest integration?** -- Claude SDK or Agno. Both require minimal wiring.
- **Using CrewAI?** -- CrewAI adapter is the only option. Note that CrewAI hooks are global (applied to every tool across all agents in the crew).

---

## Per-Adapter Snippets

### LangChain

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter
from langgraph.prebuilt import ToolNode

guard = Edictum.from_yaml("contracts.yaml")
adapter = LangChainAdapter(guard=guard, principal=Principal(role="analyst"))
wrapper = adapter.as_tool_wrapper()
# Pass to: ToolNode(tools=tools, wrap_tool_call=wrapper)
```

### OpenAI Agents

```python
from edictum import Edictum, Principal
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
from agents import function_tool

guard = Edictum.from_yaml("contracts.yaml")
adapter = OpenAIAgentsAdapter(guard=guard, principal=Principal(role="assistant"))
input_gr, output_gr = adapter.as_guardrails()
# Pass to: @function_tool(tool_input_guardrails=[input_gr], tool_output_guardrails=[output_gr])
```

### CrewAI

```python
from edictum import Edictum, Principal
from edictum.adapters.crewai import CrewAIAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = CrewAIAdapter(guard=guard, principal=Principal(role="researcher"))
adapter.register()
# Hooks are now globally registered for all CrewAI tool calls
```

### Agno

```python
from edictum import Edictum, Principal
from edictum.adapters.agno import AgnoAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = AgnoAdapter(guard=guard, principal=Principal(role="assistant"))
hook = adapter.as_tool_hook()
# Pass to: Agent(tool_hooks=[hook])
```

### Semantic Kernel

```python
from edictum import Edictum, Principal
from edictum.adapters.semantic_kernel import SemanticKernelAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = SemanticKernelAdapter(guard=guard, principal=Principal(role="analyst"))
adapter.register(kernel)
# Filter is now registered on the kernel instance
```

### Claude SDK

```python
from edictum import Edictum, Principal
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = ClaudeAgentSDKAdapter(guard=guard, principal=Principal(role="sre"))
hooks = adapter.to_sdk_hooks()
# Pass to your Claude agent/client setup: hooks=hooks
```

---

## Known Limitations

### LangChain

- `as_middleware()` is sync-only. If an asyncio event loop is already running (Jupyter, FastAPI), use `as_tool_wrapper()` (handles nested loops via ThreadPoolExecutor) or `as_async_tool_wrapper()`. See [LangChain adapter docs](../adapters/langchain.md).

### OpenAI Agents

- Guardrails are per-tool via `@function_tool()`, not per-agent. Input and output guardrails are separate functions; the adapter correlates them using insertion-order (FIFO), which assumes sequential tool execution. See [OpenAI Agents adapter docs](../adapters/openai-agents.md).

### CrewAI

- Hooks are global -- they apply to every tool across all agents in the crew. There is no per-agent hook scoping. See [CrewAI adapter docs](../adapters/crewai.md).

### Agno

- Tool callables must accept keyword arguments (the adapter spreads the args dict with `**arguments`). See [Agno adapter docs](../adapters/agno.md).

### Semantic Kernel

- `context.terminate = True` on deny stops all auto-invocations in the current turn, not just the denied tool. See [Semantic Kernel adapter docs](../adapters/semantic-kernel.md).

### Claude SDK

- Side-effect only -- the hook cannot replace the tool result. PII detection is logged but not intercepted before reaching the model. See [Claude SDK adapter docs](../adapters/claude-sdk.md).
