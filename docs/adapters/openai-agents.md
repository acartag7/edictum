# OpenAI Agents SDK Adapter

The `OpenAIAgentsAdapter` connects Edictum to the OpenAI Agents SDK through its
per-tool guardrail system. It produces a pair of guardrail objects --
`(ToolInputGuardrail, ToolOutputGuardrail)` -- that you attach to individual
tools via `@function_tool`.

## Installation

```bash
pip install edictum[openai-agents]
```

## Integration

```python
from edictum import Edictum
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
from agents import function_tool

guard = Edictum.from_yaml("contracts.yaml")
adapter = OpenAIAgentsAdapter(guard=guard)
input_gr, output_gr = adapter.as_guardrails()

@function_tool(tool_input_guardrails=[input_gr], tool_output_guardrails=[output_gr])
def search_documents(query: str) -> str:
    return perform_search(query)
```

Guardrails are passed per-tool on the `@function_tool` decorator, not on the
`Agent` constructor. Each tool that needs contract enforcement gets its own guardrail
references.

## Guardrail Behavior

**Input guardrail (pre-execution)**: Fires before each tool call. Extracts the
tool name and arguments from the guardrail data context. Returns
`ToolGuardrailFunctionOutput.allow()` to permit the call, or
`ToolGuardrailFunctionOutput.reject_content(reason)` to block it.

**Output guardrail (post-execution)**: Fires after tool execution. Runs
postconditions and records the execution in the session. The output guardrail
always returns `ToolGuardrailFunctionOutput.allow()` -- post-execution
evaluation produces audit events and warnings but does not block the response.
The SDK does not support transforming the tool result from an output guardrail.

## PII Redaction Callback

Use `on_postcondition_warn` to react to postcondition violations. Because the
output guardrail cannot transform the result, the callback is for side effects
only (logging, alerting, metrics):

```python
def log_pii_warning(result, findings):
    for f in findings:
        logger.warning("PII detected in tool output: %s", f.message)
    # Cannot modify result -- SDK controls the output guardrail result

input_gr, output_gr = adapter.as_guardrails(on_postcondition_warn=log_pii_warning)
```

## Known Limitations

- **FIFO correlation**: The SDK does not pass a shared `tool_use_id` between
  input and output guardrails. The adapter correlates them using insertion-order
  iteration over its pending state. This works correctly for sequential tool
  execution but assumes tools are not invoked in parallel within a single agent
  run.

- **Output guardrail cannot transform the result**: The output guardrail can
  only allow or reject. The `on_postcondition_warn` callback is invoked for
  side effects only -- its return value is ignored.

- **Per-tool, not per-agent**: Guardrails are attached to `@function_tool`
  decorators, not to the `Agent` constructor. You must pass `input_gr` and
  `output_gr` to each tool that needs contract enforcement.

## Full Working Example

```python
import asyncio
from edictum import Edictum, Principal
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
from agents import Agent, Runner, function_tool

# Define contracts
guard = Edictum.from_yaml("contracts.yaml")

# Create adapter
adapter = OpenAIAgentsAdapter(
    guard=guard,
    session_id="support-session-01",
    principal=Principal(user_id="support-bot", role="tier-1"),
)

# Get guardrails
input_gr, output_gr = adapter.as_guardrails()

# Define governed tools
@function_tool(tool_input_guardrails=[input_gr], tool_output_guardrails=[output_gr])
def search_knowledge_base(query: str) -> str:
    """Search the internal knowledge base."""
    return f"Results for: {query}"

@function_tool(tool_input_guardrails=[input_gr], tool_output_guardrails=[output_gr])
def create_ticket(title: str, description: str) -> str:
    """Create a support ticket."""
    return f"Created ticket: {title}"

# Build agent
agent = Agent(
    name="Support Agent",
    model="gpt-4o-mini",
    tools=[search_knowledge_base, create_ticket],
)

# Run
result = asyncio.run(Runner.run(agent, "Find docs about password resets"))
print(result.final_output)
```

## Observe Mode

Deploy contracts without enforcement to see what would be denied:

```python
guard = Edictum.from_yaml("contracts.yaml", mode="observe")
adapter = OpenAIAgentsAdapter(guard=guard)
input_gr, output_gr = adapter.as_guardrails()
```

In observe mode, the input guardrail always returns `allow()` even for calls
that would be denied. `CALL_WOULD_DENY` audit events are emitted so you can
review enforcement behavior before enabling it.
