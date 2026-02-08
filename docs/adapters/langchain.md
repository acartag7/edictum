# LangChain Adapter

The `LangChainAdapter` connects Edictum to LangChain agents. It provides three
integration methods depending on your setup: `as_tool_wrapper()` for `ToolNode`,
`as_middleware()` for `create_react_agent`, and `as_async_tool_wrapper()` for
async contexts.

## Installation

```bash
pip install edictum[langchain]
```

This installs `langchain-core >= 0.3`.

## Integration

The primary integration uses `as_tool_wrapper()` with `ToolNode`:

```python
from edictum import Edictum
from edictum.adapters.langchain import LangChainAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = LangChainAdapter(guard=guard)
wrapper = adapter.as_tool_wrapper()

tool_node = ToolNode(tools=tools, wrap_tool_call=wrapper)
# LangGraph's create_react_agent accepts a ToolNode as the tools parameter
agent = create_react_agent(model, tools=tool_node)
```

### Alternative: `as_middleware()`

For agents using `tool_call_middleware` directly:

```python
middleware = adapter.as_middleware()
agent = create_react_agent(model, tools=tools, tool_call_middleware=[middleware])
```

### Alternative: `as_async_tool_wrapper()`

For fully async contexts where you want to avoid the sync-to-async bridge:

```python
async_wrapper = adapter.as_async_tool_wrapper()
tool_node = ToolNode(tools=tools, wrap_tool_call=async_wrapper)
```

## PII Redaction Callback

All three methods accept `on_postcondition_warn`. The callback receives the
original result and a list of findings, and its return value replaces the tool
result:

```python
import re

def redact_pii(result, findings):
    text = str(result)
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[SSN REDACTED]", text)
    text = re.sub(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "[EMAIL REDACTED]", text)
    return text

wrapper = adapter.as_tool_wrapper(on_postcondition_warn=redact_pii)
tool_node = ToolNode(tools=tools, wrap_tool_call=wrapper)
```

## Known Limitations

### Event Loops

The `as_middleware()` method uses `asyncio.get_event_loop().run_until_complete()`
to bridge sync and async. This raises a `RuntimeError` if an asyncio event loop
is already running in the current thread. This can happen when:

- Running inside a Jupyter notebook
- Running inside an async web framework (FastAPI, Starlette)
- Running inside any context that already has an active event loop

The `as_tool_wrapper()` method handles this more gracefully by detecting a
running loop and bridging via `ThreadPoolExecutor`. For fully async contexts,
use `as_async_tool_wrapper()` to avoid the bridge entirely.

Workarounds for `as_middleware()`:

1. Use `nest_asyncio` to allow nested event loops:
   ```python
   import nest_asyncio
   nest_asyncio.apply()
   ```

2. Run the agent in a separate thread without an active event loop.

3. Switch to `as_tool_wrapper()` or `as_async_tool_wrapper()`.

## Full Working Example

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter
from langchain_openai import ChatOpenAI
from langchain.agents import create_react_agent
from langgraph.prebuilt import ToolNode

# Configure governance
guard = Edictum.from_yaml("contracts.yaml")

# Create adapter with identity
adapter = LangChainAdapter(
    guard=guard,
    session_id="research-session-01",
    principal=Principal(user_id="researcher", role="analyst"),
)

# Get the wrapper
wrapper = adapter.as_tool_wrapper()

# Build LangChain agent with governance
llm = ChatOpenAI(model="gpt-4o-mini")
tools = [search_tool, calculator_tool, file_reader_tool]

tool_node = ToolNode(tools=tools, wrap_tool_call=wrapper)
agent = create_react_agent(model=llm, tools=tool_node)

# Run -- tool calls are now governed
result = agent.invoke({"messages": [("user", "Summarize the Q3 report")]})
```

## Observe Mode

Deploy contracts in observation mode to see what would be denied without
blocking any tool calls:

```python
guard = Edictum.from_yaml("contracts.yaml", mode="observe")
adapter = LangChainAdapter(guard=guard)
wrapper = adapter.as_tool_wrapper()
```

In observe mode, the wrapper always allows tool calls through.
`CALL_WOULD_DENY` audit events are emitted so you can review enforcement
behavior before enabling it.
