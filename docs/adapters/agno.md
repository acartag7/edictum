# Agno Adapter

The `AgnoAdapter` produces a wrap-around hook function compatible with Agno's
`tool_hooks` parameter. Unlike other adapters, the Agno hook wraps the entire
tool execution -- it receives the callable and is responsible for invoking it.

## Installation

```bash
pip install edictum[agno]
```

## Integration

```python
from edictum import Edictum
from edictum.adapters.agno import AgnoAdapter
from agno import Agent

guard = Edictum.from_yaml("contracts.yaml")
adapter = AgnoAdapter(guard=guard)
hook = adapter.as_tool_hook()

agent = Agent(
    model="gpt-4o-mini",
    tools=[search_tool, file_tool],
    tool_hooks=[hook],
)
```

The hook is passed via the `tool_hooks` parameter on the `Agent` constructor.
It intercepts every tool call made by the agent.

## Hook Behavior

The hook function receives three arguments:

```
(function_name: str, function_call: Callable, arguments: dict) -> result
```

The adapter controls the full lifecycle:

1. Runs pre-execution governance on the tool name and arguments.
2. If allowed, calls `function_call(**arguments)` to execute the tool.
3. Runs post-execution governance on the result.
4. Returns the tool result on success or `"DENIED: <reason>"` on deny.

Because the adapter wraps the entire call, it can both block execution and
replace the returned result.

## PII Redaction Callback

Use `on_postcondition_warn` to transform tool output when postconditions flag
issues. Because this is a wrap-around adapter, the callback's return value
replaces the tool result:

```python
import re

def redact_pii(result, findings):
    text = str(result)
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[SSN REDACTED]", text)
    text = re.sub(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "[EMAIL REDACTED]", text)
    return text

hook = adapter.as_tool_hook(on_postcondition_warn=redact_pii)
```

## Known Limitations

- **Kwargs spread**: The adapter calls `function_call(**arguments)`, spreading
  the arguments dict as keyword arguments. Your tool callables must accept
  keyword arguments, not a single positional dict.

- **Async-to-sync bridging**: Agno hooks are synchronous, but Edictum's
  governance pipeline is async. When no event loop is running, the adapter uses
  `asyncio.run()`. When a loop is already running (common in async frameworks),
  it spins up a `ThreadPoolExecutor` with a single worker to run the async code
  in a fresh event loop. Objects with thread affinity (e.g., some DB
  connections) may not transfer correctly across this boundary.

- **Async tool support**: If `function_call(**arguments)` returns a coroutine,
  the adapter awaits it automatically.

## Full Working Example

```python
from edictum import Edictum, Principal
from edictum.adapters.agno import AgnoAdapter
from agno import Agent

# Configure governance
guard = Edictum.from_yaml("contracts.yaml")

adapter = AgnoAdapter(
    guard=guard,
    session_id="agno-session-01",
    principal=Principal(user_id="research-agent", role="analyst"),
)

hook = adapter.as_tool_hook()

# Define tools
def search_documents(query: str) -> str:
    """Search the document store."""
    return f"Found 3 results for: {query}"

def read_file(path: str) -> str:
    """Read a file from disk."""
    with open(path) as f:
        return f.read()

# Build agent with governance
agent = Agent(
    model="gpt-4o-mini",
    tools=[search_documents, read_file],
    tool_hooks=[hook],
)

result = agent.run("Search for quarterly earnings data")
print(result)
```

## Observe Mode

Deploy contracts without enforcement to see what would be denied:

```python
guard = Edictum.from_yaml("contracts.yaml", mode="observe")
adapter = AgnoAdapter(guard=guard)
hook = adapter.as_tool_hook()
```

In observe mode, the hook always allows tool calls through, even for calls that
would be denied. `CALL_WOULD_DENY` audit events are emitted so you can review
enforcement behavior before enabling it.
