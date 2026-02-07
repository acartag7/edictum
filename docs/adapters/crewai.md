# CrewAI Adapter

The `CrewAIAdapter` registers global before/after tool-call hooks with the
CrewAI framework. Every tool call across all agents in a crew passes through
these hooks.

## Installation

```bash
pip install edictum[crewai]
```

## Integration

```python
from edictum import Edictum
from edictum.adapters.crewai import CrewAIAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = CrewAIAdapter(guard=guard)
adapter.register()
```

The `register()` method calls CrewAI's `register_before_tool_call_hook` and
`register_after_tool_call_hook` to install the adapter's handlers as global
hooks. After this call, every tool invocation in the CrewAI runtime passes
through Edictum governance.

## PII Redaction Callback

Use `on_postcondition_warn` to react when postconditions flag issues. If the
callback returns a string, it replaces the tool result before the LLM sees it.
If it returns `None`, the original result is kept:

```python
import re

def redact_pii(result, findings):
    text = str(result)
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[SSN REDACTED]", text)
    return text  # returned string replaces the tool result

adapter.register(on_postcondition_warn=redact_pii)
```

For side-effect-only usage (logging, alerting), return `None` from the callback:

```python
import logging

logger = logging.getLogger("governance")

def log_pii_detected(result, findings):
    for f in findings:
        logger.warning("Postcondition violation: %s", f.message)
    # return None -> original result is kept

adapter.register(on_postcondition_warn=log_pii_detected)
```

## Known Limitations

- **Global hooks**: `register()` modifies global state in the CrewAI runtime.
  If you create multiple adapters, only the last one registered is active. Call
  `register()` once before any crew runs.

- **Sequential execution model**: CrewAI executes tools sequentially within a
  crew run. The adapter uses a single-pending slot (not a dict keyed by call ID)
  to correlate before/after events. This is correct for sequential execution
  but would need adaptation if CrewAI adds parallel tool calls.

- **Tool name normalization**: CrewAI tool names may use spaces or hyphens
  (e.g., "Search Documents", "Read-Database"). The adapter normalizes them to
  lowercase with underscores (e.g., "search_documents", "read_database") to
  match contract tool names. The original name is restored after governance
  runs so CrewAI sees the expected name.

- **Async-to-sync bridging**: CrewAI hooks are synchronous, but Edictum's
  pipeline is async. The adapter detects whether an event loop is running and
  bridges via `ThreadPoolExecutor` when needed.

## Full Working Example

```python
from edictum import Edictum, Principal
from edictum.adapters.crewai import CrewAIAdapter
from crewai import Agent, Crew, Task

# Configure governance
guard = Edictum.from_yaml("contracts.yaml")
adapter = CrewAIAdapter(
    guard=guard,
    session_id="crew-session-01",
    principal=Principal(user_id="deploy-crew", role="ci"),
)
adapter.register()

# Build crew as usual -- hooks are global
researcher = Agent(
    role="Researcher",
    goal="Find deployment status",
    tools=[status_tool, log_reader_tool],
)

task = Task(
    description="Check the health of the staging deployment",
    agent=researcher,
)

crew = Crew(agents=[researcher], tasks=[task])
result = crew.kickoff()
```

## Observe Mode

Deploy contracts without enforcement:

```python
guard = Edictum.from_yaml("contracts.yaml", mode="observe")
adapter = CrewAIAdapter(guard=guard)
adapter.register()
```

Denials are logged as `CALL_WOULD_DENY` audit events but tool calls proceed
normally.
