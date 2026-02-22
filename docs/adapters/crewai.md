# CrewAI Adapter

The `CrewAIAdapter` registers global before/after tool-call hooks with the
CrewAI framework. Every tool call across all agents in a crew passes through
these hooks.

## When to use this

Add Edictum to your CrewAI project when your crew's tools can cause side effects you need to govern -- deleting resources, sending messages, making purchases. The `register()` method hooks into CrewAI's global tool call lifecycle, so contracts apply to every agent in the crew without per-agent configuration. Session contracts track cumulative usage across all agents in the crew, and tool name normalization (spaces and hyphens to underscores) happens automatically so contract names match regardless of how CrewAI formats them.

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
through Edictum contract enforcement.

## Postcondition Callback

Use `on_postcondition_warn` to react when postconditions flag issues. The
callback is invoked for side effects only (logging, alerting) -- it cannot
replace the tool result:

```python
import logging

logger = logging.getLogger("edictum")

def log_pii_detected(result, findings):
    for f in findings:
        logger.warning("Postcondition violation: %s", f.message)

adapter.register(on_postcondition_warn=log_pii_detected)
```

The callback receives `(result, findings)` where `result` is the tool output
and `findings` is a list of `Finding` objects describing the postcondition
violations.

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
  match contract tool names. The original name is restored after evaluation
  so CrewAI sees the expected name.

- **Async-to-sync bridging**: CrewAI hooks are synchronous, but Edictum's
  pipeline is async. The adapter detects whether an event loop is running and
  bridges via `ThreadPoolExecutor` when needed.

## Full Working Example

```python
from edictum import Edictum, Principal
from edictum.adapters.crewai import CrewAIAdapter
from crewai import Agent, Crew, Task

# Load contracts
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
