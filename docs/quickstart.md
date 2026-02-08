# Quickstart

## 1. Install

```bash
pip install edictum[yaml]
```

Requires Python 3.11+.

## 2. Write a Contract

Save this as `contracts.yaml`:

```yaml
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: agent-safety
defaults:
  mode: enforce
contracts:
  - id: block-dotenv
    type: pre
    tool: read_file
    when:
      args.path: { contains: ".env" }
    then:
      effect: deny
      message: "Blocked read of sensitive file: {args.path}"

  - id: block-destructive-commands
    type: pre
    tool: run_command
    when:
      any:
        - args.command: { starts_with: "rm " }
        - args.command: { starts_with: "DROP " }
        - args.command: { contains: "mkfs" }
    then:
      effect: deny
      message: "Destructive command blocked: {args.command}"

  - id: session-limits
    type: session
    limits:
      max_tool_calls: 50
      max_attempts: 120
      max_calls_per_tool:
        run_command: 10
    then:
      effect: deny
      message: "Session limit reached."
```

## 3. Run It

Save this as `demo.py`:

```python
import asyncio
from edictum import Edictum, EdictumDenied


guard = Edictum.from_yaml("contracts.yaml")


async def read_file(path):
    return f"contents of {path}"


async def run_command(command):
    return f"executed: {command}"


async def main():
    # Allowed: normal file read
    result = await guard.run("read_file", {"path": "readme.txt"}, read_file)
    print(f"OK: {result}")

    # Denied: .env file
    try:
        await guard.run("read_file", {"path": ".env"}, read_file)
    except EdictumDenied as e:
        print(f"DENIED: {e.reason}")

    # Denied: destructive command
    try:
        await guard.run("run_command", {"command": "rm -rf /tmp"}, run_command)
    except EdictumDenied as e:
        print(f"DENIED: {e.reason}")


asyncio.run(main())
```

Expected output:

```
OK: contents of readme.txt
DENIED: Blocked read of sensitive file: .env
DENIED: Destructive command blocked: rm -rf /tmp
```

## 4. Add to Your Framework

Create the guard from the same YAML, then use the adapter for your framework.

```python
from edictum import Edictum

guard = Edictum.from_yaml("contracts.yaml")
```

### LangChain

```python
from edictum.adapters.langchain import LangChainAdapter

adapter = LangChainAdapter(guard)

# Option A: ToolNode wrapper
from langgraph.prebuilt import ToolNode

tool_node = ToolNode(tools=tools, wrap_tool_call=adapter.as_tool_wrapper())

# Option B: Middleware
middleware = adapter.as_middleware()
# Pass to agent as tool_call_middleware=[middleware]
```

### OpenAI Agents SDK

```python
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
from agents import function_tool

adapter = OpenAIAgentsAdapter(guard)
input_gr, output_gr = adapter.as_guardrails()

@function_tool(
    tool_input_guardrails=[input_gr],
    tool_output_guardrails=[output_gr],
)
def read_file(path: str) -> str:
    """Read a file and return its contents."""
    return open(path).read()
```

### CrewAI

```python
from edictum.adapters.crewai import CrewAIAdapter

adapter = CrewAIAdapter(guard)
adapter.register()
# Hooks are now active for all CrewAI tool calls
```

### Agno

```python
from edictum.adapters.agno import AgnoAdapter
from agno.agent import Agent

adapter = AgnoAdapter(guard)
hook = adapter.as_tool_hook()

agent = Agent(tool_hooks=[hook])
```

### Semantic Kernel

```python
from edictum.adapters.semantic_kernel import SemanticKernelAdapter
from semantic_kernel.kernel import Kernel

kernel = Kernel()
adapter = SemanticKernelAdapter(guard)
adapter.register(kernel)
```

### Claude Agent SDK

```python
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter

adapter = ClaudeAgentSDKAdapter(guard)
hooks = adapter.to_sdk_hooks()
# hooks = {"pre_tool_use": ..., "post_tool_use": ...}
```

## 5. Observe Mode

Change one line in your YAML to shadow-test contracts without blocking anything:

```yaml
defaults:
  mode: observe   # was: enforce
```

In observe mode, calls that would be denied are logged as `CALL_WOULD_DENY` audit events but allowed to proceed. Review the audit trail, tune your rules, then switch back to `enforce` when ready.
