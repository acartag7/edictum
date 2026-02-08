# Quickstart

In five minutes you will install Edictum, write a contract, and see it deny a dangerous tool call. The denied call never executes -- the agent sees a denial message and the audit trail records what happened.

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
      message: "Destructive command denied: {args.command}"

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

Three contracts: one denies reads of `.env` files, one denies destructive commands, and one caps the session at 50 tool calls.

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

    # DENIED: agent tries to read .env
    try:
        await guard.run("read_file", {"path": ".env"}, read_file)
    except EdictumDenied as e:
        print(f"DENIED: {e.reason}")

    # DENIED: agent tries to rm -rf
    try:
        await guard.run("run_command", {"command": "rm -rf /tmp"}, run_command)
    except EdictumDenied as e:
        print(f"DENIED: {e.reason}")


asyncio.run(main())
```

Run it:

```bash
python demo.py
```

Expected output:

```
OK: contents of readme.txt
DENIED: Blocked read of sensitive file: .env
DENIED: Destructive command denied: rm -rf /tmp
```

The `.env` file was never read. The `rm -rf` command never executed. Both calls were denied by contracts evaluated in Python, outside the LLM. The agent cannot talk its way past these checks.

## 4. Add to Your Framework

Create the guard from the same YAML, then use the adapter for your framework.

```python
from edictum import Edictum

guard = Edictum.from_yaml("contracts.yaml")
```

### LangChain

```python
from edictum.adapters.langchain import LangChainAdapter
from langgraph.prebuilt import ToolNode

adapter = LangChainAdapter(guard)
tool_node = ToolNode(tools=tools, wrap_tool_call=adapter.as_tool_wrapper())
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
agent = Agent(tool_hooks=[adapter.as_tool_hook()])
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

All six adapters enforce the same contracts. The YAML does not change between frameworks.

## 5. Observe Mode (Bonus)

Not ready to deny calls in production? Change one line to shadow-test contracts without denying anything:

```yaml
defaults:
  mode: observe   # was: enforce
```

In observe mode, calls that would be denied are logged as `CALL_WOULD_DENY` audit events but allowed to proceed. Review the audit trail, tune your contracts, then switch back to `enforce` when ready.

See [observe mode](concepts/observe-mode.md) for the full workflow.

## Next Steps

- **Concepts** -- start here to understand the system:
    - [How it works](concepts/how-it-works.md) -- the pipeline that evaluates every tool call
    - [Contracts](concepts/contracts.md) -- the three contract types
    - [Principals](concepts/principals.md) -- attaching identity context
    - [Observe mode](concepts/observe-mode.md) -- shadow-testing before enforcement
- [YAML reference](contracts/yaml-reference.md) -- full contract syntax
- [Adapters overview](adapters/overview.md) -- detailed setup and limitations for each framework
