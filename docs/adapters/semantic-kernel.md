# Semantic Kernel Adapter

The `SemanticKernelAdapter` registers an `AUTO_FUNCTION_INVOCATION` filter on a
Semantic Kernel `Kernel` instance. The filter intercepts every auto-invoked
tool call and enforces Edictum contracts around it.

## Installation

```bash
pip install edictum[semantic-kernel]
```

## Integration

```python
from edictum import Edictum
from edictum.adapters.semantic_kernel import SemanticKernelAdapter
from semantic_kernel import Kernel

kernel = Kernel()
guard = Edictum.from_yaml("contracts.yaml")
adapter = SemanticKernelAdapter(guard=guard)
adapter.register(kernel)
```

After calling `register(kernel)`, every auto-invoked tool call on that
kernel passes through Edictum contract enforcement. No further wiring is needed.

## Filter Behavior

The adapter registers a filter using
`@kernel.filter(FilterTypes.AUTO_FUNCTION_INVOCATION)`. Inside the filter:

1. Extracts the function name and arguments from the invocation context.
2. Evaluates preconditions.
3. **On allow**: calls `await next(context)` to let Semantic Kernel execute the
   function, then evaluates postconditions against `context.function_result`.
4. **On deny**: sets `context.function_result` to the denial string and sets
   `context.terminate = True`. The function is never executed, and the kernel
   stops further auto-invocations in the current turn.

## PII Redaction Callback

Use `on_postcondition_warn` to transform tool output when postconditions flag
issues. The callback's return value replaces `context.function_result`:

```python
import re

def redact_pii(result, findings):
    text = str(result)
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[SSN REDACTED]", text)
    text = re.sub(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "[EMAIL REDACTED]", text)
    return text

adapter.register(kernel, on_postcondition_warn=redact_pii)
```

## Known Limitations

- **Registration timing**: `adapter.register(kernel)` must be called before
  invoking prompts that trigger auto function calls. The filter is permanently
  registered on the kernel instance.

- **Terminate on deny**: Setting `context.terminate = True` stops the kernel
  from making additional function calls in the same turn. The LLM receives the
  denial message and can decide how to proceed on the next turn.

- **Error detection**: Beyond standard string-based error checking, the adapter
  also inspects Semantic Kernel `FunctionResult` objects for error metadata via
  `result.metadata.get("error")`.

## Full Working Example

```python
import asyncio
from edictum import Edictum, Principal
from edictum.adapters.semantic_kernel import SemanticKernelAdapter
from semantic_kernel import Kernel
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion
from semantic_kernel.functions import kernel_function

# Build kernel
kernel = Kernel()
kernel.add_service(OpenAIChatCompletion(service_id="chat", ai_model_id="gpt-4o-mini"))

# Define a plugin with tools
class FileOpsPlugin:
    @kernel_function(name="read_file", description="Read a file")
    def read_file(self, path: str) -> str:
        with open(path) as f:
            return f.read()

    @kernel_function(name="list_files", description="List files in a directory")
    def list_files(self, directory: str) -> str:
        import os
        return "\n".join(os.listdir(directory))

kernel.add_plugin(FileOpsPlugin(), "FileOps")

# Load contracts
guard = Edictum.from_yaml("contracts.yaml")
adapter = SemanticKernelAdapter(
    guard=guard,
    session_id="sk-session-01",
    principal=Principal(user_id="analyst", role="data-team"),
)
adapter.register(kernel)

# Use the kernel -- contracts are enforced on all auto-invoked functions
async def main():
    settings = kernel.get_prompt_execution_settings_from_service_id("chat")
    settings.function_choice_behavior = "auto"

    result = await kernel.invoke_prompt(
        "List the files in the current directory",
        settings=settings,
    )
    print(result)

asyncio.run(main())
```

## Observe Mode

Deploy contracts without enforcement to see what would be denied:

```python
guard = Edictum.from_yaml("contracts.yaml", mode="observe")
adapter = SemanticKernelAdapter(guard=guard)
adapter.register(kernel)
```

In observe mode, the filter always calls `await next(context)` to allow tool
execution, even for calls that would be denied. `CALL_WOULD_DENY` audit events
are emitted so you can review enforcement behavior before enabling it.
