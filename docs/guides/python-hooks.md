# Python Hooks

Some enforcement logic doesn't fit in YAML contracts. You might need to call an external service, check a dynamic allowlist, or log tool calls to a custom system. Python hooks let you run arbitrary code before or after tool execution, alongside your YAML contracts.

---

## Quick Example

```python
from edictum import Edictum, HookRegistration, HookDecision

def block_destructive(envelope):
    """Deny any bash command containing 'rm -rf'."""
    cmd = envelope.tool_input.get("command", "")
    if "rm -rf" in cmd:
        return HookDecision.deny("Destructive command denied")
    return HookDecision.allow()

guard = Edictum(
    hooks=[
        HookRegistration(phase="before", tool="bash", callback=block_destructive),
    ],
)
```

The hook runs before every `bash` tool call. If the command contains `rm -rf`, the call is denied and the tool never executes.

---

## Core Types

### `HookResult`

An enum with two values:

| Value | Meaning |
|-------|---------|
| `HookResult.ALLOW` | The hook permits the tool call |
| `HookResult.DENY` | The hook denies the tool call |

### `HookDecision`

A dataclass returned by before hooks to signal the pipeline's next step.

| Field | Type | Description |
|-------|------|-------------|
| `result` | `HookResult` | Whether to allow or deny |
| `reason` | `str \| None` | Denial reason (truncated to 500 characters) |

Two class methods for convenience:

```python
HookDecision.allow()               # allow the call
HookDecision.deny("reason text")   # deny with a reason
```

### `HookRegistration`

A dataclass that binds a callback to a pipeline phase and tool.

| Field | Type | Description |
|-------|------|-------------|
| `phase` | `str` | `"before"` or `"after"` |
| `tool` | `str` | Tool name to match, or `"*"` for all tools |
| `callback` | callable | The hook function |
| `when` | callable \| None | Optional filter: `when(envelope) -> bool` |

---

## Before Hooks

Before hooks run **before preconditions** in the pipeline. They receive a `ToolEnvelope` and must return a `HookDecision`.

```python
from edictum import HookRegistration, HookDecision

def check_allowlist(envelope):
    allowed_tools = {"read_file", "list_dir", "search"}
    if envelope.tool_name not in allowed_tools:
        return HookDecision.deny(f"Tool '{envelope.tool_name}' is not in the allowlist")
    return HookDecision.allow()

hook = HookRegistration(phase="before", tool="*", callback=check_allowlist)
```

If a before hook returns `HookDecision.deny(...)`, the tool call is denied immediately. Preconditions and session contracts are not evaluated.

---

## After Hooks

After hooks run **after postconditions** in the pipeline. They receive a `ToolEnvelope` and the tool's response. The return value is ignored -- after hooks are for side effects like logging or metrics.

```python
from edictum import HookRegistration

def log_tool_result(envelope, response):
    print(f"[audit] {envelope.tool_name} returned {len(str(response))} chars")

hook = HookRegistration(phase="after", tool="*", callback=log_tool_result)
```

After hooks cannot deny tool calls. The tool has already executed by the time they run.

---

## Tool Targeting

Set `tool` to a specific tool name to match only that tool, or `"*"` to match all tools:

```python
# Only fires for "deploy_service"
HookRegistration(phase="before", tool="deploy_service", callback=my_hook)

# Fires for every tool call
HookRegistration(phase="before", tool="*", callback=my_hook)
```

---

## Conditional Hooks

The `when` parameter accepts a callable that receives the `ToolEnvelope` and returns a bool. The hook only fires when `when` returns `True`:

```python
def is_production(envelope):
    return envelope.environment == "production"

hook = HookRegistration(
    phase="before",
    tool="deploy_service",
    callback=require_approval,
    when=is_production,
)
```

This hook only runs for `deploy_service` calls in the production environment.

---

## Async Support

Hook callbacks can be sync or async. The pipeline detects coroutines and awaits them automatically:

```python
import httpx
from edictum import HookRegistration, HookDecision

async def check_external_policy(envelope):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://policy.internal/check",
            json={"tool": envelope.tool_name, "args": envelope.tool_input},
        )
        if resp.json().get("denied"):
            return HookDecision.deny(resp.json()["reason"])
    return HookDecision.allow()

hook = HookRegistration(phase="before", tool="*", callback=check_external_policy)
```

---

## Error Handling

If a before hook raises an exception, the pipeline treats it as a denial:

```python
# If this hook raises, the tool call is denied with:
# "Hook error: <exception message>"
def risky_hook(envelope):
    raise RuntimeError("service unavailable")
    # Pipeline denies with: "Hook error: service unavailable"
```

If an after hook raises an exception, the error is logged but does not affect the tool result. The tool has already executed -- the pipeline does not propagate after-hook errors.

---

## Pipeline Order

Hooks fit into the pipeline at specific positions:

1. Attempt limit check
2. **Before hooks** (can deny)
3. Preconditions (can deny)
4. Session contracts (can deny)
5. Execution limits check
6. Tool executes
7. Postconditions (warn/redact/deny for READ/PURE tools)
8. **After hooks** (side effects only)
9. Audit event emitted

Before hooks run first -- a denial from a hook skips all subsequent checks. This makes hooks useful for fast-path rejections that don't need contract evaluation.

---

## Registering Hooks

Pass hooks to the `Edictum` constructor via the `hooks` parameter:

```python
from edictum import Edictum, HookRegistration, HookDecision

def audit_hook(envelope):
    print(f"Tool call: {envelope.tool_name}")
    return HookDecision.allow()

def log_result(envelope, response):
    print(f"Result: {response}")

guard = Edictum(
    hooks=[
        HookRegistration(phase="before", tool="*", callback=audit_hook),
        HookRegistration(phase="after", tool="*", callback=log_result),
    ],
    contracts=[...],
)
```

Hooks can be combined with YAML contracts. Load contracts from YAML separately and pass hooks alongside:

```python
from edictum import Edictum, HookRegistration, HookDecision
from edictum.yaml_engine.loader import load_bundle
from edictum.yaml_engine.compiler import compile_contracts

# Load YAML contracts
bundle_data, bundle_hash = load_bundle("contracts.yaml")
compiled = compile_contracts(bundle_data)

guard = Edictum(
    contracts=compiled.preconditions + compiled.postconditions + compiled.session_contracts,
    limits=compiled.limits,
    hooks=[
        HookRegistration(phase="before", tool="*", callback=my_hook),
    ],
)
```

!!! note "Python-only"
    Hooks are not available via `Edictum.from_yaml()`. They require programmatic
    setup through the `Edictum` constructor.

---

## Next Steps

- [How it works](../concepts/how-it-works.md) -- the full pipeline that hooks plug into
- [Writing contracts](writing-contracts.md) -- YAML contracts for declarative enforcement
- [Testing contracts](testing-contracts.md) -- validating your contracts and hooks
