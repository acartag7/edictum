# Mutable Principal

Agents that serve multiple users, escalate privileges mid-session, or refresh auth tokens cannot use a fixed principal. The identity context needs to change between tool calls without tearing down the adapter or losing session state.

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter

guard = Edictum.from_yaml("contracts.yaml")

adapter = LangChainAdapter(
    guard,
    principal_resolver=lambda tool, args: Principal(
        org_id=args.get("tenant_id"),
        role="customer",
    ),
)
```

Every tool call now resolves the principal from its arguments. Contracts that check `principal.org_id` or `principal.role` enforce per-tenant limits automatically.

---

## When to use this

**Multi-tenant agents** -- Your SaaS agent serves multiple customers in one session. Each tool call arrives with a different tenant context. `principal_resolver` extracts the tenant from tool_input and returns the right Principal so contracts enforce per-tenant limits:

```python
principal_resolver=lambda tool, args: Principal(
    org_id=args.get("tenant_id"),
    role="customer",
)
```

**Privilege escalation** -- An agent starts as "analyst" (read-only tools). After a human approval step mid-conversation, it becomes "operator" (write tools). `set_principal()` updates the role without reconstructing the adapter:

```python
adapter = LangChainAdapter(guard, principal=Principal(role="analyst"))

# ... agent runs read-only tools as analyst ...

# Human approves escalation
adapter.set_principal(Principal(role="operator"))

# ... agent now runs write tools as operator ...
```

**Token refresh** -- Your auth system issues short-lived tokens. When the token refreshes mid-session, `set_principal()` updates the claims without dropping the session state (attempt counts, execution history):

```python
adapter = LangChainAdapter(
    guard,
    principal=Principal(
        user_id="alice",
        claims={"token": "eyJ...old"},
    ),
)

# ... token refreshes ...

adapter.set_principal(Principal(
    user_id="alice",
    claims={"token": "eyJ...new"},
))
# Session state (attempt counts, execution counts) is preserved.
```

**Delegated execution** -- Agent A calls Agent B's tools on behalf of different users. Each tool call carries a different user context. `principal_resolver` resolves per-call identity so contracts enforce user-level permissions, not agent-level:

```python
def resolve_delegated_user(tool_name, tool_input):
    user_ctx = tool_input.get("on_behalf_of", {})
    return Principal(
        user_id=user_ctx.get("user_id"),
        role=user_ctx.get("role", "viewer"),
        org_id=user_ctx.get("org_id"),
    )

adapter = LangChainAdapter(guard, principal_resolver=resolve_delegated_user)
```

### Who benefits

- **Multi-tenant platforms** -- per-tenant governance without per-tenant adapter instances
- **Security-conscious deployments** -- principal stays current with auth state changes
- **Agent orchestration** -- dynamic identity resolution for complex agent hierarchies

### How this relates to other features

Static principal covers single-user, single-session agents -- the most common case. Mutable principal covers dynamic identity scenarios. `principal_resolver` is for per-call resolution; `set_principal()` is for explicit updates at known points. Use static for simple cases, resolver for multi-tenant, `set_principal()` for auth refresh.

---

## How it works

### `set_principal(principal)`

Updates the principal stored on the adapter (or the `Edictum` instance). All subsequent tool calls use the new principal. In-flight calls are not affected -- only calls that start after `set_principal()` see the change.

Available on:

- `Edictum.set_principal(principal)`
- `LangChainAdapter.set_principal(principal)`
- `ClaudeAgentSDKAdapter.set_principal(principal)`
- `CrewAIAdapter.set_principal(principal)`
- `AgnoAdapter.set_principal(principal)`
- `SemanticKernelAdapter.set_principal(principal)`
- `OpenAIAgentsAdapter.set_principal(principal)`

Session state (attempt counts, execution history) is preserved across `set_principal()` calls. Only the identity context changes.

### `principal_resolver`

A callable with the signature:

```python
def principal_resolver(tool_name: str, tool_input: dict[str, Any]) -> Principal:
    ...
```

- `tool_name`: the name of the tool being called
- `tool_input`: the arguments passed to the tool
- Returns a `Principal` that overrides the static principal for that call

When set, the resolver is called on every tool call before the pipeline evaluates contracts. Its return value becomes the principal on the `ToolEnvelope` for that call.

Pass it through the constructor:

```python
# On adapters
adapter = LangChainAdapter(guard, principal_resolver=my_resolver)

# On the Edictum class directly
guard = Edictum(
    contracts=[...],
    principal_resolver=my_resolver,
)
```

### Resolution order

The pipeline resolves the principal in this order:

1. If `principal_resolver` is set, call it with `(tool_name, tool_input)` and use its return value.
2. Otherwise, use the static principal (set via constructor or `set_principal()`).
3. If neither is set, the principal is `None`.

The resolver always wins. If you set both a static principal and a resolver, the resolver's return value is used for every call. The static principal is ignored while a resolver is active.

---

## Contracts with mutable principals

Contracts that reference `principal.*` selectors work identically whether the principal is static or dynamic. The contract sees whatever principal is on the envelope at evaluation time.

### Per-tenant rate limits

```yaml
apiVersion: edictum/v1
kind: ContractBundle

contracts:
  - id: tenant-query-limit
    type: session
    tool: query_db
    then:
      max_executions: 100
      message: "Tenant has exceeded 100 queries per session."
```

Combined with a `principal_resolver` that sets `org_id` per call, each tenant's queries are tracked against the session limit. Note that session contracts count at the session level -- if you need per-tenant counting, use separate session IDs per tenant.

### Role-gated escalation

```yaml
- id: write-requires-operator
  type: pre
  tool: ["deploy", "write_file", "delete_record"]
  when:
    principal.role: { not_in: [operator, admin] }
  then:
    effect: deny
    message: "Write operations require operator or admin role."
```

Before the human approval step, the agent has `role: "analyst"` and write tools are denied. After `set_principal(Principal(role="operator"))`, the same contract allows writes through.

---

## Audit trail

Every `AuditEvent` includes the principal that was active at the time of the tool call. When the principal changes mid-session, the audit trail reflects the transition:

```json
{"tool_name": "read_file", "principal": {"role": "analyst"}, "action": "call_allowed"}
{"tool_name": "deploy",    "principal": {"role": "analyst"}, "action": "call_denied"}
{"tool_name": "deploy",    "principal": {"role": "operator"}, "action": "call_allowed"}
```

The second `deploy` call succeeds because `set_principal()` updated the role between attempts. The audit trail makes this explicit.

---

## Next steps

- [Principals](../concepts/principals.md) -- principal fields, propagation, and missing-principal behavior
- [Writing contracts](writing-contracts.md) -- YAML contracts that use `principal.*` selectors
- [Adapter comparison](adapter-comparison.md) -- how each adapter handles principal resolution
- [Observability](observability.md) -- audit events include principal context for monitoring
