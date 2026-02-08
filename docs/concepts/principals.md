# Principals

A principal carries identity context -- who initiated the tool call, what role they have, what ticket authorized it. Edictum does not authenticate principals. Your application sets the principal, and contracts evaluate against it.

## Principal Fields

```python
from edictum import Principal

principal = Principal(
    user_id="alice",
    service_id="billing-agent",
    org_id="acme-corp",
    role="analyst",
    ticket_ref="INC-1234",
    claims={"department": "finance", "clearance": "confidential"},
)
```

| Field | Type | Description |
|-------|------|-------------|
| `user_id` | `str` or `None` | The human or service account that initiated the session |
| `service_id` | `str` or `None` | The agent or service making the tool call |
| `org_id` | `str` or `None` | Organization or tenant identifier |
| `role` | `str` or `None` | Role used for role-based contract conditions |
| `ticket_ref` | `str` or `None` | Change management ticket (Jira, ServiceNow, PagerDuty) |
| `claims` | `dict` | Arbitrary key-value pairs for custom authorization context |

All fields are optional. Use only what your contracts need.

## Attaching a Principal

Pass the principal when creating an adapter. It is carried through every tool call and audit event in that session.

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter

guard = Edictum.from_yaml("contracts.yaml")
principal = Principal(role="analyst", ticket_ref="INC-1234")

adapter = LangChainAdapter(guard=guard, principal=principal)
wrapper = adapter.as_tool_wrapper()
```

Or use `Edictum.run()` directly:

```python
result = await guard.run(
    "query_db",
    {"query": "SELECT * FROM users"},
    query_fn,
    principal=principal,
)
```

## Using Principals in Contracts

Contracts reference principal fields through the `principal.*` selectors.

### Require a ticket for non-admin writes

```yaml
- id: require-ticket-for-writes
  type: pre
  tool: "*"
  when:
    all:
      - principal.role: { not_in: [admin, sre] }
      - principal.ticket_ref: { exists: false }
  then:
    effect: deny
    message: "Non-admin tool calls require a ticket reference."
```

When a principal with `role: "analyst"` and no `ticket_ref` calls any tool, this contract fires. An admin or SRE can proceed without a ticket.

### Gate production deploys by role

```yaml
- id: prod-deploy-requires-senior
  type: pre
  tool: deploy_service
  when:
    all:
      - environment: { equals: production }
      - principal.role: { not_in: [senior_engineer, sre, admin] }
  then:
    effect: deny
    message: "Production deploys require senior role (sre/admin)."
```

### Use custom claims for fine-grained access

```yaml
- id: only-platform-can-scale
  type: pre
  tool: scale_service
  when:
    principal.claims.department: { not_equals: platform }
  then:
    effect: deny
    message: "Only the platform team can scale services."
```

The `claims` dict supports dotted path access: `principal.claims.department` resolves to `principal.claims["department"]`. If the key is missing, the condition evaluates to `false` and the contract does not fire.

## Principal Propagation

Set the principal once at the adapter level. It propagates automatically to:

- Every `ToolEnvelope` built for each tool call
- Every precondition and postcondition evaluation
- Every `AuditEvent` emitted by the pipeline
- Every OpenTelemetry span (as `edictum.principal.*` attributes)

You do not need to pass the principal on each tool call. The adapter carries it for the entire session.

## Missing Principal

If no principal is set:

- Contracts that check `principal.*` fields see `null` values.
- A condition like `principal.role: { not_in: [admin] }` evaluates to `false` (missing field behavior), so the contract does **not** fire.
- A condition like `principal.ticket_ref: { exists: false }` evaluates to `true`, because the field is absent.

Design your contracts to handle the no-principal case explicitly if you need to enforce principal requirements:

```yaml
- id: require-principal
  type: pre
  tool: "*"
  when:
    principal.user_id: { exists: false }
  then:
    effect: deny
    message: "A principal with user_id is required for all tool calls."
```

## Next Steps

- [Contracts](contracts.md) -- how to write preconditions, postconditions, and session contracts
- [Adapters overview](../adapters/overview.md) -- how to set a principal per framework
- [YAML reference](../contracts/yaml-reference.md) -- full selector and operator reference
- [How it works](how-it-works.md) -- where principal checks fit in the pipeline
