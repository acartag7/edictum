# YAML Contract Reference

This is the complete reference for `callguard/v1` contract bundles. A contract bundle is a single YAML file that declares all the governance rules for a CallGuard instance.

---

## Document Structure {#document-structure}

Every contract bundle starts with four required top-level fields:

```yaml
apiVersion: callguard/v1
kind: ContractBundle

metadata:
  name: my-agent-policy
  description: "Optional human-readable description."

defaults:
  mode: enforce

contracts:
  - # ... one or more contracts
```

| Field | Type | Required | Description |
|---|---|---|---|
| `apiVersion` | string | yes | Must be `callguard/v1`. |
| `kind` | string | yes | Must be `ContractBundle`. |
| `metadata.name` | string | yes | Bundle identifier. Slug format: `[a-z0-9][a-z0-9._-]*`. |
| `metadata.description` | string | no | Human-readable description. |
| `defaults.mode` | string | yes | `enforce` or `observe`. Applied to every contract that does not set its own `mode`. |
| `contracts` | array | yes | Minimum one contract. Each item is a precondition, postcondition, or session contract. |

The bundle is loaded with `CallGuard.from_yaml()`:

```python
from callguard import CallGuard

guard = CallGuard.from_yaml("contracts/my-policy.yaml")
```

A SHA256 hash of the raw YAML bytes is computed at load time and stamped as `policy_version` on every `AuditEvent` and OpenTelemetry span. This gives you an immutable link between any audit record and the exact policy file that produced it.

---

## Contract Types {#contract-types}

Every contract shares a common set of fields, plus type-specific fields determined by the `type` discriminator.

### Common Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | yes | -- | Unique within the bundle. Format: `[a-z0-9][a-z0-9_-]*`. |
| `type` | string | yes | -- | `pre`, `post`, or `session`. |
| `enabled` | boolean | no | `true` | Set to `false` to skip during evaluation. The contract still participates in validation. |
| `mode` | string | no | `defaults.mode` | Per-contract override: `enforce` or `observe`. |
| `then` | object | yes | -- | Action block. See [Action Block](#action-block). |

### Precondition (`type: pre`) {#precondition}

Preconditions evaluate **before** tool execution. If the expression matches, the tool call is denied.

| Field | Type | Required | Description |
|---|---|---|---|
| `tool` | string | yes | Tool name to target, or `"*"` for all tools. |
| `when` | Expression | yes | Boolean expression tree. See [Expression Grammar](#expression-grammar). |

**Constraints:**

- `then.effect` must be `deny`. Preconditions block; they do not warn.
- The `output.text` selector is invalid in preconditions because the tool has not run yet. Using it is a validation error.
- When `mode: observe` is set (either on the contract or via `defaults.mode`), a matching precondition emits a `CALL_WOULD_DENY` audit event instead of blocking. The tool call proceeds.

```yaml
- id: block-sensitive-reads
  type: pre
  tool: read_file
  when:
    args.path:
      contains_any: [".env", ".secret", "credentials", ".pem", "id_rsa"]
  then:
    effect: deny
    message: "Sensitive file '{args.path}' blocked. Skip and continue."
    tags: [secrets, dlp]
```

### Postcondition (`type: post`) {#postcondition}

Postconditions evaluate **after** tool execution. Because the tool has already run, postconditions can only warn -- they cannot undo what happened.

| Field | Type | Required | Description |
|---|---|---|---|
| `tool` | string | yes | Tool name to target, or `"*"` for all tools. |
| `when` | Expression | yes | Boolean expression tree. |

**Constraints:**

- `then.effect` must be `warn`. Setting `effect: deny` on a postcondition is a validation error.
- The `output.text` selector is available in postconditions. It contains the stringified tool response.

```yaml
- id: pii-in-output
  type: post
  tool: "*"
  when:
    output.text:
      matches_any:
        - '\b\d{3}-\d{2}-\d{4}\b'
        - '\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b'
  then:
    effect: warn
    message: "PII pattern detected in output. Redact before using."
    tags: [pii, compliance]
```

### Session Contract (`type: session`) {#session-contract}

Session contracts enforce session-level gates that apply across all tool calls. They track cumulative counters -- total calls, total attempts, and per-tool call counts.

| Field | Type | Required | Description |
|---|---|---|---|
| `limits` | object | yes | At least one limit field is required. |
| `limits.max_tool_calls` | integer | no* | Maximum successful tool executions in the session. |
| `limits.max_attempts` | integer | no* | Maximum governance evaluations, including denied ones. Catches denial loops. |
| `limits.max_calls_per_tool` | map | no* | Per-tool execution caps. Keys are tool names, values are integer limits. |

*At least one of `max_tool_calls`, `max_attempts`, or `max_calls_per_tool` must be present.

**Constraints:**

- `then.effect` must be `deny`.
- Session contracts do not have `tool` or `when` fields. They are tool-agnostic.

```yaml
- id: session-limits
  type: session
  limits:
    max_tool_calls: 50
    max_attempts: 120
    max_calls_per_tool:
      deploy_service: 3
      send_notification: 10
  then:
    effect: deny
    message: "Session limit reached. Summarize progress and stop."
    tags: [rate-limit]
```

---

## Expression Grammar {#expression-grammar}

The `when` field accepts a recursive expression tree. Each node is exactly one of: a boolean combinator (`all`, `any`, `not`) or a leaf comparison.

### Boolean Nodes

```yaml
# AND — all children must be true
all:
  - <expression>
  - <expression>

# OR — at least one child must be true
any:
  - <expression>
  - <expression>

# NOT — negation of one child
not: <expression>
```

Boolean nodes nest arbitrarily. Minimum one child in `all` and `any` arrays.

### Leaf Nodes

A leaf is a single selector-operator pair:

```yaml
<selector>:
  <operator>: <value>
```

Exactly one selector key per leaf. Exactly one operator per selector.

### Selectors {#selectors}

Selectors resolve fields from the `ToolEnvelope` and `Principal` at evaluation time.

| Selector | Type | Available In | Source |
|---|---|---|---|
| `environment` | string | pre, post | `ToolEnvelope.environment` |
| `tool.name` | string | pre, post | `ToolEnvelope.tool_name` |
| `args.<key>` | any | pre, post | `ToolEnvelope.args[key]` |
| `args.<key>.<subkey>` | any | pre, post | Nested dict access |
| `principal.user_id` | string or null | pre, post | `Principal.user_id` |
| `principal.service_id` | string or null | pre, post | `Principal.service_id` |
| `principal.org_id` | string or null | pre, post | `Principal.org_id` |
| `principal.role` | string or null | pre, post | `Principal.role` |
| `principal.ticket_ref` | string or null | pre, post | `Principal.ticket_ref` |
| `principal.claims.<key>` | any | pre, post | `Principal.claims[key]` |
| `output.text` | string | **post only** | Stringified tool response |

**Missing fields:** If a selector references a field that does not exist (missing key, null value, no principal), the leaf evaluates to `false`. The rule does not fire. This is not an error.

**Nested args:** Dotted paths like `args.config.timeout` resolve through nested dicts: `envelope.args["config"]["timeout"]`. If any intermediate key is missing or the value is not a dict, the leaf evaluates to `false`.

---

## Operators {#operators}

Fifteen operators are available, grouped into five categories. Each leaf uses exactly one operator.

For detailed examples of every operator, see the [Operator Reference](operators.md).

| Category | Operator | Value Type | Semantics |
|---|---|---|---|
| Presence | `exists` | boolean | `true`: field is present and not null. `false`: field is absent or null. |
| Equality | `equals` | scalar | Strict equality (`==`). |
| Equality | `not_equals` | scalar | Strict inequality (`!=`). |
| Membership | `in` | array | Selector value appears in the array. |
| Membership | `not_in` | array | Selector value does not appear in the array. |
| String | `contains` | string | Substring match (`value in field`). |
| String | `contains_any` | array of strings | Any element is a substring of the field. |
| String | `starts_with` | string | Field starts with the value. |
| String | `ends_with` | string | Field ends with the value. |
| String | `matches` | string (regex) | Python `re.search(pattern, field)` is truthy. |
| String | `matches_any` | array of strings | Any regex pattern matches. |
| Numeric | `gt` | number | Greater than. |
| Numeric | `gte` | number | Greater than or equal. |
| Numeric | `lt` | number | Less than. |
| Numeric | `lte` | number | Less than or equal. |

**Regex notes:** Patterns use Python's `re` module with `re.search()` (not `re.match()`), so patterns can match anywhere in the string. Patterns are compiled once at policy load time. Invalid regex causes a validation error at load.

**YAML regex tip:** Always use single-quoted strings for regex patterns. In YAML, `'\b'` is a literal backslash-b (word boundary). Double-quoted `"\b"` is a backspace character.

---

## Action Block {#action-block}

The `then` block defines what happens when a contract's condition matches.

```yaml
then:
  effect: deny          # required: deny or warn
  message: "..."        # required: human-readable message, max 500 chars
  tags: [a, b]          # optional: classification tags
  metadata:             # optional: arbitrary key-value pairs
    severity: high
    runbook: "https://..."
```

| Field | Type | Required | Description |
|---|---|---|---|
| `effect` | string | yes | `deny` (block execution) or `warn` (log only). Constrained by contract type. |
| `message` | string | yes | Human-readable message sent to the agent and recorded in audit. 1-500 characters. |
| `tags` | array of strings | no | Classification labels. Appear in audit events and can be filtered downstream. |
| `metadata` | object | no | Arbitrary key-value data stamped into the `Verdict` and audit event. |

### Effect Constraints

The allowed effect depends on the contract type:

| Contract Type | Allowed Effect | Rationale |
|---|---|---|
| `pre` | `deny` only | Preconditions exist to block dangerous calls. |
| `post` | `warn` only | The tool already ran; blocking is not possible. |
| `session` | `deny` only | Session limits gate further execution. |

Using the wrong effect for a contract type is a validation error at load time.

### Message Templating

Messages support `{placeholder}` expansion from the envelope context:

```yaml
message: "Blocked read of '{args.path}' by user {principal.user_id}."
```

Available placeholders follow the same selector paths as the expression grammar: `{args.path}`, `{tool.name}`, `{environment}`, `{principal.user_id}`, `{principal.role}`, and so on.

If a placeholder references a missing field, it is kept as-is in the output (no crash, no empty string). Each placeholder expansion is capped at 200 characters.

---

## Error Handling {#error-handling}

Error behavior is hardcoded and not configurable. CallGuard follows a fail-closed design: when in doubt, the contract fires.

| Scenario | Behavior |
|---|---|
| YAML parse error | `from_yaml()` raises `CallGuardConfigError`. |
| Invalid regex in `matches` / `matches_any` | Validation error at load time. |
| Duplicate contract `id` within a bundle | Validation error at load time. |
| YAML rule evaluation throws | Rule yields `deny` (pre/session) or `warn` (post) with `policy_error: true`. Other rules continue evaluating. |
| Python hook or precondition throws | Hook/contract yields `deny` with `policy_error: true`. Evaluation stops (first denial wins). |
| Python postcondition throws | Contract yields `warn` with `policy_error: true`. Other postconditions continue. |
| Selector references a missing field | Leaf evaluates to `false`. Not an error. |
| Type mismatch (e.g., `gt` applied to a string) | Rule yields `deny` or `warn` with `policy_error: true`. |
| Wrong `effect` for contract type | Validation error at load time. |
| `output.text` used in a precondition | Validation error at load time. |

---

## Audit Integration {#audit-integration}

YAML contracts integrate with the audit system automatically. Every contract evaluation stamps the following fields on `AuditEvent`:

| Audit Field | Source |
|---|---|
| `policy_version` | SHA256 hash of the raw YAML bytes. |
| `decision_name` | The contract's `id` field. |
| `decision_source` | `yaml_precondition`, `yaml_postcondition`, or `yaml_session`. |
| `contracts_evaluated[].tags` | From `then.tags` on each contract. |
| `policy_error` | `true` if rule evaluation threw an error. |

OpenTelemetry span attributes (when OTel SDK is installed):

- `callguard.policy_version` -- the bundle hash.
- `callguard.policy_error` -- set to `true` if any rule had an evaluation error.

This means you can trace any audit record or OTel span back to the exact YAML file that produced it, and to the specific contract `id` that fired.

---

## Complete Example {#complete-example}

The following bundle demonstrates all three contract types working together for a DevOps agent:

```yaml
apiVersion: callguard/v1
kind: ContractBundle

metadata:
  name: devops-agent
  description: "Governance for CI/CD and infrastructure agents."

defaults:
  mode: enforce

contracts:
  # --- File safety ---
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "kubeconfig", "credentials", ".pem", "id_rsa"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' blocked. Skip and continue."
      tags: [secrets, dlp]

  # --- Bash safety ---
  - id: block-destructive-bash
    type: pre
    tool: bash
    when:
      any:
        - args.command: { matches: '\brm\s+(-rf?|--recursive)\b' }
        - args.command: { matches: '\bmkfs\b' }
        - args.command: { matches: '\bdd\s+' }
        - args.command: { contains: '> /dev/' }
    then:
      effect: deny
      message: "Destructive command blocked: '{args.command}'. Use a safer alternative."
      tags: [destructive, safety]

  # --- Production gate: role-based ---
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
      tags: [change-control, production]

  # --- Production gate: ticket required ---
  - id: prod-requires-ticket
    type: pre
    tool: deploy_service
    when:
      all:
        - environment: { equals: production }
        - principal.ticket_ref: { exists: false }
    then:
      effect: deny
      message: "Production changes require a ticket reference."
      tags: [change-control, compliance]

  # --- Post-execution: PII detection ---
  - id: pii-in-output
    type: post
    tool: "*"
    when:
      output.text:
        matches_any:
          - '\b\d{3}-\d{2}-\d{4}\b'
          - '\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b'
    then:
      effect: warn
      message: "PII pattern detected in output. Redact before using."
      tags: [pii, compliance]

  # --- Observe mode: shadow-test a new rule ---
  - id: experimental-api-rate-check
    type: pre
    mode: observe
    tool: call_api
    when:
      args.endpoint: { contains: "/v1/expensive" }
    then:
      effect: deny
      message: "Expensive API call detected (shadow mode)."
      tags: [cost, experimental]

  # --- Session limits ---
  - id: session-limits
    type: session
    limits:
      max_tool_calls: 50
      max_attempts: 120
      max_calls_per_tool:
        deploy_service: 3
        send_notification: 10
    then:
      effect: deny
      message: "Session limit reached. Summarize progress and stop."
      tags: [rate-limit]
```

This bundle enforces six distinct governance concerns:

1. **Secret file protection** -- blocks reads of `.env`, credentials, and key files.
2. **Destructive command prevention** -- blocks `rm -rf`, `mkfs`, `dd`, and writes to `/dev/`.
3. **Role-based production gate** -- only senior engineers, SREs, and admins can deploy to production.
4. **Ticket-required production gate** -- production deploys must have a ticket reference.
5. **PII detection** -- warns when tool output contains SSN or IBAN patterns.
6. **Shadow-mode experimentation** -- logs expensive API calls without blocking, for cost analysis.
7. **Session limits** -- caps total calls at 50, attempts at 120, and per-tool limits on deploy and notification tools.
