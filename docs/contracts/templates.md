# Built-in Templates

Edictum ships three built-in contract templates for common agent patterns. Templates are complete, production-ready YAML bundles that you can load directly or use as a starting point for your own contracts.

---

## Loading a Template

Use `Edictum.from_template()` to load a built-in template by name:

```python
from edictum import Edictum

guard = Edictum.from_template("file-agent")
```

This is equivalent to calling `Edictum.from_yaml()` on the template's YAML file, which means it goes through the same validation, compilation, and contract bundle hashing path as any custom bundle.

All `from_yaml()` options are available on `from_template()`:

```python
from edictum import Edictum
from edictum.audit import FileAuditSink, RedactionPolicy

guard = Edictum.from_template(
    "devops-agent",
    environment="staging",
    mode="observe",                                # shadow-test before enforcing
    audit_sink=FileAuditSink("audit.jsonl"),
    redaction=RedactionPolicy(sensitive_keys={"database_url"}),
)
```

Available template names:

| Template | Target Use Case |
|---|---|
| `file-agent` | Agents that read/write files and run shell commands |
| `research-agent` | Agents that call APIs, search the web, and produce reports |
| `devops-agent` | Agents that manage infrastructure, deploy services, and handle CI/CD |

---

## `file-agent`

The file-agent template protects against the two most common file-handling risks: reading secrets and running destructive shell commands. It also enforces a write scope that prevents agents from writing to arbitrary absolute paths.

### Rules

| Contract ID | Type | Tool | Description |
|---|---|---|---|
| `block-sensitive-reads` | pre | `read_file` | Blocks reads of files containing `.env`, `.secret`, `kubeconfig`, `credentials`, `.pem`, or `id_rsa` in the path. |
| `block-destructive-bash` | pre | `bash` | Blocks `rm -rf` / `rm --recursive`, `mkfs` (filesystem format), and writes to `/dev/`. |
| `block-write-outside-target` | pre | `write_file` | Blocks writes to absolute paths (starting with `/`). Forces agents to use relative paths within a controlled working directory. |

### Full YAML

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: file-agent
  description: "Contracts for file-handling agents. Blocks sensitive reads and destructive bash."

defaults:
  mode: enforce

contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "kubeconfig", "credentials", ".pem", "id_rsa"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' blocked."
      tags: [secrets, dlp]

  - id: block-destructive-bash
    type: pre
    tool: bash
    when:
      any:
        - args.command: { matches: '\\brm\\s+(-rf?|--recursive)\\b' }
        - args.command: { matches: '\\bmkfs\\b' }
        - args.command: { contains: '> /dev/' }
    then:
      effect: deny
      message: "Destructive command blocked: '{args.command}'."
      tags: [destructive, safety]

  - id: block-write-outside-target
    type: pre
    tool: write_file
    when:
      args.path:
        starts_with: /
    then:
      effect: deny
      message: "Write to absolute path '{args.path}' blocked. Use relative paths."
      tags: [write-scope]
```

### Rule Details

**block-sensitive-reads** -- This precondition targets the `read_file` tool and checks whether `args.path` contains any of six sensitive file patterns. The `contains_any` operator is a substring match, so `args.path: "/home/user/.env.local"` would match on `.env`. This catches common secret files: environment configs (`.env`), credential stores, Kubernetes configs, SSH keys, and TLS certificates.

**block-destructive-bash** -- This precondition targets the `bash` tool and uses an `any` combinator to match three categories of destructive commands. The `matches` operator uses regex word boundaries (`\b`) to avoid false positives -- `rm -rf` is blocked but `perform` is not. The `contains` check for `> /dev/` catches attempts to write to device files.

**block-write-outside-target** -- This precondition targets `write_file` and uses `starts_with: /` to block any absolute path. The intent is to force agents to operate within a relative working directory, preventing writes to system paths like `/etc/` or `/usr/`. If your agent needs to write to specific absolute paths, replace this rule with a more targeted allowlist.

---

## `research-agent`

The research-agent template is designed for agents that gather information from APIs, databases, and the web. It provides secret file protection, PII detection in output, and session-level rate limiting to prevent runaway agents.

### Rules

| Contract ID | Type | Tool | Description |
|---|---|---|---|
| `block-sensitive-reads` | pre | `read_file` | Blocks reads of `.env`, `.secret`, and `credentials` files. |
| `pii-in-output` | post | `*` (all tools) | Warns when tool output contains US Social Security Number patterns. |
| `session-limits` | session | -- | Caps the session at 50 tool executions and 100 total attempts. |

### Full YAML

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: research-agent
  description: "Contracts for research agents. Rate limits and output caps."

defaults:
  mode: enforce

contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "credentials"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' blocked."
      tags: [secrets]

  - id: pii-in-output
    type: post
    tool: "*"
    when:
      output.text:
        matches_any:
          - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      effect: warn
      message: "PII pattern detected in output. Redact before using."
      tags: [pii, compliance]

  - id: session-limits
    type: session
    limits:
      max_tool_calls: 50
      max_attempts: 100
    then:
      effect: deny
      message: "Session limit reached. Summarize progress and stop."
      tags: [rate-limit]
```

### Rule Details

**block-sensitive-reads** -- A targeted version of the file-agent's secret protection. It checks for three common patterns (`.env`, `.secret`, `credentials`) rather than the full six-pattern set. Research agents typically don't interact with SSH keys or TLS certificates, so the pattern list is narrower.

**pii-in-output** -- This postcondition runs against all tools (wildcard `*`) and uses `matches_any` with a regex pattern for US Social Security Numbers (`\d{3}-\d{2}-\d{4}`). Because this is a postcondition, it cannot block the tool call -- it emits a warning so the agent (or a human reviewer) knows to redact the output before using it downstream. To detect additional PII patterns like IBAN numbers or credit card numbers, add more regex patterns to the `matches_any` array.

**session-limits** -- The session contract sets two counters. `max_tool_calls: 50` caps successful executions, preventing an agent from doing unbounded work. `max_attempts: 100` caps total contract evaluations, including denied calls. The attempt limit is set higher than the tool call limit because some denied calls are expected (the agent may probe a few blocked paths before finding an allowed one). If attempts hit the ceiling, the agent is likely stuck in a denial loop.

---

## `devops-agent`

The devops-agent template is the most comprehensive built-in contract bundle. It combines secret protection, destructive command blocking, role-based access control for production deploys, ticket-required change management, PII detection, and session limits.

### Rules

| Contract ID | Type | Tool | Description |
|---|---|---|---|
| `block-sensitive-reads` | pre | `read_file` | Blocks reads of six sensitive file patterns. |
| `block-destructive-bash` | pre | `bash` | Blocks `rm -rf`, `mkfs`, and writes to `/dev/`. |
| `prod-deploy-requires-senior` | pre | `deploy_service` | Production deploys require `senior_engineer`, `sre`, or `admin` role. |
| `prod-requires-ticket` | pre | `deploy_service` | Production deploys require a `ticket_ref` on the principal. |
| `pii-in-output` | post | `*` (all tools) | Warns on SSN patterns in output. |
| `session-limits` | session | -- | Caps at 20 tool calls, 50 attempts. |

### Full YAML

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: devops-agent
  description: "Contracts for DevOps agents. Prod gates, ticket requirements, PII detection."

defaults:
  mode: enforce

contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "kubeconfig", "credentials", ".pem", "id_rsa"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' blocked."
      tags: [secrets, dlp]

  - id: block-destructive-bash
    type: pre
    tool: bash
    when:
      any:
        - args.command: { matches: '\\brm\\s+(-rf?|--recursive)\\b' }
        - args.command: { matches: '\\bmkfs\\b' }
        - args.command: { contains: '> /dev/' }
    then:
      effect: deny
      message: "Destructive command blocked: '{args.command}'."
      tags: [destructive, safety]

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

  - id: pii-in-output
    type: post
    tool: "*"
    when:
      output.text:
        matches_any:
          - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      effect: warn
      message: "PII pattern detected in output. Redact before using."
      tags: [pii, compliance]

  - id: session-limits
    type: session
    limits:
      max_tool_calls: 20
      max_attempts: 50
    then:
      effect: deny
      message: "Session limit reached. Summarize progress and stop."
      tags: [rate-limit]
```

### Rule Details

**block-sensitive-reads** -- Identical to the file-agent version. Catches the full six-pattern set of sensitive files.

**block-destructive-bash** -- Identical to the file-agent version. Uses regex word boundaries to precisely match destructive commands without false positives.

**prod-deploy-requires-senior** -- This precondition uses an `all` combinator with two conditions: the environment must be `production` AND the principal's role must not be in the `[senior_engineer, sre, admin]` list. Both conditions must be true for the deny to fire. This means the rule only blocks production deploys by non-senior roles -- staging and development deploys by any role are unaffected. If no principal is attached to the call, `principal.role` evaluates as missing, which means the `not_in` check evaluates to `false`, and the `all` block short-circuits to `false` -- the rule does not fire. To catch missing principals, pair this with a separate `principal.role: { exists: false }` check.

**prod-requires-ticket** -- This precondition also uses `all` to combine two conditions: production environment and missing ticket reference. The `exists: false` operator checks whether `principal.ticket_ref` is absent or null. This enforces change management: every production deploy must be traceable to a ticket. Non-production environments are unaffected.

**pii-in-output** -- Same as the research-agent version. Detects US SSN patterns in tool output and emits a warning.

**session-limits** -- Tighter limits than the research-agent template (20 tool calls, 50 attempts). DevOps agents typically perform fewer but higher-impact operations, so lower caps are appropriate. The limit message instructs the agent to summarize progress and stop, which gives operators a chance to review what happened before allowing more work.

---

## Customizing Templates

Templates are a starting point. To customize a template:

1. Load the template and inspect the YAML source in `src/edictum/yaml_engine/templates/`.
2. Copy the template to your project and modify it.
3. Load your modified version with `Edictum.from_yaml()`:

```python
from edictum import Edictum

# Load your customized version
guard = Edictum.from_yaml("contracts/my-devops-policy.yaml")
```

Common customizations:

- **Add PII patterns.** Extend `pii-in-output` with IBAN, credit card, or country-specific ID number regex patterns in the `matches_any` array.
- **Adjust session limits.** Increase or decrease `max_tool_calls` and `max_attempts` based on your agent's expected workload.
- **Add per-tool limits.** Add `max_calls_per_tool` to the session contract to cap specific high-impact tools like `deploy_service` or `send_notification`.
- **Add observe-mode rules.** Add new preconditions with `mode: observe` to shadow-test rules before enforcing them. Observed denials are logged as `CALL_WOULD_DENY` audit events without denying the tool call.
- **Target additional tools.** Add preconditions for tools specific to your stack (e.g., `run_migration`, `delete_pod`, `send_email`).
- **Expand sensitive file patterns.** Add entries to `contains_any` arrays to cover patterns specific to your infrastructure (e.g., `terraform.tfvars`, `.npmrc`, `.pypirc`).
