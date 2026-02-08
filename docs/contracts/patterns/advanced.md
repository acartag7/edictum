# Advanced Patterns

This page covers patterns that combine multiple Edictum features: nested boolean logic, regex composition, principal claims, template composition, wildcards, dynamic messages, comprehensive governance bundles, and per-contract mode overrides.

---

## Nested All/Any/Not Logic

Boolean combinators (`all`, `any`, `not`) nest arbitrarily. Use them to build complex access rules from simple leaves.

**When to use:** Your access policy cannot be expressed as a single condition. You need AND, OR, and NOT logic combined.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: nested-logic

    defaults:
      mode: enforce

    contracts:
      - id: complex-deploy-gate
        type: pre
        tool: deploy_service
        when:
          all:
            - environment: { equals: production }
            - any:
                - principal.role: { not_in: [admin, sre] }
                - not:
                    principal.ticket_ref: { exists: true }
        then:
          effect: deny
          message: "Production deploy denied. Requires (admin or sre role) AND a ticket reference."
          tags: [access-control, production]
    ```

=== "Python"

    ```python
    from edictum import Verdict, precondition

    @precondition("deploy_service")
    def complex_deploy_gate(envelope):
        if envelope.environment != "production":
            return Verdict.pass_()
        # Requires (admin or sre role) AND a ticket reference
        role_ok = envelope.principal and envelope.principal.role in ("admin", "sre")
        has_ticket = envelope.principal and envelope.principal.ticket_ref
        if not role_ok or not has_ticket:
            return Verdict.fail(
                "Production deploy denied. Requires (admin or sre role) "
                "AND a ticket reference."
            )
        return Verdict.pass_()
    ```

**How to read this:** The deploy is denied when the environment is production AND (the role is not admin/sre OR there is no ticket reference). In other words, production deploys require both a privileged role and a ticket.

**Gotchas:**
- Deeply nested trees become hard to read. If your `when` block exceeds three levels of nesting, consider splitting into multiple contracts with simpler conditions.
- `not` takes a single child expression, not an array. `not: [expr1, expr2]` is a validation error.
- Boolean combinators require at least one child in `all` and `any` arrays. An empty array is a validation error.

---

## Regex with matches_any

Combine multiple regex patterns in a single postcondition to detect several categories of sensitive data at once.

**When to use:** You want one contract to catch multiple data patterns (PII, secrets, regulated content) rather than maintaining separate contracts for each.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: regex-composition

    defaults:
      mode: enforce

    contracts:
      - id: comprehensive-data-scan
        type: post
        tool: "*"
        when:
          output.text:
            matches_any:
              - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
              - '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'
              - '\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b'
              - '\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b'
              - 'AKIA[0-9A-Z]{16}'
              - 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'
        then:
          effect: warn
          message: "Sensitive data pattern detected in output. Redact before using."
          tags: [pii, secrets, compliance]
    ```

=== "Python"

    ```python
    import re
    from edictum import Verdict
    from edictum.contracts import postcondition

    @postcondition("*")
    def comprehensive_data_scan(envelope, tool_response):
        if not isinstance(tool_response, str):
            return Verdict.pass_()
        patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",                    # SSN
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # Credit card
            r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",             # Phone
            r"AKIA[0-9A-Z]{16}",                           # AWS key
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",  # JWT
        ]
        for pat in patterns:
            if re.search(pat, tool_response):
                return Verdict.fail(
                    "Sensitive data pattern detected in output. Redact before using."
                )
        return Verdict.pass_()
    ```

**Gotchas:**
- `matches_any` short-circuits on the first matching pattern. Order patterns from most likely to least likely for performance.
- All patterns are compiled at policy load time. Invalid regex in any element causes a validation error for the entire bundle.
- Use single-quoted strings in YAML for regex. Double-quoted strings interpret backslash sequences (`\b` becomes backspace, `\d` is literal `d`).

---

## Principal Claims as Dicts

The `principal.claims.<key>` selector accesses custom attributes from the `Principal.claims` dictionary. Claims support any value type: strings, numbers, booleans, and lists.

**When to use:** Your authorization model needs attributes beyond role, user_id, and org_id. Claims let you attach domain-specific metadata like department, clearance level, or feature flags.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: claims-patterns

    defaults:
      mode: enforce

    contracts:
      - id: require-clearance
        type: pre
        tool: read_file
        when:
          all:
            - args.path: { contains: "classified" }
            - principal.claims.clearance: { not_in: [secret, top-secret] }
        then:
          effect: deny
          message: "Classified file access requires secret or top-secret clearance."
          tags: [access-control, classified]

      - id: feature-flag-gate
        type: pre
        tool: send_email
        when:
          not:
            principal.claims.feature_flags_email: { equals: true }
        then:
          effect: deny
          message: "Email feature is not enabled for this principal."
          tags: [feature-flags]
    ```

=== "Python"

    ```python
    from edictum import Verdict, precondition

    @precondition("read_file")
    def require_clearance(envelope):
        path = envelope.args.get("path", "")
        if "classified" not in path:
            return Verdict.pass_()
        clearance = (
            envelope.principal.claims.get("clearance")
            if envelope.principal else None
        )
        if clearance not in ("secret", "top-secret"):
            return Verdict.fail(
                "Classified file access requires secret or top-secret clearance."
            )
        return Verdict.pass_()

    @precondition("send_email")
    def feature_flag_gate(envelope):
        enabled = (
            envelope.principal.claims.get("feature_flags_email")
            if envelope.principal else False
        )
        if not enabled:
            return Verdict.fail("Email feature is not enabled for this principal.")
        return Verdict.pass_()
    ```

**Setting claims in Python:**

```python
from edictum import Principal

principal = Principal(
    user_id="user-123",
    role="analyst",
    claims={
        "clearance": "secret",
        "department": "engineering",
        "feature_flags_email": True,
    },
)
```

**Gotchas:**
- Claims are set by your application. Edictum does not validate claim values against any external source.
- If a claim key does not exist, the leaf evaluates to `false`. Use `principal.claims.<key>: { exists: false }` to explicitly require a claim.
- Nested claims (e.g., `principal.claims.org.team`) are not supported. Claims are a flat dictionary.

---

## Template Composition

Edictum ships built-in templates that you can load directly. Templates are complete YAML bundles that go through the same validation and hashing path as custom bundles.

**When to use:** You want a ready-made policy for common agent patterns without writing YAML from scratch.

```python
from edictum import Edictum

# Load a built-in template
guard = Edictum.from_template("file-agent")

# Load with overrides
guard = Edictum.from_template(
    "devops-agent",
    environment="staging",
    mode="observe",
)
```

Available templates:

| Template | Description |
|---|---|
| `file-agent` | Blocks sensitive file reads and destructive bash commands |
| `research-agent` | Rate limits, PII detection, and sensitive file protection |
| `devops-agent` | Production gates, ticket requirements, PII detection, session limits |

To customize a template, copy its YAML source from `src/edictum/yaml_engine/templates/` into your project and modify it. Load the customized version with `Edictum.from_yaml()`.

---

## Wildcards

Use `tool: "*"` to target all tools with a single contract. This is useful for cross-cutting concerns that apply regardless of which tool the agent calls.

**When to use:** Security scanning (PII, secrets), session limits, or any rule that should apply to every tool.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: wildcard-patterns

    defaults:
      mode: enforce

    contracts:
      - id: global-pii-scan
        type: post
        tool: "*"
        when:
          output.text:
            matches_any:
              - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
        then:
          effect: warn
          message: "PII detected in {tool.name} output. Redact before using."
          tags: [pii]

      - id: block-all-in-maintenance
        type: pre
        tool: "*"
        when:
          environment: { equals: maintenance }
        then:
          effect: deny
          message: "System is in maintenance mode. All tool calls are blocked."
          tags: [maintenance]
    ```

=== "Python"

    ```python
    import re
    from edictum import Verdict, precondition
    from edictum.contracts import postcondition

    @postcondition("*")
    def global_pii_scan(envelope, tool_response):
        if not isinstance(tool_response, str):
            return Verdict.pass_()
        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", tool_response):
            return Verdict.fail(
                f"PII detected in {envelope.tool_name} output. Redact before using."
            )
        return Verdict.pass_()

    @precondition("*")
    def block_all_in_maintenance(envelope):
        if envelope.environment == "maintenance":
            return Verdict.fail("System is in maintenance mode. All tool calls are blocked.")
        return Verdict.pass_()
    ```

**Gotchas:**
- Wildcard contracts run on every tool call. In a bundle with many wildcard contracts, each tool call triggers all of them. Keep wildcard contracts lightweight.
- If you need a wildcard contract to exclude specific tools, there is no built-in exclusion syntax. Use a `not` combinator with `tool.name: { in: [...] }` to skip certain tools.

---

## Dynamic Message Interpolation

Messages support `{placeholder}` expansion using the same selector paths as the expression grammar. This makes denial messages specific and actionable.

**When to use:** Always. Generic messages like "Access denied" give the agent no guidance on how to self-correct. Specific messages with interpolated values help the agent understand what went wrong and what to do instead.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: dynamic-messages

    defaults:
      mode: enforce

    contracts:
      - id: detailed-deny-message
        type: pre
        tool: read_file
        when:
          args.path:
            contains_any: [".env", "credentials", ".pem"]
        then:
          effect: deny
          message: "Cannot read '{args.path}' (user: {principal.user_id}, role: {principal.role}). Skip this file."
          tags: [secrets]

      - id: environment-in-message
        type: pre
        tool: deploy_service
        when:
          all:
            - environment: { equals: production }
            - principal.role: { not_in: [admin, sre] }
        then:
          effect: deny
          message: "Deploy to {environment} denied for role '{principal.role}'. Requires admin or sre."
          tags: [access-control]
    ```

=== "Python"

    ```python
    from edictum import Verdict, precondition

    @precondition("read_file")
    def detailed_deny(envelope):
        path = envelope.args.get("path", "")
        for s in (".env", "credentials", ".pem"):
            if s in path:
                user = envelope.principal.user_id if envelope.principal else "unknown"
                role = envelope.principal.role if envelope.principal else "none"
                return Verdict.fail(
                    f"Cannot read '{path}' (user: {user}, role: {role}). Skip this file."
                )
        return Verdict.pass_()

    @precondition("deploy_service")
    def environment_in_message(envelope):
        if envelope.environment != "production":
            return Verdict.pass_()
        if not envelope.principal or envelope.principal.role not in ("admin", "sre"):
            role = envelope.principal.role if envelope.principal else "none"
            return Verdict.fail(
                f"Deploy to {envelope.environment} denied for role '{role}'. "
                "Requires admin or sre."
            )
        return Verdict.pass_()
    ```

**Available placeholders:**
- `{args.<key>}` -- tool argument values
- `{tool.name}` -- the tool being called
- `{environment}` -- the current environment
- `{principal.user_id}`, `{principal.role}`, `{principal.org_id}` -- principal fields
- `{principal.claims.<key>}` -- custom claims

**Gotchas:**
- If a placeholder references a missing field, it is kept as-is in the output (e.g., `{principal.user_id}` appears literally if no principal is attached). No error is raised.
- Each placeholder expansion is capped at 200 characters. Values longer than 200 characters are truncated.
- Messages have a maximum length of 500 characters. Keep messages concise.

---

## Combining Pre + Post + Session

A comprehensive governance bundle combines all three contract types: preconditions block before execution, postconditions warn after execution, and session contracts track cumulative behavior.

**When to use:** Production agent deployments where you need defense in depth across all three dimensions.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: comprehensive-governance

    defaults:
      mode: enforce

    contracts:
      # --- Preconditions: block before execution ---
      - id: block-sensitive-reads
        type: pre
        tool: read_file
        when:
          args.path:
            contains_any: [".env", "credentials", ".pem", "id_rsa"]
        then:
          effect: deny
          message: "Sensitive file '{args.path}' blocked."
          tags: [secrets, dlp]

      - id: prod-deploy-gate
        type: pre
        tool: deploy_service
        when:
          all:
            - environment: { equals: production }
            - principal.role: { not_in: [admin, sre] }
        then:
          effect: deny
          message: "Production deploys require admin or sre role."
          tags: [access-control, production]

      # --- Postconditions: warn after execution ---
      - id: pii-in-output
        type: post
        tool: "*"
        when:
          output.text:
            matches_any:
              - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
              - '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'
        then:
          effect: warn
          message: "PII detected in output. Redact before using."
          tags: [pii, compliance]

      - id: secrets-in-output
        type: post
        tool: "*"
        when:
          output.text:
            matches_any:
              - 'AKIA[0-9A-Z]{16}'
              - 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'
        then:
          effect: warn
          message: "Credentials detected in output. Do not log or reproduce."
          tags: [secrets, dlp]

      # --- Session: track cumulative behavior ---
      - id: session-limits
        type: session
        limits:
          max_tool_calls: 50
          max_attempts: 120
          max_calls_per_tool:
            deploy_service: 3
            send_email: 10
        then:
          effect: deny
          message: "Session limit reached. Summarize progress and stop."
          tags: [rate-limit]
    ```

=== "Python"

    ```python
    from edictum import Edictum, OperationLimits, Principal, Verdict, precondition
    from edictum.contracts import postcondition
    import re

    @precondition("read_file")
    def block_sensitive_reads(envelope):
        path = envelope.args.get("path", "")
        for s in (".env", "credentials", ".pem", "id_rsa"):
            if s in path:
                return Verdict.fail(f"Sensitive file '{path}' blocked.")
        return Verdict.pass_()

    @precondition("deploy_service")
    def prod_deploy_gate(envelope):
        if envelope.environment != "production":
            return Verdict.pass_()
        if not envelope.principal or envelope.principal.role not in ("admin", "sre"):
            return Verdict.fail("Production deploys require admin or sre role.")
        return Verdict.pass_()

    @postcondition("*")
    def pii_in_output(envelope, tool_response):
        if not isinstance(tool_response, str):
            return Verdict.pass_()
        patterns = [r"\b\d{3}-\d{2}-\d{4}\b", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"]
        for pat in patterns:
            if re.search(pat, tool_response):
                return Verdict.fail("PII detected in output. Redact before using.")
        return Verdict.pass_()

    @postcondition("*")
    def secrets_in_output(envelope, tool_response):
        if not isinstance(tool_response, str):
            return Verdict.pass_()
        patterns = [r"AKIA[0-9A-Z]{16}", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"]
        for pat in patterns:
            if re.search(pat, tool_response):
                return Verdict.fail("Credentials detected in output. Do not log or reproduce.")
        return Verdict.pass_()

    guard = Edictum(
        contracts=[block_sensitive_reads, prod_deploy_gate, pii_in_output, secrets_in_output],
        limits=OperationLimits(
            max_tool_calls=50,
            max_attempts=120,
            max_calls_per_tool={"deploy_service": 3, "send_email": 10},
        ),
        principal=Principal(role="analyst"),
    )
    ```

**Gotchas:**
- Contract evaluation order within a type follows the array order in the YAML. For preconditions, the first matching deny wins and stops evaluation.
- Postconditions always run, even if the tool was already denied by a precondition. However, if a precondition denies the call, the tool does not execute, so there is no output for the postcondition to inspect.
- Session contracts are checked on every tool call attempt, even before preconditions evaluate.

---

## Per-Contract Mode Override

Individual contracts can override the bundle's default mode. This lets you mix enforced and observed rules in a single bundle.

**When to use:** You are adding a new rule to an existing production bundle and want to shadow-test it before enforcing.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: mixed-mode-bundle

    defaults:
      mode: enforce

    contracts:
      # Enforced (inherits bundle default)
      - id: block-sensitive-reads
        type: pre
        tool: read_file
        when:
          args.path:
            contains_any: [".env", "credentials"]
        then:
          effect: deny
          message: "Sensitive file blocked."
          tags: [secrets]

      # Observe mode: shadow-testing a new rule
      - id: experimental-query-limit
        type: pre
        mode: observe
        tool: query_database
        when:
          args.query: { matches: '\\bSELECT\\s+\\*\\b' }
        then:
          effect: deny
          message: "SELECT * detected (shadow mode). Use explicit column lists."
          tags: [experimental, sql-quality]
    ```

=== "Python"

    ```python
    from edictum import Edictum, Verdict, precondition

    @precondition("read_file")
    def block_sensitive_reads(envelope):
        path = envelope.args.get("path", "")
        for s in (".env", "credentials"):
            if s in path:
                return Verdict.fail("Sensitive file blocked.")
        return Verdict.pass_()

    # In Python, per-contract mode override is done by running
    # separate Edictum instances: one enforced, one in observe mode.
    enforced_guard = Edictum(contracts=[block_sensitive_reads])

    # Or use a single observe-mode instance to shadow-test:
    import re

    @precondition("query_database")
    def experimental_query_limit(envelope):
        query = envelope.args.get("query", "")
        if re.search(r"\bSELECT\s+\*\b", query):
            return Verdict.fail("SELECT * detected. Use explicit column lists.")
        return Verdict.pass_()

    observe_guard = Edictum(
        mode="observe",
        contracts=[experimental_query_limit],
    )
    ```

**Gotchas:**
- Observe mode emits `CALL_WOULD_DENY` audit events. The tool call proceeds normally. Review these events before switching to enforce.
- The mode override is per-contract. Other contracts in the same bundle continue to use the bundle default.
- Postconditions are always `warn`, so `mode: observe` has no visible effect on postconditions. Observe mode is meaningful only for preconditions and session contracts.
