# Compliance and Audit Patterns

Compliance patterns address regulatory and organizational requirements: classifying contracts with tags, tracking contract bundle versions, rolling out new contracts safely with observe mode, and filtering audit events downstream.

---

## Regulatory Tags

Use the `tags` field on contract actions to classify rules by regulatory or organizational concern. Tags appear in every audit event and can be filtered, aggregated, and reported on downstream.

**When to use:** You need to demonstrate compliance with specific regulations or internal policies, and your audit system needs to categorize events by concern.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: tagged-compliance

    defaults:
      mode: enforce

    contracts:
      - id: pii-output-scan
        type: post
        tool: "*"
        when:
          output.text:
            matches_any:
              - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
              - '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'
        then:
          effect: warn
          message: "PII detected in output. Redact before downstream use."
          tags: [pii, compliance, data-protection]

      - id: sensitive-data-access
        type: pre
        tool: query_database
        when:
          args.table:
            in: [user_profiles, payment_records, access_logs]
        then:
          effect: deny
          message: "Access to '{args.table}' requires explicit authorization."
          tags: [compliance, sensitive-data, audit-required]
          metadata:
            severity: high
            regulation: internal-policy
    ```

=== "Python"

    ```python
    import re
    from edictum import Verdict, precondition
    from edictum.contracts import postcondition

    @postcondition("*")
    def pii_output_scan(envelope, tool_response):
        if not isinstance(tool_response, str):
            return Verdict.pass_()
        patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        ]
        for pat in patterns:
            if re.search(pat, tool_response):
                return Verdict.fail(
                    "PII detected in output. Redact before downstream use.",
                    tags=["pii", "compliance", "data-protection"],
                )
        return Verdict.pass_()

    @precondition("query_database")
    def sensitive_data_access(envelope):
        table = envelope.args.get("table", "")
        if table in ("user_profiles", "payment_records", "access_logs"):
            return Verdict.fail(
                f"Access to '{table}' requires explicit authorization.",
                tags=["compliance", "sensitive-data", "audit-required"],
            )
        return Verdict.pass_()
    ```

**How tags work:**
- Tags are arrays of strings attached to the `then` block. They are stamped into the `Verdict` and every `AuditEvent` produced by the contract.
- Tags are free-form. Use a consistent naming convention across your bundles (e.g., `pii`, `compliance`, `dlp`, `change-control`).
- Downstream systems can filter audit events by tag. For example, a compliance dashboard could show all events tagged `pii` or `compliance`.

**Gotchas:**
- Tags do not affect contract evaluation. They are metadata only. A contract tagged `[compliance]` behaves identically to one with no tags.
- There is no validation of tag values. Typos in tags (e.g., `complianc` instead of `compliance`) will not produce errors but will silently break downstream filtering.

---

## Contract Bundle Versioning

Every YAML bundle gets a SHA256 hash computed at load time. This hash is stamped as `policy_version` on every `AuditEvent` and OpenTelemetry span, creating an immutable link between any audit record and the exact contract bundle that produced it.

**When to use:** You need to prove which version of a contract bundle was active when an event occurred. This is essential for audits, incident investigations, and regulatory compliance.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: versioned-policy
      description: "Production policy v2.3 -- approved 2025-01-15."

    defaults:
      mode: enforce

    contracts:
      - id: block-sensitive-reads
        type: pre
        tool: read_file
        when:
          args.path:
            contains_any: [".env", "credentials", ".pem"]
        then:
          effect: deny
          message: "Sensitive file blocked."
          tags: [secrets, dlp]
          metadata:
            severity: high
    ```

=== "Python"

    ```python
    from edictum import Edictum

    # Load a versioned YAML bundle — the SHA256 hash is computed
    # automatically and stamped on every audit event.
    guard = Edictum.from_yaml("policy.yaml")

    # The policy_version attribute contains the hash
    # print(guard.policy_version)  # "a1b2c3d4..."
    ```

**How versioning works:**
1. `Edictum.from_yaml("policy.yaml")` reads the raw YAML bytes.
2. A SHA256 hash is computed from the bytes.
3. Every audit event produced by this bundle includes `policy_version: <hash>`.
4. If the YAML file changes by even one byte, the hash changes, creating a new version.

**Gotchas:**
- The hash is computed from the raw file bytes, not the parsed structure. Whitespace changes, comment additions, and reordering produce different hashes.
- Store your YAML files in version control. The hash tells you which version was active; the VCS history tells you what changed and who changed it.
- The `metadata.description` field is a good place to record human-readable version information, but it is not used in the hash computation -- the hash covers the entire file.

---

## Dual-Mode Deployment

Roll out new rules safely by starting in `observe` mode and switching to `enforce` after verifying the rule behaves as expected. Observed denials are logged as `CALL_WOULD_DENY` audit events without blocking the agent.

**When to use:** You are adding a new contract to an existing production bundle and want to validate it against real traffic before enforcing it.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: dual-mode-rollout

    defaults:
      mode: enforce

    contracts:
      # Existing enforced rule
      - id: block-sensitive-reads
        type: pre
        tool: read_file
        when:
          args.path:
            contains_any: [".env", "credentials", ".pem"]
        then:
          effect: deny
          message: "Sensitive file blocked."
          tags: [secrets, dlp]

      # New rule in observe mode -- shadow testing
      - id: experimental-cost-gate
        type: pre
        mode: observe
        tool: query_database
        when:
          args.query: { matches: '\\bJOIN\\b.*\\bJOIN\\b.*\\bJOIN\\b' }
        then:
          effect: deny
          message: "Query with 3+ JOINs detected (observe mode). Consider optimizing."
          tags: [cost, experimental]
    ```

=== "Python"

    ```python
    from edictum import Edictum, Verdict, precondition
    from edictum.audit import FileAuditSink

    @precondition("read_file")
    def block_sensitive_reads(envelope):
        path = envelope.args.get("path", "")
        for s in (".env", "credentials", ".pem"):
            if s in path:
                return Verdict.fail("Sensitive file blocked.")
        return Verdict.pass_()

    # Enforced guard (blocks tool calls)
    enforced_guard = Edictum(contracts=[block_sensitive_reads])

    # Observe guard (logs but never blocks)
    observe_guard = Edictum(
        mode="observe",
        contracts=[block_sensitive_reads],
        audit_sink=FileAuditSink("audit.jsonl"),
    )
    ```

**How dual-mode works:**
1. Set `defaults.mode: enforce` for the bundle.
2. On the new contract, add `mode: observe` to override the bundle default.
3. When the observe-mode contract matches, it emits a `CALL_WOULD_DENY` audit event. The tool call proceeds normally.
4. Review `CALL_WOULD_DENY` events in your audit logs. If the rule fires correctly with no false positives, change the contract to `mode: enforce` (or remove the override to inherit the bundle default).

**Gotchas:**
- Observe mode applies to preconditions and session contracts. Postconditions always warn regardless of mode, so observe mode has no visible effect on them.
- A `CALL_WOULD_DENY` event contains the same information as a real deny event (contract ID, message, tags, metadata). The only difference is the event type.
- Do not leave rules in observe mode indefinitely. Unreviewed observe-mode rules accumulate audit noise without providing protection.

---

## Tag-Based Filtering Downstream

Tags enable downstream systems to filter, route, and aggregate audit events by concern. This pattern shows how to design tags for common compliance workflows.

**Recommended tag taxonomy:**

| Tag | Use Case |
|---|---|
| `pii` | Events involving personally identifiable information |
| `secrets` | Events involving credentials, tokens, or keys |
| `dlp` | Data loss prevention events |
| `compliance` | Events relevant to regulatory compliance |
| `change-control` | Events related to production changes |
| `rate-limit` | Session limit events |
| `cost` | Events related to resource cost |
| `experimental` | Shadow-mode / observe-mode rules |

**Example: filtering audit events in Python:**

```python
from edictum.audit import FileAuditSink

sink = FileAuditSink("audit.jsonl")

# After loading audit events, filter by tag:
# events = [e for e in all_events if "pii" in e.tags]
```

**Gotchas:**
- Tags are arrays, so a single event can have multiple tags. An event tagged `[pii, compliance]` appears in both filters.
- Define your tag taxonomy before writing contracts. Inconsistent tagging across bundles makes downstream filtering unreliable.
