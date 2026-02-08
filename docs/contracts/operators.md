# Operator Reference

Edictum's expression grammar supports 15 operators across five categories. Each leaf in a `when` expression uses exactly one operator applied to one selector.

For the full schema context, see the [YAML Contract Reference](yaml-reference.md).

---

## Quick Reference

| Operator | Category | Selector Type | Value Type | Semantics |
|---|---|---|---|---|
| `exists` | Presence | any | boolean | Field is present (true) or absent/null (false) |
| `equals` | Equality | scalar | scalar | Strict equality |
| `not_equals` | Equality | scalar | scalar | Strict inequality |
| `in` | Membership | scalar | array | Value appears in array |
| `not_in` | Membership | scalar | array | Value does not appear in array |
| `contains` | String | string | string | Substring match |
| `contains_any` | String | string | array of strings | Any element is a substring |
| `starts_with` | String | string | string | Field starts with value |
| `ends_with` | String | string | string | Field ends with value |
| `matches` | String | string | string (regex) | Regex search matches |
| `matches_any` | String | string | array of strings | Any regex matches |
| `gt` | Numeric | number | number | Greater than |
| `gte` | Numeric | number | number | Greater than or equal |
| `lt` | Numeric | number | number | Less than |
| `lte` | Numeric | number | number | Less than or equal |

---

## Presence

### `exists`

Tests whether a field is present and non-null, or absent/null.

- **Value type:** boolean (`true` or `false`)
- **Selector type:** any
- **Behavior with `true`:** passes when the field exists and is not null.
- **Behavior with `false`:** passes when the field is missing or null.

This is the only operator that works on missing fields. All other operators evaluate to `false` when the field is absent.

```yaml
# Deny if no ticket reference is attached to the principal
- id: require-ticket
  type: pre
  tool: deploy_service
  when:
    principal.ticket_ref: { exists: false }
  then:
    effect: deny
    message: "A ticket reference is required for deployments."
```

```yaml
# Deny only when the optional 'force' flag is explicitly set
- id: block-force-flag
  type: pre
  tool: delete_resource
  when:
    args.force: { exists: true }
  then:
    effect: deny
    message: "The 'force' flag is not permitted."
```

---

## Equality

### `equals`

Strict equality comparison using Python's `==` operator.

- **Value type:** any scalar (string, number, boolean)
- **Selector type:** scalar

```yaml
# Deny tool calls in the production environment
- id: block-production
  type: pre
  tool: "*"
  when:
    environment: { equals: production }
  then:
    effect: deny
    message: "Tool calls are disabled in production."
```

```yaml
# Deny when a specific tool argument matches a value
- id: block-admin-database
  type: pre
  tool: query_database
  when:
    args.database: { equals: "admin" }
  then:
    effect: deny
    message: "Direct queries to the admin database are blocked."
```

### `not_equals`

Strict inequality comparison using Python's `!=` operator.

- **Value type:** any scalar
- **Selector type:** scalar

```yaml
# Deny if the request is not targeting the staging environment
- id: staging-only
  type: pre
  tool: run_migration
  when:
    environment: { not_equals: staging }
  then:
    effect: deny
    message: "Migrations are only allowed in the staging environment."
```

---

## Membership

### `in`

Tests whether the selector's value appears in a provided list.

- **Value type:** array (at least one element)
- **Selector type:** scalar

```yaml
# Allow only specific roles to use the deploy tool
# (deny everyone NOT in the list)
- id: deploy-role-gate
  type: pre
  tool: deploy_service
  when:
    principal.role: { not_in: [sre, admin, senior_engineer] }
  then:
    effect: deny
    message: "Your role does not have deploy permissions."
```

```yaml
# Deny calls to known dangerous tools
- id: block-dangerous-tools
  type: pre
  tool: "*"
  when:
    tool.name: { in: [drop_database, truncate_table, format_disk] }
  then:
    effect: deny
    message: "Tool '{tool.name}' is permanently blocked."
```

### `not_in`

Tests whether the selector's value does NOT appear in a provided list.

- **Value type:** array (at least one element)
- **Selector type:** scalar

```yaml
# Only allow API calls to approved endpoints
- id: approved-endpoints-only
  type: pre
  tool: call_api
  when:
    args.endpoint: { not_in: ["/v1/users", "/v1/search", "/v1/health"] }
  then:
    effect: deny
    message: "Endpoint '{args.endpoint}' is not in the approved list."
```

---

## String

String operators require the selector to resolve to a string. If the resolved value is not a string, the operator triggers a `policy_error` (fail-closed).

### `contains`

Substring match. Passes when the operator value appears anywhere in the selector's string value.

- **Value type:** string
- **Selector type:** string

```yaml
# Block reads of files with ".env" in the path
- id: block-env-reads
  type: pre
  tool: read_file
  when:
    args.path: { contains: ".env" }
  then:
    effect: deny
    message: "Reading .env files is not allowed."
```

### `contains_any`

Passes when any element in the provided array is a substring of the selector's value. This is a convenience operator equivalent to an `any` block with multiple `contains` leaves.

- **Value type:** array of strings (at least one element)
- **Selector type:** string

```yaml
# Block reads of multiple sensitive file patterns in one rule
- id: block-sensitive-reads
  type: pre
  tool: read_file
  when:
    args.path:
      contains_any: [".env", ".secret", "credentials", ".pem", "id_rsa", "kubeconfig"]
  then:
    effect: deny
    message: "Sensitive file '{args.path}' is blocked."
    tags: [secrets, dlp]
```

### `starts_with`

Passes when the selector's string value starts with the operator value.

- **Value type:** string
- **Selector type:** string

```yaml
# Block writes to absolute paths (enforce relative-only writes)
- id: block-absolute-writes
  type: pre
  tool: write_file
  when:
    args.path: { starts_with: / }
  then:
    effect: deny
    message: "Write to absolute path '{args.path}' blocked. Use relative paths."
    tags: [write-scope]
```

### `ends_with`

Passes when the selector's string value ends with the operator value.

- **Value type:** string
- **Selector type:** string

```yaml
# Warn when output is written to a log file
- id: warn-log-output
  type: post
  tool: write_file
  when:
    args.path: { ends_with: ".log" }
  then:
    effect: warn
    message: "Output written to log file '{args.path}'. Verify no sensitive data is logged."
    tags: [logging]
```

### `matches`

Regular expression match using Python's `re.search()`. The pattern can match anywhere in the string (it is not anchored).

- **Value type:** string (valid Python regex)
- **Selector type:** string

Patterns are compiled once at load time. An invalid regex causes a validation error.

**YAML tip:** Always use single-quoted strings for regex patterns. In YAML, `'\b'` is a literal backslash-b (regex word boundary). Double-quoted `"\b"` is interpreted as a backspace character.

```yaml
# Block recursive delete commands
- id: block-rm-rf
  type: pre
  tool: bash
  when:
    args.command: { matches: '\brm\s+(-rf?|--recursive)\b' }
  then:
    effect: deny
    message: "Recursive delete blocked: '{args.command}'."
    tags: [destructive]
```

```yaml
# Warn on SSN patterns in tool output
- id: ssn-in-output
  type: post
  tool: "*"
  when:
    output.text: { matches: '\b\d{3}-\d{2}-\d{4}\b' }
  then:
    effect: warn
    message: "Possible SSN detected in output. Redact before using."
    tags: [pii]
```

### `matches_any`

Passes when any regex pattern in the array matches the selector's value. Equivalent to an `any` block with multiple `matches` leaves, but more concise.

- **Value type:** array of strings (valid Python regex patterns, at least one)
- **Selector type:** string

```yaml
# Detect multiple PII patterns in a single rule
- id: pii-detection
  type: post
  tool: "*"
  when:
    output.text:
      matches_any:
        - '\b\d{3}-\d{2}-\d{4}\b'                                        # US SSN
        - '\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b'  # IBAN
        - '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'                   # credit card
  then:
    effect: warn
    message: "PII pattern detected in output. Redact before using."
    tags: [pii, compliance]
```

---

## Numeric

Numeric operators require both the selector value and the operator value to be numbers (int or float). If the selector resolves to a non-numeric type, the operator triggers a `policy_error` (fail-closed).

### `gt`

Greater than.

- **Value type:** number
- **Selector type:** number

```yaml
# Deny requests with a batch size greater than 1000
- id: limit-batch-size
  type: pre
  tool: bulk_insert
  when:
    args.batch_size: { gt: 1000 }
  then:
    effect: deny
    message: "Batch size {args.batch_size} exceeds the maximum of 1000."
```

### `gte`

Greater than or equal.

- **Value type:** number
- **Selector type:** number

```yaml
# Deny requests where retry count is 5 or more
- id: limit-retries
  type: pre
  tool: call_api
  when:
    args.max_retries: { gte: 5 }
  then:
    effect: deny
    message: "Max retries of {args.max_retries} is too high. Use 4 or fewer."
```

### `lt`

Less than.

- **Value type:** number
- **Selector type:** number

```yaml
# Warn when the confidence score is below threshold
- id: low-confidence-warning
  type: post
  tool: classify_document
  when:
    args.min_confidence: { lt: 0.5 }
  then:
    effect: warn
    message: "Classification confidence threshold is below 0.5. Results may be unreliable."
```

### `lte`

Less than or equal.

- **Value type:** number
- **Selector type:** number

```yaml
# Deny requests with a timeout of 0 or negative
- id: block-zero-timeout
  type: pre
  tool: call_api
  when:
    args.timeout: { lte: 0 }
  then:
    effect: deny
    message: "Timeout must be a positive number. Got {args.timeout}."
```

---

## Type Mismatch Behavior

When an operator receives a value of the wrong type (for example, `contains` applied to an integer, or `gt` applied to a string), the evaluation triggers a `policy_error`. This means:

- The contract fires (fail-closed design).
- The audit event includes `policy_error: true`.
- For preconditions and session contracts, this results in a deny.
- For postconditions, this results in a warn.

This behavior is intentional. If Edictum cannot evaluate a rule, it assumes the worst case and fires the rule rather than silently ignoring it.

## Missing Field Behavior

When a selector references a field that does not exist:

- The `exists` operator with `false` returns `true` (the field is indeed absent).
- The `exists` operator with `true` returns `false` (the field is not present).
- All other operators return `false` (the rule does not fire).

This means a rule like `args.path: { contains: ".env" }` will not fire if the tool call has no `path` argument. No error is raised.
