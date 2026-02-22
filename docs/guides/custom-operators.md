# Custom Operators

Edictum ships with 15 built-in operators (`contains`, `matches`, `gt`, etc.). Custom operators let you extend the expression grammar with domain-specific checks — IBAN validation, CIDR matching, semver comparison — so contracts stay declarative YAML instead of falling back to Python hooks.

```python
import ipaddress

def ip_in_cidr(field_value: str, cidr: str) -> bool:
    """Check if an IP address is within a CIDR range."""
    return ipaddress.ip_address(field_value) in ipaddress.ip_network(cidr)

guard = Edictum.from_yaml(
    "contracts.yaml",
    custom_operators={"ip_in_cidr": ip_in_cidr},
)
```

```yaml
# contracts.yaml
- id: internal-only
  type: pre
  tool: ssh_connect
  when:
    args.target_ip: { ip_in_cidr: "10.0.0.0/8" }
  then:
    effect: deny
    message: "Only internal IPs allowed. Got {args.target_ip}."
```

---

## When to use this

### Financial validation

Your fintech agent processes wire transfers. You need an operator like `is_invalid_iban: true` to validate IBAN numbers in YAML contracts instead of writing a Python precondition for every bank-related tool. The contract stays declarative: `when: args.destination_account: {is_invalid_iban: true}`.

### Network security

Your infrastructure agent manages firewall rules. You need `ip_in_cidr: "10.0.0.0/8"` to check if a target IP is in an allowed range. Without custom operators, you'd need a Python hook for what should be a one-line YAML condition.

### Healthcare compliance

Your patient-facing agent accesses medical records. You need `is_invalid_npi: true` to validate National Provider Identifier numbers before allowing record access. Domain-specific validation belongs in YAML, not scattered across Python hooks.

### Semantic versioning

Your deployment agent manages releases. You need `semver_lt: "2.0.0"` to ensure only packages above a minimum version get deployed. Custom operators keep deployment contracts readable.

### Who benefits

- **Domain teams** — express domain-specific validation in YAML instead of Python, keeping contracts readable by non-developers.
- **Security teams** — audit YAML contracts without reading Python code to understand what's being validated.
- **Platform teams** — distribute custom operators as a library alongside [templates](../contracts/templates.md).

### Overlap with Python hooks

Python `@precondition` hooks can do anything custom operators can. The difference is readability and auditability — YAML contracts with custom operators are reviewable by non-engineers, Python hooks are not. Use custom operators for domain-specific leaf checks, Python hooks for complex logic with branching. See [Python Hooks](python-hooks.md) for the hook approach.

---

## Operator contract

Every custom operator is a callable with this signature:

```python
def my_operator(field_value: Any, operator_value: Any) -> bool:
    ...
```

| Parameter | Description |
|---|---|
| `field_value` | The resolved value from the selector (e.g., the value of `args.target_ip`). |
| `operator_value` | The value from the YAML operator (e.g., `"10.0.0.0/8"`). |
| **Return** | `True` if the condition is met (contract fires), `False` otherwise. |

The return value is coerced to `bool`. Truthy non-bool values (like `1` or `"yes"`) work but `True`/`False` is preferred.

### Error handling

- If the operator raises `TypeError`, Edictum treats it as a `policy_error` (fail-closed — the contract fires).
- If the operator raises any other exception, Edictum treats it the same way (fail-closed).
- Missing fields are never passed to custom operators. When a selector resolves to a missing or null field, the expression evaluates to `False` without calling the operator.

---

## Registering operators

Pass `custom_operators` to any of the YAML loading methods:

=== "from_yaml()"

    ```python
    guard = Edictum.from_yaml(
        "contracts.yaml",
        custom_operators={"ip_in_cidr": ip_in_cidr},
    )
    ```

=== "from_yaml_string()"

    ```python
    guard = Edictum.from_yaml_string(
        yaml_content,
        custom_operators={"ip_in_cidr": ip_in_cidr},
    )
    ```

=== "from_template()"

    ```python
    guard = Edictum.from_template(
        "file-agent",
        custom_operators={"ip_in_cidr": ip_in_cidr},
    )
    ```

Multiple operators can be registered at once:

```python
guard = Edictum.from_yaml(
    "contracts.yaml",
    custom_operators={
        "ip_in_cidr": ip_in_cidr,
        "is_invalid_iban": is_invalid_iban,
        "semver_lt": semver_lt,
    },
)
```

---

## Name clash protection

Custom operator names must not collide with the 15 built-in operators. Attempting to register a name like `contains` or `equals` raises `EdictumConfigError`:

```python
# This raises EdictumConfigError
guard = Edictum.from_yaml_string(
    yaml_content,
    custom_operators={"contains": my_fn},  # clash!
)
```

```
EdictumConfigError: Custom operator names clash with built-in operators: ['contains']
```

---

## Unknown operator detection

If a YAML contract uses an operator name that is neither built-in nor registered as a custom operator, Edictum raises `EdictumConfigError` at compile time (when loading the bundle), not at evaluation time:

```python
# contracts.yaml uses `ip_in_cidr` but no custom_operators registered
guard = Edictum.from_yaml_string(yaml_content)
# EdictumConfigError: Contract 'internal-only': unknown operator 'ip_in_cidr'
```

This means typos and missing registrations are caught immediately, not when a tool call happens to trigger the contract.

---

## Composing with boolean expressions

Custom operators compose with `all:`, `any:`, and `not:` the same way built-in operators do:

```yaml
- id: internal-approved-only
  type: pre
  tool: ssh_connect
  when:
    all:
      - args.target_ip: { ip_in_cidr: "10.0.0.0/8" }
      - principal.role: { not_in: [sre, admin] }
  then:
    effect: deny
    message: "Internal access requires SRE or admin role."
```

Custom and built-in operators can be mixed freely within the same expression tree.

---

## Dry-run evaluation

Custom operators work with the [dry-run evaluation API](../evaluation.md):

```python
result = guard.evaluate(
    "ssh_connect",
    {"target_ip": "192.168.1.1"},
)
print(result.verdict)  # "deny" or "allow"
```

---

## Examples

### IBAN validation

```python
import re

IBAN_RE = re.compile(r'^[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}$')

def is_invalid_iban(field_value: str, expected: bool) -> bool:
    """Return True when the IBAN is invalid (deny condition)."""
    valid = bool(IBAN_RE.match(str(field_value)))
    return (not valid) == expected
```

```yaml
- id: validate-iban
  type: pre
  tool: wire_transfer
  when:
    args.destination_account: { is_invalid_iban: true }
  then:
    effect: deny
    message: "Invalid IBAN: {args.destination_account}"
```

### CIDR range check

```python
import ipaddress

def ip_in_cidr(field_value: str, cidr: str) -> bool:
    """Return True when the IP is within the CIDR range."""
    try:
        return ipaddress.ip_address(field_value) in ipaddress.ip_network(cidr)
    except ValueError:
        return False
```

```yaml
# Deny connections to internal IPs
- id: block-internal
  type: pre
  tool: ssh_connect
  when:
    args.target_ip: { ip_in_cidr: "10.0.0.0/8" }
  then:
    effect: deny
    message: "Internal IP {args.target_ip} denied."
```

### Semver comparison

```python
from packaging.version import Version

def semver_lt(field_value: str, threshold: str) -> bool:
    """Return True when field version is below threshold."""
    return Version(field_value) < Version(threshold)
```

```yaml
# Deny deploying packages below minimum version
- id: min-version
  type: pre
  tool: deploy_package
  when:
    args.version: { semver_lt: "2.0.0" }
  then:
    effect: deny
    message: "Version {args.version} is below the minimum 2.0.0."
```

---

## Next steps

- [Operator Reference](../contracts/operators.md) — all 15 built-in operators
- [Python Hooks](python-hooks.md) — for complex validation with branching logic
- [Writing Contracts](writing-contracts.md) — YAML contract patterns
- [Testing Contracts](testing-contracts.md) — verifying your contracts work
