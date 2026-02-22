# Contract Patterns

This section contains reusable contract recipes organized by enforcement concern. Each pattern includes both a YAML contract bundle and the equivalent Python decorator version, an explanation of when and why to use it, and common gotchas. Use the tabs on each code block to switch between YAML and Python.

All YAML examples use the `edictum/v1` ContractBundle format and compile with `Edictum.from_yaml()`. All Python examples use the `@precondition`, `@postcondition`, and `@session_contract` decorator APIs.

## When to use this

You need these patterns when you know what concern you want to enforce but need a concrete implementation to start from.

- **Designing contracts for a new agent.** You are building governance for an agent and need to decide which contract types and operators to use. Browse the six pattern categories below to find recipes that match your concerns -- each category maps to a common enforcement domain (access control, data protection, rate limiting, change control, compliance, advanced logic).
- **Implementing a specific governance requirement.** Your team has a requirement like "block production deploys without a ticket" or "scan output for PII." Find the matching pattern, copy the YAML or Python code, and adjust selectors and values for your tools. Every pattern includes gotchas that flag common mistakes.
- **Learning Edictum's contract model by example.** The [YAML Reference](../yaml-reference.md) and [Operator Reference](../operators.md) define the schema and operators. These patterns show how to combine them into real contracts. Each pattern demonstrates specific operators, boolean combinators (`all`/`any`/`not`), and contract types (`pre`/`post`/`session`) in context.

Contract authors writing YAML bundles and developers implementing governance for the first time will use these patterns as starting points.

---

## Patterns

| Pattern | Description |
|---|---|
| [Access Control](access-control.md) | Role-based gates, environment restrictions, attribute-based access, and role escalation prevention. |
| [Data Protection](data-protection.md) | PII detection, secret scanning, sensitive file blocking, and output size monitoring. |
| [Change Control](change-control.md) | Ticket requirements, approval gates, blast radius limits, dry-run enforcement, and SQL safety. |
| [Rate Limiting](rate-limiting.md) | Session-wide limits, per-tool caps, burst protection, and failure escalation detection. |
| [Compliance and Audit](compliance.md) | Regulatory tags, contract bundle versioning, dual-mode deployment, and tag-based filtering. |
| [Advanced Patterns](advanced.md) | Nested boolean logic, regex composition, principal claims, template composition, wildcards, and dynamic messages. |

---

## How to Use These Patterns

Each pattern page provides one or more complete YAML contract bundles. To use a pattern:

1. Copy the YAML block into a `.yaml` file.
2. Adjust the `metadata.name`, contract `id` values, and selectors to match your tools.
3. Load with `Edictum.from_yaml("your-file.yaml")`.

Patterns can be combined by merging contracts from multiple bundles into a single file under one `contracts:` array, or by loading multiple bundles into separate `Edictum` instances.

For the full YAML schema, see the [YAML Contract Reference](../yaml-reference.md). For operator details, see the [Operator Reference](../operators.md).
