# RFC: Environment-Based When Conditions

**Status:** Draft
**Requested by:** User feedback (v0.6.2)
**Goal:** Allow contracts to be conditionally active based on runtime flags like `DRY_RUN` — with minimal user effort.

---

## Problem Statement

Users want to define all safety contracts in a single YAML file with conditional activation based on runtime flags:

```yaml
preconditions:
  - when:
      env.DRY_RUN: { equals: "true" }
    deny:
      tool_name: { matches: "Write|Edit|Bash" }
      message: "Dry run mode — modifications blocked"
```

Current workarounds:
1. Maintain two separate YAML files and merge guards programmatically at runtime
2. Reach into private attributes: `g1._preconditions.extend(g2._preconditions)` — brittle and undocumented

---

## Options Considered

### Option A: Leverage Existing `metadata` Field

Use the existing `metadata: dict[str, Any]` on ToolEnvelope.

```yaml
when:
  metadata.dry_run: { equals: true }
```

**How it works:** Pass `metadata={"dry_run": True}` when creating envelopes.

**Pros:**
- No code changes needed — already supported by evaluator
- Flexible for any runtime context

**Cons:**
- Less ergonomic than `env.DRY_RUN`
- Requires framework adapter changes to accept metadata passthrough
- Semantic mismatch: "metadata" suggests opaque data, not governance signals

---

### Option B: New `env` Selector with Explicit Injection

Add a dedicated `env: dict[str, str | bool | int]` field to ToolEnvelope that adapters populate.

```yaml
when:
  env.DRY_RUN: { equals: true }
```

**Implementation:**

```python
@dataclass(frozen=True)
class ToolEnvelope:
    tool_name: str
    args: dict[str, Any]
    environment: str = "production"  # Keep for backward compat
    env: dict[str, str | bool | int] = field(default_factory=dict)  # NEW
    ...
```

```python
# Adapter usage
hooks = ClaudeAdapter.as_hooks(guard, env={"DRY_RUN": True})
```

**Pros:**
- Clean, intuitive API (`env.DRY_RUN`, `env.ENVIRONMENT`)
- Clear separation from "metadata"
- Schema extension is additive, non-breaking

**Cons:**
- Schema change required
- Framework adapters need modification to accept `env` parameter
- Requires user code changes to pass env values

---

### Option C: Runtime Context Injection

Add a `context` parameter at the `Edictum` or pipeline level.

```python
guard = Edictum.from_yaml("contracts.yaml", context={"DRY_RUN": True})
```

```yaml
when:
  context.DRY_RUN: { equals: true }
```

**Pros:**
- Separates contract definition from runtime context
- Context can be swapped per-instantiation (same YAML, different modes)
- Doesn't pollute ToolEnvelope with governance-specific fields

**Cons:**
- Requires pipeline-level changes to thread context through
- Slightly more complex API surface
- May conflict with "evaluate against envelope" mental model

---

### Option D: Conditional Contract Loading + Merge API

Instead of `when`-based activation, provide a cleaner merge API for combining guards.

```python
base = Edictum.from_yaml("base.yaml")
dry_run = Edictum.from_yaml("dry_run.yaml")
guard = Edictum.merge([base, dry_run])  # or Edictum.from_multiple([...])
```

**Pros:**
- No schema changes
- Clear separation of concerns (different files for different modes)
- Explicit about what's active

**Cons:**
- Still requires multiple files
- Doesn't solve "single file" goal
- Merging semantics need thought (conflict resolution, ordering)

---

### Option E: Auto-Resolve `env.*` from `os.environ` (Recommended)

The evaluator automatically reads `env.*` selectors from `os.environ` — zero code changes for users.

```yaml
when:
  env.DRY_RUN: { equals: "true" }
deny:
  tool.name: { matches: "Write|Edit|Bash" }
```

**How it works:**
1. User sets `DRY_RUN=true` in shell or .env file
2. Evaluator sees `env.DRY_RUN`, calls `os.environ.get("DRY_RUN")`
3. No adapter changes, no envelope changes, no user code changes

**Pros:**
- Works immediately with all 6 existing adapters
- Familiar pattern (env vars are standard for config)
- Zero application code changes — "set env var, edit YAML, done"

**Cons:**
- Always string comparison (`{ equals: "true" }` not `{ equals: true }`)
- Security consideration: any env var becomes readable in contracts
  - Mitigation: Document that `env.*` should only be used for flags
  - Mitigation: Add allowlist/blocklist for env var names (optional)

**Implementation:**
- Modify `evaluator.py` to handle `env.*` selector prefix
- Add `env` to allowed selectors in JSON Schema
- Add type coercion for common patterns (`"true"` → `true`, numeric strings)

---

### Option F: Load-Time Interpolation

Substitute `${VAR}` at YAML load time, not evaluation time.

```yaml
when:
  some_selector: { equals: "${DRY_RUN}" }
```

**Issues:**
- Selectors must exist in the envelope — `${DRY_RUN}` would need a corresponding field
- Contract becomes "baked in" at load time — can't change behavior during process lifetime
- Doesn't work with current schema without adding envelope fields

**Verdict:** Not recommended — creates more problems than it solves.

---

### Option G: `enabled_if` at Contract Level

A contract-level conditional that disables the entire contract.

```yaml
- type: pre
  enabled_if: ${DRY_RUN}
  deny:
    tool.name: { matches: "Write|Edit|Bash" }
    message: "Dry run mode — modifications blocked"
```

**Pros:**
- Very clear intent: "this whole contract is conditional"
- No `when` clause complexity
- Could support `${!DRY_RUN}` for inverse

**Cons:**
- New top-level field in schema
- Less flexible than `when` (can't combine with other conditions)
- Same load-time issues as Option F

---

### Option H: Truthy Env Shorthand

Shorthand for "is this env var set and truthy":

```yaml
when:
  env: DRY_RUN  # shorthand for "DRY_RUN is truthy"
```

**Pros:**
- Minimal syntax
- Covers 90% of use cases (binary flags)

**Cons:**
- Doesn't handle "equals this specific value"
- Slightly different shape than other `when` clauses
- Less composability

---

## Recommendation

**Option E (Auto-Resolve from `os.environ`)** for environment conditions.

Rationale:
- Path of least resistance — one evaluator change, zero adapter changes
- Works with all 6 adapters immediately
- Familiar mental model (env vars for config)
- Truly minimal user effort

**Implementation scope:**
1. Evaluator: Handle `env.*` selector, resolve from `os.environ`
2. Schema: Add `env` to allowed selectors
3. Type coercion: `"true"`/`"false"` → boolean, numeric strings → int
4. Security: Document safe usage, optional allowlist

---

## Secondary Feature: Guard Merging API

Public API for combining guards without touching private attributes.

### Options

```python
# Option 1: Class method (Recommended)
guard = Edictum.from_multiple([base, dry_run])

# Option 2: Instance method returning new guard
guard = base.merge(dry_run)

# Option 3: Operator overloading
guard = base + dry_run
```

**Recommendation:** `Edictum.from_multiple([...])` — clearest semantics, factory pattern, no mutation.

**Implementation:**
- Concatenate `_preconditions`, `_postconditions`, `_session_contracts`
- Preserve order (first guard's contracts have priority)
- Optional: detect duplicate contract IDs

---

## Open Questions

1. **Type coercion in Option E:** Should `"true"` auto-coerce to `true` in comparisons?
   - Proposed: Yes, for ergonomics

2. **Env var allowlist:** Should we restrict which env vars are readable?
   - Proposed: No by default, optional `allowed_env_vars` parameter

3. **Merge conflict resolution:** What happens if two guards have contracts with same ID?
   - Proposed: First wins, with warning logged

4. **Process-lifetime vs request-lifetime:** Option E reads env at evaluation time, so it supports request-lifetime changes (if env var changes mid-process). Is this desired?
   - Proposed: Yes, flexibility is good; document the behavior

---

## Implementation Plan (If Approved)

### Phase 1: Auto-Env Selector
- [ ] Modify `evaluator.py` to handle `env.*` prefix
- [ ] Add `env` to JSON Schema allowed selectors
- [ ] Add type coercion for `"true"`/`"false"` and numeric strings
- [ ] Update documentation with examples
- [ ] Add tests for env-based conditions

### Phase 2: Guard Merging API
- [ ] Add `Edictum.from_multiple(guards: list[Edictum]) -> Edictum`
- [ ] Handle contract list concatenation
- [ ] Add duplicate ID detection (optional)
- [ ] Update documentation
- [ ] Add tests for merge behavior

---

## Examples (Final API)

### Environment-Based Conditions

```yaml
# contracts.yaml
apiVersion: edictum/v1
kind: ContractBundle
contracts:
  - type: pre
    when:
      env.DRY_RUN: { equals: "true" }
    deny:
      tool.name: { matches: "Write|Edit|Bash|TodoWrite" }
      message: "Dry run mode — modifications blocked"

  - type: pre
    when:
      all:
        - env.ENVIRONMENT: { equals: "production" }
        - tool.name: { equals: "Bash" }
    deny:
      args.command: { matches: "rm -rf|DROP TABLE" }
      message: "Destructive commands blocked in production"
```

```bash
# Usage
DRY_RUN=true python agent.py
```

### Guard Merging

```python
from edictum import Edictum

base = Edictum.from_yaml("base.yaml")
dry_run = Edictum.from_yaml("dry_run.yaml")

# Single guard with all contracts
guard = Edictum.from_multiple([base, dry_run])
```
