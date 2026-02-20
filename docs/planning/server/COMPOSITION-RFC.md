# RFC: Bundle Composition & Dual-Mode Evaluation

## Status: Draft
## Authors: Discussion 2026-02-17

---

## Problem

Today, `Edictum.from_yaml()` accepts a single YAML file. Users need to:

1. Combine multiple YAML files (base + overrides)
2. Run two versions of the same contract simultaneously (one enforced, one observed)
3. Roll out Hub contract updates safely with shadow evaluation

These are all variations of **composition** — merging multiple contract sources
into a single evaluation context.

---

## Proposal

### 1. Multi-File Composition in the SDK

```python
# Single file (current, unchanged)
guard = Edictum.from_yaml("contracts.yaml")

# Multiple files with layered composition
guard = Edictum.from_yaml(
    "base.yaml",
    "team-overrides.yaml",
    "prod-overrides.yaml",
)
```

**Merge semantics:**

Files are processed left to right. Later files have higher priority.

| Element | Merge rule |
|---------|-----------|
| Contracts (same ID) | Later layer **replaces** earlier layer entirely |
| Contracts (unique ID) | Concatenated into final list |
| `defaults.mode` | Later layer wins |
| `defaults.environment` | Later layer wins |
| `limits` | Later layer wins (entire limits block replaced) |
| `tools` | Deep merge (tool configs from all layers combined) |
| `metadata` | Deep merge (later keys override earlier) |
| `observability` | Later layer wins |

**Contract replacement is by ID, not by name.** If base has `id: deny-rm-rf`
and override also has `id: deny-rm-rf`, the override version completely replaces
the base version. No partial merging of conditions within a contract.

**Why replace, not merge conditions?** Merging `when` clauses across layers
creates invisible logic combinations that are impossible to debug. If you want
to change one condition in a contract, redefine the entire contract in your
override layer. Explicit is better than implicit.

### 2. Per-Contract Mode Override

A contract in an override layer can change the mode of a base contract:

```yaml
# base.yaml
defaults:
  mode: enforce
contracts:
  - id: pharma-clinical
    type: pre
    when:
      tool.name: { in: [prescribe_medication] }
      args.dosage: { gt: 1000 }
    message: "Dosage exceeds safe limit"
```

```yaml
# experimental-override.yaml
contracts:
  - id: pharma-clinical
    mode: observe    # override: shadow this contract
    type: pre
    when:
      tool.name: { in: [prescribe_medication] }
      args.dosage: { gt: 500 }    # stricter threshold, testing
    message: "Dosage exceeds new stricter limit"
```

When composed: the override replaces the base `pharma-clinical`. Now it runs
in observe mode with the stricter threshold. Audit events show
`CALL_WOULD_DENY` instead of `CALL_DENIED`.

### 3. Dual-Mode Evaluation (Enforced + Observed)

This is the key new capability: **running two versions of the same contract
simultaneously** — one enforced, one observed.

**New composition operator: `observe_alongside`**

```yaml
# candidate-update.yaml
observe_alongside: true   # top-level flag
contracts:
  - id: pharma-clinical
    # ... updated version from Hub
```

When a file has `observe_alongside: true`, its contracts are NOT merged by ID
replacement. Instead, they are added as **shadow copies** alongside the existing
contracts:

```
Enforced bundle:
  - pharma-clinical (enforce, original)

+ candidate-update.yaml (observe_alongside: true):
  - pharma-clinical (observe, candidate)

= Final evaluation context:
  - pharma-clinical (enforce, original)     ← makes real decisions
  - pharma-clinical:candidate (observe)     ← logs what it WOULD do
```

**Internal mechanics:**

The pipeline evaluates BOTH. The enforced version produces the actual
`PreDecision`/`PostDecision`. The observed version produces shadow audit events
with `action: CALL_WOULD_DENY` or `CALL_WOULD_ALLOW`.

The `AuditEvent` includes:

```python
# For the enforced evaluation
mode: "enforce"
decision_source: "pharma-clinical"

# For the shadow evaluation (separate AuditEvent)
mode: "observe"
decision_source: "pharma-clinical:candidate"
observed: true
```

**Dashboard insight:** "The candidate version would have denied 3 calls that
the current version allowed this week."

### 4. How the Server Uses This

**Approach A (whole-bundle candidate) uses `observe_alongside`:**

```
Server stores:
  production:
    enforced_version: v3
    candidate_version: v5 (optional)

Server pushes to agents:
  1. v3 bundle bytes (enforced)
  2. v5 bundle bytes with observe_alongside: true (if candidate exists)

SDK receives both, composes them:
  - v3 contracts: enforced
  - v5 contracts: shadow/observe alongside v3
```

**Approach B (per-contract mode override) uses standard composition:**

User uploads an override layer where specific contracts have `mode: observe`.
This is just normal composition — no `observe_alongside` needed.

**Both approaches use the same SDK composition engine.**

---

## API Changes

### from_yaml() — extended

```python
# Current signature
Edictum.from_yaml(path: str | Path, **kwargs) -> Edictum

# New signature
Edictum.from_yaml(*paths: str | Path, **kwargs) -> Edictum
```

Multiple paths are composed left to right.

### from_server() — candidate support

```python
guard = Edictum.from_server(
    url="...",
    api_key="...",
    environment="production",
    # Server pushes enforced + candidate bundles automatically
)
```

The server pushes both bundles over SSE. The SDK composes them using the
same `observe_alongside` mechanics.

### New: compose_bundles() — low-level

```python
from edictum.yaml_engine import compose_bundles

composed = compose_bundles(
    load_bundle("base.yaml"),
    load_bundle("overrides.yaml"),
    load_bundle_with_flag("candidate.yaml", observe_alongside=True),
)
```

This is the primitive. `from_yaml()` and `from_server()` use it internally.

---

## Merge Conflict Reporting

When composition produces overrides, the SDK returns a `CompositionReport`:

```python
guard, report = Edictum.from_yaml(
    "base.yaml",
    "overrides.yaml",
    return_report=True,
)

report.overridden_contracts
# [CompositionOverride(
#     contract_id="deny-rm-rf",
#     overridden_by="overrides.yaml",
#     original_source="base.yaml",
# )]

report.shadow_contracts
# [ShadowContract(
#     contract_id="pharma-clinical",
#     enforced_source="base.yaml",
#     observed_source="candidate.yaml",
# )]
```

The server's deploy response includes this report. The dashboard shows it.
No silent overrides — always visible.

---

## Hub → Server Flow (Using Composition)

```
1. User copies "pharma-clinical" from Hub to their tenant
   → Server stores: { id: pharma-clinical, source_hub_slug: "pharma-clinical",
                      source_hub_revision: "sha256:abc...", yaml: "..." }

2. Hub contract updates (sha256 changes)
   → Hub UI shows badge: "Update available"
   → User clicks "Preview diff"

3. User clicks "Deploy update as candidate"
   → Server creates a candidate bundle with observe_alongside: true
   → Pushes to agents: enforced (current) + observed (Hub update)

4. Dashboard shows shadow results over time

5. User promotes candidate
   → Server moves candidate to enforced, removes old version
   → Or user rejects → candidate removed, enforced stays

6. If user edits their copy (sha256 diverges from source_hub_revision)
   → source_hub_slug preserved but link marked "customized"
   → No more update notifications
```

---

## Edge Cases

### Same ID in base + override (without observe_alongside)
Later layer wins. Full contract replacement. Report shows the override.

### Same ID in base + observe_alongside layer
Both versions kept. Enforced version from base, observed from candidate.
Internal ID becomes `{id}` (enforced) and `{id}:candidate` (observed).

### observe_alongside layer has a contract ID not in base
The contract is added in observe mode. No enforced counterpart.
Useful for testing brand-new contracts before enforcing.

### User deletes the candidate
Server removes the candidate bundle. Next SSE push sends only enforced.
SDK drops the shadow contracts on reload.

### Multiple override layers
Composition is left to right. Only the last `observe_alongside` layer produces
shadow contracts. Multiple standard layers stack normally (each can override
the previous).

### Session contracts in observe_alongside
Observed session contracts track counters separately (namespaced with
`:candidate` suffix). They don't affect real session limits.

---

## Schema Impact

**Stays `edictum/v1`.** The `observe_alongside` flag is a **composition directive**,
not a contract schema element. It lives at the bundle top level alongside
`apiVersion` and `kind`:

```yaml
apiVersion: edictum/v1
kind: ContractBundle
observe_alongside: true    # composition directive
metadata:
  name: candidate-update
contracts:
  - id: pharma-clinical
    # ...
```

Existing bundles without `observe_alongside` work exactly as before.

---

## Implementation Scope

| Component | Change | Location |
|-----------|--------|----------|
| `compose_bundles()` | New function | `yaml_engine/composer.py` (new file) |
| `from_yaml(*paths)` | Accept varargs | `__init__.py` |
| `from_server()` | Handle dual-bundle push | `server/sources.py` |
| `GovernancePipeline` | Evaluate shadow contracts alongside enforced | `pipeline.py` |
| `AuditEvent` | Already has `mode` and `observed` fields | No change |
| JSON Schema | Add optional `observe_alongside` boolean | `edictum-v1.schema.json` |
| `CompositionReport` | New dataclass | `yaml_engine/composer.py` |
| `edictum diff` CLI | Support multi-file composition | `cli/main.py` |

---

## Open Questions (Composition-Specific)

1. **Should `observe_alongside` support partial contract selection?** e.g.,
   "observe only contracts X and Y from this bundle, ignore Z." Or is it
   always all-or-nothing? All-or-nothing is simpler. Per-contract selection
   adds complexity.

2. **Max composition depth?** Should we limit to N layers? 3 layers
   (base + team + env) covers most cases. Arbitrary depth adds debugging
   complexity. Propose: max 5 layers, configurable.

3. **Composition in CLI?** Should `edictum validate base.yaml overrides.yaml`
   validate the composed result? Yes — the CLI should mirror the SDK API.

4. **Circular observe_alongside?** Can you have two bundles each observing
   alongside the other? No. Only one candidate per environment. Server enforces
   this constraint.
