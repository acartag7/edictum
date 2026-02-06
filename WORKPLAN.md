# CallGuard v0.3.0 — WORKPLAN

> **Last updated:** 2026-02-06
> **Branch:** v0.3.0
> **Target:** Enterprise-ready release with YAML contracts, enhanced principal, audit sinks, CLI, MCP proxy, docs

---

## Stream A: YAML Contract Engine (KEYSTONE)

**Depends on:** nothing
**Blocks:** Stream D (CLI), Stream E (MCP proxy)

### A1: Foundation
- [x] Create `callguard/yaml_engine/` package structure
- [x] Copy `schemas/callguard-v1.schema.json` into package
- [x] Implement `loader.py`: parse YAML, validate against JSON Schema, compute SHA256 bundle hash
- [x] Implement `CallGuardConfigError` exception in `__init__.py`
- [x] Tests: valid bundle loads, invalid bundles rejected (all 5 constraint types)

### A2: Condition Evaluator
- [x] Implement `evaluator.py`: resolve field selectors from ToolEnvelope
- [x] Implement nested arg access (`args.config.timeout`)
- [x] Implement all 15 operators (exists, equals, not_equals, in, not_in, contains, contains_any, starts_with, ends_with, matches, matches_any, gt, gte, lt, lte)
- [x] Implement boolean composition (all, any, not)
- [x] Implement missing-field → false semantics
- [x] Implement type-mismatch → deny + policy_error semantics
- [x] Tests: every operator, missing fields, type mismatches, nested booleans

### A3: Compiler
- [x] Implement `compiler.py`: convert parsed pre rules → precondition callables
- [x] Convert parsed post rules → postcondition callables
- [x] Convert parsed session rules → OperationLimits + session contracts
- [x] Implement message templating with {placeholder} expansion (200 char cap)
- [x] Implement per-rule `enabled` filtering
- [x] Implement per-rule `mode` override
- [x] Wire `then.tags` into Verdict.metadata
- [x] Tests: compilation produces correct contract objects, message templating, enabled/disabled

### A4: Integration
- [x] Implement `CallGuard.from_yaml(path, *, mode=None)` on CallGuard class
- [x] Implement `CallGuard.from_template(name)` for built-in templates
- [x] Stamp `policy_version` (bundle hash) on AuditEvent
- [x] Add `policy_version` to OTel span attributes
- [x] Add `policy_error` field to AuditEvent (done by Stream C)
- [x] End-to-end test: load YAML → create guard → evaluate envelope → check audit event has policy_version
- [x] Test: YAML-loaded guard produces identical verdicts to equivalent Python contracts

### A5: Templates
- [ ] Create `templates/file-agent.yaml` (sensitive reads, destructive bash, target dir)
- [ ] Create `templates/research-agent.yaml` (rate limits, domain allowlist, output caps)
- [ ] Create `templates/devops-agent.yaml` (prod gate, ticket required, PII detection, session limits)
- [ ] Tests: all templates pass `callguard validate`
- [ ] Tests: templates produce expected verdicts against sample envelopes

---

## Stream B: Principal Enhancement

**Depends on:** nothing (but coordinate field names with Stream A evaluator)
**Blocks:** nothing

- [x] Add `role: str | None = None` to Principal dataclass
- [x] Add `ticket_ref: str | None = None` to Principal dataclass
- [x] Add `claims: dict[str, Any] = field(default_factory=dict)` to Principal (kept frozen, documented tradeoff)
- [x] Update `create_envelope()` to propagate new Principal fields
- [x] Update AuditEvent to include new Principal fields in serialization
- [x] Update all 6 adapters to accept optional `principal` parameter
- [x] Tests: Principal creation with new fields, envelope propagation, audit serialization (21 tests in test_principal.py)

**Decision:** Principal stays `frozen=True`. The `claims` dict reference is immutable but contents are technically mutable — documented in Principal docstring. Callers should treat claims as read-only after construction.

---

## Stream C: Audit Sinks

**Depends on:** nothing
**Blocks:** nothing

### C1: WebhookAuditSink
- [x] Implement `sinks/webhook.py`: async HTTP POST, configurable URL/headers
- [x] Retry logic: exponential backoff, max 3 retries, non-blocking (fire-and-forget option)
- [x] Apply RedactionPolicy before sending
- [x] Tests: mock HTTP, verify payload shape, verify retry behavior

### C2: SplunkHECSink
- [x] Implement `sinks/splunk.py`: Splunk HEC format (event wrapper, sourcetype, index)
- [x] Token-based auth via headers
- [x] Tests: verify HEC payload format

### C3: DatadogSink
- [x] Implement `sinks/datadog.py`: Datadog Logs API format
- [x] API key auth, site configuration (datadoghq.com vs datadoghq.eu)
- [x] Tests: verify Datadog payload format

### C4: Policy Version Stamping
- [x] Add `policy_version: str | None` field to AuditEvent
- [x] Add `policy_error: bool` field to AuditEvent
- [x] Update StdoutAuditSink and FileAuditSink to include new fields
- [x] Tests: verify new fields appear in serialized events

---

## Stream D: CLI

**Depends on:** Stream A (YAML engine must be functional)
**Blocks:** nothing

- [ ] Set up `callguard/cli/main.py` with click or argparse
- [ ] `callguard validate <file.yaml>` — parse, schema validate, compile regexes, check unique IDs, report errors with line numbers
- [ ] `callguard check <file.yaml> --tool <name> --args '<json>'` — dry-run single envelope against contracts, show verdict
- [ ] `callguard check` with `--principal` flag for role/claims testing
- [ ] `callguard diff <old.yaml> <new.yaml>` — show added/removed/changed contract IDs
- [ ] `callguard replay --contracts <file.yaml> --audit-log <events.jsonl>` — replay audit trail against different contracts, show what would change
- [ ] Add `[cli]` extra to pyproject.toml for click dependency
- [ ] Tests: all commands with valid/invalid inputs

---

## Stream E: MCP Proxy

**Depends on:** Stream A (YAML engine for policy loading)
**Blocks:** nothing

- [ ] Implement `proxy/server.py` using MCP Python SDK
- [ ] Proxy wraps another MCP server (configurable upstream URL)
- [ ] Intercepts `tools/call` requests, creates ToolEnvelope, runs pipeline
- [ ] If denied: returns error response to client
- [ ] If allowed: forwards to upstream, runs postconditions on response
- [ ] Policy loaded from YAML file (CLI arg or env var)
- [ ] Dockerfile for deployment
- [ ] Tests: mock upstream MCP server, verify intercept/forward/deny behavior

---

## Stream F: Docs + Benchmarks + Compliance

**Depends on:** Stream A (for YAML reference docs)
**Blocks:** nothing

### F1: MkDocs Site
- [ ] Set up MkDocs Material configuration
- [ ] GitHub Pages deployment via GitHub Actions
- [ ] Content: landing page, quickstart, installation
- [ ] Content: YAML contract reference (from schema-spec.md)
- [ ] Content: operator reference table
- [ ] Content: adapter guides (one page per framework)
- [ ] Content: cookbook migration (Python recipes)
- [ ] Content: architecture overview
- [ ] Content: API reference (auto-generated from docstrings)

### F2: Benchmarks
- [ ] Microbenchmark: pipeline.pre_execute() latency vs number of contracts
- [ ] Microbenchmark: YAML evaluator overhead per condition
- [ ] End-to-end: adapter overhead vs bare tool call
- [ ] Publish numbers in README and docs (target: <2ms policy eval, <5ms total)

### F3: Compliance Mapping
- [ ] EU AI Act Article 9 (risk management) → CallGuard feature mapping
- [ ] EU AI Act Article 14 (human oversight) → observe mode, human gates
- [ ] SOC 2 CC6.1-CC6.8 → contract + audit trail mapping
- [ ] Format: markdown docs, linked from site and README

---

## Open Questions

_Record decisions or blockers here. Include date and resolution._

- [x] **Principal frozen dataclass + claims dict:** Decided option (b): keep frozen, accept mutable dict reference. Documented in Principal docstring. MappingProxyType rejected because it's not serializable by `dataclasses.asdict()` and adds complexity for marginal safety. — _Resolved 2026-02-06_

---

## Completed

_Move checked items here with completion date._

- **Stream B: Principal Enhancement** — completed 2026-02-06. Added role, ticket_ref, claims to Principal; updated all 6 adapters; 21 new tests.
