# CallGuard v0.3.0 — Have / Need / Plan

## What We Have (Current Codebase)

### Core Architecture (solid, doesn't need changes)
- `ToolEnvelope` — immutable snapshot with args, side_effect, environment, metadata
- `Principal` — already exists with user_id, service_id, org_id (but not wired into policies)
- `GovernancePipeline` — single source of truth: hooks → preconditions → session contracts → limits
- `Session` — atomic counters via StorageBackend (attempts, executions, per-tool, consecutive failures)
- `OperationLimits` — max_attempts, max_tool_calls, max_calls_per_tool
- `Verdict` — pass/fail with message and metadata
- `AuditEvent` — 30+ fields, already includes principal, contracts_evaluated, mode
- `AuditSink` protocol — async emit(), already implemented: StdoutAuditSink, FileAuditSink
- `RedactionPolicy` — key-based + pattern-based + secret detection + bash redaction
- `GovernanceTelemetry` — OTel tracer + meter, graceful no-op without opentelemetry
- `StorageBackend` protocol — get/set/delete/increment, MemoryBackend implementation

### Contract System (solid)
- `@precondition(tool, when=)` — before execution, receives envelope
- `@postcondition(tool, when=)` — after execution, receives envelope + response
- `@session_contract` — async, receives session, checks cumulative state
- `deny_sensitive_reads()` — built-in factory for common sensitive path/command blocking

### Adapters (6 shipped in v0.2.0)
- Claude SDK, LangChain, CrewAI, Agno, Semantic Kernel, OpenAI Agents
- All follow identical lifecycle: envelope → session → span → pipeline → audit
- ~200 lines each, thin translation only

### Demos & Cookbook
- 6 live demos with shared tools.py, contracts.py, setup.sh
- 29-recipe cookbook (1,020 lines) with 102 tests
- 316 total tests, 97% coverage

---

## What We Need (Feature Gap → v0.3.0)

### 1. YAML Policy Engine
**Gap:** Contracts require Python. Platform teams can't define policy without code.
**What exists:** Contract decorators, Verdict, pipeline evaluation order
**What's needed:**
- YAML schema definition
- Parser: YAML → contract objects (precondition, postcondition, session_contract)
- `CallGuard.from_yaml("policy.yaml")` or `CallGuard(policy="policy.yaml")`
- Built-in condition evaluators: contains, matches, equals, not_in, greater_than, etc.
- Wildcard tool matching (already supported via `"*"`)
- Composition: multiple YAML files merged

**Design decision:** YAML compiles to the SAME contract objects. Python API stays for power users. No new runtime path — YAML is just a frontend.

### 2. Principal Model Enhancement
**Gap:** Principal exists but policies can't reference it. No way to say "deny unless role=admin"
**What exists:** `Principal(user_id, service_id, org_id)` on envelope, propagated to audit
**What's needed:**
- Add `role`, `environment`, `ticket_ref`, `claims: dict` to Principal
- YAML conditions that reference `principal.role`, `principal.environment`
- `create_envelope()` accepts principal kwarg (already does via **kwargs)
- Adapters propagate principal from framework-specific context

**Design decision:** Keep Principal as a dataclass. Add a `claims: dict` for extensibility so enterprises can pass arbitrary identity attributes without us modeling every IdP.

### 3. Audit Sinks
**Gap:** Only StdoutAuditSink and FileAuditSink. Enterprise needs Splunk, Datadog, webhook.
**What exists:** `AuditSink` protocol (async emit), RedactionPolicy applied before emit
**What's needed:**
- `WebhookAuditSink(url, headers, retry_config)` — POST JSON, async with retry
- `SplunkHECSink(url, token)` — Splunk HTTP Event Collector format
- `DatadogSink(api_key, site)` — Datadog Logs API
- All sinks: async, non-blocking, configurable retry, apply redaction

**Design decision:** Each sink is a small class (~50 lines) implementing AuditSink protocol. Ship as optional extras: `pip install callguard[splunk]` etc. Or just bundle them since they're tiny.

### 4. Policy Versioning
**Gap:** No way to know which policy was active when an audit event was emitted.
**What exists:** AuditEvent has schema_version but no policy_version
**What's needed:**
- Hash the YAML policy file(s) at load time
- Add `policy_version: str` to AuditEvent
- Add `policy_hash: str` to OTel span attributes

**Design decision:** SHA256 of concatenated policy files. Stored on CallGuard instance, stamped on every audit event. Trivial to implement.

### 5. CLI
**Gap:** No command-line tools for policy management.
**What exists:** Nothing
**What's needed:**
- `callguard validate policy.yaml` — parse, check for errors, report
- `callguard check policy.yaml --tool read_file --args '{"path":".env"}'` — dry-run
- `callguard diff old.yaml new.yaml` — show policy changes
- `callguard replay --policy new.yaml --audit-log events.jsonl` — replay audit trail

**Design decision:** Use `click` or just `argparse`. Each command is a thin wrapper around library functions. The replay command reads JSONL, reconstructs envelopes, runs through pipeline, compares outcomes.

### 6. Killer Policy Templates
**Gap:** New users don't know where to start.
**What exists:** 29 cookbook recipes (Python), demo contracts.py
**What's needed:**
- `templates/file-agent.yaml` — sensitive reads, destructive ops, target dir enforcement
- `templates/research-agent.yaml` — rate limits, domain allowlist, output caps
- `templates/devops-agent.yaml` — production safeguards, role-based, ticket required
- `CallGuard.from_template("file-agent")`

**Design decision:** Templates are just YAML files bundled with the package. from_template() loads them. Users can customize by overriding.

### 7. Contract Testing Framework
**Gap:** No way to test policies against synthetic scenarios before deploying.
**What exists:** Pipeline can evaluate envelopes against contracts
**What's needed:**
- Test case YAML format: envelope + expected verdict
- `callguard test policy.yaml --scenarios tests.yaml`
- Library function for use in pytest: `assert_policy_denies(policy, envelope)`
- CI integration examples

### 8. MCP Proxy Mode
**Gap:** Enforcement only inside agent process. No server-side option.
**What exists:** Pipeline, adapters
**What's needed:**
- A CallGuard-powered MCP server that wraps another MCP server
- Intercepts tool_call, runs pipeline, forwards or denies
- Configurable via YAML policy
- Deployment: Docker container or standalone process

**Design decision:** Use the MCP Python SDK. The proxy is essentially another adapter — same lifecycle, different transport. ~200-300 lines.

### 9. Latency Benchmarks
**Gap:** No published performance numbers.
**What exists:** Demo metrics table (token counts, LLM time)
**What's needed:**
- Microbenchmarks: pipeline.pre_execute() overhead per contract count
- End-to-end: adapter overhead vs bare tool call
- Publish in README and docs

### 10. Documentation Site
**Gap:** Docs are markdown files in repo. No searchable site.
**What exists:** README, ARCHITECTURE.md, docs/quickstart.md, docs/adapters.md
**What's needed:**
- MkDocs Material configuration
- GitHub Pages deployment via CI
- Content: quickstart, YAML reference, adapter guides, cookbook, architecture, API reference
- SEO: "AI agent governance", "runtime contracts", "tool call policy"

### 11. Compliance Mapping
**Gap:** No mapping between CallGuard features and regulatory requirements.
**What exists:** Audit trail, observe mode, contract versioning (after #4)
**What's needed:**
- EU AI Act Article 9 (risk management) → how CallGuard satisfies it
- SOC 2 CC6.1-CC6.8 (logical access) → contract + audit mapping
- Document format: markdown in docs/, linked from site

---

## Work Streams (Parallelizable)

### Stream A: YAML Engine (keystone — do first)
1. Design YAML schema
2. Implement parser → contract objects
3. Integrate into CallGuard constructor
4. Write tests
5. Create 3 templates

**Depends on:** Nothing. This is the foundation.
**Blocks:** CLI (validate, check, diff, replay), templates, contract testing

### Stream B: Principal Enhancement
1. Extend Principal dataclass (role, environment, claims)
2. Wire into YAML condition evaluator
3. Update adapters to accept principal context
4. Update audit/OTel to include new fields
5. Tests

**Depends on:** YAML schema design (need to know how conditions reference principal)
**Blocks:** Nothing else directly

### Stream C: Audit Sinks
1. WebhookAuditSink
2. SplunkHECSink
3. DatadogSink
4. Policy version stamping on AuditEvent
5. Tests

**Depends on:** Nothing (AuditSink protocol is stable)
**Blocks:** Nothing

### Stream D: CLI + Tooling
1. `callguard validate`
2. `callguard check` (dry-run)
3. `callguard diff`
4. `callguard replay`
5. Contract testing framework

**Depends on:** Stream A (YAML engine must exist first)
**Blocks:** Nothing

### Stream E: MCP Proxy
1. MCP server wrapper using MCP Python SDK
2. Policy loading from YAML
3. Docker deployment config
4. Tests

**Depends on:** Stream A (YAML policies)
**Blocks:** Nothing

### Stream F: Docs + Benchmarks + Compliance
1. MkDocs setup + GitHub Pages CI
2. Content migration + YAML reference docs
3. Latency benchmarks
4. Compliance mapping documents

**Depends on:** Stream A (for YAML reference docs)
**Blocks:** Nothing

---

## Execution Order

```
Week 1, Days 1-2: Design YAML schema together (you + me)
                   This is the keystone decision — everything else hangs on it

Week 1, Days 2-3: Stream A (YAML engine) — agent team
                   Stream B (Principal) — agent team (parallel)
                   Stream C (Audit sinks) — agent team (parallel)

Week 1, Days 4-5: Stream D (CLI) — agent team (needs Stream A done)
                   Stream E (MCP proxy) — agent team
                   Stream F (Docs + benchmarks) — agent team

Week 1, Day 6-7:  Integration testing, polish
                   PR review
                   Tag v0.3.0, push to PyPI
```

---

## The One Thing We Must Get Right

The YAML schema. Everything compiles down to it. If we nail the schema, the parser is mechanical, the CLI is trivial, the templates are obvious, and the contract testing framework writes itself.

The schema needs to express:
- Tool-scoped preconditions with arg inspection
- Postconditions with output inspection
- Session contracts (limits, budgets, rate limits)
- Principal-aware conditions (role, environment, claims)
- Wildcard tools
- Composability (base policy + overrides)

And it needs to feel natural to a platform engineer who's written Kubernetes YAML and OPA policies.

**Next step: design the schema.**
