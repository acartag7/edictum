# CLAUDE.md

## What is Edictum

Runtime contract enforcement for AI agent tool calls. Deterministic pipeline: preconditions, postconditions, session contracts, principal-aware enforcement. Six framework adapters (LangChain, CrewAI, Agno, Semantic Kernel, OpenAI Agents SDK, Claude Agent SDK). Zero runtime deps in core.

Current version: 0.5.3 (PyPI: `edictum`)

## Architecture: Open-Core with ee/ Directory

Single repo, two license zones. PostHog/GitLab monorepo pattern.

```
edictum/
├── src/edictum/          <- MIT license (open source core)
│   ├── core/             pipeline, envelope, session (MemoryBackend)
│   ├── contracts/        YAML parser, templates, composition
│   ├── adapters/         6 framework adapters
│   ├── audit.py          AuditEvent, StdoutAuditSink, FileAuditSink, RedactionPolicy
│   ├── telemetry.py      OTel spans, GovernanceTelemetry
│   ├── cli/              check, test, validate, diff, replay
│   └── pii.py            PIIDetector protocol + PIIMatch (interface only)
├── ee/                   <- Proprietary license (not yet created)
│   ├── pii/              RegexPIIDetector, PresidioPIIDetector, CompositePIIDetector
│   ├── sinks/            Webhook, Splunk HEC, Datadog
│   ├── server/           Central policy server, hot-reload, dashboard
│   ├── auth/             JWT/OIDC verification, SSO
│   ├── sequences/        Sequence-aware contracts
│   └── nl_authoring/     Natural language -> YAML contract generation
├── LICENSE               <- MIT (covers everything except ee/)
└── README.md
```

## THE ONE RULE

**Core code (src/edictum/) NEVER imports from ee/.**
**ee/ imports from core freely.**

Core provides protocols/interfaces. ee/ provides implementations.

## OSS Core (MIT)

- GovernancePipeline (evaluation engine)
- ToolEnvelope, Principal model, Session (MemoryBackend)
- YAML contract parsing + validation + templates + composition
- All 6 framework adapters
- Observe mode (shadow deploy)
- on_postcondition_warn callbacks
- edictum check + edictum test CLI
- AuditEvent dataclass + StdoutAuditSink + FileAuditSink (.jsonl) + RedactionPolicy
- OTel span instrumentation + GovernanceTelemetry
- PIIDetector protocol (interface only, no implementations in core)

## Enterprise (ee/) — not yet created

- PII detection backends: RegexPIIDetector, PresidioPIIDetector, CompositePIIDetector
- YAML `pii_detection` shorthand
- Audit sinks: Webhook, Splunk HEC, Datadog
- Alert rules (denial spikes, PII detections, session exhaustion)
- Sequence-aware contracts
- NL -> YAML contract authoring
- Central Policy Server (agent pull, versioning, hot-reload)
- Dashboard (denial rates, contract drift)
- RBAC for contract management
- SSO integration (Okta, Azure AD)
- JWT/OIDC principal verification
- Human approval workflows
- Cross-agent session tracking

## Boundary Principle

The tier split follows one rule: **evaluation engine = OSS, infrastructure = enterprise.**

- Pipeline that takes a tool call and returns allow/deny/warn -- OSS
- Persistence beyond local files, networking, coordination -- enterprise
- PIIDetector protocol in OSS (users write their own). Implementations (regex, Presidio) -- enterprise
- Stdout + File (.jsonl) sinks for dev/local audit -- OSS. Network destinations (Webhook, Splunk, Datadog) -- enterprise
- OTel instrumentation (emitting spans) -- OSS. Dashboards and alerting -- enterprise
- Session (MemoryBackend) for single-process -- OSS. Multi-process coordination via Edictum Server -- enterprise

## Dropped Features (do NOT implement)

- `reset_session()` — new run_id handles this naturally
- Redis StorageBackend — not our problem, application layer concern
- DB StorageBackend — OTel already covers queryable audit data

## What's Shipped

- v0.5.0: Core library — pipeline, 6 adapters, YAML contracts, CLI check, OTel, observe mode
- v0.5.1: Adapter bug fixes (CrewAI, Agno, SK)
- v0.5.2: Adapter bug fixes (LangChain, OpenAI)
- v0.5.3: Claude SDK on_postcondition_warn callback, edictum test CLI
- Docs overhaul: homepage, quickstart, concepts section, patterns, 7 guides
- edictum-demo repo: github.com/acartag7/edictum-demo

## Session Model

MemoryBackend stores counters in a Python dict — one process, one agent. This covers the vast majority of use cases. For multi-agent coordination across processes, the Edictum Server (planned, ee/) handles centralized session tracking. There is no DIY Redis/DynamoDB path.

## Build & Test

```bash
pytest tests/ -v              # full test suite
ruff check src/ tests/        # lint
python -m mkdocs build --strict  # docs build
edictum validate contracts.yaml  # validate YAML contracts
```

## Code Conventions

- Python 3.11+
- `from __future__ import annotations` in every file
- Frozen dataclasses for immutable data
- Type hints everywhere
- Async: all pipeline, session, and audit sink methods are async
- Testing: pytest + pytest-asyncio, maintain 97%+ coverage
- Commits: conventional commits (feat/fix/docs/test/refactor/chore), no Co-Authored-By
- PRs: small and focused, Linear ticket in PR description not title

## YAML Schema (locked)

- `apiVersion: edictum/v1`, `kind: ContractBundle`
- Contract types: `type: pre` (deny only), `type: post` (warn only), `type: session` (deny only)
- Conditions: `when:` with boolean AST (`all/any/not`) and leaves (`selector: {operator: value}`)
- 15 operators: exists, equals, not_equals, in, not_in, contains, contains_any, starts_with, ends_with, matches, matches_any, gt, gte, lt, lte
- Missing fields evaluate to `false`. Type mismatches yield deny/warn + `policy_error: true`
- Regex: Python `re` module, single-quoted in YAML docs (`'\b'` not `"\b"`)
- Bundle hash: SHA256 of raw YAML bytes -> `policy_version` on every audit event
