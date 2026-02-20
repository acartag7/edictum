# Architectural Decisions Record

## ADR-001: Local evaluation, not server-side
**Decision:** Contracts evaluated locally in the agent process.
**Why:** Zero latency. Graceful degradation if server unreachable.
**Rejected:** Server-side evaluation (latency, SPOF). Moved to Phase 4 optional.

## ADR-002: SSE over WebSocket for contract push
**Decision:** Server-Sent Events for pushing contracts to agents.
**Why:** Unidirectional (exactly the push model). HTTP-native, auto-reconnect,
works through proxies/CDNs. Simpler than WebSocket.
**Rejected:** WebSocket (bidirectional not needed for push channel).

## ADR-003: Ed25519 for bundle signing (Phase 1, not optional)
**Decision:** Ed25519 signatures on every deployed bundle.
**Why:** Fast (~62K sigs/sec), small keys (32B), small signatures (64B).
Governance product cannot ship without tamper protection.
**Rejected:** RSA (slower, larger). HMAC (shared secret = insecure).

## ADR-004: At-least-once delivery for audit sinks
**Decision:** At-least-once with dedup by `call_id`.
**Why:** Exactly-once requires distributed transactions. At-least-once + idempotency
achieves same result. Dead letter queue for persistent failures.
**Rejected:** Exactly-once (too complex). At-most-once (unacceptable for audit).

## ADR-005: Bundle composition over inheritance
**Decision:** Layers merged into flat bundle (base + team + env override by contract ID).
**Why:** Flat bundles are self-contained. Override-by-ID is predictable.
**Rejected:** Contract inheritance/extends (complex, ambiguous resolution).

## ADR-006: Content-addressed revisions + monotonic versions
**Decision:** SHA256 hash = machine identity. Monotonic integer = human label.
**Why:** Content addressing guarantees immutability. Integers are intuitive.
**Rejected:** Semver (doesn't map). UUIDs (not human-friendly).

## ADR-007: Server SDK in public repo
**Decision:** `ServerContractSource`, `ServerAuditSink`, `ServerBackend` in public
`edictum` repo under `src/edictum/server/`, gated by `pip install edictum[server]`.
**Why:** DX. HTTP POST, SSE reads, and signature verification aren't proprietary.
LaunchDarkly's SDKs are all open source. The server is the product.
**Rejected:** Separate package (packaging complexity). Private repo (bad DX).

## ADR-008: Path C (Hub frontend + new API backend)
**Decision:** Extend existing Hub with dashboard pages. New FastAPI backend for agents.
**Why:** Hub is built and polished. Convex for community, PostgreSQL+Redis for agents.
One site, one login. API backend separable for on-prem.
**Rejected:** Hub-only (Convex can't handle event ingestion). Separate products (duplicate UI).

## ADR-009: Neon PostgreSQL for MVP
**Decision:** Neon for all storage. Migrate events to ClickHouse/TimescaleDB later.
**Why:** Serverless (scales to zero). DB branching for agent dev. One DB to manage.
**Rejected:** Supabase (bundles things we don't need). ClickHouse day-one (overkill for MVP).

## ADR-010: Schema stays edictum/v1
**Decision:** `consistency` block on session contracts added within v1.
**Why:** Optional, has defaults, existing contracts unchanged = backward compatible.
v2 is for breaking changes, not additions.

## ADR-011: Python (FastAPI) for the server
**Decision:** Pure Python. No Rust, no polyglot.
**Why:** AI agents move 2-3x faster in Python. MVP scale doesn't need Rust.
Rewrite the bottleneck (event ingestion) later if needed. Discord/Figma playbook.
**Rejected:** Rust day-one (slower dev). Polyglot (complexity without benefit at MVP).

## ADR-012: Hub-to-Server contract flow (copy + track, not link)
**Decision:** User copies Hub contract to their tenant (independent copy). Server
stores `source_hub_slug` + `source_hub_revision` (SHA256). If Hub updates, user
sees diff + can deploy update as candidate (observe mode). If user modifies
their copy (SHA256 diverges), link is marked "customized", no more update alerts.
**Why:** No runtime coupling between Convex and PostgreSQL. The browser is the
bridge (talks to both). Copy is simple, deterministic, auditable.
**Rejected:** Live reference/pointer (backend coupling, harder to reason about).

## ADR-013: Dual-mode evaluation (enforce + observe alongside)
**Decision:** Support both per-contract mode override (Approach B) and whole-bundle
candidate deployment (Approach A). B is the primitive, A is sugar on top.
`observe_alongside: true` flag on a bundle makes its contracts shadow-evaluate
alongside the enforced bundle without replacing them.
**Why:** Per-contract mode is needed for gradual rollout. Whole-bundle candidate
is needed for Hub update testing. Both compose through the same SDK engine.
**Rejected:** Only A or only B. Both have valid use cases at different granularities.

## ADR-014: WebSocket for dashboard live feed
**Decision:** WebSocket (not SSE) for the dashboard event feed. Server-side
filtering from day one.
**Why:** Dashboard is interactive — user changes filters (agent, tool, verdict),
server adjusts the stream. At scale, pushing all events to browser is wasteful.
Agent push (SSE) is different — unidirectional, no filtering needed.

## ADR-015: Edictum Hub made private
**Decision:** Make edictum-hub repo private.
**Why:** No one knows the product yet. Hub will contain dashboard UI for the
commercial product. Can open-source later if there's a reason.

## ADR-016: Hub shows private tenant contracts
**Decision:** Hub UI shows both community contracts (Convex) and user's private
deployed contracts (FastAPI). Hub is the unified contract management UI.
**Why:** Single place to manage all contracts. Community browse + private
workspace + deployment controls in one interface.
