# SDK Work for Edictum Server

Work that happens in THIS repo (edictum, public) to enable server connectivity.

**Full server planning docs live in:** `~/project/edictum-server/docs/planning/`

## Document Index

| Document | What it covers |
|----------|---------------|
| [SDK-CHANGES.md](SDK-CHANGES.md) | All SDK changes: protocols, factory methods, server client |
| [DECISIONS.md](DECISIONS.md) | Architectural decisions (shared across repos) |
| [COMPOSITION-RFC.md](COMPOSITION-RFC.md) | Bundle composition + dual-mode evaluation (separate session) |
| [SDK-TESTING.md](SDK-TESTING.md) | Test strategy for all SDK changes |
| [SDK-PROBLEMS.md](SDK-PROBLEMS.md) | SDK-side problems: cache, reload, resilience, consistency |

## What Gets Built Here

### WS-A: SDK Foundation (src/edictum/)

| File | What | New/Modified |
|------|------|-------------|
| `sources.py` | `ContractSource` protocol + `FileContractSource` + local cache | New |
| `signing.py` | Ed25519 signature verification (verify only, not sign) | New |
| `yaml_engine/loader.py` | `load_bundle_from_bytes()` | Modified |
| `yaml_engine/compiler.py` | `consistency` block parsing for session contracts | Modified |
| `yaml_engine/edictum-v1.schema.json` | Add optional `consistency` + `observe_alongside` | Modified |
| `__init__.py` | `Edictum.from_server()`, `Edictum.reload()` | Modified |

### WS-C: Server Connectivity SDK (src/edictum/server/)

| File | What | New/Modified |
|------|------|-------------|
| `server/__init__.py` | Package init, public exports | New |
| `server/sources.py` | `ServerContractSource` — SSE client, reconnection, backpressure | New |
| `server/sinks.py` | `ServerAuditSink` — batched HTTP, dead letter, gzip | New |
| `server/backend.py` | `ServerBackend` — session state, tiered consistency | New |
| `server/client.py` | `EdictumServerClient` — wraps all three, lifecycle | New |

### Composition (separate session — see COMPOSITION-RFC.md)

| File | What | New/Modified |
|------|------|-------------|
| `yaml_engine/composer.py` | `compose_bundles()`, layer merge, `observe_alongside` | New |
| `__init__.py` | `from_yaml(*paths)` varargs | Modified |
| `pipeline.py` | Dual-mode evaluation (shadow contracts) | Modified |

### Dependencies

```toml
# pyproject.toml additions
[project.optional-dependencies]
server = ["httpx", "pynacl", "aiohttp-sse-client"]
```
