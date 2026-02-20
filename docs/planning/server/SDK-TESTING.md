# SDK Testing Strategy

## WS-A: SDK Foundation Tests

| Test Area | Approach | Location |
|-----------|----------|----------|
| `load_bundle_from_bytes()` | Unit: same validation as file-based, property tests for hash stability, verify SHA256 matches file-based loading for identical content | `tests/yaml_engine/test_loader.py` |
| `ContractSource` protocol | Unit: `FileContractSource` with temp files — connect/disconnect/poll/on_update/healthy lifecycle | `tests/test_sources.py` |
| `FileContractSource` | Unit: file exists, file missing, file changes (mtime), file corrupt, disconnect no-op | `tests/test_sources.py` |
| `Edictum.reload()` | Unit: verify contracts swap atomically, verify policy_version updates, verify in-flight evaluations use old contracts | `tests/test_reload.py` |
| Ed25519 verification | Unit: sign with test key → verify succeeds, tamper with bytes → verify fails, wrong key → verify fails, verify performance (<1ms) | `tests/test_signing.py` |
| Local bundle cache | Unit: write to cache, read back, corrupt cache file (signature fails → reject), missing cache dir (auto-create), cache path is `~/.edictum/cache/{env}.bundle` | `tests/test_cache.py` |
| `consistency` block parsing | Unit: YAML with consistency block, without (defaults apply), invalid sync_threshold (>1.0), invalid on_unavailable, consistency on pre/post (ignored) | `tests/yaml_engine/test_compiler.py` |
| JSON Schema update | Unit: validate YAML with `observe_alongside: true`, validate YAML with `consistency` block, existing YAML without these still valid | `tests/yaml_engine/test_schema.py` |

## WS-C: Server Connectivity SDK Tests

| Test Area | Approach | Location |
|-----------|----------|----------|
| `ServerContractSource` | Unit with mock SSE server: connect → receive bundle → on_update fires, reconnection on disconnect (exponential backoff), backpressure (rapid updates → skip intermediates, compile latest only), healthy property reflects connection state, verify Ed25519 signature before accepting bundle | `tests/server/test_sources.py` |
| `ServerAuditSink` | Unit with mock HTTP: batch buffering (accumulate 100 or 5s), flush on threshold, gzip compression, dead letter on persistent failure (3 retries exhausted), replay from dead letter, call_id in every event, RedactionPolicy applied before send | `tests/server/test_sinks.py` |
| `ServerBackend` | Unit with mock HTTP: get/set/delete/increment map to HTTP, tiered consistency — below threshold: async (fire-and-forget increment, cached read), at threshold: synchronous, on_unavailable: deny/allow/last_known behavior, connection pooling | `tests/server/test_backend.py` |
| `EdictumServerClient` | Unit: lifecycle (connect all → healthy → disconnect all), from_server() factory integration | `tests/server/test_client.py` |
| `X-Edictum-*` headers | Unit: verify all HTTP requests include Policy-Version, Agent-Id, Environment headers | `tests/server/test_headers.py` |

## Integration Tests (after server exists)

| Test | What it verifies |
|------|-----------------|
| SDK connects to real server | `from_server()` → SSE stream opens → bundle received → contracts loaded |
| Hot-reload works | Deploy new bundle on server → SDK receives via SSE → reload() → new contracts active |
| Audit events arrive | SDK makes tool call → ServerAuditSink batches → server receives within 10s |
| Session state round-trip | SDK increments counter → server stores → SDK reads back correct value |
| Graceful degradation | Kill server → SDK uses cached bundle → reconnects when server returns |
| Signature rejection | Push tampered bundle → SDK rejects → stays on previous bundle |

## Test Fixtures Needed

| Fixture | Purpose |
|---------|---------|
| `ed25519_keypair` | Test signing key pair (generated per test session) |
| `sample_bundle_bytes` | Valid edictum/v1 YAML as bytes |
| `signed_bundle` | sample_bundle_bytes + Ed25519 signature |
| `mock_sse_server` | aiohttp test server emitting SSE events |
| `mock_http_server` | aiohttp test server for event ingestion + session state |
| `tmp_cache_dir` | Temp directory for bundle cache tests |
