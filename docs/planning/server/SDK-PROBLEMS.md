# SDK-Side Problems to Solve

These are the problems that must be solved in THIS repo (edictum SDK).
Server-side problems are in the server repo's `PROBLEMS.md`.

## P1: Graceful Degradation (Cache + Fallback)

**Problem:** Server goes down → agent must keep working.

**Solution — degradation chain:**
```
server (live) → local cache (stale) → embedded bundle (fallback) → deny-all
```

**Cache implementation:**
- Location: `~/.edictum/cache/{environment}.bundle` (signed bundle bytes)
- Written on every successful bundle update from server
- Read on startup if server unreachable
- Signature-verified before loading (tampered cache → reject → next fallback)
- `contract_source` field in AuditEvent: `"server"` | `"cache"` | `"embedded"` | `"deny-all"`

**Embedded fallback:**
- `from_server()` accepts optional `fallback_bundle=` parameter (path to a local YAML)
- If no fallback and no cache: deny all tool calls (safe default)

**Reconnection:**
- Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 60s
- Jitter: ±25% to prevent thundering herd
- On reconnect: server pushes current bundle, SDK verifies + swaps

## P2: Atomic Hot-Reload

**Problem:** Agent mid-evaluation when new bundle arrives.

**Solution:**
```python
def reload(self, bundle_bytes: bytes, signature: bytes) -> None:
    # 1. Verify signature FIRST (reject tampered bundles)
    verify_signature(bundle_bytes, signature, self._signing_public_key)
    # 2. Parse + validate + compile (may fail — old contracts stay)
    bundle_dict, bundle_hash = load_bundle_from_bytes(bundle_bytes)
    compiled = compile_contracts(bundle_dict)
    # 3. Atomic reference swaps (GIL-safe)
    self._preconditions = compiled.preconditions
    self._postconditions = compiled.postconditions
    self._session_contracts = compiled.session_contracts
    self._policy_version = bundle_hash
    # 4. Write to cache (async, non-blocking)
    self._cache.write(bundle_bytes, signature)
```

**Key property:** If step 2 fails (invalid YAML, schema error), the old
contracts remain active. The reload is all-or-nothing.

**In-flight evaluations:** They hold references to the old contract lists.
Python's reference counting ensures the old lists stay alive until all
in-flight evaluations complete. New evaluations pick up the new lists.

## P3: Session Consistency (SDK side)

**Problem:** `ServerBackend` adds latency to every session check.

**SDK implementation of tiered consistency:**

```python
class ServerBackend:
    def __init__(self, http_client, cache_ttl=5.0):
        self._http = http_client
        self._local_cache: dict[str, float] = {}
        self._cache_timestamps: dict[str, float] = {}
        self._cache_ttl = cache_ttl

    async def increment(self, key: str, amount: float = 1) -> float:
        # Always increment locally (optimistic)
        self._local_cache[key] = self._local_cache.get(key, 0) + amount
        # Fire-and-forget to server (async, non-blocking)
        asyncio.create_task(self._http.post(f"/sessions/.../increment"))
        return self._local_cache[key]

    async def get(self, key: str) -> str | None:
        # Check local cache freshness
        cached_at = self._cache_timestamps.get(key, 0)
        if time.monotonic() - cached_at < self._cache_ttl:
            return str(self._local_cache.get(key, 0))
        # Cache stale → fetch from server
        value = await self._http.get(f"/sessions/.../keys/{key}")
        self._local_cache[key] = float(value)
        self._cache_timestamps[key] = time.monotonic()
        return value
```

**Threshold switching:** When `get()` returns a value >= `sync_threshold * limit`,
the backend switches to synchronous mode for that key. All subsequent
`increment()` calls become synchronous (await the HTTP POST, return server value).

**Fallback on server unavailable:** Controlled by `on_unavailable` policy.
The `ServerBackend` raises `ServerUnavailableError`. The pipeline catches it
and applies the policy: deny, allow, or use last_known cached value.

## P4: SSE Backpressure

**Problem:** Rapid successive deploys → SSE delivers multiple bundles faster
than `compile_contracts()` can process.

**Solution:** The `ServerContractSource` buffers incoming SSE events. On each
`poll()` call (or `on_update` trigger), it takes only the LATEST event,
discards intermediates:

```python
class ServerContractSource:
    def __init__(self):
        self._pending: tuple[bytes, bytes, str] | None = None  # (bytes, sig, hash)
        self._skipped = 0

    def _on_sse_event(self, event):
        if self._pending is not None:
            self._skipped += 1
        self._pending = (event.data, event.signature, event.revision)

    async def poll(self):
        if self._pending is None:
            return None
        bundle_bytes, signature, revision = self._pending
        self._pending = None
        if self._skipped > 0:
            logger.warning(f"Skipped {self._skipped} intermediate bundle versions")
            self._skipped = 0
        return (bundle_bytes, signature, revision)
```

## P5: Dead Letter Queue (Audit Sink)

**Problem:** Server unreachable → audit events must not be lost.

**Solution:**
```
Normal:     events → batch buffer → HTTP POST → server
On failure: events → batch buffer → HTTP POST → RETRY 3x → dead letter file
Recovery:   edictum replay-dead-letter → read file → HTTP POST → server
```

- Dead letter location: `~/.edictum/dead_letter/server_audit.jsonl`
- Each line is one `AuditEvent` as JSON
- Replay command: `edictum replay-dead-letter --sink server --url <server_url>`
- On successful replay: events removed from dead letter file
- Dead letter file size monitoring: SDK emits metric `edictum.sink.dead_letter.count`
