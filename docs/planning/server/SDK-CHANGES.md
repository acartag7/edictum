# SDK Changes Required

## Changes to OSS Core (src/edictum/)

| Change | File | Scope |
|--------|------|-------|
| `load_bundle_from_bytes(raw: bytes)` | `yaml_engine/loader.py` | ~15 lines |
| `Edictum.from_server(url, api_key, env)` | `__init__.py` | ~40 lines |
| `Edictum.reload(bundle_bytes)` | `__init__.py` | ~30 lines |
| `ContractSource` protocol | New: `sources.py` | Full lifecycle |
| `FileContractSource` | `sources.py` | Wraps from_yaml() |
| `consistency` block parsing | `yaml_engine/compiler.py` | Optional on session |
| Ed25519 verify | New: `signing.py` | Verify only |
| Local bundle cache | `sources.py` | `~/.edictum/cache/` |

## ContractSource Protocol

```python
@runtime_checkable
class ContractSource(Protocol):
    async def connect(self) -> None: ...
    async def disconnect(self) -> None: ...
    async def poll(self) -> tuple[bytes, str] | None: ...
    def on_update(self, callback: Callable[[bytes, str], None]) -> None: ...
    @property
    def healthy(self) -> bool: ...
    @property
    def source_type(self) -> str: ...  # 'file', 'server', 'cache'
```

**Backpressure:** Rapid SSE updates -> skip intermediates, compile only latest.

## Server Client SDK (src/edictum/server/)

Lives in **public repo**, behind `pip install edictum[server]`.

```toml
[project.optional-dependencies]
server = ["httpx", "pynacl", "aiohttp-sse-client"]
```

| Component | File | Purpose |
|-----------|------|---------|
| `ServerContractSource` | `server/sources.py` | SSE client, receives bundles |
| `ServerAuditSink` | `server/sinks.py` | Batched HTTP + dead letter |
| `ServerBackend` | `server/backend.py` | Session state, tiered consistency |
| `EdictumServerClient` | `server/client.py` | Wraps all three |

All requests include `X-Edictum-Policy-Version`, `X-Edictum-Agent-Id`,
`X-Edictum-Environment` headers.

## Atomic Reload Pattern

```python
def reload(self, bundle_bytes: bytes) -> None:
    bundle_dict, bundle_hash = load_bundle_from_bytes(bundle_bytes)
    compiled = compile_contracts(bundle_dict)
    # GIL-safe atomic swaps
    self._preconditions = compiled.preconditions
    self._postconditions = compiled.postconditions
    self._session_contracts = compiled.session_contracts
    self._policy_version = bundle_hash
```
