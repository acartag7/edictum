# CallGuard v0.3.0 — Code Review & Security Review

> **Reviewed:** 2026-02-06
> **Branch:** v0.3.0
> **Scope:** All files in `src/callguard/`, `tests/`, `schemas/`, `pyproject.toml`
> **Reviewers:** Code Quality (R1) + Security (R2)

---

## 1. Critical — Must Fix Before Release

### C-1: Schema file path breaks on pip install (R1)
**File:** `src/callguard/yaml_engine/loader.py:20`

```python
_SCHEMA_PATH = Path(__file__).parent.parent.parent.parent / "schemas" / "callguard-v1.schema.json"
```

This traverses to the project root, which only works from a source checkout. When installed via `pip install callguard[yaml]`, `__file__` resolves to `site-packages/callguard/yaml_engine/loader.py`, and walking up 4 parents lands outside site-packages entirely. **Every `from_yaml()` call will fail for pip-installed users.**

**Why it matters:** This is the primary v0.3.0 feature. If it doesn't work when installed, the release is broken.

**Fix:** Bundle the schema inside the package using `importlib.resources`:
```python
import importlib.resources as _resources

def _get_schema() -> dict:
    global _schema_cache
    if _schema_cache is None:
        import json
        schema_text = _resources.files("callguard.yaml_engine").joinpath("callguard-v1.schema.json").read_text()
        _schema_cache = json.loads(schema_text)
    return _schema_cache
```
Copy the schema into `src/callguard/yaml_engine/` and update `pyproject.toml` to include it in the wheel (or use `package-data`).

---

### C-2: Regexes not compiled at load time — ReDoS vector (R2)
**File:** `src/callguard/yaml_engine/evaluator.py:241,247`

```python
def _op_matches(field_value: Any, op_value: str) -> bool:
    return bool(re.search(op_value, field_value))  # recompiles every call

def _op_matches_any(field_value: Any, op_value: list[str]) -> bool:
    return any(re.search(p, field_value) for p in op_value)  # recompiles every call
```

The SKILL.md spec says "Regex: Python `re` module, compiled at load time." The loader validates that patterns compile (`_try_compile_regex`), but **discards the compiled objects**. Every `_op_matches` call recompiles the pattern via `re.search(string_pattern, ...)`.

**Security concern:** Even patterns that pass `re.compile()` validation can catastrophically backtrack. An AI agent that controls tool args can craft strings that cause exponential time against innocent-looking patterns like `(a+)+b`. The YAML author writes the pattern, but the agent controls the input string.

**Performance concern:** Regex compilation is expensive relative to the target of <2ms policy eval.

**Fix:** Compile patterns during `compile_contracts()` and store compiled regex objects in the closure:
```python
# In compiler.py, when building the when_expr:
import re
def _precompile_regexes(expr):
    """Walk expression tree and replace string patterns with compiled regex."""
    if "all" in expr:
        for sub in expr["all"]: _precompile_regexes(sub)
    elif "any" in expr:
        for sub in expr["any"]: _precompile_regexes(sub)
    elif "not" in expr:
        _precompile_regexes(expr["not"])
    else:
        for selector, ops in expr.items():
            if isinstance(ops, dict):
                if "matches" in ops:
                    ops["matches"] = re.compile(ops["matches"])
                if "matches_any" in ops:
                    ops["matches_any"] = [re.compile(p) for p in ops["matches_any"]]
```
Then update `_op_matches` to accept `re.Pattern`:
```python
def _op_matches(field_value, op_value):
    if isinstance(op_value, re.Pattern):
        return bool(op_value.search(field_value))
    return bool(re.search(op_value, field_value))
```

For ReDoS mitigation, consider adding a timeout via `re.search` with a signal alarm, or document that patterns must be reviewed for catastrophic backtracking.

---

### C-3: All 6 adapters missing `policy_version` in audit events (R1)
**Files:** All files in `src/callguard/adapters/`

Every adapter's `_emit_audit_pre()` and post-execution audit `emit()` constructs `AuditEvent` without `policy_version`. Example from `claude_agent_sdk.py:156-176`:

```python
await self._guard.audit_sink.emit(
    AuditEvent(
        action=audit_action,
        # ...
        mode=self._guard.mode,
        # policy_version= is MISSING
    )
)
```

The `CallGuard.run()` method correctly stamps `policy_version=self.policy_version` (lines 332, 372, 405), but all 6 adapters omit it. **When using any adapter with YAML contracts, audit events will have `policy_version: None` even though the guard has it set.**

**Why it matters:** Policy version is the tamper-evidence hash for compliance. Without it in audit events, you lose the ability to prove which policy version governed each decision.

**Fix:** Add `policy_version=self._guard.policy_version` to every `AuditEvent()` construction in all 6 adapters. There are 2 emit sites per adapter (pre + post) = 12 total changes.

---

### C-4: `replay` command reads audit log file twice (R1)
**File:** `src/callguard/cli/main.py:325`

```python
lines = log_path.read_text().strip().split("\n") if log_path.read_text().strip() else []
```

This reads the entire file into memory twice — once for the truthiness check, once for the split. For a large audit log (millions of events), this doubles memory usage and I/O time. More importantly, it's a correctness risk if the file changes between reads.

**Fix:**
```python
content = log_path.read_text().strip()
lines = content.split("\n") if content else []
```

---

## 2. High — Should Fix Before Release

### H-1: FileAuditSink uses blocking I/O in async context (R1)
**File:** `src/callguard/audit.py:212`

```python
async def emit(self, event: AuditEvent) -> None:
    # ...
    with open(self._path, "a") as f:
        f.write(line)
```

This is a synchronous file write inside an `async def`. It blocks the event loop for the duration of the write. Under high throughput, this causes latency spikes for all concurrent coroutines.

**Fix:** Use `asyncio.to_thread()` or `aiofiles`:
```python
async def emit(self, event: AuditEvent) -> None:
    # ...
    await asyncio.to_thread(self._write_line, line)

def _write_line(self, line: str) -> None:
    with open(self._path, "a") as f:
        f.write(line)
```

---

### H-2: Sinks create new `aiohttp.ClientSession` per emit (R1/R2)
**Files:** `sinks/webhook.py:61`, `sinks/splunk.py:68`, `sinks/datadog.py:72`

All three sinks create `async with aiohttp.ClientSession() as session:` inside every `emit()` call. This means a new TCP connection (with TLS handshake) per audit event. For a system processing hundreds of events per second, this is extremely wasteful.

**Why it matters:** Performance — connection setup dominates latency. Resource exhaustion — under high throughput, this can exhaust file descriptors or trigger rate limiting.

**Fix:** Accept a shared `ClientSession` in the constructor or create one lazily and reuse:
```python
class WebhookAuditSink:
    def __init__(self, ...):
        # ...
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
```

---

### H-3: No request timeout on sink HTTP calls (R2)
**Files:** `sinks/webhook.py:62`, `sinks/splunk.py:69`, `sinks/datadog.py:73`

None of the three sinks specify a timeout on `session.post()`. A slow or unresponsive endpoint will hang the pipeline indefinitely (or until the default `aiohttp` timeout of 5 minutes).

**Fix:** Add `timeout=aiohttp.ClientTimeout(total=10)` to each session or post call.

---

### H-4: Compiler session contract hardcodes default limit value (R1)
**File:** `src/callguard/yaml_engine/compiler.py:179`

```python
if limits.max_attempts < 500 and attempt_count >= limits.max_attempts:
```

The `500` is the default value of `OperationLimits.max_attempts`. If the default changes, this check silently becomes wrong.

**Why it matters:** This condition exists to avoid double-checking session limits that the pipeline already enforces. But the magic number couples the compiler to a specific default.

**Fix:** Reference the actual default:
```python
_DEFAULT_MAX_ATTEMPTS = OperationLimits().max_attempts

# In _compile_session:
if limits.max_attempts < _DEFAULT_MAX_ATTEMPTS and attempt_count >= limits.max_attempts:
```
Or better: remove the `< 500` guard entirely and let the session contract always check, since it's a cheap comparison.

---

### H-5: Splunk/Datadog sinks silently swallow exceptions (R2)
**Files:** `sinks/splunk.py:75-76`, `sinks/datadog.py:79-80`

```python
except Exception:
    logger.exception("Splunk HEC POST to %s failed", self._url)
```

Unlike `WebhookAuditSink` which has retry logic, Splunk and Datadog sinks catch all exceptions and only log them. A transient network error causes **silent audit event loss** with no retry.

**Why it matters:** For compliance-critical deployments, audit gaps are unacceptable. A single network blip drops the event permanently.

**Fix:** Add retry logic similar to `WebhookAuditSink._send_with_retry()`, or factor out a shared `_RetryingSender` base.

---

### H-6: `pyproject.toml` version still `0.2.0` (R1)
**File:** `pyproject.toml:7`

```toml
version = "0.2.0"
```

Should be `0.3.0` for this release branch.

---

### H-7: Webhook fire-and-forget silently drops events on failure (R2)
**File:** `sinks/webhook.py:94-95`

```python
if self._fire_and_forget:
    asyncio.create_task(self._send_with_retry(payload))
```

If the task fails after 3 retries, the only trace is a log message. The event is permanently lost. There's no dead-letter queue or callback.

**Why it matters:** Users who enable `fire_and_forget=True` may not realize they're opting into silent data loss. At minimum, this should be prominently documented.

**Fix:** Add a `on_failure` callback parameter, or document the behavior prominently in the docstring and constructor.

---

## 3. Medium — Fix in Next Release

### M-1: No YAML file size limit (R2)
**File:** `src/callguard/yaml_engine/loader.py:142`

```python
raw_bytes = path.read_bytes()
```

A 100MB YAML file would be read entirely into memory, then parsed by PyYAML (which builds a full object tree). This could cause OOM in constrained environments.

**Fix:** Add a size check before reading:
```python
MAX_BUNDLE_SIZE = 1_048_576  # 1MB
stat = path.stat()
if stat.st_size > MAX_BUNDLE_SIZE:
    raise CallGuardConfigError(f"Bundle file too large: {stat.st_size} bytes (max {MAX_BUNDLE_SIZE})")
```

---

### M-2: `_validate_unique_ids` is O(n^2) (R1)
**File:** `src/callguard/yaml_engine/loader.py:66-71`

```python
ids: list[str] = []
for contract in data.get("contracts", []):
    contract_id = contract.get("id")
    if contract_id in ids:  # O(n) scan per check
        raise CallGuardConfigError(...)
    ids.append(contract_id)
```

Using a `list` for membership checks is O(n) per check, making this O(n^2) overall.

**Fix:** Use a `set`:
```python
ids: set[str] = set()
for contract in data.get("contracts", []):
    contract_id = contract.get("id")
    if contract_id in ids:
        raise CallGuardConfigError(...)
    ids.add(contract_id)
```

---

### M-3: `_expand_message` leaks untrusted data into messages (R2)
**File:** `src/callguard/yaml_engine/compiler.py:225-246`

The message template `"Blocked: {args.path}"` expands `args.path` from the ToolEnvelope, which comes from untrusted AI agent input. The 200-char cap helps, but the expanded value is inserted directly into the denial message, which then flows to:
- Audit events (stored in logs/SIEM)
- Agent context (the LLM sees the denial reason)
- CLI output (escaped via Rich `escape()` — safe)
- OTel spans

An agent could craft `args.path = "IGNORE PREVIOUS INSTRUCTIONS..."` which gets embedded in the denial message and fed back to the LLM as context. This is a **prompt injection vector via denial messages**.

**Mitigation:** Consider sanitizing expanded values (strip control chars, limit to alphanumeric + common path chars) or documenting that message templates should only reference trusted fields like `tool.name`.

---

### M-4: Missing tests for v0.3.0 adapter integration (R1)

No test verifies that adapters propagate `policy_version` (see C-3). Additional missing test scenarios:

- **Adapter + YAML contracts end-to-end:** Load YAML, use adapter, verify audit event has `policy_version`
- **ReDoS-like pattern with large input:** Verify evaluator doesn't hang
- **Concurrent sink emissions:** Verify webhook retry doesn't corrupt shared state
- **`from_template()` with non-existent template:** Tested, but not with templates that fail validation
- **CLI `replay` with very large audit log:** No test for memory behavior
- **Evaluator with `bool` field values:** `equals: true` when field is int 1 (Python truthiness edge case)

---

### M-5: `AuditEvent.schema_version` still `"0.0.1"` (R1)
**File:** `src/callguard/audit.py:32`

```python
schema_version: str = "0.0.1"
```

The audit event schema has changed in v0.3.0 (added `policy_version`, `policy_error`). The `schema_version` should reflect this so consumers can distinguish old vs. new events.

---

### M-6: No connection pool reuse in Agno adapter's thread bridge (R1)
**File:** `src/callguard/adapters/agno.py:71-80`

```python
with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
    return pool.submit(asyncio.run, ...).result()
```

A new `ThreadPoolExecutor` is created per tool call. This is correct but wasteful — thread creation overhead adds latency.

**Fix:** Store the executor on the adapter instance and reuse it.

---

## 4. Low — Nice to Have

### L-1: `CompiledBundle` field types use bare `list` (R1)
**File:** `src/callguard/yaml_engine/compiler.py:23-25`

```python
preconditions: list = field(default_factory=list)
postconditions: list = field(default_factory=list)
session_contracts: list = field(default_factory=list)
```

Should be `list[Callable]` or a more specific type for better IDE support and documentation.

---

### L-2: Duplicate `_serialize_event` method across all 3 sinks (R1)
**Files:** `sinks/webhook.py:44-52`, `sinks/splunk.py:38-46`, `sinks/datadog.py:39-47`

Identical 9-line method copy-pasted in all three sinks. Could be extracted to a shared utility or base class.

---

### L-3: `_PolicyError` could be a proper exception subclass (R1)
**File:** `src/callguard/yaml_engine/evaluator.py:38-48`

`_PolicyError` is a sentinel class with `__bool__` returning `True`. While this works for the evaluator's control flow, making it a non-exception class that's truthy is surprising. A more explicit pattern would be returning a tagged union or using `isinstance` checks (which the compiler already does).

---

### L-4: CLI `diff` exit code semantics (R1)
**File:** `src/callguard/cli/main.py:302`

```python
sys.exit(1 if has_changes else 0)
```

Exit code 1 typically means "error." Using it for "changes detected" (like `diff(1)`) is a convention but should be documented in the `--help` output so users know it's intentional.

---

### L-5: `requires-python = ">=3.11"` vs SKILL.md saying "Python 3.12+" (R1)
**File:** `pyproject.toml:10` vs `SKILL.md` line 11

The pyproject.toml says `>=3.11` but the SKILL.md says `Python: 3.12+`. The codebase uses `StrEnum` (3.11+) and `str | None` syntax (3.10+), so 3.11 is technically accurate. But if the team wants 3.12+ as documented, this should be aligned.

---

## 5. Positive Findings

### P-1: Clean separation of concerns
The adapter pattern is excellent. All governance logic lives in `GovernancePipeline`, and adapters are genuinely thin translation layers. This is the hardest architectural pattern to maintain, and it's done well here. The consistency across all 6 adapters is notable.

### P-2: Immutable-first design
`ToolEnvelope` and `Principal` are frozen dataclasses. `create_envelope()` deep-copies args via JSON round-trip. The `claims` dict mutability tradeoff is well-documented. This prevents a whole class of state-corruption bugs.

### P-3: `yaml.safe_load` used correctly
**File:** `loader.py:146` — `yaml.safe_load(raw_bytes)` is used, never `yaml.load()`. No instances of unsafe YAML deserialization anywhere in the codebase.

### P-4: Robust redaction system
`RedactionPolicy` is thorough: recursive dict/list traversal, key normalization, value pattern detection (OpenAI keys, AWS keys, JWTs, GitHub tokens, Slack tokens), bash command redaction, payload size capping. This is better than most production systems.

### P-5: Fail-closed per rule
The evaluator correctly implements fail-closed: `_PolicyError.__bool__` returns `True`, and the compiler catches exceptions and converts them to deny+policy_error verdicts. This is the right default for a security system.

### P-6: Comprehensive test suite
563 collected tests covering core pipeline, all adapters, YAML engine (loader, evaluator, compiler), sinks, CLI, and end-to-end integration. Test assertions are meaningful — they check specific field values, not just "no exception." The evaluator tests cover all 15 operators, missing fields, type mismatches, and boolean composition. The end-to-end tests verify full lifecycle (YAML load -> evaluate -> audit -> verify).

### P-7: Bundle hash integrity
SHA256 hash computed from raw YAML bytes (before parsing) and stamped as `policy_version`. This means any whitespace or comment change produces a different hash — maximally tamper-evident.

### P-8: Good error messages
Denial messages are instructive: "Attempt limit reached (500). Agent may be stuck in a retry loop. Stop and reassess." This helps the AI agent self-correct, which is the whole point of the system.

### P-9: No unsafe patterns
No `eval()`, `exec()`, `pickle.load()`, `subprocess` with unsanitized input, or other dangerous patterns found anywhere in the codebase. Dependencies use `>=` lower bounds (not unpinned `*`), and the core library has zero required dependencies.

### P-10: Zero-dependency core
`callguard` has no required dependencies — only optional extras for YAML, OTel, sinks, and adapters. This is excellent for adoption and minimizes supply chain risk.

---

## Summary

| Severity | Count | Action |
|----------|-------|--------|
| Critical | 4     | Must fix before release |
| High     | 7     | Should fix before release |
| Medium   | 6     | Fix in next release |
| Low      | 5     | Nice to have |
| Positive | 10    | Keep doing this |

**Top 3 priorities:**
1. Fix schema file path for pip-installed packages (C-1) — blocks the entire YAML feature
2. Compile regexes at load time and add to evaluator (C-2) — security + performance
3. Add `policy_version` to all adapter audit events (C-3) — data integrity for compliance
