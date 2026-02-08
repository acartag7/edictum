# Testing Your Contracts

This guide covers how to validate, dry-run, unit test, and regression test your Edictum contracts.

---

## CLI Validation

Run `edictum validate` to catch schema, syntax, and semantic errors before deployment:

```
$ edictum validate contracts.yaml

  contracts.yaml — 5 contracts (2 post, 2 pre, 1 session)
```

Validation checks include:

- YAML parse errors
- Missing required fields (`apiVersion`, `kind`, `metadata.name`, `defaults.mode`)
- Invalid regex patterns in `matches` / `matches_any`
- Duplicate contract IDs within a bundle
- Wrong effect for contract type (`deny` on a postcondition, `warn` on a precondition)
- Use of `output.text` in a precondition

---

## CLI Dry Run

Use `edictum check` to simulate a tool call against your contracts without executing anything:

```
$ edictum check contracts.yaml \
    --tool read_file \
    --args '{"path": ".env"}' \
    --principal-role analyst

DENIED by rule block-secret-reads
  Message: Analysts cannot read '.env'. Ask an admin for help.
  Tags: secrets, dlp
  Rules evaluated: 1
```

Verify allowed calls:

```
$ edictum check contracts.yaml \
    --tool read_file \
    --args '{"path": "readme.txt"}' \
    --principal-role analyst

ALLOWED
  Rules evaluated: 1 contract(s)
```

This is useful for quick spot-checks during development. For comprehensive coverage, use unit tests.

---

## Unit Testing With pytest

Write pytest tests that exercise your contracts programmatically using `Edictum.run()`:

```python
import asyncio
import pytest
from edictum import Edictum, EdictumDenied

@pytest.fixture
def guard():
    return Edictum.from_yaml("contracts.yaml")

def test_sensitive_read_denied(guard):
    async def read_file(path):
        return f"contents of {path}"

    with pytest.raises(EdictumDenied):
        asyncio.run(guard.run("read_file", {"path": ".env"}, read_file))

def test_normal_read_allowed(guard):
    async def read_file(path):
        return f"contents of {path}"

    result = asyncio.run(guard.run("read_file", {"path": "readme.txt"}, read_file))
    assert "contents" in result
```

Test patterns to cover:

- **Denied calls** -- assert that `EdictumDenied` is raised for calls that should be blocked.
- **Allowed calls** -- assert that the tool result is returned for calls that should pass.
- **Edge cases** -- test boundary values, missing principal fields, wildcard tool targets.
- **Session limits** -- call `guard.run()` in a loop to verify session-level limits fire at the correct count.

---

## Integration Testing With Observe Mode

Test contracts in a running system without blocking real tool calls. Deploy with `mode: observe` and collect audit events:

```python
from edictum import Edictum, Principal
from edictum.audit import FileAuditSink, RedactionPolicy

redaction = RedactionPolicy()
sink = FileAuditSink("test-audit.jsonl", redaction=redaction)

guard = Edictum.from_yaml("contracts.yaml", audit_sink=sink, redaction=redaction)
# defaults.mode should be "observe" in the YAML
```

After running your agent through a test scenario, inspect `test-audit.jsonl` for:

- `CALL_WOULD_DENY` events -- these are calls that would be blocked in enforce mode.
- Absence of false positives -- legitimate calls should not produce would-deny events.

---

## Regression Testing

Save audit logs from a known-good run and compare against updated contracts using `edictum replay`:

```
$ edictum replay contracts/v2.yaml --audit-log audit/baseline.jsonl

Replayed 340 events, 0 would change
```

If the replay shows changes, investigate before deploying:

```
$ edictum replay contracts/v2.yaml --audit-log audit/baseline.jsonl

Replayed 340 events, 2 would change

Changed verdicts:
  read_file: call_allowed -> denied
    Rule: block-config-reads
  bash: call_allowed -> denied
    Rule: block-destructive-commands
```

Incorporate replay into your CI pipeline to catch unintended policy regressions:

```yaml
# GitHub Actions example
- name: Validate contracts
  run: edictum validate contracts/production.yaml

- name: Replay baseline audit log
  run: |
    edictum replay contracts/production.yaml \
      --audit-log tests/audit-baseline.jsonl
```

---

## Testing Checklist

1. **Validate** -- `edictum validate` passes with zero errors.
2. **Dry-run** -- `edictum check` produces expected deny/allow for key scenarios.
3. **Unit tests** -- pytest tests cover denied, allowed, and edge cases.
4. **Observe mode** -- deploy in observe mode and review `CALL_WOULD_DENY` events.
5. **Replay** -- `edictum replay` against a baseline audit log shows no regressions.
6. **Enforce** -- flip to `mode: enforce` after all checks pass.
