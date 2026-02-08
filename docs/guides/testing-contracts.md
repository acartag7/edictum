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

This is useful for quick spot-checks during development. For batch testing, use `edictum test`.

---

## Batch Testing With YAML Test Cases

Use `edictum test` to run a suite of test cases against your contracts. Define expected
outcomes in a YAML file and let the CLI verify them all at once:

```yaml
# tests/contract-cases.yaml
cases:
  - id: block-env-file
    tool: read_file
    args:
      path: "/app/.env"
    principal:
      role: analyst
    expect: deny
    match_contract: block-sensitive-reads

  - id: allow-readme
    tool: read_file
    args:
      path: "README.md"
    principal:
      role: analyst
    expect: allow

  - id: deny-deploy-without-ticket
    tool: deploy_service
    args:
      service: api
      env: production
    principal:
      role: sre
    expect: deny
    match_contract: require-ticket

  - id: allow-deploy-with-ticket
    tool: deploy_service
    args:
      service: api
      env: production
    principal:
      role: sre
      ticket_ref: JIRA-456
    expect: allow

  - id: platform-team-access
    tool: deploy_service
    args:
      env: production
    principal:
      role: developer
      claims:
        department: platform
        clearance: high
    expect: allow
```

Run it:

```
$ edictum test contracts.yaml --cases tests/contract-cases.yaml

  block-env-file: read_file {"path": "/app/.env"} -> DENIED (block-sensitive-reads)
  allow-readme: read_file {"path": "README.md"} -> ALLOWED
  deny-deploy-without-ticket: deploy_service {"service": "api", "env": "production"} -> DENIED (require-ticket)
  allow-deploy-with-ticket: deploy_service {"service": "api", "env": "production"} -> ALLOWED
  platform-team-access: deploy_service {"env": "production"} -> ALLOWED

5/5 passed, 0 failed
```

Key features:

- **`expect`** -- `allow` or `deny`. The test passes if the precondition verdict matches.
- **`match_contract`** -- optional. When set, verifies that the specific contract ID triggered the denial. Catches cases where the right verdict happens for the wrong reason.
- **`principal`** -- supports `role`, `user_id`, `ticket_ref`, and `claims` (arbitrary key-value pairs). Omit to test without principal context.

!!! note "Preconditions only"
    `edictum test` evaluates preconditions only. Postconditions require actual tool
    output, and session contracts (rate limits, max-calls policies) require
    accumulated state across multiple calls. For postcondition and session contract
    testing, use pytest (see below).

This is the recommended approach for contract regression testing in CI. Keep your test
cases file alongside your contracts and run `edictum test` on every PR.

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
3. **Batch test** -- `edictum test` passes all YAML test cases with correct verdicts and contract matches.
4. **Unit tests** -- pytest tests cover denied, allowed, and edge cases (especially postconditions).
5. **Observe mode** -- deploy in observe mode and review `CALL_WOULD_DENY` events.
6. **Replay** -- `edictum replay` against a baseline audit log shows no regressions.
7. **Enforce** -- flip to `mode: enforce` after all checks pass.
