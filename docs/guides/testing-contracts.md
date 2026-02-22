# Testing Your Contracts

This guide covers how to validate, dry-run, unit test, and regression test your Edictum contracts.

---

## When to use this

You need to verify that your contracts produce the correct verdicts before deploying them.

- **Gating contract changes in CI.** Your team merges contract YAML alongside application code. You need `edictum validate` and `edictum test --cases` in your CI pipeline so that a broken contract or an unintended verdict change fails the build before reaching production.

- **Debugging a contract that denies (or allows) unexpectedly.** A tool call that should be allowed is getting denied, or vice versa. You need to test specific scenarios without running the full agent. Use `edictum check` for a single tool call, or `guard.evaluate()` in Python for programmatic dry-run evaluation with full `EvaluationResult` details including `contract_id`, `deny_reasons`, and `policy_error`.

- **Regression testing after contract updates.** You edited a contract's `when` clause and need to confirm that previously-allowed calls are still allowed. Use `edictum replay` against a baseline audit log to detect verdict changes across hundreds of historical tool calls, or `edictum test --cases` with a YAML test suite that covers your known-good scenarios.

- **Evaluating postconditions against sample output.** Precondition testing is straightforward (tool name + args), but postconditions need tool output to evaluate. Use `edictum test --calls` with a JSON file containing `output` fields, or `guard.evaluate("tool", args, output="...")` in pytest to test postcondition matching and effects.

This guide covers the full testing ladder: `edictum validate` for schema validation, `edictum check` for spot-checks, `edictum test` for batch testing, `guard.evaluate()` / `guard.evaluate_batch()` for programmatic tests, and `edictum replay` for regression testing against audit logs.

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

## CLI Contract Check

Use `edictum check` to simulate a tool call against your contracts without executing anything:

```
$ edictum check contracts.yaml \
    --tool read_file \
    --args '{"path": ".env"}' \
    --principal-role analyst

DENIED by contract block-secret-reads
  Message: Analysts cannot read '.env'. Ask an admin for help.
  Tags: secrets, dlp
  Contracts evaluated: 1
```

Verify allowed calls:

```
$ edictum check contracts.yaml \
    --tool read_file \
    --args '{"path": "readme.txt"}' \
    --principal-role analyst

ALLOWED
  Contracts evaluated: 1
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
    `--cases` evaluates preconditions only. For postcondition testing, use `--calls`
    (see below) or pytest with `guard.evaluate()`.

This is the recommended approach for contract regression testing in CI. Keep your test
cases file alongside your contracts and run `edictum test` on every PR.

---

## Evaluating Tool Calls With `--calls`

When you need to test postconditions or want a quick evaluation without defining expected verdicts, use `--calls` with a JSON file:

```json
[
  {"tool": "read_file", "args": {"path": "README.md"}},
  {"tool": "read_file", "args": {"path": "/app/.env"}},
  {"tool": "read_file", "args": {"path": "data.txt"}, "output": "SSN: 123-45-6789"}
]
```

Run it:

```
$ edictum test contracts.yaml --calls tests/calls.json

  #  Tool        Verdict  Contracts  Details
  1  read_file   ALLOW    1          all contracts passed
  2  read_file   DENY     1          Sensitive file '/app/.env' denied.
  3  read_file   WARN     1          PII detected.
```

Key differences from `--cases`:

- **Postconditions supported** -- include an `output` field to trigger postcondition evaluation.
- **Exhaustive evaluation** -- all matching contracts run, no short-circuit on first denial.
- **No expected verdicts** -- results report what happened, not pass/fail against expectations.
- **JSON output** -- add `--json` for machine-readable output in CI pipelines.

See the [CLI reference](../cli.md#edictum-test) for the full format.

---

## Unit Testing With pytest

For programmatic testing, use `guard.evaluate()` for dry-run checks or `guard.run()` to test with actual tool execution.

### Dry-run with `evaluate()`

`evaluate()` checks a tool call against all matching contracts without executing the tool. It evaluates exhaustively (all matching contracts, no short-circuit) and returns an `EvaluationResult`:

```python
from edictum import Edictum, Principal

guard = Edictum.from_yaml("contracts.yaml")

# Test a precondition denial
result = guard.evaluate("read_file", {"path": ".env"})
assert result.verdict == "deny"
assert "block-dotenv" in result.contracts[0].contract_id

# Test an allowed call
result = guard.evaluate("read_file", {"path": "readme.txt"})
assert result.verdict == "allow"

# Test a postcondition warning (pass output to trigger postconditions)
result = guard.evaluate("read_file", {"path": "data.txt"}, output="SSN: 123-45-6789")
assert result.verdict == "warn"
assert len(result.warn_reasons) > 0

# Test with principal context
result = guard.evaluate(
    "deploy_service",
    {"service": "api"},
    principal=Principal(role="sre", ticket_ref="JIRA-123"),
)
assert result.verdict == "allow"
```

`evaluate()` is sync and does not require `asyncio`. The `EvaluationResult` contains:

| Field | Type | Description |
|-------|------|-------------|
| `verdict` | `str` | `"allow"`, `"deny"`, or `"warn"` |
| `tool_name` | `str` | The tool name evaluated |
| `contracts` | `list[ContractResult]` | Per-contract results with `contract_id`, `passed`, `message`, `tags`, `observed`, `policy_error` |
| `deny_reasons` | `list[str]` | Messages from failed preconditions |
| `warn_reasons` | `list[str]` | Messages from failed postconditions |
| `contracts_evaluated` | `int` | Total number of contracts checked |
| `policy_error` | `bool` | `True` if any contract had an evaluation error |

For batch evaluation, use `evaluate_batch()`:

```python
results = guard.evaluate_batch([
    {"tool": "read_file", "args": {"path": ".env"}},
    {"tool": "read_file", "args": {"path": "readme.txt"}},
])
assert results[0].verdict == "deny"
assert results[1].verdict == "allow"
```

### Full execution with `run()`

Use `guard.run()` when you need to test the complete pipeline including tool execution, session tracking, and audit:

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

- **Denied calls** -- assert that `EdictumDenied` is raised for calls that should be denied.
- **Allowed calls** -- assert that the tool result is returned for calls that should pass.
- **Edge cases** -- test boundary values, missing principal fields, wildcard tool targets.
- **Session limits** -- call `guard.run()` in a loop to verify session-level limits fire at the correct count.

!!! tip "When to use `evaluate()` vs `run()`"
    Use `evaluate()` for contract logic testing -- it's sync, fast, and doesn't need
    mock tool functions. Use `run()` when you need to test the full pipeline including
    session state, hooks, and audit.

---

## Integration Testing With Observe Mode

Test contracts in a running system without denying real tool calls. Deploy with `mode: observe` and collect audit events:

```python
from edictum import Edictum, Principal
from edictum.audit import FileAuditSink, RedactionPolicy

redaction = RedactionPolicy()
sink = FileAuditSink("test-audit.jsonl", redaction=redaction)

guard = Edictum.from_yaml("contracts.yaml", audit_sink=sink, redaction=redaction)
# defaults.mode should be "observe" in the YAML
```

After running your agent through a test scenario, inspect `test-audit.jsonl` for:

- `CALL_WOULD_DENY` events -- these are calls that would be denied in enforce mode.
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
    Contract: block-config-reads
  bash: call_allowed -> denied
    Contract: block-destructive-commands
```

Incorporate replay into your CI pipeline to catch unintended contract regressions:

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
3. **Batch test (cases)** -- `edictum test --cases` passes all YAML test cases with correct verdicts and contract matches.
4. **Batch test (calls)** -- `edictum test --calls` evaluates representative tool calls including postconditions.
5. **Unit tests** -- pytest tests with `guard.evaluate()` cover preconditions, postconditions, and edge cases. Use `guard.run()` for session limit tests.
6. **Observe mode** -- deploy in observe mode and review `CALL_WOULD_DENY` events.
7. **Replay** -- `edictum replay` against a baseline audit log shows no regressions.
8. **Enforce** -- flip to `mode: enforce` after all checks pass.
