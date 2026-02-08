# CLI Reference

Edictum ships a command-line interface for validating contract files, dry-running
tool calls, diffing policy versions, and replaying audit logs against updated contracts.

## Installation

```bash
pip install edictum[cli]
```

This pulls in [Click](https://click.palletsprojects.com/) and
[Rich](https://rich.readthedocs.io/) as additional dependencies. The `edictum`
command becomes available on your `PATH` via the entry point defined in `pyproject.toml`
(`edictum.cli.main:cli`).

---

## Commands

### `edictum validate`

Parse one or more YAML contract bundle files, validate them against the Edictum JSON
Schema, compile all regex patterns, check for unique contract IDs, and report any errors.

**Usage**

```
edictum validate FILES...
```

Takes one or more file paths as positional arguments. Each file is validated independently.

**Example**

```
$ edictum validate contracts/production.yaml

  production.yaml — 12 contracts (2 post, 8 pre, 2 session)
```

When validation fails:

```
$ edictum validate contracts/broken.yaml

  broken.yaml — Invalid YAML: ...
```

Exit codes: `0` on success, `1` on validation errors.

---

### `edictum check`

Dry-run a single tool call envelope against your contracts. Builds a `ToolEnvelope`
from the provided tool name and arguments, evaluates all matching preconditions, and
prints the verdict. No tool actually executes.

**Usage**

```
edictum check <file.yaml> --tool <name> --args '<json>'
```

**Options**

| Flag | Description |
|------|-------------|
| `--tool TEXT` | Tool name to simulate (required) |
| `--args TEXT` | Tool arguments as a JSON string (required) |
| `--environment TEXT` | Environment name, defaults to `production` |
| `--principal-role TEXT` | Principal role |
| `--principal-user TEXT` | Principal user ID |
| `--principal-ticket TEXT` | Principal ticket ref |

**Example -- allowed call**

```
$ edictum check contracts/production.yaml \
    --tool read_file \
    --args '{"path": "/app/config.json"}'

ALLOWED
  Rules evaluated: 1 contract(s)
```

**Example -- denied call with principal**

```
$ edictum check contracts/production.yaml \
    --tool read_file \
    --args '{"path": "/home/user/.env"}' \
    --principal-role sre \
    --principal-user alice \
    --principal-ticket INC-4421

DENIED by rule block-sensitive-reads
  Message: Sensitive file '/home/user/.env' blocked.
  Tags: secrets, dlp
  Rules evaluated: 1
```

**Example -- role-gated production deploy**

```
$ edictum check contracts/production.yaml \
    --tool deploy_service \
    --args '{"env": "production", "service": "api"}' \
    --principal-role developer

DENIED by rule prod-deploy-requires-senior
  Message: Production deploys require senior role (sre/admin).
  Tags: change-control, production
  Rules evaluated: 2
```

**Example -- passing with ticket and senior role**

```
$ edictum check contracts/production.yaml \
    --tool deploy_service \
    --args '{"env": "production", "service": "api"}' \
    --principal-role sre \
    --principal-user alice \
    --principal-ticket INC-4421

ALLOWED
  Rules evaluated: 2 contract(s)
```

The principal flags map directly to `Principal` fields:

| CLI Flag | Principal Field |
|----------|----------------|
| `--principal-role TEXT` | `Principal.role` |
| `--principal-user TEXT` | `Principal.user_id` |
| `--principal-ticket TEXT` | `Principal.ticket_ref` |

A `Principal` is constructed only when at least one `--principal-*` flag is provided. If none are set, the check runs without principal context (all `principal.*` selectors evaluate to `false`).

Exit codes: `0` on allow, `1` on deny, `2` on invalid JSON.

---

### `edictum diff`

Compare two YAML contract files and report which contract IDs were added, removed,
or changed.

**Usage**

```
edictum diff <old.yaml> <new.yaml>
```

**Example**

```
$ edictum diff contracts/v1.yaml contracts/v2.yaml

Added:
  + require-ticket-ref (type: pre)

Removed:
  - legacy-read-block (type: pre)

Changed:
  ~ no-secrets

Summary: 1 added, 1 removed, 1 changed, 3 unchanged
```

Exit codes: `0` if identical, `1` if differences found.

---

### `edictum replay`

Replay an audit log (JSONL) against a contract file and report what would change.
Each event in the audit log is re-evaluated as if the new contracts were in effect at
the time. This answers the question: "If I deploy these contracts, which past calls
would have been treated differently?"

**Usage**

```
edictum replay <file.yaml> --audit-log <events.jsonl>
```

**Options**

| Flag | Description |
|------|-------------|
| `--audit-log PATH` | JSONL audit log file to replay (required) |
| `--output PATH` | Write detailed report as JSONL |

**Example**

```
$ edictum replay contracts/v2.yaml --audit-log audit/last-week.jsonl

Replayed 1247 events, 2 would change

Changed verdicts:
  Bash: call_allowed -> denied
    Rule: no-sensitive-reads
  Write: call_allowed -> denied
    Rule: no-secrets
```

Exit codes: `0` if no changes, `1` if changes detected.

---

### `edictum test`

Run a batch of test cases against your contracts and report pass/fail results. Each
test case specifies a tool call with expected verdict — like `pytest` for contracts.
Only preconditions are evaluated; postcondition testing requires actual tool output
and is not supported in dry-run mode.

**Usage**

```
edictum test <file.yaml> --cases <cases.yaml>
```

**Options**

| Flag | Description |
|------|-------------|
| `--cases PATH` | YAML file with test cases (required) |

**Test cases format**

```yaml
cases:
  - id: test-sensitive-read
    tool: read_file
    args:
      path: "/app/.env"
    principal:
      role: analyst
    expect: deny
    match_contract: block-sensitive-reads  # optional

  - id: test-normal-read
    tool: read_file
    args:
      path: "report.txt"
    principal:
      role: analyst
    expect: allow

  - id: test-with-claims
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

Each test case supports:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | No | Test case identifier (shown in output) |
| `tool` | Yes | Tool name to simulate |
| `args` | Yes | Tool arguments as a YAML mapping |
| `expect` | Yes | Expected verdict: `allow` or `deny` |
| `principal` | No | Principal context (see below) |
| `match_contract` | No | Verify that this contract ID triggered the result |

The `principal` field supports `role`, `user_id`, `ticket_ref`, and `claims` (arbitrary key-value pairs).

**Example -- all passing**

```
$ edictum test contracts/production.yaml --cases tests/cases.yaml

  test-sensitive-read: read_file {"path": "/app/.env"} -> DENIED (block-sensitive-reads)
  test-normal-read: read_file {"path": "report.txt"} -> ALLOWED

2/2 passed, 0 failed
```

**Example -- with failures**

```
$ edictum test contracts/production.yaml --cases tests/cases.yaml

  test-block-env: read_file {"path": "/app/.env"} -> DENIED (block-sensitive-reads)
  test-wrong-expect: read_file {"path": "safe.txt"} -> expected DENY, got ALLOWED

1/2 passed, 1 failed
```

**Example -- wrong contract match**

When `match_contract` is specified but the wrong contract fires, the output shows
which contract actually triggered:

```
$ edictum test contracts/production.yaml --cases tests/cases.yaml

  test-wrong-match: read_file {"path": "/app/.env"} -> expected contract wrong-id, got block-sensitive-reads

0/1 passed, 1 failed
```

Exit codes: `0` if all cases pass, `1` if any case fails.

!!! note "Preconditions only"
    `edictum test` evaluates preconditions only. Postconditions require actual tool
    output which doesn't exist in a dry-run, and session contracts (rate limits,
    max-calls policies) require accumulated state across multiple calls. For
    postcondition and session contract testing, use
    [unit tests with pytest](guides/testing-contracts.md#unit-testing-with-pytest).

---

## Combining with CI/CD

All commands return structured exit codes suitable for pipeline gating:

```yaml
# GitHub Actions example
- name: Validate contracts
  run: edictum validate contracts/production.yaml

- name: Test contracts against cases
  run: edictum test contracts/production.yaml --cases tests/contract-cases.yaml

- name: Diff against main
  run: |
    git show main:contracts/production.yaml > /tmp/old.yaml
    edictum diff /tmp/old.yaml contracts/production.yaml

- name: Replay last week's audit log
  run: |
    edictum replay contracts/production.yaml \
      --audit-log audit/last-week.jsonl \
      --output replay-report.jsonl
```
