# CLI Reference

CallGuard ships a command-line interface for validating contract files, dry-running
tool calls, diffing policy versions, and replaying audit logs against updated contracts.

## Installation

```bash
pip install callguard[cli]
```

This pulls in [Click](https://click.palletsprojects.com/) and
[Rich](https://rich.readthedocs.io/) as additional dependencies. The `callguard`
command becomes available on your `PATH` via the entry point defined in `pyproject.toml`
(`callguard.cli.main:cli`).

---

## Commands

### `callguard validate`

Parse one or more YAML contract bundle files, validate them against the CallGuard JSON
Schema, compile all regex patterns, check for unique contract IDs, and report any errors.

**Usage**

```
callguard validate FILES...
```

Takes one or more file paths as positional arguments. Each file is validated independently.

**Example**

```
$ callguard validate contracts/production.yaml

  production.yaml — 12 contracts (2 post, 8 pre, 2 session)
```

When validation fails:

```
$ callguard validate contracts/broken.yaml

  broken.yaml — Invalid YAML: ...
```

Exit codes: `0` on success, `1` on validation errors.

---

### `callguard check`

Dry-run a single tool call envelope against your contracts. Builds a `ToolEnvelope`
from the provided tool name and arguments, evaluates all matching preconditions, and
prints the verdict. No tool actually executes.

**Usage**

```
callguard check <file.yaml> --tool <name> --args '<json>'
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
$ callguard check contracts/production.yaml \
    --tool read_file \
    --args '{"path": "/app/config.json"}'

ALLOWED
  Rules evaluated: 1 contract(s)
```

**Example -- denied call with principal**

```
$ callguard check contracts/production.yaml \
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

Exit codes: `0` on allow, `1` on deny, `2` on invalid JSON.

---

### `callguard diff`

Compare two YAML contract files and report which contract IDs were added, removed,
or changed.

**Usage**

```
callguard diff <old.yaml> <new.yaml>
```

**Example**

```
$ callguard diff contracts/v1.yaml contracts/v2.yaml

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

### `callguard replay`

Replay an audit log (JSONL) against a contract file and report what would change.
Each event in the audit log is re-evaluated as if the new contracts were in effect at
the time. This answers the question: "If I deploy these contracts, which past calls
would have been treated differently?"

**Usage**

```
callguard replay <file.yaml> --audit-log <events.jsonl>
```

**Options**

| Flag | Description |
|------|-------------|
| `--audit-log PATH` | JSONL audit log file to replay (required) |
| `--output PATH` | Write detailed report as JSONL |

**Example**

```
$ callguard replay contracts/v2.yaml --audit-log audit/last-week.jsonl

Replayed 1247 events, 2 would change

Changed verdicts:
  Bash: call_allowed -> denied
    Rule: no-sensitive-reads
  Write: call_allowed -> denied
    Rule: no-secrets
```

Exit codes: `0` if no changes, `1` if changes detected.

---

## Combining with CI/CD

All commands return structured exit codes suitable for pipeline gating:

```yaml
# GitHub Actions example
- name: Validate contracts
  run: callguard validate contracts/production.yaml

- name: Diff against main
  run: |
    git show main:contracts/production.yaml > /tmp/old.yaml
    callguard diff /tmp/old.yaml contracts/production.yaml

- name: Replay last week's audit log
  run: |
    callguard replay contracts/production.yaml \
      --audit-log audit/last-week.jsonl \
      --output replay-report.jsonl
```
