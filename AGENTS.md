# AGENTS.md

This file helps AI coding agents understand the Edictum project. Read [CLAUDE.md](CLAUDE.md) for the full project context — architecture, tier boundaries, dropped features, conventions, and YAML schema.

## Quick Orientation

Edictum is a Python library that enforces runtime contracts on AI agent tool calls. Contracts are written in YAML, evaluated deterministically by a pipeline, and enforced via framework adapters.

**Before writing any code, read [CLAUDE.md](CLAUDE.md).** It contains the tier boundary rule that governs every contribution.

## The One Rule

Core code (`src/edictum/`) NEVER imports from `ee/`. Enterprise code (`ee/`) imports from core freely. If you are unsure where something belongs, check the Boundary Principle section in [CLAUDE.md](CLAUDE.md).

## Key Constraints

- **Dropped features**: no Redis/DB StorageBackend, no `reset_session()`. See CLAUDE.md for why.
- **Contract types**: `pre` contracts deny only, `post` contracts warn only, `session` contracts deny only.
- **YAML regex**: single-quoted strings (`'\b'` not `"\b"`).
- **`not` combinator**: wraps expressions (`not: { selector: ... }`), it is NOT a leaf operator.
- **Async**: all pipeline, session, and audit methods are async.
- **Immutability**: `ToolEnvelope` and `Principal` are frozen dataclasses. Always use `create_envelope()`.

## Directory Map

| Path | What | License |
|------|------|---------|
| `src/edictum/` | OSS core — pipeline, adapters, YAML engine, CLI, audit | MIT |
| `ee/` | Enterprise — PII backends, network sinks, server (not yet created) | Proprietary |
| `docs/` | MkDocs Material documentation | MIT |
| `tests/` | pytest test suite | MIT |

## Build Commands

```bash
pytest tests/ -v              # test suite
ruff check src/ tests/        # lint
python -m mkdocs build --strict  # docs build
edictum validate contracts.yaml  # validate YAML contracts
```

## Documentation Style

See [.docs-style-guide.md](.docs-style-guide.md) for terminology. Key terms: "contracts" not "policies", "denied" not "blocked", "adapter" not "plugin", "observe mode" not "shadow mode", "finding" not "alert", "pipeline" not "engine".

## Further Reading

- [CLAUDE.md](CLAUDE.md) — full project context (read this first)
- [.docs-style-guide.md](.docs-style-guide.md) — terminology reference for documentation
- [docs/roadmap.md](docs/roadmap.md) — what's shipped, in progress, and planned
