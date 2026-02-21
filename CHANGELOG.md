# Changelog

## 0.8.1

### Changed
- Renamed `RuleResult` → `ContractResult` (`rule_id` → `contract_id`, `rule_type` → `contract_type`, `rules` → `contracts`, `rules_evaluated` → `contracts_evaluated`)
- CLI output now uses "contract" instead of "rule" in all user-facing strings

### Fixed
- Fixed terminology violations in comments, docstrings, and CLI output per .docs-style-guide.md
- Fixed GitHub release notes for v0.5.4, v0.7.0, and v0.8.0 (terminology and YAML schema corrections)

### Added
- Added terminology enforcement guardrails and pre-release checklist to CLAUDE.md

## 0.8.0

### Added
- `compose_bundles()` — multi-file YAML composition with deterministic left-to-right merge
- `from_yaml()` now accepts multiple file paths with automatic composition
- `observe_alongside: true` — dual-mode evaluation (shadow contracts run without affecting decisions)
- `CompositionReport` with override and shadow tracking
- `edictum validate` and `edictum diff` support multi-file arguments
- CLI composition report output for overrides and shadow contracts

## 0.7.0

### Added
- `env.*` selector — contracts can reference environment variables with automatic type coercion
- `Edictum.from_multiple()` — merge contracts from multiple guard instances
- Claude Code GitHub Actions workflow

## 0.6.2

### Changed
- Renamed `to_sdk_hooks()` → `to_hook_callables()` on Claude Agent SDK adapter

## 0.6.1

### Added
- YAML `tools:` section for declaring tool side-effect classifications
- `from_yaml(tools=)` parameter for programmatic tool classification

## 0.6.0

### Added
- Postcondition enforcement effects: `redact` and `deny` (in addition to existing `warn`)
- `SideEffect` classification (PURE, READ, WRITE, IRREVERSIBLE) controls which effects apply
- Postcondition regex-based pattern redaction
- Output suppression for `deny` effect on READ/PURE tools

## 0.5.4

### Added
- `guard.evaluate()` and `evaluate_batch()` — dry-run evaluation API
- `edictum test --calls` mode for JSON tool call evaluation

## 0.5.3

### Added
- `edictum test` CLI command — validate contracts against YAML test cases
  without spinning up an agent. Supports precondition testing with principal
  claims, expected verdicts, and contract ID matching.
- Tests for `on_postcondition_warn` callback in Claude SDK adapter — all 6
  adapters now have test coverage for postcondition callbacks.

### Notes
- `edictum test` evaluates preconditions only. Postcondition testing requires
  tool output and is not supported in dry-run mode.

## 0.5.2

### Fixed
- **OpenAI Agents SDK:** `as_guardrails()` now returns correctly typed
  `ToolInputGuardrail` / `ToolOutputGuardrail` with 1-arg functions matching
  the SDK's calling convention. Previously unusable due to signature mismatch.
- **CrewAI:** `register()` now uses `register_before_tool_call_hook()` /
  `register_after_tool_call_hook()` internally instead of decorators, fixing
  `setattr` failure on bound methods.
- **Semantic Kernel:** Tool call denial and postcondition remediation now wrap
  values in `FunctionResult` for SK 1.39+ pydantic compatibility.

### Added
- CrewAI adapter: automatic tool name normalization
  ("Search Documents" → "search_documents")
- Comprehensive framework comparison documentation in `docs/adapters/overview.md`
  covering integration patterns, PII redaction capabilities, token costs,
  and known limitations for all 6 frameworks
- Framework-specific `on_postcondition_warn` callback behavior documented
  in `docs/findings.md`

### Documentation
- `docs/adapters/overview.md`: Full rewrite with real-world integration patterns,
  cross-framework comparison table, choosing-a-framework guide, and
  per-adapter known limitations
- `docs/findings.md`: Added framework-specific callback behavior table
- SK adapter: Documented chat history TOOL role filtering requirement
- CrewAI adapter: Documented global hooks, generic denial messages,
  token cost (~3x), and tracing prompt suppression

## 0.5.1

### Added
- `Finding` dataclass -- structured postcondition detection results
- `PostCallResult` dataclass -- tool call result with findings attached
- `on_postcondition_warn` callback parameter on all 6 adapters
- `classify_finding()` helper for standard finding type classification
- `docs/findings.md` -- full documentation with remediation examples

### Changed
- All 6 adapters support optional postcondition remediation callbacks

### Breaking (internal)
- Adapter internal `_post*` methods now return `PostCallResult` instead of
  `None`/`{}`. Code that subclasses adapters or calls `_post_tool_call` /
  `_post` / `_after_hook` directly must handle `PostCallResult` instead of
  the previous return type. Public wrapper APIs (`as_tool_wrapper`,
  `as_middleware`, `as_tool_hook`, etc.) are unchanged — they still return
  the tool result directly.

### Fixed
- Postcondition findings no longer depend on audit sink state (eliminates race condition
  with parallel tool calls when using `tracking_sink.last_event` pattern)

## 0.5.0

- OTel-native observability
- Custom sinks removed in favor of OpenTelemetry spans
- `configure_otel()` helper for quick setup
