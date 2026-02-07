# Changelog

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
- Comprehensive framework comparison documentation in `docs/adapters.md`
  covering integration patterns, PII redaction capabilities, token costs,
  and known limitations for all 6 frameworks
- Framework-specific `on_postcondition_warn` callback behavior documented
  in `docs/findings.md`

### Documentation
- `docs/adapters.md`: Full rewrite with real-world integration patterns,
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
