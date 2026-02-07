# Changelog

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
