# Changelog

## 0.5.1

### Added
- `Finding` dataclass -- structured postcondition detection results
- `PostCallResult` dataclass -- tool call result with findings attached
- `on_postcondition_warn` callback parameter on all 6 adapters
- `classify_finding()` helper for standard finding type classification
- `docs/findings.md` -- full documentation with remediation examples

### Changed
- Adapter `_post_tool_call` now returns `PostCallResult` instead of `None`
- All 6 adapters support optional postcondition remediation callbacks

### Fixed
- Postcondition findings no longer depend on audit sink state (eliminates race condition
  with parallel tool calls when using `tracking_sink.last_event` pattern)

## 0.5.0

- OTel-native observability
- Custom sinks removed in favor of OpenTelemetry spans
- `configure_otel()` helper for quick setup
