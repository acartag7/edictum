# Codebase Audit Findings (2026-02-21)

Full audit of Edictum codebase for hardcoded, inflexible, and broken patterns.
79 issues total: 22 HIGH, 33 MEDIUM, 24 LOW.

## HIGH SEVERITY (22 issues)

### Correctness Bugs (5)

1. **MemoryBackend silently ignores TTL** — `storage.py:44` accepts `ttl` parameter but never uses it. Time-windowed session limits don't work. Decision needed: implement TTL with timestamps, or raise `NotImplementedError`.

2. **OpenAI output guardrail always returns allow** — `openai_agents.py:134` returns `ToolGuardrailFunctionOutput.allow()` unconditionally. Postcondition `effect: deny` silently degrades to warn on the guardrails path.

3. **RedactionPolicy replaces keys instead of merging** — `audit.py:129` uses `sensitive_keys or self.DEFAULT_SENSITIVE_KEYS` (OR replaces, doesn't merge). Users passing custom keys lose all 18 default sensitive key detections. Docs at `sinks.md:301` incorrectly say "merged."

4. **CrewAI double `on_postcondition_warn` invocation** — Callback fires in `crewai.py:300` (in `_after_hook()`) AND again in `crewai.py:141` (in `register()` wrapper). Two invocations with different first arguments.

5. **CrewAI `_deny()` discards denial reason** — `crewai.py:345-348` returns `False` (boolean), losing the reason string. All other adapters return `f"DENIED: {reason}"`. Agent has no idea why call was denied.

### Ghost Feature (1)

6. **PIIDetector protocol documented but doesn't exist** — CLAUDE.md lists `pii.py` with `PIIDetector protocol + PIIMatch`. `architecture.md:242-243` describes it. `roadmap.md:27-28` says "v0.6.0 In Progress." File was never created. We're at v0.8.1. `from edictum import PIIDetector` would ImportError.

### Hardcoded/Inflexible APIs (11)

7. **`from_template()` hardcoded to internal directory** — `__init__.py:271-309` only searches `Path(__file__).parent / "yaml_engine" / "templates"`. Users can't register custom template directories.

8. **Operator registry is closed** — `evaluator.py:315-330` has `_OPERATORS` as a private module constant. No API to register custom operators (e.g., `ip_in_cidr`, `semver_gte`). Users must write Python hooks instead of YAML contracts.

9. **Selector resolver is hardcoded** — `evaluator.py:132-182` has fixed if/elif chain for `tool.name`, `args.*`, `principal.*`, `output.text`, `env.*`. No custom selectors. Envelope `metadata` dict (`envelope.py:86`) is completely invisible to YAML contracts.

10. **`from_yaml()` doesn't accept string/bytes** — `__init__.py:156-269` and `loader.py:154-192` only accept file paths. Must write to temp files for programmatic YAML or testing.

11. **No `on_deny` callback in any adapter** — All 6 adapters. `on_postcondition_warn` exists but nothing for precondition denials. Users can't intercept denials without parsing audit logs.

12. **`_check_tool_success()` hardcoded error patterns** — All 6 adapters. Checks `startswith("Error:")` or `startswith("fatal:")`. Different tools return errors differently. Wrong `tool_success` cascades into wrong session counts.

13. **Principal frozen at construction** — All 6 adapters. `self._principal = principal` set once. Can't update mid-conversation for privilege escalation, auth refresh, or multi-tenant.

14. **No composite/multi-sink support** — `__init__.py:123` accepts only one `audit_sink`. Users wanting stdout + file must write a composite wrapper.

15. **SK `terminate=True` kills entire agent turn** — `semantic_kernel.py:97` sets `context.terminate = True` on one denial. All remaining tool calls in the turn are killed even if they'd be allowed.

16. **Claude SDK hooks not SDK-native compatible** — `claude_agent_sdk.py:63-70` docstring explicitly says hooks are NOT directly compatible with `ClaudeAgentOptions(hooks=...)`. Only adapter requiring manual bridging.

### CI/Docs Blockers (5)

17. **`check` CLI has no `--json` flag** — `main.py:207-269` only outputs Rich-formatted text. Blocks CI/CD automation.

18. **`test --cases` has no `--environment` flag** — `main.py:554` doesn't pass environment. Falls back to `"production"`. Wrong results for env-specific contracts.

19. **Agno import path inconsistency** — `adapters/agno.md:18` says `from agno import Agent`, `quickstart.md:169` says `from agno.agent import Agent`. One is wrong.

20. **RedactionPolicy docs say "merged" but code replaces** — `sinks.md:301` comment says "merged with defaults." Code at `audit.py:129` replaces. (Docs manifestation of bug #3.)

21. **`POSTCONDITION_WARNING` AuditAction defined but never emitted** — `audit.py:28` defines it. Not documented in `sinks.md:73`. Appears to be dead code.

22. **OTel `configure_otel` hardcodes `insecure=True`** — `otel.py:110` always uses `insecure=True` for gRPC. Blocks production TLS deployments.

---

## MEDIUM SEVERITY (33 issues)

### Adapter Gaps (9)
1. No access to full PreDecision/PostDecision objects from adapters
2. Hardcoded "DENIED:" prefix string in 4 adapters (LangChain, Agno, OpenAI, SK)
3. Session private and not sharable across adapters
4. No `on_allow` callback
5. No envelope enrichment hook (can't attach request ID, correlation ID)
6. CrewAI and Agno lack native async (use ThreadPoolExecutor bridge)
7. OpenAI FIFO output guardrail correlation fragile with parallel tools (`openai_agents.py:124-126`)
8. Agno hardcoded exception handling — catches all, converts to string (`agno.py:113-116`)
9. LangChain `as_middleware()` crashes in async contexts — `run_until_complete` (`langchain.py:79-80`)

### YAML Engine Gaps (6)
10. No `list_templates()` API — discovery requires triggering error
11. `MAX_REGEX_INPUT` silently truncates at 10K chars (`evaluator.py:17`) — security gap
12. JSON Schema uses `additionalProperties: false` — no custom YAML fields (`loader.py:26-36`)
13. BashClassifier `READ_ALLOWLIST` not extensible, overrides ToolRegistry (`envelope.py:122-150`, `envelope.py:223`)
14. No contract introspection API on Edictum instances — `_preconditions`, `_postconditions` are private
15. `compose_bundles()` no conflict resolution strategy — silent override (`composer.py:43-91`)

### CLI Gaps (5)
16. `check` — no `--verbose` flag for per-contract details
17. `validate` — no `--json` flag (`main.py:138-199`)
18. `diff` — no `--json` flag (`main.py:282-373`)
19. `test --cases` — no `--json` output mode (`main.py:486-589`)
20. No CLI `list` or `inspect` command

### Audit/Telemetry/Session (6)
21. StdoutAuditSink — no format or filter options (`audit.py:186-197`)
22. FileAuditSink — no rotation, no max file size (`audit.py:200-219`)
23. RedactionPolicy — hardcoded `MAX_PAYLOAD_SIZE` 32KB (`audit.py:121`)
24. GovernanceTelemetry — only 2 metrics: allowed + denied counters (`telemetry.py:52-62`)
25. Session — no state introspection API (`session.py:1-53`)
26. Pipeline — hardcoded fail-closed on hook errors, no fail-open option (`pipeline.py:91-94`)

### Pipeline/Core (3)
27. Pipeline short-circuits on first deny — can't get "all failures at once" (`pipeline.py:134-151`)
28. Pipeline — no `on_deny` callback at pipeline level (`pipeline.py:60-226`)
29. `from_multiple()` silently uses first guard's config on merge conflicts (`__init__.py:334-343`)

### Docs Gaps (4)
30. SK docs say "cancel" but code does "terminate" (`adapter-comparison.md:15` vs `semantic_kernel.py:97`)
31. `from_template()` docs claim all `from_yaml()` options available — `return_report` missing
32. Hooks API (`HookRegistration`, `HookDecision`, `HookResult`) exported in `__all__` but undocumented
33. `evaluate()` and `evaluate_batch()` APIs undocumented — only CLI docs reference them indirectly

---

## LOW SEVERITY (24 issues)

### Hardcoded Limits (5)
1. `Verdict.fail()` truncation at 500 chars (`contracts.py:22-28`)
2. `MAX_BUNDLE_SIZE` hardcoded at 1MB (`loader.py:20`)
3. `_PLACEHOLDER_CAP` at 200 chars for message expansion (`compiler.py:16`)
4. RedactionPolicy hardcoded string truncation at 1000 chars (`audit.py:146-147`)
5. RedactionPolicy `redact_result` default max_length 500 (`audit.py:167`)

### Minor Extension Gaps (7)
6. `RedactionPolicy.SECRET_VALUE_PATTERNS` not extensible for custom API key formats (`audit.py:113-119`)
7. `classify_finding()` hardcoded keyword matching — no custom finding types (`findings.py:71-88`)
8. FileAuditSink hardcoded JSON format (`audit.py:212`)
9. Audit sinks have no async batching (`audit.py:192-218`)
10. GovernanceTelemetry — no selective enable/disable (`telemetry.py:43-48`)
11. GovernanceTelemetry — hardcoded meter/tracer name "edictum" (`telemetry.py:45-46`)
12. GovernanceTelemetry — not injectable on Edictum constructor (`__init__.py:124`)

### Adapter Minor (3)
13. CrewAI tool name normalization not customizable (`crewai.py:56-70`)
14. OpenAI hardcoded guardrail names (`openai_agents.py:137-143`)
15. LangChain fallback ToolMessage class missing attributes (`langchain.py:358-366`)

### Other (5)
16. Session — no per-counter reset (`session.py:1-53`)
17. MemoryBackend — no thread safety (`storage.py:25-54`)
18. Pipeline — hardcoded warning message strings (`pipeline.py:267-301`)
19. Duplicate `NoOpSpan` classes (`telemetry.py:15-34` and `otel.py:127-149`)
20. Duplicate `_NullSink` classes (`__init__.py:242-244` and `cli/main.py:598-600`)

### Docs Cosmetic (4)
21. "Alert notifications" in roadmap — should be "finding" (`roadmap.md:53`)
22. "alert a human" in contracts concept page — should be "notify" (`concepts/contracts.md:49`)
23. `from_yaml()` docs never show `backend` parameter
24. Roadmap says PII is "v0.6.0 In Progress" — stale version label
