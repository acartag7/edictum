# Security Retrospective -- v0.11.1

**Date**: 2026-02-25
**Scope**: 6 security findings identified via deep audit of v0.11.1 (commit `1358c6b`)
**Status**: Fixes staged in working tree on branch `fix/security-remediation-v0.11.2`, not yet committed

---

## Timeline

| Event | Date | Commit/PR |
|-------|------|-----------|
| Foundation code written (storage.py, envelope.py) | 2026-02-06 | `0097bbb` |
| Rename callguard to edictum (code carried forward as-is) | 2026-02-07 | `94825aa` |
| CI workflow introduced (pytest + ruff only) | 2026-02-06 | `621ced8` |
| AI code review workflow introduced (review.yml) | 2026-02-22 | PR #48 |
| Approval protocol shipped (introduces timeout audit bug) | 2026-02-22 | PR #51, `231c645` |
| Server SDK shipped (introduces fail-open bug) | 2026-02-22 | PR #52, `bb5d7d7` |
| Sandbox contracts shipped (introduces symlink escape) | 2026-02-24 | PR #54, `f877432` |
| v0.11.1 released (normpath fix only) | 2026-02-25 | `1358c6b` |
| Full security audit performed | 2026-02-25 | SECURITY_AUDIT_REPORT.md |
| Remaining 5 fixes identified and staged | 2026-02-25 | Branch `fix/security-remediation-v0.11.2` |

---

## Root Causes (per finding)

### 1. ServerBackend.get() fail-open

| Attribute | Detail |
|-----------|--------|
| **Introduced in** | PR #52 (`bb5d7d7`, 2026-02-22) |
| **Introduced by** | `f0a3fe4` -- initial server SDK implementation |
| **Root cause** | Defensive-looking `except Exception: return None` intended to make `get()` tolerant of missing keys, but conflated "key not found" with "server unreachable". The result: network errors silently return None, which the session layer interprets as counter=0, resetting all rate limits. |
| **Why missed** | The PR included tests (`test_backend.py`) but only tested the happy path and 404 case. No test existed for non-404 server errors or connection failures until the fix added `test_get_raises_on_connection_error`, `test_get_raises_on_timeout`, and `test_get_raises_on_500`. The code reviewer checklist (code-reviewer.md) lists "session exhaustion" under agentic engineering (section 10), but this is phrased as "limits are enforced and tested" -- it does not specifically call out fail-open vs fail-closed behavior in storage backends. |
| **Time exposed** | 3 days (2026-02-22 to 2026-02-25). Server SDK is `pip install edictum[server]`, an optional dependency, limiting blast radius. |

### 2. BashClassifier bypass vectors

| Attribute | Detail |
|-----------|--------|
| **Introduced in** | `0097bbb` (2026-02-06) -- foundation commit, day 1 of the project |
| **Introduced by** | Original BashClassifier implementation with incomplete SHELL_OPERATORS list |
| **Root cause** | The SHELL_OPERATORS list was designed as a blocklist of dangerous characters, but omitted several categories: newline/carriage-return injection, process substitution, here-documents, and variable expansion syntax. The missing entries allow multi-command injection, data exfiltration via process substitution, and content injection via here-docs -- all while being classified as READ. |
| **Why missed** | The BashClassifier docstring explicitly says "This is a heuristic, not a security boundary", which created a false sense that completeness did not matter. No adversarial/red-team tests existed for the classifier -- all tests were positive cases (does `ls` get classified as READ?). The review checklist does not call out "input validation completeness" or "blocklist bypass" as review criteria. |
| **Time exposed** | 19 days (2026-02-06 to 2026-02-25). Present since project inception. |

### 3. Symlink sandbox escape

| Attribute | Detail |
|-----------|--------|
| **Introduced in** | PR #54 (`f877432`, 2026-02-24) -- sandbox contracts feature |
| **Introduced by** | `c399034` -- initial sandbox implementation using `os.path.normpath` |
| **Root cause** | `_extract_paths()` and `_compile_sandbox()` used `os.path.normpath()` to normalize paths. This handles `..` traversal but does not resolve symlinks. A symlink inside an allowed directory pointing outside it passes the string-prefix check but resolves to an unauthorized location at the OS level. The v0.11.1 fix (`16a750b`) only addressed the `..` traversal vector with normpath; the symlink vector requires `os.path.realpath()`, which was not used. |
| **Why missed** | The v0.11.1 fix was specifically scoped to path traversal (`..` sequences) and explicitly chose normpath over realpath to avoid filesystem I/O in the evaluation path. The commit message notes "Pure string operation -- no filesystem I/O, no symlink resolution, works in test harnesses and remote evaluation." The tradeoff was deliberate but the symlink risk was documented only in the audit report, not considered during the original fix. Sandbox behavior tests (`test_sandbox_red_team.py`, `test_sandbox_path_traversal.py`) were added alongside the v0.11.1 fix but focused on `..` traversal, not symlinks. |
| **Time exposed** | 1 day (2026-02-24 to 2026-02-25). The sandbox feature was brand new. |

### 4. Approval timeout audit mislabel

| Attribute | Detail |
|-----------|--------|
| **Introduced in** | PR #51 (`231c645`, 2026-02-22) -- approval protocol implementation |
| **Introduced by** | `a936136` -- pipeline approval wiring |
| **Root cause** | The approval resolution logic uses `approved = decision.approved` at the top, then checks `if not approved and decision.status == ApprovalStatus.TIMEOUT` for the timeout case, and `elif decision.approved` for the explicit approval case. The bug: when `LocalApprovalBackend` returns a timeout with `approved=True` (for `timeout_effect: allow`), the code enters the `elif decision.approved` branch and emits `CALL_APPROVAL_GRANTED` instead of `CALL_APPROVAL_TIMEOUT`. The tool call proceeds correctly, but the audit trail incorrectly records it as an explicit human approval rather than a timeout-with-fallback. |
| **Why missed** | The test `test_timeout_effect_allow_executes_tool` verifies the tool executes (functional correctness), but does not assert which audit action was emitted. The audit report section 6.2 investigated this path and concluded "Bug does NOT exist" because it tested the functional outcome (tool execution), not the audit fidelity. The code reviewer checklist mentions "Audit completeness: every code path emits an audit event" (section 10) but does not specify "audit events must accurately describe the decision path taken." |
| **Time exposed** | 3 days (2026-02-22 to 2026-02-25). Only affects audit trail accuracy, not enforcement correctness. |

### 5. tool_name validation missing

| Attribute | Detail |
|-----------|--------|
| **Introduced in** | `0097bbb` (2026-02-06) -- foundation commit |
| **Introduced by** | Original `create_envelope()` factory, which deep-copies args and metadata but performs no validation on `tool_name` |
| **Root cause** | `create_envelope()` was designed as an immutability guarantee (deep-copy args, metadata, principal), not an input validation boundary. The `tool_name` parameter was assumed to come from framework adapters, which receive it from LLM tool-use APIs. No validation was added for null bytes, control characters, or path separators, which could corrupt session storage keys (`f"s:{sid}:tool:{tool_name}"`), audit records, or log output. |
| **Why missed** | The API Design Checklist in CLAUDE.md says "Every accepted parameter has an observable effect" but `tool_name` is a required positional parameter, not an optional one -- the checklist was interpreted as applying to optional/configurable parameters only. No adversarial input tests existed for `create_envelope()`. The `ToolEnvelope` is a frozen dataclass, so there was an implicit assumption that "whatever goes in is correct." |
| **Time exposed** | 19 days (2026-02-06 to 2026-02-25). Present since project inception. |

### 6. MemoryBackend race condition

| Attribute | Detail |
|-----------|--------|
| **Introduced in** | `0097bbb` (2026-02-06) -- foundation commit |
| **Introduced by** | Original `MemoryBackend` implementation with no locking on `increment()` or `delete()` |
| **Root cause** | `MemoryBackend.increment()` performs read-modify-write on `self._counters[key]` without an `asyncio.Lock`. In concurrent async code (multiple tool calls evaluated in parallel via `asyncio.gather`), two coroutines can read the same counter value before either writes, causing a lost update. The protocol docstring says "increment() MUST be atomic" but the implementation did not enforce this. Similarly, `delete()` pops from two dicts non-atomically. |
| **Why missed** | MemoryBackend is documented as "In-memory storage for development and testing" and "single-process scripts." The assumption was that single-process means single-threaded, but Python's async model allows concurrent coroutines within a single process and single thread. No concurrent test existed -- all MemoryBackend tests were sequential single-call tests. The protocol docstring's "MUST be atomic" requirement was not verified by any test. |
| **Time exposed** | 19 days (2026-02-06 to 2026-02-25). Present since project inception. Practical impact is low in sequential usage patterns but becomes real with `asyncio.gather`-based parallel tool evaluation. |

---

## Review Process Gaps

### Gap 1: No adversarial/negative testing culture

All 6 findings share a common pattern: the code was tested for correctness (does it work when used as intended?) but not for adversarial resilience (what happens with malicious, malformed, or unexpected input?). Specific gaps:

- **BashClassifier**: Tested that `ls` returns READ. Never tested that `"ls\nrm -rf /"` returns IRREVERSIBLE.
- **ServerBackend**: Tested happy path and 404. Never tested ConnectionError or 500.
- **create_envelope()**: Tested with normal tool names. Never tested with null bytes or control characters.
- **MemoryBackend**: Tested sequential calls. Never tested concurrent calls.
- **Sandbox**: Tested that `..` traversal is denied (added in v0.11.1). Never tested symlink resolution.

### Gap 2: "Not a security boundary" disclaimers suppress scrutiny

The BashClassifier docstring says "This is a heuristic, not a security boundary." While technically accurate, this framing discouraged anyone from investing in completeness. In practice, the BashClassifier's output (`SideEffect.READ` vs `IRREVERSIBLE`) determines whether postcondition effects like `effect: redact` or `effect: deny` are applied. A bypass of the classifier has real governance consequences even if the classifier itself is not the "boundary."

### Gap 3: Audit fidelity not tested separately from functional correctness

The approval timeout bug (finding #4) passed all functional tests -- the tool call was correctly allowed or denied. But the audit event emitted to sinks was inaccurate. Tests verified `EdictumDenied` was raised or not raised, but never asserted on the specific `AuditAction` enum value passed to the sink. This is a class of bug where "the system does the right thing but lies about why."

### Gap 4: Protocol contracts not enforced by tests

`StorageBackend` protocol says "increment() MUST be atomic." `MemoryBackend` implements the protocol but violates this requirement. No test asserts atomicity. Protocol docstrings are promises to users; without tests, they are unenforceable documentation.

### Gap 5: Fail-open vs fail-closed not part of review vocabulary

The code reviewer checklist (code-reviewer.md section 9 "Security") covers injection, deserialization, and hardcoded secrets, but does not include "fail-open vs fail-closed" as a review criterion. For a governance library, the most important security property is that errors result in denial, not silent allowance. The ServerBackend fail-open bug would have been trivially caught by a checklist item like: "Exception handlers in governance-relevant code paths: do they fail open or fail closed?"

---

## CI Gaps

### What CI covers

| Check | Coverage |
|-------|----------|
| `pytest tests/ -v` | Functional correctness across Python 3.11, 3.12, 3.13 |
| `ruff check src/ tests/` | Style and basic code quality |
| AI code review (review.yml) | Architecture, terminology, docs-code sync, API design |

### What CI does NOT cover

| Missing Check | Would Have Caught |
|---------------|-------------------|
| **No SAST tool** (bandit, semgrep, CodeQL) | ServerBackend `except Exception` fail-open (bandit B110), broad exception catching patterns |
| **No adversarial test suite** | BashClassifier bypasses, tool_name injection, sandbox symlink escape |
| **No concurrency tests** | MemoryBackend race condition |
| **No audit assertion tests** | Approval timeout mislabel (correct action, wrong audit event) |
| **No protocol compliance tests** | MemoryBackend violating "MUST be atomic" protocol contract |
| **No security-focused markers** | `pytest -m security` does not exist as a CI step; `@pytest.mark.security` markers exist in the fix but are not enforced |

### Review workflow timing

The AI code review workflow (review.yml) was introduced on 2026-02-22 (PR #48). The Server SDK (PR #52) and Approval Protocol (PR #51) were merged the **same day**. The review workflow was being iterated on during the same period these features shipped. It is unclear whether #51 and #52 received full AI review or were merged during the workflow transition.

The sandbox feature (PR #54, 2026-02-24) was merged after the review workflow was stable, and did receive AI review. However, the reviewer checklist does not include path traversal, symlink resolution, or filesystem security as review criteria -- these fall outside the categories defined in code-reviewer.md.

---

## Preventive Measures

### Immediate (before v0.11.2 release)

1. **Commit the staged fixes** on `fix/security-remediation-v0.11.2` and open a PR.
2. **Add `@pytest.mark.security` marker** to all security-relevant tests and add `pytest -m security` as a CI step.
3. **Add fail-open/fail-closed to the review checklist**: In `.claude/agents/code-reviewer.md` section 9, add: "Exception handlers in governance-critical code paths must fail closed (deny), not open (allow). Flag any `except Exception: return None` or similar patterns."

### Short-term (next 2 releases)

4. **Add bandit to CI**: `pip install bandit && bandit -r src/ -ll` catches broad exception handlers (B110), hardcoded passwords, and other common patterns. Low effort, high signal.
5. **Add adversarial test fixtures**: Create `tests/test_adversarial/` with:
   - `test_bash_classifier_bypass.py` -- all known bypass categories (without specific exploit strings)
   - `test_tool_name_injection.py` -- null bytes, control chars, path separators
   - `test_sandbox_escape.py` -- symlinks, double encoding, case sensitivity
   - `test_backend_failure_modes.py` -- network errors, timeouts, partial failures
6. **Add audit assertion helpers**: Create a `CapturingAuditSink` test fixture that records emitted `AuditAction` values. Use it to assert not just "was the tool allowed/denied" but "was the correct audit action emitted."
7. **Add protocol compliance tests**: For every Protocol class, add a test that verifies the implementation satisfies the documented invariants (e.g., atomicity of increment under concurrent access).

### Structural (ongoing)

8. **Red team every new enforcement boundary**: Before shipping any new feature that makes allow/deny decisions (sandbox, approval, new contract types), run a structured adversarial session against it. Document the attack vectors tested and the results.
9. **Separate "works correctly" tests from "resists abuse" tests**: Functional tests answer "does it work?" Security tests answer "can it be bypassed?" These are different test suites with different review standards.
10. **Treat audit fidelity as a first-class correctness property**: An audit event that misrepresents the decision path is a bug, even if the enforcement outcome is correct. Audit consumers (compliance teams, dashboards) depend on accurate labels.

---

## Summary

Three of the six findings (BashClassifier bypasses, tool_name validation, MemoryBackend race condition) trace back to the project's very first code commit on 2026-02-06. They were carried forward through the rename and 18 subsequent releases without detection. The remaining three were introduced in the rapid v0.10.0/v0.11.0 feature push on 2026-02-22 to 2026-02-24, a 3-day period that shipped the approval protocol, server SDK, and sandbox contracts.

The common thread is not carelessness but a systematic gap: the project has strong positive testing (97%+ coverage, behavior tests, adapter parity tests, docs-code sync) but no adversarial testing discipline. Every finding would have been caught by a test that asks "what happens when the input is hostile?" rather than "does it work with well-formed input?"

The CI pipeline runs pytest and ruff but lacks static analysis (SAST) tooling that would flag broad exception handlers, missing input validation, and race conditions. Adding bandit alone would have caught finding #1 on the day it was introduced.
