# Compliance Mapping

Edictum provides runtime governance for AI agent tool calls. This page maps
Edictum features to specific requirements in the EU AI Act and SOC 2 Trust
Services Criteria, with concrete configuration guidance for each control.

---

## EU AI Act

### Article 9 -- Risk Management System

Article 9 requires providers of high-risk AI systems to establish a risk management
system that identifies risks, estimates their likelihood and severity, adopts
mitigation measures, and documents the process throughout the system lifecycle.

| Requirement | Edictum Feature | Evidence / Configuration |
|-------------|-------------------|------------------------|
| Risk identification | Preconditions define what constitutes a risky tool call. Each contract names a specific risk (e.g. `no-destructive-bash`, `no-secrets-in-args`). | YAML contract file listing all governed risks. `edictum validate` confirms contracts are well-formed. |
| Risk estimation and evaluation | Observe mode (`mode: observe`) runs contracts in shadow without blocking, letting you measure how often each contract would fire on real traffic. | Audit events with `action: call_would_deny` record shadow denials. Query `decision_name` to get per-rule frequency. |
| Risk mitigation | Enforce mode (`mode: enforce`) blocks tool calls that violate contracts. Side-effect classification (`pure`, `read`, `write`, `irreversible`) scales the response to the severity of the action. | Audit events with `action: call_denied` confirm active mitigation. `side_effect` field in each event shows the risk tier. |
| Documentation throughout lifecycle | `policy_version` (SHA-256 of YAML) tracks which contract set was active for every decision. `edictum diff` shows changes between versions. `edictum replay` quantifies the impact of proposed changes. | Audit log with `policy_version` field. CI pipeline running `edictum diff` on every contract change PR. |
| Residual risk monitoring | Postconditions run after tool execution and record warnings when results violate expectations. Failures are recorded on the `CALL_EXECUTED` event. | Audit events with `action: call_executed` and `postconditions_passed: false`. |

### Article 14 -- Human Oversight

Article 14 requires that high-risk AI systems are designed to be effectively
overseen by natural persons, including the ability to understand the system's
capacities and limitations, to monitor operation, and to intervene or interrupt.

| Requirement | Edictum Feature | Evidence / Configuration |
|-------------|-------------------|------------------------|
| Understand capacities and limitations | Contract files are human-readable YAML that declare exactly what the agent is and is not allowed to do. `edictum check` lets a human test any hypothetical tool call without running it. | YAML contract file reviewed in code review. `edictum check` output in documentation or runbooks. |
| Monitor operation | Audit sinks stream every governance decision to local logs. OpenTelemetry spans route decisions to any observability backend (Datadog, Splunk, Grafana, Jaeger) via an OTel Collector. | `StdoutAuditSink` or `FileAuditSink` for local logs. `configure_otel()` or YAML `observability.otel` block for OTel span emission. OTel `edictum.calls.denied` / `edictum.calls.allowed` counters on dashboards. |
| Human-in-the-loop shadow testing | Observe mode evaluates contracts without enforcing them, producing `call_would_deny` audit events. Teams review shadow denials before switching to enforce mode. | Pipeline configured with `mode: observe`. Audit log analysis showing shadow denial rates over time before cutover. |
| Intervene and interrupt | Principal-based gating allows human-specified context (role, ticket reference) to gate tool access. Session limits (`max_attempts`, `max_tool_calls`) automatically halt runaway agents. | Contracts with `principal.role` conditions. `OperationLimits` configured with appropriate caps. Audit events showing `decision_source: attempt_limit` or `decision_source: operation_limit`. |
| Ability to override or reverse | Per-contract observe mode lets operators disable enforcement on individual rules without a full redeploy. `edictum replay` lets operators preview the impact before re-enabling enforcement. | Per-contract `mode: observe` in YAML. `edictum replay --only-changes` output in change management ticket. |

---

## SOC 2 Trust Services Criteria (CC6)

### CC6.1 -- Logical Access Security

The entity implements logical access security software, infrastructure, and
architectures to protect information assets.

| Requirement | Edictum Feature | Evidence / Configuration |
|-------------|-------------------|------------------------|
| Logical access controls over AI agent actions | `Principal` object carries identity context (`user_id`, `service_id`, `org_id`, `role`, `ticket_ref`, `claims`) through the entire governance pipeline. Preconditions can gate tool access based on any principal field. | Preconditions checking `envelope.principal.role`, `envelope.principal.claims`. Audit events containing the full `principal` dict. |
| Protection of sensitive data | `deny_sensitive_reads()` built-in blocks access to common secret paths (`~/.ssh/`, `.env`, `/var/run/secrets/`, AWS credentials). `RedactionPolicy` scrubs sensitive data from audit payloads. | `deny_sensitive_reads()` registered in Edictum. `RedactionPolicy` configured on all audit sinks. |
| Classification of information assets | `SideEffect` classification (`pure`, `read`, `write`, `irreversible`) categorizes every tool call by its potential impact. Unregistered tools default to `irreversible` (most restrictive). | `ToolRegistry` configuration with explicit side-effect assignments. Default `IRREVERSIBLE` for unknown tools. |

### CC6.2 -- Prior to Issuing System Credentials and Granting System Access

The entity authorizes, establishes, and manages credentials for system users.

| Requirement | Edictum Feature | Evidence / Configuration |
|-------------|-------------------|------------------------|
| Identity propagation | `Principal` is set at the adapter level and propagated to every `ToolEnvelope`, `AuditEvent`, and governance decision. All six adapters support principal injection. | Adapter configuration passing `Principal(user_id=..., service_id=..., org_id=...)`. Audit events with `principal` field populated. |
| Credential-based access decisions | Preconditions can require specific principal fields to be present or match expected values before allowing tool execution. | Preconditions checking `envelope.principal is not None`, `envelope.principal.role == "admin"`, `envelope.principal.ticket_ref is not None`. |

### CC6.3 -- Authorization of System Access

The entity authorizes access to system resources consistent with job
responsibilities.

| Requirement | Edictum Feature | Evidence / Configuration |
|-------------|-------------------|------------------------|
| Role-based tool access | Preconditions gate tool access by `principal.role`. Different roles can have different tool permissions. | YAML contracts with conditions like `principal.role in ["admin", "sre"]` for destructive operations. |
| Ticket-based authorization | `principal.ticket_ref` enables change-management workflows where destructive operations require an associated incident or change ticket. | Preconditions requiring `envelope.principal.ticket_ref is not None` for write/irreversible tools. |
| Claims-based fine-grained access | `principal.claims` is an extensible dict that carries arbitrary authorization context (e.g. team membership, feature flags, ABAC attributes). | Preconditions checking `envelope.principal.claims.get("team") == "platform"` or similar custom claims. |

### CC6.6 -- System Operations

The entity implements logical access security measures to protect against
threats from sources outside its system boundaries.

| Requirement | Edictum Feature | Evidence / Configuration |
|-------------|-------------------|------------------------|
| Comprehensive audit trail | Every governance decision produces an `AuditEvent` with 30+ fields covering identity, tool details, principal, decision rationale, execution outcome, and session counters. | Audit sinks configured and emitting. JSONL files or log aggregator queries showing complete event records. |
| Session boundary enforcement | `OperationLimits` caps total attempts (`max_attempts`), total executions (`max_tool_calls`), and per-tool executions (`max_calls_per_tool`). | `OperationLimits(max_attempts=500, max_tool_calls=200, max_calls_per_tool={"Bash": 50})`. Audit events with `decision_source: operation_limit`. |
| Runaway agent detection | `max_attempts` counts denied calls too, catching agents stuck in retry loops. Consecutive failure tracking via `Session.consecutive_failures()` enables circuit-breaker contracts. | Session contracts that check `await session.consecutive_failures() < threshold`. Audit events with `session_attempt_count` and `session_execution_count`. |

### CC6.8 -- Change Management

The entity authorizes, designs, develops, configures, documents, tests,
approves, and implements changes to infrastructure and software.

| Requirement | Edictum Feature | Evidence / Configuration |
|-------------|-------------------|------------------------|
| Policy versioning | `policy_version` in every audit event is the SHA-256 hash of the YAML contract file. This ties every decision to a specific, reproducible policy state. | Audit events with `policy_version` field. Contract files stored in version control. |
| Change impact analysis | `edictum diff` compares two contract files and reports added, removed, and changed contract IDs. `edictum replay` re-evaluates historical audit events against a proposed contract file and reports what would change. | `edictum diff old.yaml new.yaml` in CI on every PR. `edictum replay --contracts new.yaml --audit-log prod.jsonl --only-changes` in change approval workflow. |
| Policy error detection | `policy_error: true` in audit events indicates a contract loading failure. The system fails closed (denies calls) when the policy cannot be loaded, and records the error state for monitoring. | Alerts on `policy_error: true` in audit events. Monitoring dashboard for contract load failures. |
| Staged rollout | Per-contract observe mode allows new contracts to be deployed in shadow mode, evaluated against real traffic, and promoted to enforce mode after validation. | New contracts added with `mode: observe`. Observe-mode audit events analyzed. Mode changed to `enforce` after review. |

---

## Audit Evidence Matrix

For auditors who need a quick reference mapping evidence artifacts to controls:

| Evidence Artifact | EU AI Act | SOC 2 |
|-------------------|-----------|-------|
| YAML contract file in version control | Art. 9 (documentation) | CC6.8 (change management) |
| `edictum validate` output in CI | Art. 9 (risk identification) | CC6.8 (testing) |
| `edictum diff` output in PR review | Art. 9 (lifecycle documentation) | CC6.8 (change impact) |
| `edictum replay` report | Art. 9 (risk estimation), Art. 14 (override preview) | CC6.8 (change impact analysis) |
| Audit events with `action: call_denied` | Art. 9 (risk mitigation) | CC6.6 (system operations) |
| Audit events with `action: call_would_deny` | Art. 14 (shadow testing) | CC6.8 (staged rollout) |
| Audit events with `principal` populated | Art. 14 (oversight) | CC6.1 (logical access), CC6.2 (credentials) |
| Audit events with `policy_version` | Art. 9 (documentation) | CC6.8 (versioning) |
| Audit events with `policy_error: true` | Art. 9 (residual risk) | CC6.8 (error detection) |
| OTel dashboards with denial rates | Art. 14 (monitoring) | CC6.6 (system operations) |
| `RedactionPolicy` configuration | -- | CC6.1 (data protection) |
| `OperationLimits` configuration | Art. 14 (interrupt capability) | CC6.6 (boundary enforcement) |
