# Roadmap

This page tracks what Edictum has shipped, what is actively being built, and what is planned. Items move through three stages: [Shipped], [In Progress], and [Planned].

---

## [Shipped] Core Pipeline (v0.5.x)

The foundation is production-usable today as an in-process library (v0.5.3).

- **Enforcement pipeline** with preconditions, postconditions, and session contracts
- **6 framework adapters**: LangChain, OpenAI Agents SDK, CrewAI, Agno, Semantic Kernel, Claude Agent SDK
- **YAML contract engine** with JSON Schema validation and SHA-256 versioning
- **CLI tools**: `edictum validate`, `edictum check`, `edictum diff`, `edictum replay`, `edictum test`
- **OpenTelemetry** span emission with OTel Collector support
- **Observe mode** for shadow-testing contracts against live traffic before enforcing
- **Postcondition findings** interface with remediation callbacks (`on_postcondition_warn`)
- **Automatic secret redaction** in audit events via `RedactionPolicy`
- **Built-in contract templates**: `file-agent`, `research-agent`, `devops-agent`

---

## [In Progress] PII Detection (v0.6.0)

Tool outputs often contain personally identifiable information that should not propagate back to the LLM or appear in logs. v0.6.0 adds pluggable PII detection as a first-class pipeline feature.

- **PIIDetector protocol** in core (MIT-licensed) -- a pluggable detection interface that any implementation can satisfy
- **RegexPIIDetector** -- 8 built-in patterns: SSN, email, phone, IBAN, credit card, patient ID, date of birth, name
- **YAML `pii_detection` shorthand** for declaring PII checks directly in contract bundles
- **Enterprise detectors** (separate `edictum-ee` package, shipped under `ee/`):
    - `PresidioPIIDetector` -- ML/NER-based detection via Microsoft Presidio
    - `CompositePIIDetector` -- combine multiple detectors with configurable thresholds

---

## [Planned] Production Observability

Production deployments need audit data flowing to existing infrastructure, not just stdout.

- **Enterprise audit sinks**: File (`.jsonl`), Webhook, Splunk HEC, Datadog
- **Deployment recipes**: end-to-end guides for OTel to Grafana, Datadog, and Splunk

---

## [Planned] Enterprise Control Plane

Single-agent, in-process enforcement covers most use cases today. For organizations running fleets of agents, the next step is centralized contract management.

- **Central Policy Server** -- agents pull contracts on startup, with versioning and hot-reload
- **Governance Dashboard** -- visualize contract evaluations, denial rates, and contract drift across agents
- **RBAC for contract management** -- control who can create, modify, and deploy contracts
- **SSO integration** -- Okta, Azure AD
- **Human approval workflows** -- require human sign-off before specific tool calls execute
- **Cross-agent session tracking** -- correlate tool calls across multiple agents in a single workflow
