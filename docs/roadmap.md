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

## [Planned] Contract Composition

As contract bundles grow, teams need to share common rules across YAML files without copy-paste.

- **Contract imports** -- reference shared contract fragments from other YAML files
- **Composition** -- build bundles from reusable pieces, override defaults per-bundle

This stays in OSS core. The contract language and its ergonomics are part of the evaluation engine.

---

## [Planned] Production Observability

Stdout and File (.jsonl) sinks ship today in OSS core for development and local audit. Production deployments need audit data flowing to existing infrastructure.

- **Enterprise audit sinks**: Webhook, Splunk HEC, Datadog -- network destinations for compliance-grade audit trails
- **Alert rules** -- notifications on abnormal patterns (denial spikes, PII detections, session exhaustion)
- **Deployment recipes**: end-to-end guides for OTel to Grafana, Datadog, and Splunk

---

## [Planned] Enterprise Contracts

Single-call contracts cover most enforcement scenarios. Some problems require looking across multiple calls or letting non-engineers author rules.

- **Sequence-aware contracts** -- detect suspicious patterns across multiple tool calls, not just single calls (e.g., read credentials then call external API)
- **NL → YAML authoring** -- compliance officers describe a rule in English, system generates the YAML contract

---

## [Planned] Enterprise Control Plane

Single-agent, in-process enforcement covers most use cases today. For organizations running fleets of agents, the next step is centralized contract management.

- **Central Policy Server** -- agents pull contracts on startup, with versioning and hot-reload
- **Governance Dashboard** -- visualize contract evaluations, denial rates, and contract drift across agents
- **RBAC for contract management** -- control who can create, modify, and deploy contracts
- **SSO integration** -- Okta, Azure AD
- **JWT/OIDC principal verification** -- server verifies the agent's claimed identity instead of trusting the caller
- **Human approval workflows** -- require human sign-off before specific tool calls execute
- **Cross-agent session tracking** -- correlate tool calls across multiple agents in a single workflow
