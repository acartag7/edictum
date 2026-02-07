# Edictum

**Runtime contracts for AI agents.**

AI agents that call tools -- reading files, querying databases, invoking APIs -- operate with real-world side effects. A misconfigured agent can exfiltrate secrets, exceed rate limits, or mutate production data before anyone notices. Edictum sits between your agent and its tools, enforcing contracts that deny dangerous calls before they execute.

```yaml
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: file-safety
defaults:
  mode: enforce
contracts:
  - type: pre
    tool: read_file
    when:
      any:
        - args.path: { contains: ".env" }
        - args.path: { starts_with: "/etc/shadow" }
        - args.path: { matches: ".*\\.(pem|key)$" }
    then:
      effect: deny
      message: "Blocked read of sensitive path: {args.path}"
```

With this contract loaded, any agent framework integrated through Edictum will be denied access to `.env` files, shadow passwords, and private keys -- regardless of which LLM is driving the agent.

---

## Feature Highlights

### Deterministic Governance Pipeline

Every tool call passes through a fixed evaluation order: attempt limits, before-hooks, preconditions, session contracts, then execution limits. No probabilistic filtering. No LLM-in-the-loop judgment calls. A contract either passes or it denies.

### YAML Contracts

Define preconditions, postconditions, and session limits in declarative YAML. Contracts support a full expression grammar with `all`, `any`, and `not` combinators, field selectors like `args.<key>` and `principal.role`, and operators from simple equality to regex matching. No Python required.

### Six Framework Adapters

Thin translation layers for **Claude Agent SDK**, **LangChain**, **CrewAI**, **Agno**, **Semantic Kernel**, and **OpenAI Agents**. Each adapter maps the framework's native hook or middleware pattern into Edictum's canonical pipeline. Swap frameworks without rewriting your security policy.

### Observe Mode

Shadow-test contracts against live traffic before enforcing them. In observe mode, calls that would be denied are logged as `CALL_WOULD_DENY` audit events but allowed to proceed. Roll out new policies with zero risk of breaking production agents.

### Principal-Aware Policies

Attach identity context -- `user_id`, `role`, `org_id`, `ticket_ref`, and arbitrary `claims` -- to every tool call. Write contracts that allow SREs to read logs but deny interns, or require a ticket reference for database mutations.

### Structured Audit Trail

Every evaluation produces an `AuditEvent` with the tool name, verdict, principal, timing, and policy version. Ship events to stdout or JSON files for local development, and route OpenTelemetry spans to any backend (Datadog, Splunk, Grafana, Jaeger) for production observability. Automatic secret redaction ensures credentials never leak into your audit stream.

### OpenTelemetry Integration

Optional spans and metrics for every contract evaluation. If the OpenTelemetry SDK is installed, Edictum emits traces automatically. If not, it degrades to a silent no-op. Zero configuration required either way.

### Zero Runtime Dependencies

The core library has no runtime dependencies beyond Python 3.11+. YAML support, adapter extras, and telemetry are opt-in installs.

---

## Installation

```bash
# Core library (Python contracts, pipeline, audit)
pip install edictum

# With YAML contract support
pip install edictum[yaml]

# Everything (all adapters, YAML, telemetry)
pip install edictum[all]
```

---

## Next Steps

- [**Quickstart**](quickstart.md) -- install, write a contract, and block your first dangerous call in five minutes
- **YAML Reference** -- full schema documentation for `edictum/v1` contract bundles
- **Adapter Guides** -- framework-specific integration for all six supported agent libraries
- **Audit and Observability** -- configure local sinks and OpenTelemetry for production monitoring
