# Edictum

[![PyPI](https://img.shields.io/pypi/v/edictum?cacheSeconds=3600)](https://pypi.org/project/edictum/)
[![License](https://img.shields.io/pypi/l/edictum?cacheSeconds=86400)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/edictum?cacheSeconds=86400)](https://pypi.org/project/edictum/)

**Runtime contracts for AI agents.**

AI agents make tool calls. Tool calls have side effects. Nobody governs what happens between "agent decides" and "tool executes." Edictum is that governance layer — preconditions, postconditions, session limits, and a full audit trail, enforced at the point where decision becomes action.

## Show Me

**contracts.yaml**

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: my-policy

defaults:
  mode: enforce

contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "credentials", ".pem", "id_rsa"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' blocked."
      tags: [secrets, dlp]
```

**Python**

```python
import asyncio
from edictum import Edictum, EdictumDenied

async def main():
    guard = Edictum.from_yaml("contracts.yaml")

    try:
        result = await guard.run("read_file", {"path": "/app/config.json"}, read_file_fn)
        print(result)
    except EdictumDenied as e:
        print(f"Denied: {e}")

asyncio.run(main())
```

**CLI**

```bash
$ edictum validate contracts.yaml
✓ contracts.yaml — 1 contract (1 pre)

$ edictum check contracts.yaml --tool read_file --args '{"path": ".env"}'
⛔ DENIED by block-sensitive-reads
   Message: Sensitive file '.env' blocked.
   Tags: secrets, dlp
   Rules evaluated: 1
```

**Framework integration (one adapter, same guard)**

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = LangChainAdapter(guard, principal=Principal(role="analyst"))
wrapper = adapter.as_tool_wrapper()
# Wraps any LangChain tool — preconditions, audit, and session limits apply automatically
```

## Features

- **YAML contracts** — Preconditions, postconditions, and session limits declared in version-controlled YAML files
- **6 framework adapters** — LangChain, CrewAI, Agno, Semantic Kernel, OpenAI Agents SDK, Claude Agent SDK
- **Audit trail** — Structured JSON events with automatic redaction of secrets (OpenAI keys, AWS creds, JWTs, GitHub tokens)
- **Observe mode** — Shadow-deploy contracts without blocking; review `CALL_WOULD_DENY` events before enforcing
- **CLI tooling** — `validate`, `check`, `diff`, and `replay` commands for CI/CD integration
- **Principal context** — Role, ticket ref, and claims propagated through every decision and audit event
- **Postcondition findings** — Structured detection results from tool output checks, with optional remediation callbacks (redact PII, replace secrets, log and continue)
- **Session limits** — Cap total calls, attempts, and per-tool executions to catch runaway agents
- **Zero runtime deps** — Pure Python 3.11+. OTel and adapters are optional extras

## How It Compares

| Approach | Scope | Runtime enforcement | Audit trail |
|---|---|---|---|
| Prompt/output guardrails | Input/output text | No — advisory only | No |
| API gateways / MCP proxies | Network transport | Yes — at the proxy | Partial |
| Security scanners | Post-hoc analysis | No — detection only | Yes |
| Manual if-statements | Per-tool, ad hoc | Yes — scattered logic | No |
| **Edictum** | **Tool call contracts** | **Yes — deterministic pipeline** | **Yes — structured + redacted** |

## Framework Support

Edictum integrates with 6 agent frameworks. Same YAML contracts,
same governance, different integration patterns:

| Framework | Integration | PII Redaction | Complexity |
|-----------|------------|---------------|------------|
| LangChain + LangGraph | `as_tool_wrapper()` | Full interception | Low |
| OpenAI Agents SDK | `as_guardrails()` | Logged only | Medium |
| Agno | `as_tool_hook()` | Full interception | Low |
| Semantic Kernel | `register()` | Full interception | Medium–High |
| CrewAI | `register()` | Partial | High |
| Claude Agent SDK | `to_sdk_hooks()` | Logged only | Low |

See [Adapter Docs](https://acartag7.github.io/edictum/adapters/overview/) for setup, known limitations, and recommendations.

## Install

```bash
pip install edictum              # core (zero deps)
pip install edictum[yaml]        # + YAML contract engine
pip install edictum[otel]        # + OpenTelemetry span emission
pip install edictum[cli]         # + validate/check/diff/replay CLI
pip install edictum[all]         # everything
```

## Built-in Templates

```python
guard = Edictum.from_template("file-agent")      # secret file protection, destructive cmd blocking
guard = Edictum.from_template("research-agent")   # output PII detection, session limits
guard = Edictum.from_template("devops-agent")     # role gates, ticket requirements, bash safety
```

## Demos & Examples

- **[edictum-demo](https://github.com/acartag7/edictum-demo)** -- Full scenario demos, adversarial tests, benchmarks, and Grafana observability
- **[Contract Patterns](https://acartag7.github.io/edictum/contracts/patterns/)** -- Real-world contract recipes by concern
- **[Framework Adapters](https://acartag7.github.io/edictum/adapters/overview/)** -- Integration guides for 6 frameworks

## Links

- [Documentation](https://acartag7.github.io/edictum/)
- [GitHub](https://github.com/acartag7/edictum)
- [PyPI](https://pypi.org/project/edictum/)
- [Changelog](CHANGELOG.md)
- [License](LICENSE) (MIT)