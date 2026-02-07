# CallGuard

[![PyPI](https://img.shields.io/pypi/v/callguard)](https://pypi.org/project/callguard/)
[![License](https://img.shields.io/pypi/l/callguard)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/callguard)](https://pypi.org/project/callguard/)

**Runtime contracts for AI agents.**

AI agents make tool calls. Tool calls have side effects. Nobody governs what happens between "agent decides" and "tool executes." CallGuard is that governance layer — preconditions, postconditions, session limits, and a full audit trail, enforced at the point where decision becomes action.

## Show Me

**contracts.yaml**

```yaml
apiVersion: callguard/v1
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
from callguard import CallGuard, CallGuardDenied

async def main():
    guard = CallGuard.from_yaml("contracts.yaml")

    try:
        result = await guard.run("read_file", {"path": "/app/config.json"}, read_file_fn)
        print(result)
    except CallGuardDenied as e:
        print(f"Denied: {e}")

asyncio.run(main())
```

**CLI**

```bash
$ callguard validate contracts.yaml
✓ contracts.yaml — 1 contract (1 pre)

$ callguard check contracts.yaml --tool read_file --args '{"path": ".env"}'
⛔ DENIED by block-sensitive-reads
   Message: Sensitive file '.env' blocked.
   Tags: secrets, dlp
   Rules evaluated: 1
```

**Framework integration (one adapter, same guard)**

```python
from callguard.adapters.langchain import CallGuardMiddleware

middleware = CallGuardMiddleware(guard)
# Wraps any LangChain tool — preconditions, audit, and session limits apply automatically
```

## Features

- **YAML contracts** — Preconditions, postconditions, and session limits declared in version-controlled YAML files
- **6 framework adapters** — LangChain, CrewAI, Agno, Semantic Kernel, OpenAI Agents SDK, Claude Agent SDK
- **Audit trail** — Structured JSON events with automatic redaction of secrets (OpenAI keys, AWS creds, JWTs, GitHub tokens)
- **Observe mode** — Shadow-deploy contracts without blocking; review `CALL_WOULD_DENY` events before enforcing
- **CLI tooling** — `validate`, `check`, `diff`, and `replay` commands for CI/CD integration
- **Principal context** — Role, ticket ref, and claims propagated through every decision and audit event
- **Session limits** — Cap total calls, attempts, and per-tool executions to catch runaway agents
- **Zero runtime deps** — Pure Python 3.11+. OTel, sinks, and adapters are optional extras

## How It Compares

| Approach | Scope | Runtime enforcement | Audit trail |
|---|---|---|---|
| Prompt/output guardrails | Input/output text | No — advisory only | No |
| API gateways / MCP proxies | Network transport | Yes — at the proxy | Partial |
| Security scanners | Post-hoc analysis | No — detection only | Yes |
| Manual if-statements | Per-tool, ad hoc | Yes — scattered logic | No |
| **CallGuard** | **Tool call contracts** | **Yes — deterministic pipeline** | **Yes — structured + redacted** |

## Install

```bash
pip install callguard              # core (zero deps)
pip install callguard[yaml]        # + YAML contract engine
pip install callguard[sinks]       # + webhook, Splunk, Datadog sinks
pip install callguard[cli]         # + validate/check/diff/replay CLI
pip install callguard[all]         # everything
```

## Built-in Templates

```python
guard = CallGuard.from_template("file-agent")      # secret file protection, destructive cmd blocking
guard = CallGuard.from_template("research-agent")   # output PII detection, session limits
guard = CallGuard.from_template("devops-agent")     # role gates, ticket requirements, bash safety
```

## Links

- [Documentation](https://acartag7.github.io/callguard/)
- [GitHub](https://github.com/acartag7/callguard)
- [PyPI](https://pypi.org/project/callguard/)
- [Changelog](CHANGELOG.md)
- [License](LICENSE) (MIT)