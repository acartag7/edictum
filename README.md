# Edictum

[![PyPI](https://img.shields.io/pypi/v/edictum?cacheSeconds=3600)](https://pypi.org/project/edictum/)
[![License](https://img.shields.io/pypi/l/edictum?cacheSeconds=86400)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/edictum?cacheSeconds=86400)](https://pypi.org/project/edictum/)

**Runtime contract enforcement for AI agent tool calls.**

AI agents call tools with real-world side effects -- reading files, querying databases, executing commands. The standard defense is prompt engineering, but prompts are suggestions the LLM can ignore. Edictum enforces contracts at the decision-to-action seam: before a tool call executes, Edictum checks it against YAML contracts and denies it if it violates policy. The agent cannot bypass it.

This is not feature flags. This is not prompt guardrails. Edictum is a deterministic enforcement point for tool calls -- preconditions before execution, postconditions after, session limits across turns, and a full audit trail.

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
      message: "Sensitive file '{args.path}' denied."
      tags: [secrets, dlp]
```

**Python**

```python
import asyncio
from edictum import Edictum, EdictumDenied

async def read_file_fn(path):
    return open(path).read()

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
  contracts.yaml -- 1 contract (1 pre)

$ edictum check contracts.yaml --tool read_file --args '{"path": ".env"}'
  DENIED by block-sensitive-reads
   Message: Sensitive file '.env' denied.
   Tags: secrets, dlp
   Rules evaluated: 1
```

**Framework integration (one adapter, same contracts)**

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = LangChainAdapter(guard, principal=Principal(role="analyst"))
wrapper = adapter.as_tool_wrapper()
# Wraps any LangChain tool -- preconditions, audit, and session limits apply automatically
```

## How It Works

1. **Write contracts in YAML.** Preconditions deny dangerous calls before execution. Postconditions check tool output after. Session limits cap total calls and retries.
2. **Attach to your agent framework.** One adapter line. Same contracts across all six frameworks.
3. **Every tool call passes through the pipeline.** Preconditions, session limits, and principal context are evaluated. If any contract fails, the call is denied and never executes.
4. **Full audit trail.** Every evaluation produces a structured event with automatic secret redaction.

## How It Compares

| Approach | Scope | Runtime enforcement | Audit trail |
|---|---|---|---|
| Prompt/output guardrails | Input/output text | No -- advisory only | No |
| API gateways / MCP proxies | Network transport | Yes -- at the proxy | Partial |
| Security scanners | Post-hoc analysis | No -- detection only | Yes |
| Manual if-statements | Per-tool, ad hoc | Yes -- scattered logic | No |
| **Edictum** | **Tool call contracts** | **Yes -- deterministic pipeline** | **Yes -- structured + redacted** |

## Framework Support

Edictum integrates with six agent frameworks. Same YAML contracts, same enforcement, different adapter patterns:

| Framework | Integration | PII Redaction | Complexity |
|-----------|------------|---------------|------------|
| LangChain + LangGraph | `as_tool_wrapper()` | Full interception | Low |
| OpenAI Agents SDK | `as_guardrails()` | Logged only | Medium |
| Agno | `as_tool_hook()` | Full interception | Low |
| Semantic Kernel | `register()` | Full interception | Medium-High |
| CrewAI | `register()` | Partial | High |
| Claude Agent SDK | `to_sdk_hooks()` | Logged only | Low |

See [Adapter Docs](https://acartag7.github.io/edictum/adapters/overview/) for setup, known limitations, and recommendations.

## Install

Requires Python 3.11+. Current version: **v0.5.3**.

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
- **[Framework Adapters](https://acartag7.github.io/edictum/adapters/overview/)** -- Integration guides for six frameworks

## Links

- [Documentation](https://acartag7.github.io/edictum/)
- [GitHub](https://github.com/acartag7/edictum)
- [PyPI](https://pypi.org/project/edictum/)
- [Changelog](CHANGELOG.md)
- [License](LICENSE) (MIT)
