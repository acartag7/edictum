# Edictum

Your AI agent is one tool call away from a data breach.

```yaml
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: file-safety
defaults:
  mode: enforce
contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      any:
        - args.path: { contains: ".env" }
        - args.path: { contains: ".pem" }
        - args.path: { matches: ".*id_rsa$" }
    then:
      effect: deny
      message: "Blocked read of sensitive file: {args.path}"
```

```python
from edictum import Edictum, EdictumDenied

guard = Edictum.from_yaml("contracts.yaml")
result = await guard.run("read_file", {"path": "config.txt"}, read_file_fn)  # allowed
result = await guard.run("read_file", {"path": ".env"}, read_file_fn)        # raises EdictumDenied
```

## Install

```bash
pip install edictum[yaml]
```

## What It Does

- **Preconditions** -- block dangerous tool calls before they execute
- **Postconditions** -- warn when tool output contains PII or secrets
- **Session limits** -- cap total tool calls, per-tool calls, and retry attempts
- **Observe mode** -- shadow-test contracts against live traffic before enforcing
- **Audit trail** -- structured events for every tool call, with automatic secret redaction

## Next Steps

- [Quickstart](quickstart.md) -- install, write a contract, and block your first call in five minutes
- [Why Edictum?](why.md) -- benchmarks, adapter comparison, and what contracts solve that prompts cannot
- [YAML Reference](contracts/yaml-reference.md) -- full schema for `edictum/v1` contract bundles
- [Adapters](adapters/overview.md) -- integration guides for all six supported frameworks
