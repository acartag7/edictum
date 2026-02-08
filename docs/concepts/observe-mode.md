# Observe Mode

Observe mode lets you shadow-test contracts against live traffic without denying any tool calls. Preconditions that would fire emit `CALL_WOULD_DENY` audit events instead of denying. The tool call proceeds normally.

This gives you real data on what your contracts would do before you enforce them.

## The Workflow

```
1. Deploy contracts in observe mode
        |
2. Review CALL_WOULD_DENY audit events
        |
3. Tune contracts (fix false positives, tighten loose rules)
        |
4. Switch to enforce mode
```

**Step 1: Deploy in observe mode.** Set `mode: observe` in your contract bundle and deploy to production. Agents run normally -- no tool calls are denied.

**Step 2: Review audit events.** Every precondition that would have denied a call emits a `CALL_WOULD_DENY` event. Query your audit sink (stdout, file, OTel) for these events to see which contracts fire and how often.

**Step 3: Tune.** If a contract fires too often (false positives), narrow its `when` condition. If it never fires, check that the selectors match your tool arguments. Use `edictum check` to test specific tool calls against your contracts without running them.

**Step 4: Enforce.** Change `mode: observe` to `mode: enforce`. Contracts now actively deny tool calls.

## Enabling Observe Mode

### Pipeline-level: all contracts observe

Set the default mode in your contract bundle:

```yaml
defaults:
  mode: observe
```

Every contract in the bundle runs in observe mode. No tool calls are denied.

### Per-contract: shadow-test one rule

Leave the bundle default as `enforce` and set `mode: observe` on specific contracts:

```yaml
defaults:
  mode: enforce

contracts:
  - id: block-dotenv
    type: pre
    tool: read_file
    when:
      args.path: { contains: ".env" }
    then:
      effect: deny
      message: "Blocked read of sensitive file: {args.path}"

  - id: experimental-api-check
    type: pre
    mode: observe
    tool: call_api
    when:
      args.endpoint: { contains: "/v1/expensive" }
    then:
      effect: deny
      message: "Expensive API call detected (observe mode)."
```

Here, `block-dotenv` enforces (denies matching calls) while `experimental-api-check` observes (logs what it would deny but allows the call).

## What Changes in Observe Mode

| Behavior | Enforce Mode | Observe Mode |
|----------|-------------|--------------|
| Precondition matches | Tool call is denied | Tool call proceeds |
| Audit event action | `CALL_DENIED` | `CALL_WOULD_DENY` |
| Tool executes | No | Yes |
| Postconditions run | N/A (tool didn't run) | Yes (tool ran) |
| Audit trail records the match | Yes | Yes |
| Session counters | Attempt counted, execution not | Attempt counted, execution counted |

The critical difference: in observe mode, the tool always executes. The audit trail shows you exactly what enforcement would have done, without any impact on the agent.

## Postconditions in Observe Mode

Postconditions always produce findings (warnings), never denials. In observe mode, postcondition findings are logged as `would_warn` instead of `postcondition_warning`. The `on_postcondition_warn` callback fires in both modes.

## When to Use Observe Mode

**Rolling out new contracts.** Write a new precondition, deploy it in observe mode, and watch the `CALL_WOULD_DENY` events for a few days. If the false positive rate is acceptable, switch to enforce.

**Testing in production.** Your staging environment may not exercise the same tool call patterns as production. Observe mode lets you validate contracts against real agent behavior.

**Compliance shadow runs.** Compliance teams can define contracts for upcoming regulatory requirements, deploy them in observe mode, and measure the impact before the deadline. The audit trail serves as evidence of preparedness.

**Gradual rollout.** Start with all contracts in observe mode. Promote them to enforce one at a time as you gain confidence, starting with the most critical contracts (secret protection, destructive command prevention).

## Reviewing Observe-Mode Events

Audit events from observe mode include the same fields as enforce-mode events: tool name, arguments, principal, contract ID, policy version, and session counters. The `action` field distinguishes them:

- `CALL_DENIED` -- enforce mode, call was denied
- `CALL_WOULD_DENY` -- observe mode, call would have been denied

Filter your audit sink for `CALL_WOULD_DENY` to see the shadow denial report. Group by `decision_name` (the contract `id`) to see which contracts fire most often.

## Next Steps

- [Contracts](contracts.md) -- writing preconditions, postconditions, and session contracts
- [How it works](how-it-works.md) -- the full pipeline walkthrough
- [Quickstart](../quickstart.md) -- try observe mode in the bonus step
- [YAML reference](../contracts/yaml-reference.md) -- `mode` field and `defaults` block
