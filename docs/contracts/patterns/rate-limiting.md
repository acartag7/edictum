# Rate Limiting Patterns

Rate limiting contracts use session-level counters to govern cumulative agent behavior across tool calls. They prevent runaway agents from burning through API calls, hammering external services, or spinning in retry loops.

Session contracts have no `tool` or `when` fields. They track three types of counters: total successful executions, total attempts (including denied calls), and per-tool execution counts.

---

## Session-Wide Limits

Cap the total number of tool calls in a session. This is the most common session contract and the simplest way to prevent unbounded agent work.

**When to use:** You want a hard ceiling on how much work an agent can do before stopping and reporting progress.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: session-wide-limits

    defaults:
      mode: enforce

    contracts:
      - id: session-execution-cap
        type: session
        limits:
          max_tool_calls: 50
          max_attempts: 120
        then:
          effect: deny
          message: "Session limit reached. Summarize progress and stop."
          tags: [rate-limit]
    ```

=== "Python"

    ```python
    from edictum import Edictum, OperationLimits

    guard = Edictum(
        contracts=[...],
        limits=OperationLimits(
            max_tool_calls=50,
            max_attempts=120,
        ),
    )
    ```

**How it works:**
- `max_tool_calls` counts successful tool executions. When the agent has completed 50 tool calls, further calls are denied.
- `max_attempts` counts all contract evaluations, including denied calls. If the agent hits 120 attempts before 50 successful calls, something is wrong -- the agent is likely stuck in a denial loop.

**Gotchas:**
- Set `max_attempts` higher than `max_tool_calls`. Some denied attempts are normal -- the agent may probe a few blocked paths before finding an allowed one. A ratio of roughly 2:1 to 3:1 (attempts to calls) is typical.
- Session counters persist for the lifetime of the `Edictum` instance. If you reuse the instance across multiple logical sessions, counters accumulate. Create a new instance for each session if isolation is needed.

---

## Per-Tool Caps

Limit how many times a specific tool can be called. This prevents agents from overusing high-impact or expensive tools while leaving other tools uncapped.

**When to use:** Certain tools have outsized impact (deployments, notifications, external API calls) and should be capped independently of the overall session limit.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: per-tool-caps

    defaults:
      mode: enforce

    contracts:
      - id: per-tool-limits
        type: session
        limits:
          max_tool_calls: 100
          max_calls_per_tool:
            deploy_service: 3
            send_email: 10
            query_database: 30
        then:
          effect: deny
          message: "Tool call limit reached. Check which tool hit its cap and adjust your approach."
          tags: [rate-limit]
    ```

=== "Python"

    ```python
    from edictum import Edictum, OperationLimits

    guard = Edictum(
        contracts=[...],
        limits=OperationLimits(
            max_tool_calls=100,
            max_calls_per_tool={
                "deploy_service": 3,
                "send_email": 10,
                "query_database": 30,
            },
        ),
    )
    ```

**How it works:**
- `max_calls_per_tool` is a map of tool names to integer limits. Each tool is tracked independently.
- The session contract fires when any limit is exceeded -- either the overall `max_tool_calls` or any individual tool cap.
- Tools not listed in `max_calls_per_tool` are only constrained by `max_tool_calls`.

**Gotchas:**
- Per-tool caps and `max_tool_calls` are enforced together. If `max_tool_calls: 100` and `deploy_service: 3`, the agent is limited to 3 deploys AND 100 total calls. The first limit hit wins.
- The denial message is the same regardless of which limit triggered. If you need different messages per tool, use separate session contracts.

---

## Burst Protection

Combine `max_attempts` with `max_tool_calls` to detect and stop agents that are making rapid failed attempts -- a sign of a retry loop or misconfigured tool.

**When to use:** You want to detect agents that are stuck hammering a broken tool and stop them before they waste more resources.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: burst-protection

    defaults:
      mode: enforce

    contracts:
      - id: burst-detection
        type: session
        limits:
          max_tool_calls: 50
          max_attempts: 80
        then:
          effect: deny
          message: "Too many attempts relative to successful calls. The agent may be stuck. Review and adjust."
          tags: [rate-limit, burst]
    ```

=== "Python"

    ```python
    from edictum import Edictum, OperationLimits

    guard = Edictum(
        contracts=[...],
        limits=OperationLimits(
            max_tool_calls=50,
            max_attempts=80,
        ),
    )
    ```

**How it works:**
- If the agent reaches 80 attempts with far fewer than 50 successful calls, the `max_attempts` limit fires first. This catches the scenario where the agent is repeatedly denied and retrying the same operation.
- The tighter the ratio between `max_attempts` and `max_tool_calls`, the more aggressively you detect retry loops. A 1.5:1 ratio (like 80 attempts / 50 calls) is aggressive. A 3:1 ratio is more forgiving.

**Gotchas:**
- Every precondition evaluation counts as an attempt, even if the tool was ultimately allowed. In bundles with many preconditions, a single tool call may generate multiple attempt counts. Test your ratios against your actual contract bundle.

---

## Failure Escalation Detection

Detect when the ratio of attempts to executions indicates the agent is not making progress. This is a signal that the agent is stuck and needs to change its approach.

**When to use:** You want to detect agents that are failing repeatedly without learning from their mistakes. This is distinct from burst protection -- failure escalation looks at the success rate across the entire session, not just the absolute counts.

The following bundle uses both a session contract and a tight attempts-to-calls ratio:

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: failure-escalation

    defaults:
      mode: enforce

    contracts:
      - id: stuck-agent-detection
        type: session
        limits:
          max_attempts: 30
          max_tool_calls: 50
        then:
          effect: deny
          message: "Agent appears stuck. Too many denied attempts. Change approach or ask for help."
          tags: [rate-limit, stuck]
    ```

=== "Python"

    ```python
    from edictum import Edictum, OperationLimits, Verdict, session_contract

    # Option A: Use OperationLimits (simple)
    guard = Edictum(
        contracts=[...],
        limits=OperationLimits(
            max_attempts=30,
            max_tool_calls=50,
        ),
    )

    # Option B: Use a session contract (precise control)
    @session_contract
    async def stuck_detection(session):
        attempts = await session.attempt_count()
        executions = await session.execution_count()
        if attempts > 10 and executions < attempts * 0.3:
            return Verdict.fail(
                f"Progress stall detected: {executions} successes out of "
                f"{attempts} attempts ({executions/attempts:.0%} success rate). "
                "Change approach or ask for help."
            )
        return Verdict.pass_()
    ```

**How it works:**
- When `max_attempts` is set lower than `max_tool_calls`, it acts as an early-exit trigger. The agent will hit the attempt ceiling before the execution ceiling only if a significant number of calls are being denied.
- In a healthy session, attempts and executions track closely (ratio near 1:1). As the agent hits more denials, the gap widens and the attempt limit fires first.

**Gotchas:**
- This pattern is a heuristic. The attempt counter includes all evaluations, so a bundle with many preconditions per tool can inflate the attempt count even when the agent is working correctly.
- For more precise stuck detection with Python, use a session contract that compares `await session.attempt_count()` to `await session.execution_count()` and fires when the success rate drops below a threshold (e.g., 30%).
