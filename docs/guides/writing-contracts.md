# Tutorial: Creating Contracts

This guide walks through the full workflow of creating, validating, and deploying an Edictum contract -- from requirement to production enforcement.

---

## Step 1: Start With a Requirement

Suppose your team has this rule:

> Analysts should not be able to read secret files like `.env`, `.pem`, or credential files.

This is a precondition -- you want to block the tool call *before* it executes.

---

## Step 2: Translate to a YAML Contract

Create a file called `contracts.yaml` with a complete ContractBundle:

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: analyst-file-policy
  description: "Prevent analysts from reading secret files."

defaults:
  mode: observe

contracts:
  - id: block-secret-reads
    type: pre
    tool: read_file
    when:
      all:
        - args.path:
            contains_any: [".env", ".secret", "credentials", ".pem", "id_rsa"]
        - principal.role:
            equals: analyst
    then:
      effect: deny
      message: "Analysts cannot read '{args.path}'. Ask an admin for help."
      tags: [secrets, dlp]
```

Key decisions in this contract:

- **`type: pre`** -- evaluate before the tool runs.
- **`tool: read_file`** -- only applies to the `read_file` tool.
- **`all`** -- both conditions must be true (sensitive path AND analyst role).
- **`effect: deny`** -- block the call. This is the only valid effect for preconditions.
- **`mode: observe`** in defaults -- start by observing, not enforcing.

---

## Step 3: Validate the Contract

Run the CLI validator to catch syntax and schema errors before deployment:

```
$ edictum validate contracts.yaml

  contracts.yaml — 1 contracts (1 pre)
```

If there are errors (bad regex, wrong effect, duplicate IDs), the validator reports them and exits with code 1.

---

## Step 4: Test With a Dry Run

Simulate a tool call against the contract without executing anything:

```
$ edictum check contracts.yaml \
    --tool read_file \
    --args '{"path": ".env"}' \
    --principal-role analyst

DENIED by rule block-secret-reads
  Message: Analysts cannot read '.env'. Ask an admin for help.
  Tags: secrets, dlp
  Rules evaluated: 1
```

Verify that allowed calls pass:

```
$ edictum check contracts.yaml \
    --tool read_file \
    --args '{"path": "readme.txt"}' \
    --principal-role analyst

ALLOWED
  Rules evaluated: 1 contract(s)
```

---

## Step 5: Deploy in Observe Mode

Notice that `defaults.mode` is set to `observe`. In this mode, Edictum logs what *would* be denied without actually blocking anything. This is safe for production rollout.

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter

guard = Edictum.from_yaml("contracts.yaml")

adapter = LangChainAdapter(
    guard=guard,
    principal=Principal(user_id="alice", role="analyst"),
)

middleware = adapter.as_middleware()
# Tool calls proceed normally, but denials are logged
```

---

## Step 6: Review Audit Logs

In observe mode, denied calls produce `CALL_WOULD_DENY` audit events. Review them to confirm the contract fires on the right calls and not on legitimate ones:

```json
{
  "event_type": "CALL_WOULD_DENY",
  "tool_name": "read_file",
  "decision_name": "block-secret-reads",
  "args": {"path": ".env"},
  "principal": {"user_id": "alice", "role": "analyst"},
  "message": "Analysts cannot read '.env'. Ask an admin for help."
}
```

Check for:

- **False positives** -- legitimate calls that would be blocked.
- **False negatives** -- calls that should be blocked but are not.
- **Missing principal fields** -- if `principal.role` is null, the leaf evaluates to `false` and the rule never fires.

---

## Step 7: Flip to Enforce

Once you are confident in the contract behavior, change `mode` from `observe` to `enforce`:

```yaml
defaults:
  mode: enforce
```

Now denied calls are actually blocked. The tool callable is never invoked, and the agent sees the denial message.

---

## Common Mistakes

### Wrong operator

Using `equals` when you need `contains`:

```yaml
# Wrong -- only matches if the entire path is literally ".env"
args.path:
  equals: ".env"

# Right -- matches any path containing ".env"
args.path:
  contains: ".env"
```

### Missing principal field

If the principal does not have a `role` field set, selectors like `principal.role` resolve to null. A null selector causes the leaf to evaluate to `false`, so the rule never fires. The call is silently allowed.

Fix: ensure the principal is populated when creating the adapter:

```python
principal = Principal(user_id="alice", role="analyst")
adapter = LangChainAdapter(guard=guard, principal=principal)
```

### Regex escaping in YAML

YAML double-quoted strings interpret escape sequences. `"\b"` is a backspace character, not a word boundary. Always use single quotes for regex:

```yaml
# Wrong -- "\b" is backspace
args.command:
  matches: "\brm\b"

# Right -- '\b' is literal backslash-b (word boundary)
args.command:
  matches: '\brm\b'
```

### Using output.text in preconditions

The `output.text` selector is only available in postconditions (after the tool has run). Using it in a precondition is a validation error at load time:

```yaml
# Wrong -- output.text does not exist before the tool runs
- id: bad-pre
  type: pre
  tool: read_file
  when:
    output.text:
      contains: "SECRET"
  then:
    effect: deny
    message: "..."
```

### Setting effect: deny on postconditions

Postconditions can only use `effect: warn`. The tool already executed -- denying after the fact does not undo the action. Setting `effect: deny` on a postcondition is a validation error:

```yaml
# Wrong -- postconditions cannot deny
- id: bad-post
  type: post
  tool: "*"
  when:
    output.text:
      contains: "SSN"
  then:
    effect: deny   # validation error
    message: "..."
```

Use `effect: warn` and handle it with an `on_postcondition_warn` callback instead.
