---
name: implement-feature
description: Scope and implement a Linear ticket collaboratively. Multiple PRs per ticket expected.
user-invocable: true
allowed-tools: Read, Edit, Bash, Write, Grep, Glob, WebFetch
---

# Implement Feature

Collaboratively scope and implement a Linear ticket. The user wants to understand the codebase and be part of planning.

## Arguments

- `ticket`: Linear ticket ID (e.g., `CG-1`)

## Workflow Philosophy

**This is a collaboration, not a handoff.**

1. You scope the work WITH the user
2. Break into small PRs together
3. User understands what's changing and why
4. Multiple PRs per ticket is the norm

**Never implement without discussing approach first.**

## Step 1: Gather context

1. **Read the Linear ticket** (via URL or user provides details)

2. **Read the relevant code:**
   ```
   Read: src/callguard/{relevant_module}.py
   Read: tests/test_{relevant_module}.py
   ```

3. **Summarize to user:**
   - What the ticket asks for
   - What the current code does
   - Where changes would go

## Step 2: Scope together

**Ask the user:**
- "This ticket has X parts. Want to start with [specific piece]?"
- "I see two approaches: A or B. Which feels right?"
- "This could be one PR or split into [X, Y]. Preference?"

**Wait for their input.** They own the architecture.

Typical scoping questions:
- Which acceptance criteria first?
- New file or extend existing?
- Edge cases to handle now vs later?

## Step 3: Agree on PR scope

Before any code changes, confirm with user:
- "PR 1 will do [X]. Sound good?"
- Get explicit approval before proceeding

## Step 4: Create branch

Branch naming: `{ticket}-{short-description}`

```
Bash: git checkout main && git pull origin main
Bash: git checkout -b CG-1-add-redis-backend
```

## Step 5: Implement together

1. **Explain your approach** before writing code
2. **Show the user** key changes as you make them
3. **Ask about edge cases** you encounter
4. **Add/update tests** - discuss test cases with user

## Step 6: Verify

Run checks in sequence. Abort if any fail.

```
Bash: pytest tests/test_{module}.py -v    # Relevant test file first
Bash: pytest tests/ -v                    # Full test suite
Bash: ruff check src/ tests/              # Lint
```

## Step 7: Commit

Commit message format: Conventional Commits

```
Bash: git add -A
Bash: git commit -m "feat: add Redis storage backend"
```

**Conventional commit types:**
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `test:` adding/updating tests
- `refactor:` code change that neither fixes nor adds
- `chore:` maintenance tasks

**Commit message rules:**
- Use conventional commit format
- Use imperative mood ("add" not "added")
- Be specific about what changed
- Do NOT include `Co-Authored-By`
- Do NOT include ticket ID in commit message

## Step 8: Push and create PR

```
Bash: git push -u origin HEAD
```

**Create PR with:**
- **Title:** `feat: add Redis storage backend` (conventional commit style)
- **Description:** Include Linear ticket reference

Example PR description:
```
Resolves CG-1

Adds RedisBackend implementing StorageBackend protocol with atomic
increment via INCRBYFLOAT and optional TTL support.

## Changes
- Added extras/redis.py with RedisBackend
- Added tests for all StorageBackend operations
```

**Ask the user:**
- "Ready to create PR?"
- "Want to continue with the next piece of this ticket?"

## Important Notes

- **Collaborate** - user wants to understand and decide
- **Small PRs** - one focused change per PR
- **Ask first** - never assume, always confirm approach
- **Teach** - explain the codebase as you go
- **Conventional commits** - feat/fix/docs/test/refactor/chore
- **Linear ticket in PR description** - not in title or commits
