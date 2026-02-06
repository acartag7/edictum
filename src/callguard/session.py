"""Session — atomic counters backed by StorageBackend."""

from __future__ import annotations

from callguard.storage import StorageBackend


class Session:
    """Tracks execution state via atomic counters in StorageBackend.

    All methods are ASYNC because StorageBackend is async.

    Counter semantics:
    - attempt_count: every PreToolUse, including denied (pre-execution)
    - execution_count: every PostToolUse (tool actually ran)
    - per_tool_exec_count:{tool}: per-tool execution count
    - consecutive_failures: resets on success, increments on failure
    """

    def __init__(self, session_id: str, backend: StorageBackend):
        self._sid = session_id
        self._backend = backend

    @property
    def session_id(self) -> str:
        return self._sid

    async def increment_attempts(self) -> int:
        """Increment attempt counter. Called in PreToolUse (before governance)."""
        return int(await self._backend.increment(f"s:{self._sid}:attempts"))

    async def attempt_count(self) -> int:
        return int(await self._backend.get(f"s:{self._sid}:attempts") or 0)

    async def record_execution(self, tool_name: str, success: bool) -> None:
        """Record a tool execution. Called in PostToolUse."""
        await self._backend.increment(f"s:{self._sid}:execs")
        await self._backend.increment(f"s:{self._sid}:tool:{tool_name}")

        if success:
            await self._backend.set(f"s:{self._sid}:consec_fail", "0")
        else:
            await self._backend.increment(f"s:{self._sid}:consec_fail")

    async def execution_count(self) -> int:
        return int(await self._backend.get(f"s:{self._sid}:execs") or 0)

    async def tool_execution_count(self, tool: str) -> int:
        return int(await self._backend.get(f"s:{self._sid}:tool:{tool}") or 0)

    async def consecutive_failures(self) -> int:
        return int(await self._backend.get(f"s:{self._sid}:consec_fail") or 0)
