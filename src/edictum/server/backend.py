"""Server-backed storage backend for distributed session state."""

from __future__ import annotations

from edictum.server.client import EdictumServerClient, EdictumServerError


class ServerBackend:
    """Storage backend that delegates session state to edictum-server.

    Implements the StorageBackend protocol, forwarding all operations
    to the server's session state API.
    """

    def __init__(self, client: EdictumServerClient) -> None:
        self._client = client

    async def get(self, key: str) -> str | None:
        """Retrieve a value from the server session store."""
        try:
            response = await self._client.get(f"/api/v1/sessions/{key}")
            return response.get("value")
        except Exception:
            return None

    async def set(self, key: str, value: str) -> None:
        """Set a value in the server session store."""
        await self._client.put(f"/api/v1/sessions/{key}", {"value": value})

    async def delete(self, key: str) -> None:
        """Delete a key from the server session store."""
        try:
            await self._client.delete(f"/api/v1/sessions/{key}")
        except EdictumServerError as exc:
            if exc.status_code != 404:
                raise

    async def increment(self, key: str, amount: float = 1) -> float:
        """Atomically increment a counter on the server."""
        response = await self._client.post(
            f"/api/v1/sessions/{key}/increment",
            {"amount": amount},
        )
        return response["value"]
