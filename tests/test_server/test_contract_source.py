"""Tests for ServerContractSource."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from edictum.server.client import EdictumServerClient
from edictum.server.contract_source import ServerContractSource


class TestServerContractSource:
    def test_init(self):
        client = MagicMock(spec=EdictumServerClient)
        source = ServerContractSource(client, reconnect_delay=2.0, max_reconnect_delay=120.0)
        assert source._reconnect_delay == 2.0
        assert source._max_reconnect_delay == 120.0
        assert source._connected is False
        assert source._closed is False

    def test_init_defaults(self):
        client = MagicMock(spec=EdictumServerClient)
        source = ServerContractSource(client)
        assert source._reconnect_delay == 1.0
        assert source._max_reconnect_delay == 60.0

    @pytest.mark.asyncio
    async def test_connect(self):
        client = MagicMock(spec=EdictumServerClient)
        source = ServerContractSource(client)
        await source.connect()
        assert source._connected is True
        assert source._closed is False

    @pytest.mark.asyncio
    async def test_close(self):
        client = MagicMock(spec=EdictumServerClient)
        source = ServerContractSource(client)
        await source.connect()
        await source.close()
        assert source._closed is True
        assert source._connected is False

    @pytest.mark.asyncio
    async def test_close_without_connect(self):
        client = MagicMock(spec=EdictumServerClient)
        source = ServerContractSource(client)
        await source.close()  # Should not raise
        assert source._closed is True
