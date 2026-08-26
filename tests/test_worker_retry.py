"""Worker process survives transient orchestrator unavailability."""

from __future__ import annotations

import asyncio

import pytest

from forge.pipeline import worker


@pytest.mark.asyncio
async def test_worker_retries_connection_start(monkeypatch: pytest.MonkeyPatch) -> None:
    starts = 0

    class Connection:
        async def start(self) -> None:
            nonlocal starts
            starts += 1
            if starts == 1:
                raise ConnectionError("orchestrator unavailable")
            raise asyncio.CancelledError

    def connect(*args: object, **kwargs: object) -> Connection:
        del args, kwargs
        return Connection()

    monkeypatch.setattr(worker.inngest.connect, "connect", connect)

    async def no_wait(_: float) -> None:
        return None

    monkeypatch.setattr(worker.asyncio, "sleep", no_wait)
    with pytest.raises(asyncio.CancelledError):
        await worker.run()
    assert starts == 2
