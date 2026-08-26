"""Long-lived Inngest Connect worker for VPS/container deployment."""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from typing import Any, cast

import inngest.connect

from forge.pipeline.client import client
from forge.pipeline.functions import functions

_logger = logging.getLogger("forge.pipeline.worker")


async def run() -> None:
    gateway = os.environ.get("INNGEST_CONNECT_GATEWAY", "ws://inngest:8289/v0/connect")
    delay = 1.0
    while True:
        try:
            connection = inngest.connect.connect(
                [(client, cast("Any", functions))],
                instance_id=os.environ.get("HOSTNAME", socket.gethostname()),
                rewrite_gateway_endpoint=lambda _: gateway,
                max_worker_concurrency=int(
                    os.environ.get("INNGEST_CONNECT_MAX_WORKER_CONCURRENCY", "1")
                ),
            )
            await connection.start()
        except Exception:
            _logger.exception("Inngest connection failed; retrying in %.1fs", delay)
        else:
            _logger.warning("Inngest connection ended; reconnecting in %.1fs", delay)
        await asyncio.sleep(delay)
        delay = min(delay * 2, 30.0)


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
