"""Credential-gated MCP discovery; unavailable servers are omitted entirely."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class MCPServerConfig:
    name: str
    url: str
    required_env: tuple[str, ...]
    trust: str
    allowed_uses: tuple[str, ...]


_SERVERS = (
    MCPServerConfig(
        name="tinyfish",
        url=os.environ.get("TINYFISH_MCP_URL", "http://tinyfish-mcp:3711/mcp"),
        required_env=("TINYFISH_API_KEY",),
        trust="untrusted-public-web",
        allowed_uses=("search", "fetch"),
    ),
)


def available_mcp_servers() -> list[MCPServerConfig]:
    """Return only fully configured servers; never advertise unavailable tools."""
    return [server for server in _SERVERS if all(os.environ.get(key) for key in server.required_env)]
