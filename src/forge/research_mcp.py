"""Credential-gated MCP discovery; unavailable servers are omitted entirely."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import httpx

from forge.research_snapshots import ResearchSnapshotStore

if TYPE_CHECKING:
    from pathlib import Path

    from forge.contracts.contracts import ResearchSnapshot


@dataclass(frozen=True)
class MCPServerConfig:
    name: str
    url: str
    required_env: tuple[str, ...]
    trust: str
    allowed_uses: tuple[str, ...]


def available_mcp_servers() -> list[MCPServerConfig]:
    """Return only fully configured servers; never advertise unavailable tools."""
    servers = (
        MCPServerConfig(
            name="tinyfish",
            url=os.environ.get("TINYFISH_MCP_URL", "http://tinyfish-mcp:3711/mcp"),
            required_env=("TINYFISH_API_KEY",),
            trust="untrusted-public-web",
            allowed_uses=("search", "fetch"),
        ),
    )
    return [server for server in servers if all(os.environ.get(key) for key in server.required_env)]


class TinyFishResearchClient:
    """Search/fetch-only MCP client that stores immutable hostile-data snapshots."""

    def __init__(self, snapshot_root: Path, *, timeout_seconds: float = 30, max_chars: int = 200_000) -> None:
        servers = {server.name: server for server in available_mcp_servers()}
        if "tinyfish" not in servers:
            raise RuntimeError("TinyFish is not configured")
        self.server = servers["tinyfish"]
        self.timeout_seconds = timeout_seconds
        self.max_chars = max_chars
        self.snapshots = ResearchSnapshotStore(snapshot_root)
        self.session_id: str | None = None
        self._initialize()

    def search(self, query: str) -> dict[str, Any]:
        return self._call("search", {"query": query, "domain_type": "research_paper"})

    def fetch_snapshot(self, url: str, *, title: str = "TinyFish public source") -> ResearchSnapshot:
        result = self._call("fetch_content", {"urls": [url], "format": "markdown", "ttl": 0})
        text = json.dumps(result, sort_keys=True)
        if len(text) > self.max_chars:
            raise ValueError("TinyFish response exceeds research snapshot limit")
        return self.snapshots.record(
            source_url=url,
            title=title,
            content=text,
            provider="tinyfish-mcp",
            parser_version="tinyfish-fetch-v1",
        )

    def _call(self, name: str, arguments: dict[str, object]) -> dict[str, Any]:
        if self.session_id is None:
            raise RuntimeError("TinyFish MCP session is not initialized")
        return self._request(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
        )

    def _initialize(self) -> None:
        response = httpx.post(
            self.server.url,
            headers={"Accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "forge-research", "version": "1.0"},
                },
            },
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        session_id = response.headers.get("Mcp-Session-Id")
        if not session_id:
            raise RuntimeError("TinyFish MCP did not return a session ID")
        self.session_id = session_id

    def _request(self, request: dict[str, object]) -> dict[str, Any]:
        response = httpx.post(
            self.server.url,
            headers={
                "Accept": "application/json, text/event-stream",
                "Mcp-Session-Id": self.session_id or "",
            },
            json=request,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        body = response.text
        if len(body) > self.max_chars:
            raise ValueError("TinyFish MCP response exceeds limit")
        if body.startswith("event:") or body.startswith("data:"):
            data_lines = [line.removeprefix("data:").strip() for line in body.splitlines() if line.startswith("data:")]
            body = data_lines[-1]
        payload = cast("dict[str, Any]", json.loads(body))
        if "error" in payload:
            raise RuntimeError(f"TinyFish MCP error: {payload['error']}")
        return cast("dict[str, Any]", payload.get("result", {}))
