"""stdio shim: Regent between an MCP client and a stdio MCP server, no gateway.

    regent shim --pack packs/ria -- npx @modelcontextprotocol/server-filesystem /data

Client <-> (this process) <-> child server. Every ``tools/call`` request from
the client is decided before being forwarded; deny/hold become JSON-RPC error
responses (code -32003) with the Regent decision in ``error.data``. Everything
else passes through byte-for-byte. Interactive approvals via CLIApprover.

This is the "if agentgateway disappeared tomorrow" path and the fastest demo.
"""
from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from regent.core.engine import Engine
from regent.core.models import Principal, ToolCall, Verdict
from regent.core.ports import Decider

REGENT_ERROR_CODE = -32003


class StdioShim:
    name = "stdio_shim"

    def __init__(self, engine: Engine, cmd: list[str], target: str = "local", principal: Principal | None = None):
        self.engine, self.cmd, self.target = engine, cmd, target
        self.principal = principal or Principal(user="local-user", agent="stdio-shim")

    async def serve(self, decide: Decider | None = None) -> None:
        decide = decide or self.engine.decide
        proc = await asyncio.create_subprocess_exec(*self.cmd, stdin=asyncio.subprocess.PIPE,
                                                    stdout=asyncio.subprocess.PIPE)
        assert proc.stdin and proc.stdout
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
        out_lock = asyncio.Lock()

        async def emit(obj: dict[str, Any]) -> None:
            async with out_lock:
                sys.stdout.write(json.dumps(obj) + "\n")
                sys.stdout.flush()

        async def client_to_server() -> None:
            while True:
                line = await reader.readline()
                if not line:
                    proc.stdin.close()
                    return
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    proc.stdin.write(line)
                    continue
                if isinstance(msg, dict) and msg.get("method") == "tools/call":
                    params = msg.get("params") or {}
                    call = ToolCall(tool=f"{self.target}.{params.get('name')}", args=dict(params.get("arguments") or {}),
                                    principal=self.principal)
                    d = await decide(call)
                    if d.verdict is not Verdict.ALLOW:
                        await emit({"jsonrpc": "2.0", "id": msg.get("id"),
                                    "error": {"code": REGENT_ERROR_CODE, "message": f"regent: {d.verdict.value}: {d.reason}",
                                              "data": d.to_dict()}})
                        continue
                proc.stdin.write(line)
                await proc.stdin.drain()

        async def server_to_client() -> None:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    return
                async with out_lock:
                    sys.stdout.write(line.decode("utf-8", "replace"))
                    sys.stdout.flush()

        await asyncio.gather(client_to_server(), server_to_client())
        await self.engine.drain()
