"""Verify the hosted MCP server with a real MCP client.

Connects with the official Python MCP SDK client (Streamable HTTP,
stateless), lists tools, and calls ``search_writeups``. This is a
manual verification script, not a test: it needs live network and
the server dependencies (``pip install ".[server]"``).

Usage: ``python scripts/verify_mcp_client.py [mcp-url]``
"""

from __future__ import annotations

import asyncio
import json
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

DEFAULT_URL = "http://129.150.57.82:10005/mcp"
EXPECTED_TOOLS = {
    "search_writeups",
    "get_writeup",
    "get_writeup_skill",
    "list_vuln_classes",
    "list_programs",
    "check_freshness",
}


async def main(url: str) -> int:
    async with streamable_http_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [tool.name for tool in tools.tools]
            print("tools:", json.dumps(names))
            if set(names) != EXPECTED_TOOLS:
                print(f"expected tools {sorted(EXPECTED_TOOLS)}")
                return 1
            result = await session.call_tool(
                "search_writeups", {"query": "CSRF", "limit": 3}
            )
            if getattr(result, "is_error", False):
                print("search_writeups returned an error")
                return 1
            for block in result.content:
                text = getattr(block, "text", "")
                print(text[:400])
                data = json.loads(text)
                if not data["results"]:
                    print("search_writeups returned no results")
                    return 1
    print("MCP client check OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL)))
