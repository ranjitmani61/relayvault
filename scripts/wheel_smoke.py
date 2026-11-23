"""Run with python -I after installing the built wheel in a clean environment."""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import relayvault


async def main():
    assert "site-packages" in str(Path(relayvault.__file__).resolve()), "Test must import the installed wheel"
    with tempfile.TemporaryDirectory(prefix="relayvault-wheel-") as home:
        env = {name: value for name, value in os.environ.items() if not name.startswith("RELAYVAULT_")}
        env["RELAYVAULT_HOME"] = home
        params = StdioServerParameters(command=str(Path(sys.executable).parent / "relayvault-mcp"), env=env)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                assert len((await session.list_tools()).tools) == 3
                result = await session.call_tool(
                    "relayvault_commit_checkpoint",
                    arguments={
                        "workspace_id": "smoke",
                        "source_model": "wheel",
                        "objective": "demo@example.org",
                        "locked_decisions": [],
                        "failed_approaches": [],
                        "artifacts": {},
                        "next_steps": [],
                    },
                )
                assert not result.isError
                assert json.loads(result.content[0].text)["redactions_applied"] == 1
                result = await session.call_tool(
                    "relayvault_checkout_handoff", arguments={"workspace_id": "smoke"}
                )
                assert not result.isError
                assert "demo@example.org" not in result.content[0].text
        print("Installed wheel: authenticated vault and real MCP stdio handshake passed")


if __name__ == "__main__":
    asyncio.run(main())
