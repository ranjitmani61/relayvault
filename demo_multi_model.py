"""Deterministic synthetic handoff; opt-in live provider function-call contract.

Default: actual MCP stdio producer -> actual REST consumer -> local restoration.
Live: additionally sends tool schemas to a selected provider, dispatches its
checkout call, returns the tool result and checks every expected token.
"""

import asyncio
import json
import os
import secrets
import sys
import tempfile

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from relayvault.providers import run_contract
from relayvault.redaction import TOKEN_RE


async def main():
    from relayvault.rest_api import app, engine, get_universal_tool_schemas

    workspace = "demo-workspace"
    api_key = secrets.token_urlsafe(32)
    rehydrate_key = secrets.token_urlsafe(32)
    os.environ["RELAYVAULT_API_KEY"] = api_key
    os.environ["RELAYVAULT_REHYDRATE_KEY"] = rehydrate_key
    os.environ["RELAYVAULT_WORKSPACES"] = json.dumps({workspace: ["read", "write"]})
    os.environ.pop("RELAYVAULT_AUTH_FILE", None)
    samples = [
        "sk_" + "live_" + "9876543210abcdefghij123456",
        "sk-proj-99887766554433221100aabbccddeeff",
        "demo@example.org",
        "10.42.19.88",
    ]
    original = (
        "\n".join(
            f"{name} = '{value}'"
            for name, value in zip(["STRIPE_API_KEY", "OPENAI_API_KEY", "CONTACT", "HOST"], samples)
        )
        + "\n"
    )
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "relayvault.mcp_server"], env=os.environ.copy()
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = {tool.name for tool in (await session.list_tools()).tools}
            assert names == {
                "relayvault_commit_checkpoint",
                "relayvault_checkout_handoff",
                "relayvault_list_history",
            }
            result = await session.call_tool(
                "relayvault_commit_checkpoint",
                arguments={
                    "workspace_id": workspace,
                    "source_model": "synthetic-model-a",
                    "objective": "Implement retries",
                    "locked_decisions": [],
                    "failed_approaches": [],
                    "artifacts": {"config.py": original},
                    "next_steps": [],
                },
            )
            assert not result.isError
            commit = json.loads(result.content[0].text)
            assert commit["redactions_applied"] == 4
    print("[VERIFIED] MCP stdio producer committed 4 detected synthetic values.")
    headers = {"Authorization": f"Bearer {api_key}"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as local:

        async def dispatch(arguments):
            response = await local.post("/v1/checkpoints/checkout", headers=headers, json=arguments)
            response.raise_for_status()
            return response.json()

        handoff = await dispatch({"workspace_id": workspace, "target_model": "synthetic-model-b"})
        assert all(value not in json.dumps(handoff) for value in samples)
        output = handoff["artifacts"]["config.py"]
        expected = set(TOKEN_RE.findall(output))
        assert len(expected) == 4
        print("[VERIFIED] REST consumer received tokens; none of the 4 synthetic values leaked.")
        if os.environ.get("RELAYVAULT_DEMO_LIVE") == "1":
            required = ("RELAYVAULT_LIVE_PROVIDER", "RELAYVAULT_LIVE_MODEL", "RELAYVAULT_LIVE_API_KEY")
            if any(not os.environ.get(name) for name in required):
                raise ValueError(
                    "Live mode requires RELAYVAULT_LIVE_PROVIDER, RELAYVAULT_LIVE_MODEL and RELAYVAULT_LIVE_API_KEY"
                )
            output = await run_contract(
                *(os.environ[name] for name in required),
                workspace,
                get_universal_tool_schemas(),
                dispatch,
                expected,
            )
            print("[VERIFIED] Live provider issued a checkout call and preserved all expected tokens.")
        else:
            print("[LOCAL ONLY] No external model called; provider contract was not exercised.")
        response = await local.post(
            "/v1/vault/rehydrate",
            headers={
                **headers,
                "X-RelayVault-Local-Intent": "rehydrate",
                "X-RelayVault-Rehydrate-Key": rehydrate_key,
            },
            json={"workspace_id": workspace, "text_with_vault_tokens": output},
        )
        if response.is_error:
            raise RuntimeError(f"Rehydrate failed ({response.status_code}): {response.text}")
        restored = response.json()
        assert restored["tokens_rehydrated"] == 4
        assert all(value in restored["rehydrated_text"] for value in samples)
        if os.environ.get("RELAYVAULT_DEMO_LIVE") != "1":
            assert restored["rehydrated_text"] == original
        engine.verify_all()
        print(
            "[VERIFIED] Separate-key local rehydration restored all 4 synthetic values; vault integrity passed."
        )


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="relayvault-demo-") as directory:
        os.environ["RELAYVAULT_HOME"] = directory
        # Demo isolation: never inherit access or detector policy from a personal server.
        for name in (
            "RELAYVAULT_ALLOW_AGENT_REHYDRATE",
            "RELAYVAULT_REDACTION_POLICY",
            "RELAYVAULT_DETECTORS_FILE",
            "RELAYVAULT_SALT",
        ):
            os.environ.pop(name, None)
        asyncio.run(main())
