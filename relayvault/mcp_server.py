import argparse
import hashlib
import json
import os
from typing import Dict, List, Optional
from mcp.server.fastmcp import FastMCP
from relayvault.engine import RelayVaultEngine

mcp = FastMCP(
    "RelayVault",
    dependencies=["pydantic>=2.9.0"],
)
engine = RelayVaultEngine()


@mcp.tool()
def relayvault_commit_checkpoint(
    workspace_id: str,
    source_model: str,
    objective: str,
    locked_decisions: List[str],
    failed_approaches: List[str],
    artifacts: Dict[str, str],
    next_steps: List[str],
    branch: str = "main",
    parent_hash: Optional[str] = None,
) -> str:
    """
    Save a deterministic, zero-trust task checkpoint before switching AI models or hitting a rate limit.
    Automatically scrubs API keys, credentials, emails, and private IPs into local <RV_VAULT:...> tokens.
    """
    result = engine.commit_checkpoint(
        workspace_id=workspace_id,
        source_model=source_model,
        objective=objective,
        locked_decisions=locked_decisions,
        failed_approaches=failed_approaches,
        artifacts=artifacts,
        next_steps=next_steps,
        branch=branch,
        parent_hash=parent_hash,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def relayvault_checkout_handoff(
    workspace_id: str,
    branch: str = "main",
    commit_hash: Optional[str] = None,
    target_model: Optional[str] = None,
) -> str:
    """
    Load the latest (or specific commit_hash) task state checkpoint from another AI model.
    Returns structured state plus a synthesized handoff prompt with redacted <RV_VAULT:...> tokens intact.
    """
    result = engine.checkout_handoff(
        workspace_id=workspace_id,
        branch=branch,
        commit_hash=commit_hash,
        target_model=target_model,
    )
    if not result:
        return json.dumps({"error": f"No checkpoint found for workspace='{workspace_id}' branch='{branch}'"})
    return json.dumps(result, indent=2)


def relayvault_rehydrate_output(workspace_id: str, text_with_vault_tokens: str) -> str:
    """
    Locally replace <RV_VAULT:TYPE:HASH> placeholders in model-generated code or configs with real secrets.
    Only run this on your trusted local machine after receiving output from an external model.
    """
    restored_text, count = engine.rehydrate_text(workspace_id, text_with_vault_tokens)
    return json.dumps(
        {
            "workspace_id": workspace_id,
            "tokens_rehydrated": count,
            "rehydrated_text": restored_text,
        },
        indent=2,
    )


_agent_rehydration_enabled = False


def enable_agent_rehydration() -> None:
    """Explicitly expose plaintext rehydration to the connected MCP client."""
    global _agent_rehydration_enabled
    if not _agent_rehydration_enabled:
        mcp.add_tool(relayvault_rehydrate_output)
        _agent_rehydration_enabled = True


if os.environ.get("RELAYVAULT_ALLOW_AGENT_REHYDRATE") == "1":
    enable_agent_rehydration()


@mcp.tool()
def relayvault_list_history(workspace_id: str, branch: Optional[str] = None, limit: int = 10) -> str:
    """List recent cross-model checkpoints and DAG lineage for a workspace."""
    items = engine.list_checkpoints(workspace_id=workspace_id, branch=branch, limit=limit)
    return json.dumps({"workspace_id": workspace_id, "checkpoints": items}, indent=2)


@mcp.resource("rv://{workspace_id}/{branch}/head")
def get_branch_head_resource(workspace_id: str, branch: str) -> str:
    """MCP Resource exposing the latest synthesized handoff state for direct context attachment."""
    state = engine.checkout_handoff(workspace_id=workspace_id, branch=branch)
    if not state:
        return f"No active checkpoint found in rv://{workspace_id}/{branch}/head"
    return state["synthesized_handoff_prompt"]


def compute_tool_manifest_pin() -> str:
    """Hash the tool names; this does not validate descriptions or schemas."""
    manifest = [
        "relayvault_commit_checkpoint",
        "relayvault_checkout_handoff",
        "relayvault_list_history",
    ]
    if _agent_rehydration_enabled:
        manifest.append("relayvault_rehydrate_output")
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode("utf-8")).hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RelayVault MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport protocol (stdio for local Claude/Cursor, streamable-http for remote connectors)",
    )
    parser.add_argument("--port", type=int, default=8090, help="Port for HTTP/SSE transport")
    parser.add_argument("--allow-agent-rehydrate", action="store_true", help="Expose plaintext rehydration to MCP clients")
    args = parser.parse_args()

    if args.allow_agent_rehydrate:
        enable_agent_rehydration()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.settings.port = args.port
        mcp.run(transport=args.transport)


def run_stdio() -> None:
    """Entry point for relayvault-mcp console script (stdio transport)."""
    parser = argparse.ArgumentParser(description="RelayVault MCP stdio server")
    parser.add_argument("--allow-agent-rehydrate", action="store_true", help="Expose plaintext rehydration to MCP clients")
    if parser.parse_args().allow_agent_rehydrate:
        enable_agent_rehydration()
    mcp.run(transport="stdio")
