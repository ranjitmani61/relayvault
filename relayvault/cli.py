import argparse
import json
import sys
from pathlib import Path
import uvicorn
from relayvault.engine import RelayVaultEngine


def main() -> None:
    parser = argparse.ArgumentParser(prog="relayvault", description="RelayVault CLI & Server Runner")
    sub = parser.add_subparsers(dest="command", required=True)

    # 1. MCP Server command
    mcp_p = sub.add_parser("serve-mcp", help="Start the RelayVault MCP server")
    mcp_p.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio")
    mcp_p.add_argument("--port", type=int, default=8090)
    mcp_p.add_argument("--allow-agent-rehydrate", action="store_true", help="Expose plaintext rehydration to MCP clients")

    # 2. REST API command
    api_p = sub.add_parser("serve-api", help="Start the FastAPI OpenAPI 3.1 REST server")
    api_p.add_argument("--host", default="127.0.0.1")
    api_p.add_argument("--port", type=int, default=8000)

    # 3. Rehydrate local file in-place or to stdout
    reh_p = sub.add_parser("rehydrate-file", help="Replace <RV_VAULT:...> tokens in a local file with real secrets")
    reh_p.add_argument("--workspace", required=True, help="Workspace ID")
    reh_p.add_argument("--file", required=True, help="Path to file containing vault tokens")
    reh_p.add_argument("--in-place", action="store_true", help="Overwrite the file in-place")

    deh_p = sub.add_parser("dehydrate-file", help="Vault secrets in a local UTF-8 file")
    deh_p.add_argument("--workspace", required=True, help="Workspace ID")
    deh_p.add_argument("--file", required=True, help="Path to file containing secrets")
    deh_p.add_argument("--in-place", action="store_true", help="Overwrite the file in-place")

    # 4. Inspect workspace checkpoint history
    log_p = sub.add_parser("log", help="List checkpoints for a workspace")
    log_p.add_argument("--workspace", required=True, help="Workspace ID")
    log_p.add_argument("--branch", default=None, help="Optional branch filter")

    args = parser.parse_args()
    if args.command == "serve-mcp":
        from relayvault.mcp_server import mcp, enable_agent_rehydration
        if args.allow_agent_rehydrate:
            enable_agent_rehydration()
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            mcp.settings.port = args.port
            mcp.run(transport=args.transport)

    elif args.command == "serve-api":
        uvicorn.run("relayvault.rest_api:app", host=args.host, port=args.port)

    elif args.command in ("rehydrate-file", "dehydrate-file"):
        engine = RelayVaultEngine()
        target = Path(args.file)
        if not target.exists():
            print(f"Error: File not found: {target}", file=sys.stderr)
            sys.exit(1)
        content = target.read_bytes().decode("utf-8")
        if args.command == "rehydrate-file":
            transformed, count = engine.rehydrate_text(args.workspace, content)
            verb = "Rehydrated"
        else:
            transformed, count = engine.redact_text(args.workspace, content)
            verb = "Dehydrated"
        if args.in_place:
            target.write_bytes(transformed.encode("utf-8"))
            print(f"{verb} {count} secret token(s) in-place in {target}")
        else:
            sys.stdout.buffer.write(transformed.encode("utf-8"))

    elif args.command == "log":
        engine = RelayVaultEngine()
        history = engine.list_checkpoints(workspace_id=args.workspace, branch=args.branch)
        print(json.dumps(history, indent=2))


if __name__ == "__main__":
    main()
