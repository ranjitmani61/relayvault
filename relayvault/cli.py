import argparse
import json
import os
import sys
from pathlib import Path

from relayvault.engine import RelayVaultEngine
from relayvault.files import atomic_write


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="relayvault", description="Local pattern redaction and task handoffs"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    mcp = sub.add_parser("serve-mcp")
    mcp.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio")
    mcp.add_argument("--port", type=int, default=8090)
    mcp.add_argument("--allow-agent-rehydrate", action="store_true")
    api = sub.add_parser("serve-api")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8000)
    for name in ("rehydrate-file", "dehydrate-file", "preview-file"):
        p = sub.add_parser(name)
        p.add_argument("--workspace", required=True)
        p.add_argument("--file", required=True)
        if name != "preview-file":
            p.add_argument("--in-place", action="store_true")
        if name == "rehydrate-file":
            p.add_argument(
                "--allow-partial", action="store_true", help="Explicitly allow unresolved placeholders"
            )
        if name == "dehydrate-file":
            p.add_argument(
                "--reviewed", action="store_true", help="Confirm local review when review policy is enabled"
            )
    log = sub.add_parser("log")
    log.add_argument("--workspace", required=True)
    log.add_argument("--branch")
    for name in ("inspect-checkpoint", "approve-checkpoint"):
        p = sub.add_parser(name)
        p.add_argument("--workspace", required=True)
        p.add_argument("--commit", required=True)
        if name == "approve-checkpoint":
            p.add_argument(
                "--reviewed",
                action="store_true",
                required=True,
                help="Confirm that you inspected this exact checkpoint locally",
            )
    for name in ("backup", "restore", "rotate-key", "migrate-vault"):
        p = sub.add_parser(name)
        p.add_argument("--destination", required=True, help="New private vault directory; must not exist")
        if name == "restore":
            p.add_argument("--source", required=True)
    sub.add_parser("verify-vault")
    args = parser.parse_args()
    try:
        execute(args)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


def execute(args):
    if args.command == "serve-mcp":
        from relayvault.mcp_server import run_server

        run_server(args.transport, args.port, args.allow_agent_rehydrate)
        return
    if args.command == "serve-api":
        import uvicorn

        from relayvault.access import configured_clients

        configured_clients()
        uvicorn.run("relayvault.rest_api:app", host=args.host, port=args.port, proxy_headers=False)
        return
    if args.command in ("migrate-vault", "restore"):
        from relayvault.maintenance import migrate_vault, restore_vault

        destination = Path(args.destination).absolute()
        if args.command == "restore":
            restore_vault(Path(args.source).absolute(), destination)
        else:
            migrate_vault(
                Path(os.environ.get("RELAYVAULT_HOME", Path.home() / ".relayvault")).absolute(), destination
            )
        print(f"Verified {args.command} at {destination}; original home unchanged")
        return
    engine = RelayVaultEngine()
    if args.command in ("rehydrate-file", "dehydrate-file", "preview-file"):
        target = Path(args.file)
        if target.is_symlink() or not target.is_file():
            raise ValueError("Input must be a regular file, not a symlink")
        if target.stat().st_size > 2_000_000:
            raise ValueError("Input exceeds the 2 MB file limit")
        content = target.read_bytes().decode("utf-8")
        if args.command == "preview-file":
            print(json.dumps(engine.preview_text(content), indent=2))
            return
        if args.command == "rehydrate-file":
            transformed, count = engine.rehydrate_text(
                args.workspace, content, allow_partial=args.allow_partial
            )
        else:
            if engine.policy == "review" and not args.reviewed:
                raise ValueError("Local review required; inspect preview-file then pass --reviewed")
            transformed, count = engine.redact_text(args.workspace, content)
        if args.in_place:
            # Plaintext output is private regardless of the original file's group/other permissions.
            mode = 0o600 if args.command == "rehydrate-file" else None
            atomic_write(target, transformed.encode("utf-8"), mode=mode)
            print(f"Processed {count} secret token(s) in-place in {target}")
        else:
            sys.stdout.buffer.write(transformed.encode("utf-8"))
    elif args.command == "log":
        print(json.dumps(engine.list_checkpoints(args.workspace, args.branch), indent=2))
    elif args.command == "inspect-checkpoint":
        state = engine.checkout_handoff(args.workspace, commit_hash=args.commit, _local_review=True)
        if state is None:
            raise ValueError("Checkpoint not found")
        print(json.dumps(state, indent=2))
    elif args.command == "approve-checkpoint":
        engine.approve_checkpoint(args.workspace, args.commit)
        print("Checkpoint approved for export")
    elif args.command == "verify-vault":
        engine.verify_all()
        print("Vault integrity verified")
    elif args.command in ("backup", "rotate-key"):
        from relayvault.maintenance import backup_vault, rotate_key

        operation = backup_vault if args.command == "backup" else rotate_key
        operation(engine, Path(args.destination))
        print(f"Verified {args.command} at {args.destination}; original home unchanged")


if __name__ == "__main__":
    main()
