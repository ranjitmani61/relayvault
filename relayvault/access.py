"""Authentication and workspace grants shared by HTTP MCP and REST.

Static bearer keys are provisioned locally, not an OAuth authorization server.
Never send these credentials to an LLM provider.
"""

import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

from relayvault.crypto import private_path


@dataclass(frozen=True)
class Principal:
    name: str
    grants: dict

    def authorize(self, workspace: str, operation: str):
        if operation not in self.grants.get(workspace, []):
            raise PermissionError("Workspace permission denied")


def configured_clients() -> dict:
    config = os.environ.get("RELAYVAULT_AUTH_FILE")
    if config:
        path = Path(config)
        private_path(path)
        clients = json.loads(path.read_text())
    else:
        key = os.environ.get("RELAYVAULT_API_KEY")
        if not key:
            raise RuntimeError("RELAYVAULT_API_KEY or RELAYVAULT_AUTH_FILE must be configured")
        grants = os.environ.get("RELAYVAULT_WORKSPACES")
        if not grants:
            raise RuntimeError("Explicit RELAYVAULT_WORKSPACES grants are required for HTTP clients")
        clients = {"local-client": {"key": key, "workspaces": json.loads(grants)}}
    if not isinstance(clients, dict) or not clients:
        raise RuntimeError("At least one HTTP client must be configured")
    keys = set()
    for name, config in clients.items():
        if not isinstance(config, dict):
            raise RuntimeError("Invalid HTTP client configuration")
        key, grants = config.get("key"), config.get("workspaces")
        if (
            not isinstance(name, str)
            or not isinstance(key, str)
            or not key
            or key in keys
            or not isinstance(grants, dict)
        ):
            raise RuntimeError("Invalid HTTP client configuration or duplicate key")
        keys.add(key)
        for workspace, permissions in grants.items():
            if (
                not isinstance(workspace, str)
                or workspace == "*"
                or not isinstance(permissions, list)
                or not permissions
                or any(not isinstance(p, str) or p not in ("read", "write") for p in permissions)
            ):
                raise RuntimeError("HTTP grants must name explicit workspaces and read/write operations")
    return clients


def authenticate(token: str) -> Principal | None:
    result = None
    for name, config in configured_clients().items():
        if hmac.compare_digest(token.encode(), config["key"].encode()):
            result = Principal(name, config["workspaces"])
    return result


def verify_rehydration_key(provided: str | None):
    expected = os.environ.get("RELAYVAULT_REHYDRATE_KEY")
    if not expected:
        raise PermissionError("REST rehydration is disabled; configure a distinct RELAYVAULT_REHYDRATE_KEY")
    if any(
        hmac.compare_digest(expected.encode(), item["key"].encode()) for item in configured_clients().values()
    ):
        raise PermissionError("Rehydration key must differ from every model-facing API key")
    if provided is None or not hmac.compare_digest(provided.encode(), expected.encode()):
        raise PermissionError("Invalid rehydration key")
