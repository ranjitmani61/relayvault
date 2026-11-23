"""All tests use isolated homes and deterministic service configuration."""

import json
import os

import pytest

from relayvault.engine import RelayVaultEngine


@pytest.fixture(autouse=True)
def isolate_environment(tmp_path, monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("RELAYVAULT_") and not name.startswith("RELAYVAULT_LIVE_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("RELAYVAULT_HOME", str(tmp_path / "home"))


@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("RELAYVAULT_WORKSPACES", json.dumps({"test-workspace": ["read", "write"]}))
    return RelayVaultEngine()
