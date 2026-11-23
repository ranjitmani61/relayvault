"""Local wire-contract tests are protocol simulations, never live-model evidence."""

import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import httpx
import pytest

from relayvault.providers import ENDPOINTS, TOOL, run_contract
from relayvault.redaction import TOKEN_RE


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", list(ENDPOINTS))
@pytest.mark.parametrize("behavior", ["valid", "wrong-workspace", "lost-token"])
async def test_provider_wire_contract(vault, monkeypatch, provider, behavior):
    from relayvault import rest_api

    monkeypatch.setattr(rest_api, "engine", vault)
    monkeypatch.setenv("RELAYVAULT_API_KEY", "local-key-never-send")
    original = "CONTACT = 'demo@example.org'\n"
    vault.commit_checkpoint("test-workspace", "source", "Task", [], [], {"config.py": original}, [])
    handoff = vault.checkout_handoff("test-workspace")
    artifact = handoff["artifacts"]["config.py"]
    expected = set(TOKEN_RE.findall(artifact))
    requests = []
    arguments = {"workspace_id": "denied" if behavior == "wrong-workspace" else "test-workspace"}
    output = "token disappeared" if behavior == "lost-token" else artifact

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((dict(self.headers), body))
            first = len(requests) == 1
            if provider == "anthropic":
                result = {
                    "content": [{"type": "tool_use", "id": "call1", "name": TOOL, "input": arguments}]
                    if first
                    else [{"type": "text", "text": output}]
                }
            elif provider == "gemini":
                result = {
                    "candidates": [
                        {
                            "content": {
                                "role": "model",
                                "parts": [
                                    {
                                        "functionCall": {"name": TOOL, "args": arguments, "id": "call1"},
                                        "thoughtSignature": "preserve-me",
                                    }
                                ]
                                if first
                                else [{"text": output}],
                            }
                        }
                    ]
                }
            else:
                message = (
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call1",
                                "type": "function",
                                "function": {"name": TOOL, "arguments": json.dumps(arguments)},
                            }
                        ],
                        "reasoning_content": "preserve reasoning",
                    }
                    if first
                    else {"role": "assistant", "content": output}
                )
                result = {"choices": [{"message": message}]}
            data = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setitem(ENDPOINTS, provider, f"http://127.0.0.1:{server.server_port}/provider")
    dispatched = []
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=rest_api.app), base_url="http://test"
        ) as local:

            async def dispatch(args):
                dispatched.append(args)
                response = await local.post(
                    "/v1/checkpoints/checkout",
                    headers={"Authorization": "Bearer local-key-never-send"},
                    json=args,
                )
                response.raise_for_status()
                return response.json()

            if behavior == "valid":
                actual = await run_contract(
                    provider,
                    "selected-model",
                    "synthetic-provider-key",
                    "test-workspace",
                    rest_api.get_universal_tool_schemas(),
                    dispatch,
                    expected,
                )
                assert actual == artifact
                assert vault.rehydrate_text("test-workspace", actual)[0] == original
                assert len(requests) == 2 and len(dispatched) == 1
                assert artifact.split("'")[1] in json.dumps(requests[1][1])
            else:
                with pytest.raises(ValueError):
                    await run_contract(
                        provider,
                        "selected-model",
                        "synthetic-provider-key",
                        "test-workspace",
                        rest_api.get_universal_tool_schemas(),
                        dispatch,
                        expected,
                    )
                if behavior == "wrong-workspace":
                    assert dispatched == [] and len(requests) == 1
            assert requests[0][1]["tools"]
            assert "relayvault_rehydrate_output" not in json.dumps(requests)
            assert "local-key-never-send" not in json.dumps(requests)
            assert "demo@example.org" not in json.dumps(requests)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.live
def test_live_provider_contract():
    if os.environ.get("RELAYVAULT_LIVE_TESTS") != "1":
        pytest.skip("Live provider contract requires explicit opt-in and provider credentials")
    required = ("RELAYVAULT_LIVE_PROVIDER", "RELAYVAULT_LIVE_MODEL", "RELAYVAULT_LIVE_API_KEY")
    assert all(os.environ.get(name) for name in required), "Live provider configuration is incomplete"
    env = dict(os.environ, RELAYVAULT_DEMO_LIVE="1")
    result = subprocess.run(
        [sys.executable, "demo_multi_model.py"], env=env, capture_output=True, text=True, timeout=240
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[VERIFIED] Live provider issued a checkout call" in result.stdout
