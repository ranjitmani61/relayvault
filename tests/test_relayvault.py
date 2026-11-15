import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

import httpx
from jsonschema import Draft202012Validator
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from relayvault.engine import RelayVaultEngine

ROOT = Path(__file__).resolve().parents[1]
# Synthetic Stripe-shaped fixture, assembled to avoid resembling a real credential in source.
STRIPE_TEST_SECRET = "sk_" + "live_" + "9876543210abcdefghij123456"


@pytest.fixture
def vault(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("RELAYVAULT_HOME", str(home))
    return RelayVaultEngine(db_path=str(home / "relayvault.db"))


def commit(engine, model="claude-opus-4.7", branch="main", objective="Build a service"):
    return engine.commit_checkpoint("test-workspace", model, objective, [], [], {}, [], branch)


def test_cryptographic_at_rest(vault):
    keeper = sqlite3.connect(vault.db_path)
    keeper.execute("BEGIN")
    keeper.execute("SELECT COUNT(*) FROM secret_vault").fetchone()
    secrets = {
        "OPENAI_KEY": "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        "ANTHROPIC_KEY": "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        "AWS_ACCESS_KEY": "AKIA1234567890ABCDEF",
        "GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        "SLACK_TOKEN": "xoxb-1234567890-ABCDEFGHIJKL",
        "STRIPE_KEY": STRIPE_TEST_SECRET,
        "JWT_TOKEN": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmno12345",
        "PRIVATE_KEY_BLOCK": "-----BEGIN PRIVATE KEY-----\nABCD1234privatekeycontent\n-----END PRIVATE KEY-----",
        "GENERIC_BEARER_ASSIGNMENT": "Az09+/Qwerty1234567890",
        "EMAIL": "person@example.org",
        "IPV4_PRIVATE_OR_PROD": "10.23.45.67",
        "CREDIT_CARD": "4532015112830366",
    }
    original = "\n".join((f"secret = \"{value}\"" if kind == "GENERIC_BEARER_ASSIGNMENT" else value)
                         for kind, value in secrets.items())
    original += '\n4532015112830367\npassword = "aaaaabbbbbcccccdddddeeeee"\n'
    redacted, count = vault.redact_text("test-workspace", original)
    assert count == len(secrets)
    for kind, value in secrets.items():
        assert value not in redacted
        assert f"<RV_VAULT:{kind}:" in redacted
    assert "4532015112830367" in redacted
    assert 'password = "aaaaabbbbbcccccdddddeeeee"' in redacted
    with sqlite3.connect(vault.db_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        rows = connection.execute("SELECT raw_value FROM secret_vault").fetchall()
    assert len(rows) == len(secrets)
    assert all(row[0].startswith("gAAAAA") for row in rows)
    assert Path(vault.db_path + "-wal").exists()
    for path in Path(vault.db_path).parent.glob(Path(vault.db_path).name + "*"):
        data = path.read_bytes()
        for secret in secrets.values():
            assert secret.encode() not in data, path
    keeper.close()
    restored, restored_count = vault.rehydrate_text("test-workspace", redacted)
    assert restored == original
    assert restored_count == len(secrets)
    again, _ = vault.redact_text("test-workspace", original)
    assert again == redacted
    with sqlite3.connect(vault.db_path) as connection:
        assert connection.execute("SELECT raw_value FROM secret_vault").fetchall() == rows
    assert RelayVaultEngine(db_path=vault.db_path).rehydrate_text("test-workspace", redacted)[0] == original
    assert vault.rehydrate_text("other-workspace", redacted) == (redacted, 0)


def test_artifact_dictionary_key_is_redacted_at_rest(vault):
    key_secret = STRIPE_TEST_SECRET
    value_secret = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    keeper = sqlite3.connect(vault.db_path)
    keeper.execute("BEGIN")
    keeper.execute("SELECT COUNT(*) FROM checkpoints").fetchone()
    result = vault.commit_checkpoint("test-workspace", "test", "task", [], [], {f"config-{key_secret}.py": value_secret}, [])
    assert result["redactions_applied"] == 2
    checkout = vault.checkout_handoff("test-workspace")
    key, value = next(iter(checkout["artifacts"].items()))
    assert re.fullmatch(r"config-<RV_VAULT:STRIPE_KEY:[0-9a-f]{10}>\.py", key)
    assert re.fullmatch(r"<RV_VAULT:OPENAI_KEY:[0-9a-f]{10}>", value)
    assert vault.rehydrate_text("test-workspace", key)[0] == f"config-{key_secret}.py"
    assert vault.rehydrate_text("test-workspace", value)[0] == value_secret
    assert key_secret not in checkout["synthesized_handoff_prompt"]
    with sqlite3.connect(vault.db_path) as connection:
        stored = connection.execute("SELECT artifacts_json FROM checkpoints").fetchone()[0]
        assert json.loads(stored) == {key: value}
        rows = connection.execute("SELECT raw_value FROM secret_vault").fetchall()
        assert len(rows) == 2 and all(row[0].startswith("gAAAAA") for row in rows)
    assert Path(vault.db_path + "-wal").exists()
    for path in Path(vault.db_path).parent.glob(Path(vault.db_path).name + "*"):
        contents = path.read_bytes()
        assert key_secret.encode() not in contents and value_secret.encode() not in contents
    keeper.close()


def test_stripe_style_secret_with_underscores_is_redacted(vault):
    secret = "sk_" + "live_codex_mcp_verify_998877665544332211"
    redacted, count = vault.redact_text("self-host-test", secret)
    assert count == 1
    assert re.fullmatch(r"<RV_VAULT:STRIPE_KEY:[0-9a-f]{10}>", redacted)
    assert vault.rehydrate_text("self-host-test", redacted) == (secret, 1)
    with sqlite3.connect(vault.db_path) as connection:
        ciphertext = connection.execute("SELECT raw_value FROM secret_vault").fetchone()[0]
    assert ciphertext.startswith("gAAAAA") and secret not in ciphertext


def test_nested_dictionary_keys_and_collisions(vault):
    secret = STRIPE_TEST_SECRET
    redacted, count = vault._redact_structure("test-workspace", {"nested": [{secret: secret}]})
    token, value = next(iter(redacted["nested"][0].items()))
    assert token == value and token.startswith("<RV_VAULT:STRIPE_KEY:")
    assert count == 2
    with pytest.raises(ValueError, match="keys collide"):
        vault._redact_structure("test-workspace", {secret: "first", token: "second"})


def test_dag_branch_isolation(vault):
    first = commit(vault)
    second = commit(vault, model="gemini-3.1-pro")
    third = commit(vault, branch="experiment-redis")
    assert second["parent_hash"] == first["commit_hash"]
    assert third["parent_hash"] is None
    head = vault.checkout_handoff("test-workspace", branch="main")
    assert head["commit_hash"] == second["commit_hash"]
    assert [item["commit_hash"] for item in head["branch_lineage"]] == [first["commit_hash"], second["commit_hash"]]
    assert vault.checkout_handoff("test-workspace", branch="experiment-redis")["commit_hash"] == third["commit_hash"]
    fork = vault.commit_checkpoint("test-workspace", "test", "fork", [], [], {}, [], "fork", first["commit_hash"])
    assert [item["commit_hash"] for item in vault.checkout_handoff("test-workspace", branch="fork")["branch_lineage"]] == [first["commit_hash"], fork["commit_hash"]]
    with pytest.raises(ValueError, match="Parent checkpoint"):
        vault.commit_checkpoint("test-workspace", "test", "bad parent", [], [], {}, [], "fork", "missing")


def test_concurrent_commits_form_a_single_chain(vault):
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda n: commit(vault, model=f"model-{n}"), range(8)))
    lineage = vault.checkout_handoff("test-workspace")["branch_lineage"]
    assert len(lineage) == len(results) == 8
    by_hash = {item["commit_hash"]: item for item in results}
    assert by_hash[lineage[0]["commit_hash"]]["parent_hash"] is None
    for previous, current in zip(lineage, lineage[1:]):
        assert by_hash[current["commit_hash"]]["parent_hash"] == previous["commit_hash"]


def test_missing_master_key_does_not_generate_a_replacement(vault):
    vault.redact_text("test-workspace", STRIPE_TEST_SECRET)
    key = Path(os.environ["RELAYVAULT_HOME"]) / "master.key"
    key.unlink()
    with pytest.raises(RuntimeError, match="master.key is missing"):
        RelayVaultEngine(db_path=vault.db_path)
    assert not key.exists()


@pytest.mark.asyncio
async def test_rest_auth_openapi_and_real_round_trip(vault, monkeypatch):
    from relayvault import rest_api
    previous = rest_api.engine
    rest_api.engine = vault
    monkeypatch.setenv("RELAYVAULT_API_KEY", "test-api-key")
    monkeypatch.delenv("RELAYVAULT_REHYDRATE_KEY", raising=False)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=rest_api.app), base_url="http://test") as client:
            payload = {"workspace_id": "test-workspace", "source_model": "test", "objective": STRIPE_TEST_SECRET}
            assert (await client.post("/v1/checkpoints/commit", json=payload)).status_code in (401, 403)
            assert (await client.post("/v1/checkpoints/commit", headers={"Authorization": "Bearer wrong-key"}, json=payload)).status_code == 401
            response = await client.get("/openapi.json")
            assert response.status_code == 200 and response.json()["openapi"] == "3.1.0"
            response = await client.get("/v1/schemas/tools")
            assert response.status_code == 200
            schemas = response.json()
            expected = {"relayvault_commit_checkpoint", "relayvault_checkout_handoff"}
            assert "relayvault_rehydrate_output" not in json.dumps(schemas)
            assert {x["function"]["name"] for x in schemas["openai_deepseek_kimi_grok"]} == expected
            assert {x["name"] for x in schemas["anthropic_claude"]} == expected
            assert {x["name"] for group in schemas["google_gemini"] for x in group["function_declarations"]} == expected
            for schema in ([x["function"]["parameters"] for x in schemas["openai_deepseek_kimi_grok"]]
                           + [x["input_schema"] for x in schemas["anthropic_claude"]]
                           + [x["parameters"] for group in schemas["google_gemini"] for x in group["function_declarations"]]):
                Draft202012Validator.check_schema(schema)
                assert schema["type"] == "object" and schema["properties"]
            headers = {"Authorization": "Bearer test-api-key"}
            assert (await client.post("/v1/checkpoints/commit", headers=headers, json=payload)).status_code == 200
            checkout = await client.post("/v1/checkpoints/checkout", headers=headers, json={"workspace_id": "test-workspace"})
            assert checkout.status_code == 200
            token = checkout.json()["objective"]
            assert token.startswith("<RV_VAULT:STRIPE_KEY:")
            request = {"workspace_id": "test-workspace", "text_with_vault_tokens": f"prefix {token} suffix\n"}
            assert (await client.post("/v1/vault/rehydrate", headers=headers, json=request)).status_code == 403
            assert (await client.post("/v1/vault/rehydrate", headers={**headers, "X-RelayVault-Local-Intent": "wrong"}, json=request)).status_code == 403
            assert (await client.post("/v1/vault/rehydrate", headers={"X-RelayVault-Local-Intent": "rehydrate"}, json=request)).status_code in (401, 403)
            assert (await client.post("/v1/vault/rehydrate", headers={"Authorization": "Bearer wrong-key", "X-RelayVault-Local-Intent": "rehydrate"}, json=request)).status_code == 401
            rehydrated = await client.post("/v1/vault/rehydrate", headers={**headers, "X-RelayVault-Local-Intent": "rehydrate"}, json=request)
            assert rehydrated.status_code == 200
            assert rehydrated.json()["rehydrated_text"] == f"prefix {payload['objective']} suffix\n"
            assert rehydrated.json()["tokens_rehydrated"] == 1
            monkeypatch.delenv("RELAYVAULT_API_KEY")
            assert (await client.post("/v1/checkpoints/commit", headers=headers, json=payload)).status_code == 503
    finally:
        rest_api.engine = previous


@pytest.mark.asyncio
async def test_rest_rehydrate_key_and_loopback_restrictions(vault, monkeypatch):
    from relayvault import rest_api
    previous = rest_api.engine
    rest_api.engine = vault
    monkeypatch.setenv("RELAYVAULT_API_KEY", "test-api-key")
    secret = STRIPE_TEST_SECRET
    token, _ = vault.redact_text("test-workspace", secret)
    payload = {"workspace_id": "test-workspace", "text_with_vault_tokens": token}
    headers = {"Authorization": "Bearer test-api-key", "X-RelayVault-Local-Intent": "rehydrate"}
    try:
        monkeypatch.setenv("RELAYVAULT_REHYDRATE_KEY", "independent-rehydrate-key")
        for host in ("127.0.0.1", "203.0.113.7"):
            transport = httpx.ASGITransport(app=rest_api.app, client=(host, 1234))
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                assert (await client.post("/v1/vault/rehydrate", headers=headers, json=payload)).status_code == 403
                assert (await client.post("/v1/vault/rehydrate", headers={**headers, "X-RelayVault-Rehydrate-Key": "wrong"}, json=payload)).status_code == 403
                correct = {**headers, "X-RelayVault-Rehydrate-Key": "independent-rehydrate-key"}
                response = await client.post("/v1/vault/rehydrate", headers=correct, json=payload)
                assert response.status_code == 200 and response.json()["rehydrated_text"] == secret
                assert (await client.post("/v1/vault/rehydrate", headers={"X-RelayVault-Local-Intent": "rehydrate", "X-RelayVault-Rehydrate-Key": "independent-rehydrate-key"}, json=payload)).status_code in (401, 403)
        monkeypatch.delenv("RELAYVAULT_REHYDRATE_KEY")
        for host in ("127.0.0.1", "::1", "testclient", "203.0.113.7", "localhost"):
            transport = httpx.ASGITransport(app=rest_api.app, client=(host, 1234))
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post("/v1/vault/rehydrate", headers=headers, json=payload)
                if host in ("127.0.0.1", "::1", "testclient"):
                    assert response.status_code == 200 and response.json()["rehydrated_text"] == secret
                else:
                    assert response.status_code == 403
        monkeypatch.setenv("RELAYVAULT_REHYDRATE_KEY", "")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=rest_api.app), base_url="http://test") as client:
            assert (await client.post("/v1/vault/rehydrate", headers=headers, json=payload)).status_code == 503
    finally:
        rest_api.engine = previous


@pytest.mark.asyncio
async def test_rest_proxied_loopback_requires_rehydration_key(vault, monkeypatch):
    from relayvault import rest_api
    previous = rest_api.engine
    rest_api.engine = vault
    monkeypatch.setenv("RELAYVAULT_API_KEY", "test-api-key")
    monkeypatch.delenv("RELAYVAULT_REHYDRATE_KEY", raising=False)
    secret = STRIPE_TEST_SECRET
    token, _ = vault.redact_text("test-workspace", secret)
    payload = {"workspace_id": "test-workspace", "text_with_vault_tokens": token}
    headers = {"Authorization": "Bearer test-api-key", "X-RelayVault-Local-Intent": "rehydrate"}
    proxy_headers = ("X-Forwarded-For", "X-Real-IP", "Forwarded", "CF-Connecting-IP", "True-Client-IP", "X-Client-IP")
    try:
        transport = httpx.ASGITransport(app=rest_api.app, client=("127.0.0.1", 1234))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            for header in proxy_headers:
                response = await client.post("/v1/vault/rehydrate", headers={**headers, header: "203.0.113.5"}, json=payload)
                assert response.status_code == 403
                assert response.json()["detail"] == "Proxied requests require RELAYVAULT_REHYDRATE_KEY to be configured"
            # Header presence, even with an empty value, must fail closed.
            assert (await client.post("/v1/vault/rehydrate", headers={**headers, "Forwarded": ""}, json=payload)).status_code == 403
            monkeypatch.setenv("RELAYVAULT_REHYDRATE_KEY", "separate-rehydrate-key")
            for header in proxy_headers:
                forwarded = {**headers, header: "203.0.113.5"}
                assert (await client.post("/v1/vault/rehydrate", headers=forwarded, json=payload)).status_code == 403
                assert (await client.post("/v1/vault/rehydrate", headers={**forwarded, "X-RelayVault-Rehydrate-Key": "wrong"}, json=payload)).status_code == 403
                response = await client.post("/v1/vault/rehydrate", headers={**forwarded, "X-RelayVault-Rehydrate-Key": "separate-rehydrate-key"}, json=payload)
                assert response.status_code == 200 and response.json()["rehydrated_text"] == secret
    finally:
        rest_api.engine = previous


@pytest.mark.asyncio
async def test_mcp_stdio_protocol(tmp_path):
    env = os.environ.copy()
    env.pop("RELAYVAULT_ALLOW_AGENT_REHYDRATE", None)
    env["RELAYVAULT_HOME"] = str(tmp_path / "mcp-home")
    params = StdioServerParameters(command=sys.executable, args=["-m", "relayvault.mcp_server", "--transport", "stdio"], env=env)
    secret = STRIPE_TEST_SECRET
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {tool.name for tool in tools.tools} == {"relayvault_commit_checkpoint", "relayvault_checkout_handoff", "relayvault_list_history"}
            result = await session.call_tool("relayvault_commit_checkpoint", arguments={"workspace_id": "mcp-test", "source_model": "test", "objective": secret, "locked_decisions": [], "failed_approaches": [], "artifacts": {}, "next_steps": []})
            assert not result.isError
            assert json.loads(result.content[0].text)["redactions_applied"] == 1
            result = await session.call_tool("relayvault_checkout_handoff", arguments={"workspace_id": "mcp-test"})
            assert not result.isError
            checkout = json.loads(result.content[0].text)
            token = checkout["objective"]
            assert re.fullmatch(r"<RV_VAULT:STRIPE_KEY:[0-9a-f]{10}>", token)
            resource = await session.read_resource("rv://mcp-test/main/head")
            assert token in resource.contents[0].text
            assert "RELAYVAULT DETERMINISTIC STATE HANDOFF" in resource.contents[0].text
            result = await session.call_tool("relayvault_rehydrate_output", arguments={"workspace_id": "mcp-test", "text_with_vault_tokens": token})
            assert result.isError
            assert secret not in str(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("opt_in", ["environment", "module_flag", "cli_flag", "entrypoint_flag"])
async def test_mcp_explicit_rehydration_opt_in(tmp_path, opt_in):
    env = os.environ.copy()
    env.pop("RELAYVAULT_ALLOW_AGENT_REHYDRATE", None)
    env["RELAYVAULT_HOME"] = str(tmp_path / "mcp-opt-in-home")
    if opt_in == "environment":
        env["RELAYVAULT_ALLOW_AGENT_REHYDRATE"] = "1"
    if opt_in == "cli_flag":
        command = str(Path(sys.executable).parent / "relayvault")
        args = ["serve-mcp", "--allow-agent-rehydrate"]
    elif opt_in == "entrypoint_flag":
        command = str(Path(sys.executable).parent / "relayvault-mcp")
        args = ["--allow-agent-rehydrate"]
    else:
        command = sys.executable
        args = ["-m", "relayvault.mcp_server", "--transport", "stdio"]
        if opt_in == "module_flag":
            args.append("--allow-agent-rehydrate")
    params = StdioServerParameters(command=command, args=args, env=env)
    secret = STRIPE_TEST_SECRET
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            assert {tool.name for tool in (await session.list_tools()).tools} == {"relayvault_commit_checkpoint", "relayvault_checkout_handoff", "relayvault_list_history", "relayvault_rehydrate_output"}
            committed = await session.call_tool("relayvault_commit_checkpoint", arguments={"workspace_id": "opt-in", "source_model": "test", "objective": secret, "locked_decisions": [], "failed_approaches": [], "artifacts": {}, "next_steps": []})
            assert not committed.isError
            checkout = await session.call_tool("relayvault_checkout_handoff", arguments={"workspace_id": "opt-in"})
            token = json.loads(checkout.content[0].text)["objective"]
            result = await session.call_tool("relayvault_rehydrate_output", arguments={"workspace_id": "opt-in", "text_with_vault_tokens": token})
            assert not result.isError
            assert json.loads(result.content[0].text)["rehydrated_text"] == secret


def test_cli_rehydrate_file_and_log(vault, tmp_path):
    secret = STRIPE_TEST_SECRET
    commit(vault, objective=secret)
    token = vault.checkout_handoff("test-workspace")["objective"]
    target = tmp_path / "config.py"
    target.write_text(f"API_KEY = '{token}'\n")
    executable = str(Path(sys.executable).parent / "relayvault")
    subprocess.run([executable, "rehydrate-file", "--workspace", "test-workspace", "--file", str(target), "--in-place"], check=True, capture_output=True, text=True)
    assert target.read_text() == f"API_KEY = '{secret}'\n"
    result = subprocess.run([executable, "log", "--workspace", "test-workspace"], check=True, capture_output=True, text=True)
    history = json.loads(result.stdout)
    assert len(history) == 1 and history[0]["objective"] == token


def test_cli_dehydrate_rehydrate_preserves_original_bytes(vault, tmp_path):
    secret = STRIPE_TEST_SECRET.encode("ascii")
    original = b"\xef\xbb\xbf# caf\xc3\xa9\r\nTOKEN = '" + secret + b"'\r\nother = 1\nlast line\r"
    target = tmp_path / "config.py"
    target.write_bytes(original)
    executable = str(Path(sys.executable).parent / "relayvault")
    base = ["--workspace", "test-workspace", "--file", str(target)]
    output = subprocess.run([executable, "dehydrate-file", *base], check=True, capture_output=True).stdout
    assert secret not in output and b"<RV_VAULT:STRIPE_KEY:" in output
    assert target.read_bytes() == original
    subprocess.run([executable, "dehydrate-file", *base, "--in-place"], check=True, capture_output=True)
    assert target.read_bytes() == output
    restored_stdout = subprocess.run([executable, "rehydrate-file", *base], check=True, capture_output=True).stdout
    assert restored_stdout == original and target.read_bytes() == output
    subprocess.run([executable, "rehydrate-file", *base, "--in-place"], check=True, capture_output=True)
    assert target.read_bytes() == original


def test_manifest_and_demo(tmp_path):
    manifest = json.loads((ROOT / "server.json").read_text())
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert manifest["version"] == project["project"]["version"] == "0.1.0"
    assert manifest["name"] == "io.github.ranjitmani61/relayvault"
    assert manifest["repository"]["url"] == "https://github.com/ranjitmani61/relayvault"
    env = os.environ.copy()
    env["RELAYVAULT_HOME"] = str(tmp_path / "demo-home")
    env.pop("RELAYVAULT_DEMO_LIVE", None)
    env.pop("RELAYVAULT_REHYDRATE_KEY", None)
    result = subprocess.run([sys.executable, str(ROOT / "demo_multi_model.py")], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count("[VERIFIED]") >= 2
