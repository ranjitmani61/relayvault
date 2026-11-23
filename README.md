# RelayVault

<!-- mcp-name: io.github.ranjitmani61/relayvault -->

[![CI](https://github.com/ranjitmani61/relayvault/actions/workflows/ci.yml/badge.svg)](https://github.com/ranjitmani61/relayvault/actions/workflows/ci.yml)


RelayVault stores redacted task checkpoints in a local SQLite WAL database and provides MCP, REST, and CLI interfaces for handing work between models. Detected secrets are replaced with stable workspace-specific tokens; their original values are encrypted in the local vault.

```text
 [Model A: Claude / GPT]
             |
          (commit)
             v
 [RelayVault Redaction Engine] ----(Fernet AES ciphertext)----> [Local SQLite secret_vault]
             |                                                  [master.key (0600)]
             |  Scrubbed <RV_VAULT:...> DAG state
             v
 [Model B: DeepSeek / Kimi / Gemini / Grok]
             |
             |  Code with <RV_VAULT:...> intact
             v
 [Local CLI: relayvault rehydrate-file]
```

The boundary protects the **outgoing redacted handoff** to Model B, not plaintext already sent to Model A before a commit. To avoid sending secrets to either model, run `dehydrate-file` locally before supplying text to a model, and review the resulting text. Detection is heuristic and cannot guarantee that all sensitive data is removed.

## Install and quickstart

Python 3.11 or later is required. RelayVault **0.2.0** is available on [PyPI](https://pypi.org/project/relayvault/0.2.0/). Existing vaults require the explicit [v2 migration](docs/SECURITY.md#legacy-migration). For a clean installation:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install "relayvault==0.2.0"

# Choose a long random value; keep it outside source control.
export RELAYVAULT_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export RELAYVAULT_WORKSPACES='{"example":["read","write"]}'
relayvault serve-api --host 127.0.0.1 --port 8000
```

In another terminal, with the same environment and `RELAYVAULT_HOME`:

```bash
curl -sS -X POST http://127.0.0.1:8000/v1/checkpoints/commit \
  -H "Authorization: Bearer $RELAYVAULT_API_KEY" -H 'Content-Type: application/json' \
  -d '{"workspace_id":"example", "source_model":"model-a", "objective":"Implement a retry handler"}'

curl -sS -X POST http://127.0.0.1:8000/v1/checkpoints/checkout \
  -H "Authorization: Bearer $RELAYVAULT_API_KEY" -H 'Content-Type: application/json' \
  -d '{"workspace_id":"example", "target_model":"model-b"}'
```

The server also exposes `/openapi.json`, `/docs`, and `/v1/schemas/tools`. `RELAYVAULT_HOME` selects the data directory; the default is `~/.relayvault`. All clients that need to share a vault must use the same home and salt.

For development from a cloned repository, use the hash-pinned dependencies and editable install instead of the PyPI installation command:

```bash
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
```

## Connect MCP clients

These examples run the server locally over stdio. By default the available tools are `relayvault_commit_checkpoint`, `relayvault_checkout_handoff`, and `relayvault_list_history`; agent rehydration is disabled. The CLI and REST examples below do not require an MCP client.

### Claude Code

From the directory containing your `.venv`, use an absolute executable path so the server does not depend on the client's PATH. Set a shared vault home explicitly:

```bash
claude mcp add --transport stdio \
  --env "RELAYVAULT_HOME=$HOME/.relayvault" \
  relayvault -- "$PWD/.venv/bin/relayvault-mcp"
claude mcp get relayvault
```

See the [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp) for scopes and troubleshooting.

### Claude Desktop

Add this entry to `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows, or `~/.config/Claude/claude_desktop_config.json` on Linux. Replace both example paths with **absolute paths** on your machine; on Windows use the virtual environment's `Scripts\\relayvault-mcp.exe` and escaped JSON backslashes. Merge the entry with any existing `mcpServers`, then fully restart Claude Desktop.

```json
{
  "mcpServers": {
    "relayvault": {
      "command": "/absolute/path/to/relayvault/.venv/bin/relayvault-mcp",
      "args": [],
      "env": {"RELAYVAULT_HOME": "/absolute/path/to/.relayvault"}
    }
  }
}
```

See [MCP's local server configuration guide](https://modelcontextprotocol.io/docs/develop/connect-local-servers).

### Cursor

Add this entry to `.cursor/mcp.json` in a project or `~/.cursor/mcp.json` for the current user. Replace the example paths with absolute paths, and restart or reload Cursor.

```json
{
  "mcpServers": {
    "relayvault": {
      "type": "stdio",
      "command": "/absolute/path/to/relayvault/.venv/bin/relayvault-mcp",
      "args": [],
      "env": {"RELAYVAULT_HOME": "/absolute/path/to/.relayvault"}
    }
  }
}
```

See [Cursor's MCP configuration](https://cursor.com/docs/mcp). Do not set `RELAYVAULT_ALLOW_AGENT_REHYDRATE` in model-facing client configurations unless the client is trusted to receive plaintext secrets.

## REST and provider function calling

Run RelayVault locally as shown in Quickstart. The `/v1/schemas/tools` response contains two model-facing function definitions for `openai_deepseek_kimi_grok`, `anthropic_claude`, and `google_gemini`; it never contains a rehydration function. The following examples send a **new request to an external provider**, may incur charges, and require that provider's credentials and access to a compatible model. Use only reviewed, redacted content.

### OpenAI, DeepSeek, and Kimi: Chat Completions

Choose one configuration and a model available to your account. These examples target the Chat Completions tool format; some OpenAI models require the Responses API instead.

```bash
# OpenAI:
export PROVIDER_URL='https://api.openai.com/v1/chat/completions'
export PROVIDER_API_KEY="$OPENAI_API_KEY"

# DeepSeek (use instead of the two lines above):
# export PROVIDER_URL='https://api.deepseek.com/chat/completions'
# export PROVIDER_API_KEY="$DEEPSEEK_API_KEY"

# Kimi / Moonshot international (use instead):
# export PROVIDER_URL='https://api.moonshot.ai/v1/chat/completions'
# export PROVIDER_API_KEY="$KIMI_API_KEY"

export MODEL='replace-with-a-chat-completions-model-available-to-your-account'
python - <<'PY'
import os
import httpx

schemas = httpx.get('http://127.0.0.1:8000/v1/schemas/tools').raise_for_status().json()
response = httpx.post(
    os.environ['PROVIDER_URL'],
    headers={'Authorization': 'Bearer ' + os.environ['PROVIDER_API_KEY']},
    json={
        'model': os.environ['MODEL'],
        'messages': [{'role': 'user', 'content': 'Check out the latest handoff for workspace example.'}],
        'tools': schemas['openai_deepseek_kimi_grok'],
    },
    timeout=60,
)
response.raise_for_status()
print(response.json())
PY
```

This prints the provider response, including any proposed tool calls. The application must validate the function name and arguments, execute only the intended local endpoint (`/v1/checkpoints/commit` or `/v1/checkpoints/checkout`) with `RELAYVAULT_API_KEY`, and return the tool result to the provider in its required format. Sending schemas alone does **not** execute the functions. Never pass either RelayVault credential to the provider. See [OpenAI Chat Completions tools](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create), [DeepSeek Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/), and [Kimi provider configuration](https://moonshotai.github.io/kimi-code/en/configuration/providers.html).

### Gemini: generateContent

Set `GEMINI_API_KEY` and choose an available model in `MODEL`. This example converts the exported function parameters to Gemini's `parametersJsonSchema` field and prints any proposed function call; the application must validate, execute, and return results as described above.

```bash
export MODEL='replace-with-a-gemini-model-available-to-your-account'
python - <<'PY'
import os
import httpx

schemas = httpx.get('http://127.0.0.1:8000/v1/schemas/tools').raise_for_status().json()
declarations = []
for group in schemas['google_gemini']:
    for function in group['function_declarations']:
        declarations.append({
            'name': function['name'],
            'description': function['description'],
            'parametersJsonSchema': function['parameters'],
        })
response = httpx.post(
    'https://generativelanguage.googleapis.com/v1beta/models/' + os.environ['MODEL'] + ':generateContent',
    headers={'x-goog-api-key': os.environ['GEMINI_API_KEY']},
    json={
        'contents': [{'parts': [{'text': 'Check out the latest handoff for workspace example.'}]}],
        'tools': [{'functionDeclarations': declarations}],
    },
    timeout=60,
)
response.raise_for_status()
print(response.json())
PY
```

See the [Gemini function declaration reference](https://ai.google.dev/api/generate-content) for provider schema and response details. Provider model availability and supported schemas can change; test the integration against your selected model before deployment.

## HTTP authentication and workspace permissions

Stdio trusts the OS user running the server. Both HTTP MCP transports and REST require explicit workspace grants. For a single client use the Quickstart environment above; for multiple clients set `RELAYVAULT_AUTH_FILE` to a private 0600 JSON file:

```json
{
  "coding-agent": {
    "key": "replace-with-a-unique-random-agent-key",
    "workspaces": {"example": ["read", "write"]}
  },
  "reviewer": {
    "key": "replace-with-another-random-key",
    "workspaces": {"example": ["read"]}
  }
}
```

This file takes precedence over `RELAYVAULT_API_KEY` / `RELAYVAULT_WORKSPACES`. Wildcard workspaces are not accepted. Send the selected client's key as `Authorization: Bearer ...`. For HTTP MCP, use `relayvault serve-mcp --transport streamable-http --port 8090` (`/mcp`), or legacy `--transport sse` (`/sse`). These listeners bind to localhost; expose them through an authenticated TLS deployment only after configuring network controls. Clients must support explicitly supplied bearer headers; RelayVault is not an OAuth authorization server.

REST rehydration is disabled until a **different** `RELAYVAULT_REHYDRATE_KEY` is configured. It requires the ordinary credential, workspace read permission and both additional headers, even on loopback:

```bash
# Set on the trusted server and rehydration host; do not give it to the agent.
export RELAYVAULT_REHYDRATE_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
# Restart the server with this environment, then send a local restoration request:
curl -sS http://127.0.0.1:8000/v1/vault/rehydrate \
  -H "Authorization: Bearer $RELAYVAULT_API_KEY" \
  -H 'X-RelayVault-Local-Intent: rehydrate' \
  -H "X-RelayVault-Rehydrate-Key: $RELAYVAULT_REHYDRATE_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"workspace_id":"example","text_with_vault_tokens":"paste the exact vaulted output here"}'
```

The endpoint is absent from OpenAPI/tool schemas. **Proxy deployments require the separate rehydration key**, just like local deployments; client addresses and forwarding headers never grant decryption privileges.

## Detection preview and local review

The default `block-uncertain` policy rejects unclassified high-entropy credential-like strings. Review mode also withholds checkpoint exports until a trusted local review:

```bash
export RELAYVAULT_REDACTION_POLICY=review
relayvault preview-file --workspace example --file config.py
relayvault dehydrate-file --workspace example --file config.py --in-place --reviewed
# After an MCP/REST commit, use the returned commit hash:
relayvault inspect-checkpoint --workspace example --commit COMMIT_HASH
relayvault approve-checkpoint --workspace example --commit COMMIT_HASH --reviewed
```

Review the actual output for unstructured PII and unexpected credentials before approving. There is no model-facing approval tool. Optional `RELAYVAULT_DETECTORS_FILE` points to trusted JSON such as `[{"name":"EMPLOYEE_ID","pattern":"EMP-[0-9]{6}"}]`; add bounded patterns and regression cases for your domain.

## CLI reference

| Command | Purpose and options |
| --- | --- |
| `serve-mcp [--transport stdio\|sse\|streamable-http] [--port 8090] [--allow-agent-rehydrate]` | MCP; stdio default. HTTP requires bearer keys and workspace grants. Plaintext opt-in is stdio-only. |
| `serve-api [--host 127.0.0.1] [--port 8000]` | REST; requires bearer keys and workspace grants. |
| `preview-file --workspace ID --file PATH` | Display detected spans as preview markers and an uncertainty count without vaulting the file. |
| `dehydrate-file --workspace ID --file PATH [--in-place] [--reviewed]` | Vault detected values; review policy requires explicit local review. |
| `rehydrate-file --workspace ID --file PATH [--in-place] [--allow-partial]` | Restore tokens; unresolved/malformed tokens fail by default. |
| `log --workspace ID [--branch BRANCH]` | Integrity-checked, redacted history. |
| `inspect-checkpoint --workspace ID --commit HASH` | Trusted local preview of a pending checkpoint. |
| `approve-checkpoint --workspace ID --commit HASH --reviewed` | Approve that exact reviewed checkpoint for export. |
| `verify-vault` | Verify every record, checkpoint, head and lineage. |
| `backup --destination NEW_DIR` | Consistent SQLite snapshot with key and salt configuration. |
| `restore --source BACKUP_DIR --destination NEW_DIR` | Verify and restore into a new home. |
| `rotate-key --destination NEW_DIR` | Reencrypt into a new home; preserve tokens and checkpoint IDs. |
| `migrate-vault --destination NEW_DIR` | Explicit legacy migration; preserve old token recovery and require local checkpoint reviews. |

Prefix commands with `relayvault`. File commands support UTF-8 and preserve original bytes/line endings on successful round trips. Atomic in-place rehydration writes a 0600 plaintext file. `relayvault-mcp` is the stdio entry point. Stop clients before maintenance/cutover and update their `RELAYVAULT_HOME` together; maintenance commands never overwrite the source or an existing destination.

## Security model & limitations

- **Caught patterns:** structured API keys, contextual bearer/basic credentials, quoted/unquoted secret assignments, JWTs, PEM private keys, emails, validated private IPv4s and Luhn-valid card candidates. Nested dictionary keys and values are scanned; sensitive identifier fields are rejected. Detection remains heuristic.
- **Not comprehensively caught:** prose PII such as human names and street addresses without additional NER, encoded or fragmented credentials, unknown secret formats and arbitrary low-entropy values. Zero detections do not establish safety. A curated corpus is not a real-world accuracy score.
- **Local secrets:** v2 tokens use a secret HMAC key with 128-bit identifiers. Fernet authenticates values together with their record identity. Checkpoint/head HMACs detect modifications; whole-database rollback and deletion require external protections.
- **Keys and backups:** keep `master.key`, `relayvault.db` and `vault-config.json` (including any custom salt) together. Use `backup` for a consistent WAL snapshot, restrict access and protect backups separately. Existing ownership and permissions are checked. Lost keys cannot be recovered.
- **Prompt injection:** handoffs are untrusted task data with self-reported provenance. Review and host-enforced tool permissions remain necessary. Prompt wording cannot establish a security boundary.
- **OS boundary:** an agent with the vault owner's shell/filesystem access can decrypt secrets. Use a separate account/host and scoped HTTP credentials to isolate such an agent; do not give it the master or rehydration key.

Read the full [security model, migration and recovery guide](docs/SECURITY.md) before deployment. `server.json` describes the verified PyPI package for MCP Registry publication; a registry listing requires a separate submission. See [release verification](docs/RELEASE.md).

## Verify and measure

```bash
pytest -v
python demo_multi_model.py
python scripts/redaction_report.py
ruff check .
ruff format --check .
pip-audit --require-hashes -r requirements.lock
python -m build
```

The default demo runs an actual MCP stdio producer, REST consumer and separate-key restoration with synthetic data in a temporary vault. It calls no external model. CI checks Python 3.11/3.12 on Ubuntu/macOS, lint, corpus, demo, wheel installation and dependency vulnerabilities. Hash-pinned runtime/development lockfiles support reproducible installation; see the release guide to regenerate them.

To test an actual provider, choose `openai`, `deepseek`, `kimi`, `anthropic` or `gemini`, supply a model available to your account and explicitly enable the live contract:

```bash
export RELAYVAULT_LIVE_PROVIDER=deepseek
export RELAYVAULT_LIVE_MODEL='your-supported-tool-calling-model'
export RELAYVAULT_LIVE_API_KEY="$DEEPSEEK_API_KEY"
RELAYVAULT_DEMO_LIVE=1 python demo_multi_model.py
# Or run the opt-in pytest contract:
RELAYVAULT_LIVE_TESTS=1 pytest -v -m live
```

This sends synthetic scrubbed data to the chosen provider and may incur charges. The runner sends real tool definitions, requires a checkout call, validates its workspace/name/arguments, dispatches through REST, returns the tool result and checks all expected tokens before local restoration. It fails if tokens are missing, changed or invented. The normal test suite uses a local simulated provider for wire-format tests and explicitly skips the live contract. Passing local tests is not proof of live provider interoperability or user adoption.
