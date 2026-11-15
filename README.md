# RelayVault

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

Python 3.10 or later is required. From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e . pytest pytest-asyncio

# Choose a long random value; keep it outside source control.
export RELAYVAULT_API_KEY='replace-with-a-long-random-local-api-key'
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

## Connect MCP clients

These examples run the server locally over stdio. By default the available tools are `relayvault_commit_checkpoint`, `relayvault_checkout_handoff`, and `relayvault_list_history`; agent rehydration is disabled. The CLI and REST examples below do not require an MCP client.

### Claude Code

From the repository root, use an absolute executable path so the server does not depend on the client's PATH. Set a shared vault home explicitly:

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

Run RelayVault locally as shown in Quickstart. The `/v1/schemas/tools` response contains two safe function definitions for `openai_deepseek_kimi_grok`, `anthropic_claude`, and `google_gemini`; it never contains a rehydration function. The following examples send a **new request to an external provider**, may incur charges, and require that provider's credentials and access to a compatible model. Use only reviewed, redacted content.

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

## CLI reference

| Command | Purpose and options |
| --- | --- |
| `relayvault serve-mcp [--transport stdio\|sse\|streamable-http] [--port 8090] [--allow-agent-rehydrate]` | Start MCP; stdio is the default. The final flag exposes plaintext rehydration to the connected agent. |
| `relayvault serve-api [--host 127.0.0.1] [--port 8000]` | Start the authenticated REST server. |
| `relayvault dehydrate-file --workspace ID --file PATH [--in-place]` | Vault detected secrets in a UTF-8 file; write scrubbed text to stdout or overwrite the file. |
| `relayvault rehydrate-file --workspace ID --file PATH [--in-place]` | Restore tokens from that workspace to stdout or overwrite the UTF-8 file. |
| `relayvault log --workspace ID [--branch BRANCH]` | Print checkpoint history as JSON. |

Both file commands preserve UTF-8 bytes and line endings on a successful round trip. In-place rehydration writes plaintext to disk. `relayvault-mcp` is a stdio-only entry point; it also accepts `--allow-agent-rehydrate`. Run any command with `--help` for details.

## Security model & limitations

- **Detected patterns:** structured OpenAI, Anthropic, Google, AWS, GitHub, Slack, and Stripe keys; some quoted high-entropy secret/password/token assignments; JWTs; PEM private-key blocks; email addresses; private IPv4 patterns; and Luhn-valid credit-card numbers. String keys and values in nested dictionaries are scanned. These are pattern checks, not comprehensive classifiers.
- **Not detected reliably:** unstructured prose PII such as human names and street addresses, which would require additional detection such as a NER model. Unrecognized credentials and fields used as identifiers may also remain plaintext. Review handoffs before sending them externally.
- **Key and backups:** `master.key` is created with owner-only permissions (0600) in `RELAYVAULT_HOME`. Back up the key, `relayvault.db`, and any custom `RELAYVAULT_SALT` together, using a consistent SQLite backup that accounts for WAL. Losing the key or changing the salt prevents rehydration. Protect backups separately from the database. Vaults from the original hard-coded-key version require an explicit migration.
- **REST rehydration:** `/v1/vault/rehydrate` requires the Bearer API key and `X-RelayVault-Local-Intent: rehydrate`. Set a distinct, nonempty `RELAYVAULT_REHYDRATE_KEY` and send it as `X-RelayVault-Rehydrate-Key` to authorize rehydration independently. When unset, only loopback clients without recognized forwarding headers are accepted. An empty configured key fails closed. **Proxy deployments require the separate rehydration key**: proxies may strip or use unrecognized headers, or alter the reported client address. Restrict network access and trusted proxy settings as well; the header check is not a substitute for proxy authentication.
- **Agent access:** MCP rehydration is off by default. `RELAYVAULT_ALLOW_AGENT_REHYDRATE=1` or `--allow-agent-rehydrate` enables it and gives that MCP client access to plaintext secrets. Use only with fully trusted clients; keep this option disabled for model-facing tools.
- **At rest:** the vault encrypts detected values, not the entire database or filesystem. Deterministic truncated token hashes reveal equality and may permit guessing low-entropy values. Plaintext can still exist in inputs, rehydrated files, application memory, logs, and backups; an attacker with the master key can decrypt the vault.

`server.json` is local registry metadata; its presence does not establish that a package or registry entry has been published.

## Verify

```bash
pytest -v
python demo_multi_model.py
```

The demo uses temporary data and runs locally by default. It contacts configured providers only when `RELAYVAULT_DEMO_LIVE=1` is explicitly set; those calls may incur charges and send the redacted handoff externally. CI is configured for Python 3.11 and 3.12 on Ubuntu and macOS.
