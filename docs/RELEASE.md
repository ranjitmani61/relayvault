# Release verification

RelayVault v0.2.0 is published on PyPI and has passed an independent clean installation. `server.json` now identifies this verified PyPI distribution for MCP Registry submission. Committing the manifest does **not** publish the registry listing. For subsequent releases, use these gates:

1. Run the pinned install, lint, full local suite, synthetic corpus report, demo and dependency audit from README.
2. Build the wheel/sdist. Install the wheel in a clean environment and test its CLI/MCP entry points. CI repeats this on Python 3.11/3.12 and Linux/macOS.
3. Run the opt-in live contract with a selected model and synthetic data. Record provider, model, date, outcome and token-preservation result; API schema compatibility alone is not successful interoperation.
4. Complete a trusted-publisher PyPI release from an authorized account. This repository does not publish automatically.
5. Verify the exact version via the official PyPI JSON API, compare artifact digests against the built artifacts, and test installation from PyPI in a clean environment. Only then update the PyPI package entry in `server.json`, validate against the current MCP Registry schema, and publish registry metadata separately after approval.
6. Verify migration and recovery using a disposable legacy vault before changing a personal/production home.

Runtime and development lockfiles are hash-pinned. Regenerate both deliberately and review/audit the diff:

```bash
pip-compile pyproject.toml --generate-hashes --strip-extras -o requirements.lock
pip-compile pyproject.toml --extra dev --generate-hashes --strip-extras --allow-unsafe -c requirements.lock -o requirements-dev.lock
```

For product validation, recruit users with a concrete handoff workflow and measure setup time, detector misses/false positives on consented workloads, cross-client task completion, and recovery success. These outcomes cannot be established by adding more synthetic unit tests.

## MCP Registry submission

The `server.json` manifest advertises the verified PyPI package `relayvault==0.2.0`, with `uvx` and the `serve-mcp` CLI argument over stdio. The PyPI README contains the matching `mcp-name` ownership marker. This is registry preparation, not proof of a live registry listing.

On a trusted machine, install the official `mcp-publisher` CLI, then run these as distinct steps:

```bash
mcp-publisher validate
mcp-publisher login github
# Once the manifest has passed validation and publication is approved:
mcp-publisher publish
```

Authenticate as the GitHub account `ranjitmani61` so the `io.github.ranjitmani61/*` namespace is authorized. Validate the public listing after publication. Do not enable agent rehydration in model-facing MCP client configurations.

## Recorded live provider contracts

| Date | Provider | Model | Outcome | Token preservation |
| :--- | :--- | :--- | :--- | :--- |
| 2026-11-23 | `openai` | `gpt-4o-mini` | Passed (`test_live_provider_contract`) | 4/4 synthetic tokens preserved and locally rehydrated |
| 2026-11-23 | `deepseek` | `deepseek-chat` | Passed (`test_live_provider_contract`) | 4/4 synthetic tokens preserved and locally rehydrated |
