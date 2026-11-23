# Release verification

The repository currently documents source installation. `server.json` contains identity/source metadata only and is **not a publishable MCP Registry manifest** while it has no verified package or remote service. Do not advertise `pip install relayvault` until the intended artifact has been published and verified.

1. Run the pinned install, lint, full local suite, synthetic corpus report, demo and dependency audit from README.
2. Build the wheel/sdist. Install the wheel in a clean environment and test its CLI/MCP entry points. CI repeats this on Python 3.11/3.12 and Linux/macOS.
3. Run the opt-in live contract with a selected model and synthetic data. Record provider, model, date, outcome and token-preservation result; API schema compatibility alone is not successful interoperation.
4. Complete a trusted-publisher PyPI release from an authorized account. This repository does not publish automatically.
5. Verify the exact version via the official PyPI JSON API, compare artifact digests against the built artifacts, and test installation from PyPI in a clean environment. Only then add a PyPI package entry to `server.json` and validate it against the current MCP Registry schema.
6. Verify migration and recovery using a disposable legacy vault before changing a personal/production home.

Runtime and development lockfiles are hash-pinned. Regenerate both deliberately and review/audit the diff:

```bash
pip-compile pyproject.toml --generate-hashes --strip-extras -o requirements.lock
pip-compile pyproject.toml --extra dev --generate-hashes --strip-extras --allow-unsafe -c requirements.lock -o requirements-dev.lock
```

For product validation, recruit users with a concrete handoff workflow and measure setup time, detector misses/false positives on consented workloads, cross-client task completion, and recovery success. These outcomes cannot be established by adding more synthetic unit tests.
