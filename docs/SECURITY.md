# Security model and operations

RelayVault redacts **detected patterns** and stores their originals encrypted locally. It does not certify that a handoff is safe, provide comprehensive PII detection, or prevent an LLM from following malicious instructions. Use a restricted host-side tool dispatcher and review data before sending it to a provider.

## Trust boundaries

| Principal | Intended access |
| --- | --- |
| External model | Reviewed checkpoint data and opaque placeholders; no local credentials or master key |
| HTTP MCP / REST client | Explicit workspace `read` and/or `write` grants |
| Trusted rehydration host | Workspace `read` grant **and** independent rehydration credential, or local CLI access |
| Vault OS owner | Full vault access, migration, approval, backup and rotation |

An agent with the vault owner's shell, filesystem, environment, or CLI permissions can read the key and decrypt the vault. MCP tool restrictions cannot contain that agent. For hostile agents, run the vault/broker under a separate OS account or host; give agents only scoped HTTP credentials. Keep the rehydration key out of model-facing processes, prompts, tool definitions and logs. Static bearer authentication is not a full OAuth service.

REST decryption always requires `Authorization: Bearer ...`, `X-RelayVault-Local-Intent: rehydrate`, and `X-RelayVault-Rehydrate-Key`. No loopback or proxy-header exemption exists. A missing, empty, or reused rehydration key disables decryption. The endpoint is omitted from OpenAPI and provider function schemas, but authorization is enforced independently of discovery. Reverse proxies must use TLS, enforce network access and preserve Authorization. `serve-api` ignores forwarded client addresses; none are trusted for authorization.

Both MCP HTTP transports require authentication on all protocol endpoints, and tool/resource handlers enforce workspace grants. Streamable HTTP runs statelessly; legacy SSE uses the SDK's authenticated session ownership and rechecks credentials for every tool call. Stdio trusts the process owner; optional `RELAYVAULT_WORKSPACES` further restricts it. Plaintext MCP rehydration is opt-in, stdio-only, and unsuitable for model-facing clients.

## Detection and review

Built-in detectors cover structured OpenAI, Anthropic, Google, AWS, GitHub (including fine-grained), Slack and Stripe credentials; bearer/basic authorization values; quoted and unquoted password/key/token assignments; JWTs; PEM private keys; emails; valid RFC1918 IPv4s; and Luhn-valid card candidates. Strings in nested dictionary keys and values are scanned. Existing placeholders must belong to the current workspace and authenticate successfully; fabricated placeholders cannot exempt input from scanning. Neighboring text around a valid placeholder is still scanned. Identifier fields accept 1–64 ASCII letters/digits/dots/underscores/hyphens, starting with a letter/digit; recognized sensitive identifiers are rejected before storage. Exported handoffs and history receive an additional scan.

These heuristics miss unstructured names, street addresses, unfamiliar credential formats, encoded/fragmented secrets, and potentially arbitrary opaque values. Low-entropy secrets outside a recognized context can be missed. Generic assignment detection can classify code expressions as credentials; use preview and custom detectors to evaluate your workload. Do not interpret zero detections as proof of confidentiality.

`RELAYVAULT_REDACTION_POLICY=block-uncertain` (default) rejects unclassified high-entropy credential-like strings. It excludes common hexadecimal digests and cannot detect every uncertain value. `review` additionally vaults those candidate strings and withholds checkpoints/history until a trusted local approval. Only local CLI/Python code can approve; the MCP and REST interfaces expose no approval operation. Approval does not make content trustworthy. Source model names are self-reported, and handoff decisions are claims, never privileged instructions.

Custom detector JSON is trusted administrator code: Python regular expressions can consume excessive CPU if poorly designed. Do not accept detector files from model output. Add bounded patterns, test on the corpus and representative private inputs, and protect configuration permissions. Requests/file transformations are limited in the engine to 2 MB per checkpoint/text; network gateways must enforce body size, concurrency and rate limits before parsing.

## Encryption and integrity

New tokens use a 128-bit truncated HMAC-SHA256 identifier over version, workspace, secret type and value. The HMAC key is independently derived with HKDF, then wrapped with the vault key; it is not a public salt. Equality is visible within one vault/workspace. Different keys produce different tokens. Collision detection refuses conflicting entries.

Fernet envelopes authenticate the plaintext **together with** workspace, token ID and secret type. Checkpoints have full SHA-256 content hashes and independent HMACs covering stored metadata, review status and content. Branch heads are explicitly stored, authenticated and updated in the same SQLite transaction as the commit. All checkout/history paths verify integrity. `verify-vault` checks every record and lineage, including SQLite consistency.

This protects against record substitution or editing by a database-only attacker. It cannot prevent deletion, denial of service, replay of a previously valid branch head, or restoration of an entire older valid database. Detecting rollback requires an external monotonic/audit anchor. An attacker holding the master key can decrypt data and forge new records. The entire database is not encrypted: redacted content, equality, identifiers, timing and lineage remain visible to a database reader.

## Key lifecycle, backups and recovery

The vault directory must be owned by the current user and private (0700). Key/config/database files must have no group/other access (normally 0600). Symlink keys are refused. Incorrect ownership/permissions, missing keys for populated vaults, and mismatched key/salt metadata fail closed. Use an OS-level secret manager or separately managed host for stronger isolation; RelayVault does not yet integrate a keychain/KMS.

`backup` uses SQLite's backup API to include committed WAL data. Its output contains `master.key`, `relayvault.db`, and `vault-config.json` (including the custom salt), plus any migration map. Back up and protect **all of them together**. Backups contain the decryption key: store them separately from the working database with restricted access and encrypted storage. A missing key cannot be recovered from ciphertext.

`restore`, `rotate-key`, and `migrate-vault` refuse an existing destination. They build a private temporary home, verify it and rename it into place. The source remains unchanged. Rotation reencrypts every row and wraps the independent token/integrity keys with a new random master; existing tokens and commit hashes remain valid. Stop clients, verify the new home and update their `RELAYVAULT_HOME` together before resuming. The commands do not provide an online cutover: writes after the snapshot remain only in the old home. Rotation does not revoke old backups, change access credentials, or make an already exposed plaintext secret safe; rotate the underlying credentials as well when needed.

Unresolved or malformed placeholders fail rehydration before any file output. `--allow-partial` is an explicit CLI escape hatch. In-place writes use a same-directory temporary file, fsync and atomic replacement; rehydrated files become 0600. No guarantee of secure erasure on SSDs, snapshots or backups is made.

## Legacy migration

Legacy vaults are never upgraded automatically. Stop all clients and use the original salt:

```bash
export RELAYVAULT_HOME="$HOME/.relayvault"
# Set RELAYVAULT_SALT here if the legacy vault used a custom salt.
relayvault migrate-vault --destination "$HOME/.relayvault-v2"
RELAYVAULT_HOME="$HOME/.relayvault-v2" relayvault verify-vault
```

The command verifies legacy ciphertext/token hashes and checkpoint content hashes, binds old records to their identities, rescans checkpoint content using current detectors, writes new checkpoint hashes and records the mapping in `migration-map.json`. The migrated branch head follows original insertion order, not timestamps. Sensitive identifier fields or damaged lineage block migration and require trusted local remediation; they are never silently exported. Every migrated checkpoint requires local inspection and approval before export. The migration cannot prove the authenticity of legacy data before it received HMAC protection.

Legacy ten-character tokens remain decryptable and retain their original guessing/equality limitations. To replace them in active files, rehydrate locally and dehydrate again in the migrated vault; new redactions use v2 tokens. Old token aliases remain available for historic output. Keep the original vault as a private recovery copy until the migration and application cutover have been verified.

## Verification boundaries

The committed corpus measures curated synthetic credential examples and selected false positives. It is not a representative accuracy benchmark. Local provider wire tests exercise protocol envelopes against a local simulated provider, actual REST handlers and actual vault data. Only the explicitly enabled live contract calls a provider. No claim of real-world adoption, universal client compatibility, comprehensive PII coverage or independent security certification is made.

Report security issues privately through the repository's GitHub security reporting channel if enabled; otherwise contact the maintainer before posting a reproduction containing sensitive material. Never submit real credentials, personal vault files, or decrypted logs in public issues.
