import hashlib
import json
import math
import os
import re
import sqlite3
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from relayvault.crypto import get_or_create_fernet


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def luhn_checksum_valid(card_number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", card_number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class RelayVaultEngine:
    """
    Core SQLite WAL engine providing:
    1. Content-addressable Git-like DAG checkpoints for cross-model task state.
    2. Deterministic, reversible PII & secret tokenization vault.
    """

    SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
        ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-api\d{2}-[A-Za-z0-9_-]{20,}\b")),
        ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
        ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
        ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b")),
        ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
        ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z_]{24,99}(?![0-9a-zA-Z_])")),
        ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
        ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")),
        ("GENERIC_BEARER_ASSIGNMENT", re.compile(r"(?i)(?:api[_-]?key|secret|password|token|passwd)\s*[:=]\s*['\"]([A-Za-z0-9/+_=.-]{16,})['\"]")),
        ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
        ("IPV4_PRIVATE_OR_PROD", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b")),
    ]

    CANDIDATE_CC_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    def __init__(self, db_path: Optional[str] = None, vault_salt: Optional[str] = None):
        default_dir = Path(os.environ.get("RELAYVAULT_HOME", Path.home() / ".relayvault"))
        default_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db_path = str(db_path or (default_dir / "relayvault.db"))
        self.vault_salt = (vault_salt or os.environ.get("RELAYVAULT_SALT", "rv-local-default-salt-2026")).encode("utf-8")
        if not (default_dir / "master.key").exists() and Path(self.db_path).is_file():
            with sqlite3.connect(self.db_path) as conn:
                table = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='secret_vault'").fetchone()
                if table and conn.execute("SELECT 1 FROM secret_vault LIMIT 1").fetchone():
                    raise RuntimeError("Vault contains secrets but master.key is missing; restore the original key before opening it")
        self.cipher = get_or_create_fernet(self.vault_salt)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS checkpoints (
                    commit_hash TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    parent_hash TEXT,
                    source_model TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    locked_decisions_json TEXT NOT NULL,
                    failed_approaches_json TEXT NOT NULL,
                    artifacts_json TEXT NOT NULL,
                    next_steps_json TEXT NOT NULL,
                    redaction_count INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_workspace_branch
                ON checkpoints(workspace_id, branch, created_at DESC);

                CREATE TABLE IF NOT EXISTS secret_vault (
                    token_id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    secret_type TEXT NOT NULL,
                    raw_value TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )

    def _make_vault_token(self, workspace_id: str, secret_type: str, raw_value: str) -> str:
        digest = hashlib.sha256(self.vault_salt + workspace_id.encode("utf-8") + raw_value.encode("utf-8")).hexdigest()[:10]
        token_id = f"<RV_VAULT:{secret_type}:{digest}>"
        encrypted_value = self.cipher.encrypt(raw_value.encode("utf-8")).decode("utf-8")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO secret_vault (token_id, workspace_id, secret_type, raw_value, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (token_id, workspace_id, secret_type, encrypted_value, time.time()),
            )
            row = conn.execute("SELECT workspace_id, raw_value FROM secret_vault WHERE token_id = ?", (token_id,)).fetchone()
            if row["workspace_id"] != workspace_id or self.cipher.decrypt(row["raw_value"].encode("utf-8")).decode("utf-8") != raw_value:
                raise RuntimeError("Vault token collision; refusing to overwrite an existing secret")
        return token_id

    def redact_text(self, workspace_id: str, text: str) -> Tuple[str, int]:
        """Scans text for secrets/PII, stores originals in local SQLite vault, and replaces with deterministic tokens."""
        if not text:
            return text, 0

        redaction_count = 0
        redacted = text

        for secret_type, pattern in self.SECRET_PATTERNS:
            def _replacer(match: re.Match) -> str:
                nonlocal redaction_count
                # If the pattern captured a group (like GENERIC_BEARER_ASSIGNMENT), redact only the secret group
                if match.lastindex and match.lastindex >= 1:
                    secret_val = match.group(1)
                    if shannon_entropy(secret_val) < 3.2:
                        return match.group(0)
                    token = self._make_vault_token(workspace_id, secret_type, secret_val)
                    redaction_count += 1
                    full = match.group(0)
                    start, end = match.span(1)
                    rel_start = start - match.start(0)
                    rel_end = end - match.start(0)
                    return full[:rel_start] + token + full[rel_end:]
                else:
                    secret_val = match.group(0)
                    token = self._make_vault_token(workspace_id, secret_type, secret_val)
                    redaction_count += 1
                    return token

            redacted = pattern.sub(_replacer, redacted)

        # Check Luhn-valid credit cards
        def _cc_replacer(match: re.Match) -> str:
            nonlocal redaction_count
            candidate = match.group(0)
            if luhn_checksum_valid(candidate):
                redaction_count += 1
                return self._make_vault_token(workspace_id, "CREDIT_CARD", candidate)
            return candidate

        redacted = self.CANDIDATE_CC_REGEX.sub(_cc_replacer, redacted)
        return redacted, redaction_count

    def _redact_structure(self, workspace_id: str, obj: Any) -> Tuple[Any, int]:
        if isinstance(obj, str):
            return self.redact_text(workspace_id, obj)
        if isinstance(obj, list):
            total = 0
            out = []
            for item in obj:
                r_item, c = self._redact_structure(workspace_id, item)
                out.append(r_item)
                total += c
            return out, total
        if isinstance(obj, dict):
            total = 0
            out = {}
            for k, v in obj.items():
                r_k, key_count = self.redact_text(workspace_id, k) if isinstance(k, str) else (k, 0)
                r_v, value_count = self._redact_structure(workspace_id, v)
                if r_k in out:
                    raise ValueError("Dictionary keys collide after redaction")
                out[r_k] = r_v
                total += key_count + value_count
            return out, total
        return obj, 0

    def rehydrate_text(self, workspace_id: str, text: str) -> Tuple[str, int]:
        """Restores vaulted secrets/PII back into model-generated code or text locally."""
        token_pattern = re.compile(r"<RV_VAULT:[A-Z0-9_]+:[0-9a-f]{10}>")
        matches = set(token_pattern.findall(text))
        if not matches:
            return text, 0

        restored_count = 0
        rehydrated = text
        with self._connect() as conn:
            for token_id in matches:
                row = conn.execute(
                    "SELECT raw_value FROM secret_vault WHERE token_id = ? AND workspace_id = ?",
                    (token_id, workspace_id),
                ).fetchone()
                if row:
                    decrypted_value = self.cipher.decrypt(row["raw_value"].encode("utf-8")).decode("utf-8")
                    rehydrated = rehydrated.replace(token_id, decrypted_value)
                    restored_count += 1
        return rehydrated, restored_count

    def commit_checkpoint(
        self,
        workspace_id: str,
        source_model: str,
        objective: str,
        locked_decisions: List[str],
        failed_approaches: List[str],
        artifacts: Dict[str, str],
        next_steps: List[str],
        branch: str = "main",
        parent_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Commits a redacted, content-addressable task state checkpoint."""
        r_objective, c1 = self.redact_text(workspace_id, objective)
        r_decisions, c2 = self._redact_structure(workspace_id, locked_decisions)
        r_failed, c3 = self._redact_structure(workspace_id, failed_approaches)
        r_artifacts, c4 = self._redact_structure(workspace_id, artifacts)
        r_next, c5 = self._redact_structure(workspace_id, next_steps)
        total_redactions = c1 + c2 + c3 + c4 + c5

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if not parent_hash:
                head = conn.execute(
                    """
                    SELECT commit_hash FROM checkpoints
                    WHERE workspace_id = ? AND branch = ?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (workspace_id, branch),
                ).fetchone()
                if head:
                    parent_hash = head["commit_hash"]
            elif not conn.execute("SELECT 1 FROM checkpoints WHERE workspace_id = ? AND commit_hash = ?", (workspace_id, parent_hash)).fetchone():
                raise ValueError("Parent checkpoint does not exist in this workspace")

            created_at = time.time()
            canonical_payload = json.dumps(
                {
                    "workspace_id": workspace_id,
                    "branch": branch,
                    "parent_hash": parent_hash,
                    "source_model": source_model,
                    "objective": r_objective,
                    "locked_decisions": r_decisions,
                    "failed_approaches": r_failed,
                    "artifacts": r_artifacts,
                    "next_steps": r_next,
                    "created_at": created_at,
                },
                sort_keys=True,
            )
            commit_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()[:16]

            conn.execute(
                """
                INSERT INTO checkpoints (
                    commit_hash, workspace_id, branch, parent_hash, source_model,
                    objective, locked_decisions_json, failed_approaches_json,
                    artifacts_json, next_steps_json, redaction_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    commit_hash,
                    workspace_id,
                    branch,
                    parent_hash,
                    source_model,
                    r_objective,
                    json.dumps(r_decisions),
                    json.dumps(r_failed),
                    json.dumps(r_artifacts),
                    json.dumps(r_next),
                    total_redactions,
                    created_at,
                ),
            )

        return {
            "commit_hash": commit_hash,
            "uri": f"rv://{workspace_id}/{branch}@{commit_hash}",
            "workspace_id": workspace_id,
            "branch": branch,
            "parent_hash": parent_hash,
            "source_model": source_model,
            "redactions_applied": total_redactions,
            "created_at": created_at,
        }

    def checkout_handoff(
        self,
        workspace_id: str,
        branch: str = "main",
        commit_hash: Optional[str] = None,
        target_model: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieves a redacted checkpoint and formats a deterministic handoff briefing for the receiving model."""
        with self._connect() as conn:
            if commit_hash:
                row = conn.execute(
                    "SELECT * FROM checkpoints WHERE workspace_id = ? AND commit_hash = ?",
                    (workspace_id, commit_hash),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT * FROM checkpoints
                    WHERE workspace_id = ? AND branch = ?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (workspace_id, branch),
                ).fetchone()

            if not row:
                return None

            lineage_rows = []
            current = row
            seen = set()
            while current is not None:
                if current["commit_hash"] in seen:
                    raise RuntimeError("Cycle detected in checkpoint lineage")
                seen.add(current["commit_hash"])
                lineage_rows.append({key: current[key] for key in ("commit_hash", "source_model", "created_at", "redaction_count")})
                current = conn.execute(
                    "SELECT * FROM checkpoints WHERE workspace_id = ? AND commit_hash = ?",
                    (workspace_id, current["parent_hash"]),
                ).fetchone() if current["parent_hash"] else None
            lineage_rows.reverse()

        decisions = json.loads(row["locked_decisions_json"])
        failed = json.loads(row["failed_approaches_json"])
        artifacts = json.loads(row["artifacts_json"])
        next_steps = json.loads(row["next_steps_json"])

        handoff_prompt = (
            f"=== RELAYVAULT DETERMINISTIC STATE HANDOFF ===\n"
            f"Checkpoint URI: rv://{workspace_id}/{row['branch']}@{row['commit_hash']}\n"
            f"Previous Model: {row['source_model']} -> Receiving Model: {target_model or 'Current Agent'}\n"
            f"Zero-Trust Vault Notice: Any <RV_VAULT:TYPE:HASH> tokens represent sensitive secrets/PII "
            f"redacted locally. Preserve those exact token strings verbatim in your code/outputs so the user's "
            f"local RelayVault engine can rehydrate them.\n\n"
            f"1. PRIMARY OBJECTIVE:\n{row['objective']}\n\n"
            f"2. LOCKED ARCHITECTURAL DECISIONS (DO NOT RE-LITIGATE):\n"
            + ("\n".join(f"- {d}" for d in decisions) if decisions else "- None")
            + "\n\n3. FAILED APPROACHES / DEAD ENDS (DO NOT REPEAT):\n"
            + ("\n".join(f"- {f}" for f in failed) if failed else "- None")
            + "\n\n4. ACTIVE ARTIFACTS / CODE SNIPPETS:\n"
            + (
                "\n\n".join(f"--- [{k}] ---\n{v}" for k, v in artifacts.items())
                if artifacts
                else "- None"
            )
            + "\n\n5. IMMEDIATE NEXT STEPS TO EXECUTE:\n"
            + ("\n".join(f"{idx + 1}. {s}" for idx, s in enumerate(next_steps)) if next_steps else "- None")
        )

        return {
            "commit_hash": row["commit_hash"],
            "uri": f"rv://{workspace_id}/{row['branch']}@{row['commit_hash']}",
            "workspace_id": row["workspace_id"],
            "branch": row["branch"],
            "parent_hash": row["parent_hash"],
            "source_model": row["source_model"],
            "target_model": target_model,
            "objective": row["objective"],
            "locked_decisions": decisions,
            "failed_approaches": failed,
            "artifacts": artifacts,
            "next_steps": next_steps,
            "redaction_count": row["redaction_count"],
            "created_at": row["created_at"],
            "branch_lineage": lineage_rows,
            "synthesized_handoff_prompt": handoff_prompt,
        }

    def list_checkpoints(self, workspace_id: str, branch: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            if branch:
                rows = conn.execute(
                    """
                    SELECT commit_hash, workspace_id, branch, parent_hash, source_model,
                           objective, redaction_count, created_at
                    FROM checkpoints
                    WHERE workspace_id = ? AND branch = ?
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (workspace_id, branch, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT commit_hash, workspace_id, branch, parent_hash, source_model,
                           objective, redaction_count, created_at
                    FROM checkpoints
                    WHERE workspace_id = ?
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (workspace_id, limit),
                ).fetchall()
        return [dict(r) for r in rows]
