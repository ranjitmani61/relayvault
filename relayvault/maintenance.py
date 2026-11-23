"""Copy-based maintenance: existing homes are never overwritten.

Backups contain plaintext master key material and must be kept private. Rotation
writes and verifies a replacement home; stop clients before switching to it.
"""

import hashlib
import os
import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import InvalidToken

from relayvault.crypto import DEFAULT_SALT, cipher_for, load_master, private_path
from relayvault.engine import IntegrityError, RelayVaultEngine, canonical
from relayvault.files import atomic_write


@contextmanager
def destination_directory(destination: Path):
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("Destination must not exist; existing vaults are never overwritten")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".relayvault-maintenance-", dir=destination.parent))
    try:
        yield stage
        if destination.exists() or destination.is_symlink():
            raise ValueError("Destination appeared during maintenance")
        os.rename(stage, destination)
        directory = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def snapshot(engine: RelayVaultEngine, destination: Path):
    atomic_write(destination / "master.key", engine.master, mode=0o600)
    atomic_write(
        destination / "vault-config.json", (engine.home / "vault-config.json").read_bytes(), mode=0o600
    )
    atomic_write(destination / "relayvault.db", b"", mode=0o600)
    with engine._connect() as source:
        target = sqlite3.connect(destination / "relayvault.db")
        try:
            source.backup(target)
        finally:
            target.close()
    mapping = engine.home / "migration-map.json"
    if mapping.exists():
        atomic_write(destination / mapping.name, mapping.read_bytes(), mode=0o600)


def backup_vault(engine: RelayVaultEngine, destination: Path):
    with destination_directory(destination) as stage:
        snapshot(engine, stage)
        RelayVaultEngine(home=stage).verify_all()


def restore_vault(source: Path, destination: Path):
    private_path(source, directory=True)
    engine = RelayVaultEngine(home=source)
    backup_vault(engine, destination)


def rotate_key(engine: RelayVaultEngine, destination: Path):
    with destination_directory(destination) as stage:
        snapshot(engine, stage)
        copy = RelayVaultEngine(home=stage)
        copy.verify_all()
        new_master = os.urandom(32)
        new_cipher = cipher_for(new_master, copy.vault_salt)
        with copy._connect() as conn:
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute("SELECT * FROM secret_vault").fetchall()
            # Preserve record IDs and the independent token/integrity keys.
            for row in rows:
                plaintext = copy.cipher.decrypt(row["raw_value"].encode())
                conn.execute(
                    "UPDATE secret_vault SET raw_value=? WHERE token_id=?",
                    (new_cipher.encrypt(plaintext).decode(), row["token_id"]),
                )
            copy.cipher = new_cipher
            conn.execute("UPDATE vault_meta SET value=? WHERE name='keys-v2'", (copy._wrapped_keys(),))
        with copy._connect() as conn:
            conn.execute("VACUUM")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        atomic_write(stage / "master.key", new_master, mode=0o600)
        RelayVaultEngine(home=stage).verify_all()


def migrate_vault(source: Path, destination: Path):
    """Verify legacy records before wrapping identities and authenticating checkpoints.

    A valid legacy hash cannot establish who wrote the old database. Migration is
    a local trust decision; every migrated checkpoint requires local review.
    """
    private_path(source, directory=True)
    master = load_master(source, create=False)
    salt = os.environ.get("RELAYVAULT_SALT", DEFAULT_SALT.decode())
    legacy_cipher = cipher_for(master, salt.encode())
    db = source / "relayvault.db"
    if db.is_symlink() or not db.is_file():
        raise ValueError("Legacy database must be a regular file")
    conn = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        # A read transaction gives a coherent snapshot including WAL content.
        conn.execute("BEGIN")
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='vault_meta'").fetchone():
            raise ValueError("Vault is already migrated; use backup or rotate-key")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise IntegrityError("Legacy database integrity check failed")
        secrets = conn.execute("SELECT * FROM secret_vault").fetchall()
        checkpoints = conn.execute("SELECT * FROM checkpoints ORDER BY rowid").fetchall()
        with destination_directory(destination) as stage:
            atomic_write(stage / "master.key", master, mode=0o600)
            target = RelayVaultEngine(home=stage, vault_salt=salt)
            target.policy = "review"
            with target._connect() as out:
                for row in secrets:
                    try:
                        value = legacy_cipher.decrypt(row["raw_value"].encode()).decode()
                    except (InvalidToken, UnicodeError) as exc:
                        raise IntegrityError("Legacy key/salt mismatch or ciphertext damage") from exc
                    digest = hashlib.sha256(
                        salt.encode() + row["workspace_id"].encode() + value.encode()
                    ).hexdigest()[:10]
                    expected = f"<RV_VAULT:{row['secret_type']}:{digest}>"
                    if expected != row["token_id"]:
                        raise IntegrityError("Legacy record identity mismatch")
                    target.detector.validate_identifier(row["workspace_id"], "workspace_id")
                    target.detector.validate_identifier(row["secret_type"], "secret_type")
                    out.execute(
                        "INSERT INTO secret_vault VALUES (?, ?, ?, ?, ?)",
                        (
                            row["token_id"],
                            row["workspace_id"],
                            row["secret_type"],
                            target._encrypt_record(
                                row["workspace_id"], row["secret_type"], row["token_id"], value
                            ),
                            row["created_at"],
                        ),
                    )
            mapping = {}
            pending = list(checkpoints)
            while pending:
                progress = False
                for row in pending[:]:
                    payload = target._checkpoint_payload(row)
                    digest = hashlib.sha256(canonical(payload)).hexdigest()[:16]
                    if digest != row["commit_hash"]:
                        raise IntegrityError("Legacy checkpoint hash mismatch")
                    parent = row["parent_hash"]
                    if parent and parent not in mapping:
                        continue
                    payload.pop("created_at")
                    payload["parent_hash"] = mapping.get(parent)
                    result = target.commit_checkpoint(**payload)
                    mapping[row["commit_hash"]] = result["commit_hash"]
                    pending.remove(row)
                    progress = True
                if not progress:
                    raise IntegrityError("Legacy lineage has missing parents or a cycle")
            atomic_write(stage / "migration-map.json", canonical(mapping), mode=0o600)
            target.verify_all()
    finally:
        conn.close()
