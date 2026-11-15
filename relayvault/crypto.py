"""Local key management for the encrypted vault."""

import base64
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def get_or_create_fernet(vault_salt: bytes) -> Fernet:
    """Derive a vault key from a private, persistent random local master key.

    The atomic link ensures concurrent processes never observe a partial key or
    replace one another's key. Back up master.key alongside the database.
    """
    home = Path(os.environ.get("RELAYVAULT_HOME", Path.home() / ".relayvault"))
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = home / "master.key"
    if not key_path.exists():
        fd, name = tempfile.mkstemp(prefix=".master-key-", dir=home)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(os.urandom(32))
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(name, key_path)
            except FileExistsError:
                pass
        finally:
            os.unlink(name)
    master_key = key_path.read_bytes()
    if len(master_key) != 32:
        raise ValueError(f"Invalid RelayVault master key at {key_path}")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=vault_salt,
               info=b"relayvault-fernet-v1").derive(master_key)
    return Fernet(base64.urlsafe_b64encode(key))


def generate_vault_salt() -> bytes:
    """Generate a random salt for callers managing their own vaults."""
    return os.urandom(16)
