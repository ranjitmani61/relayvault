"""Persistent local key management. Keys never appear in logs or tool responses."""

import base64
import os
import stat
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_SALT = b"rv-local-default-salt-2026"


def private_path(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not (
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    ):
        raise RuntimeError("Vault paths must be regular files/private directories, never symlinks")
    if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise RuntimeError(
            "Unsafe vault ownership or permissions; require owner-only access (0700 directories, 0600 files)"
        )


def derive_key(master: bytes, salt: bytes, purpose: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=purpose).derive(master)


def cipher_for(master: bytes, salt: bytes) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(derive_key(master, salt, b"relayvault-fernet-v1")))


def load_master(home: Path, *, create: bool) -> bytes:
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_path(home, directory=True)
    key_path = home / "master.key"
    if not key_path.exists() and not key_path.is_symlink():
        if not create:
            raise RuntimeError("master.key is missing; restore the original key and matching database")
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
    private_path(key_path)
    # O_NOFOLLOW also protects the final component against substitution after lstat.
    fd = os.open(key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise RuntimeError("Unsafe master.key permissions")
        master = handle.read()
    if len(master) != 32:
        raise ValueError("Invalid RelayVault master key")
    return master


def get_or_create_fernet(vault_salt: bytes) -> Fernet:
    home = Path(os.environ.get("RELAYVAULT_HOME", Path.home() / ".relayvault"))
    return cipher_for(load_master(home, create=True), vault_salt)


def generate_vault_salt() -> bytes:
    return os.urandom(32)
