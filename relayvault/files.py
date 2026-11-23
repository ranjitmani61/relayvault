"""Atomic local writes: never truncate the source file before replacement is ready."""

import os
import stat
import tempfile
from pathlib import Path


def atomic_write(path: Path, data: bytes, *, mode: int = None) -> None:
    if path.is_symlink():
        raise ValueError("Refusing to replace a symlink")
    if mode is None:
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    fd, temporary = tempfile.mkstemp(prefix=".relayvault-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
