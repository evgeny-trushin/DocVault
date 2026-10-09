"""Persistence barriers required before archive publication and plaintext cleanup.

On macOS F_FULLFSYNC flushes the drive cache; failure stops the operation.
Call through the module so tests can inject failures at specific points.
"""

import fcntl
import os

from . import macos
from .errors import DurabilityError

_O_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW | os.O_CLOEXEC


def full_sync(fd: int) -> None:
    """Flush ``fd`` through the device cache."""
    try:
        if macos.IS_DARWIN:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
        else:
            os.fsync(fd)
    except OSError as e:
        operation = "F_FULLFSYNC" if macos.IS_DARWIN else "fsync"
        raise DurabilityError(f"{operation} failed: {e}") from e


def sync_dir(path) -> None:
    fd = os.open(path, _O_DIR)
    try:
        full_sync(fd)
    finally:
        os.close(fd)


def write_new_file(path, data: bytes, *, mode: int = 0o600) -> None:
    """Create ``path`` (which must not exist), write ``data`` and flush it."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        full_sync(fd)
    finally:
        os.close(fd)
