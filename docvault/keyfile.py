"""One password-wrapped random 7z password, never stored in plaintext.

Local password + stored random salt --Argon2id (default: 3 passes, 256 MiB)-->
32-byte derived key --XChaCha20-Poly1305--> random 7z archive password.
Only the derived key enters the envelope cipher; neither the local password
nor that derived key is saved in the key file.
"""

import os
from pathlib import Path
import stat
import socket
import tempfile

from . import crypto, durable, limits, strictjson as sj
from .errors import Unsupported, UsageError
from .oplock import OperationLock

DEFAULT_KEY = Path('/usr/local/bin/key')
KEY_FORMAT = 'docvault-7z-key'


def canonical(path: Path) -> Path:
    path = path.expanduser().absolute()
    if path.is_symlink():
        raise Unsupported('The local key must be a regular file, not a symbolic link')
    return path.parent.resolve() / path.name


def private_directory(path: Path) -> None:
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise Unsupported(f'Key directory must be owned by you and private (chmod 700): {path}')
    from . import macos
    if macos.has_extended_acl(path):
        raise Unsupported(f'Key directory has an ACL: {path}')


def key_lock(path: Path) -> OperationLock:
    private_directory(path.parent)
    return OperationLock(path.parent / f'.{path.name}.lock')


def read(path: Path) -> crypto.Envelope:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise Unsupported(f'Key must be a private file owned by you (chmod 600): {path}')
        from . import macos
        if macos.has_extended_acl(path):
            raise Unsupported(f'Key file has an ACL: {path}')
        return parse(os.read(fd, limits.MAX_ENVELOPE_BYTES + 1))
    finally:
        os.close(fd)


def parse(data: bytes) -> crypto.Envelope:
    obj = sj.loads(data, max_bytes=limits.MAX_ENVELOPE_BYTES, what='7z key file')
    sj.require_object(obj, {'format', 'version', 'envelope'}, '7z key file')
    sj.require_header(obj, KEY_FORMAT, 1, '7z key file')
    return crypto.Envelope.parse(sj.dumps(obj['envelope']))


def read_privileged_fd(fd: int) -> crypto.Envelope:
    """Consume a root-owned, read-only descriptor supplied by the sudo helper."""
    import fcntl
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600
                or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY):
            raise Unsupported('Privileged key descriptor must refer to a root-owned read-only 600 file')
        return parse(os.read(fd, limits.MAX_ENVELOPE_BYTES + 1))
    finally:
        os.close(fd)  # Never let 7z inherit the descriptor.


def publish_privileged(fd: int, envelope: crypto.Envelope) -> None:
    """Send only encrypted bytes to the root writer, and wait for durable publication."""
    with socket.socket(fileno=fd) as channel:
        channel.sendall(encode(envelope))
        channel.shutdown(socket.SHUT_WR)
        response = b''
        while len(response) < 2:
            chunk = channel.recv(2 - len(response))
            if not chunk:
                break
            response += chunk
        if response != b'OK':
            raise UsageError('Privileged key publication failed. Preserve the key and your backups;'
                             ' if changing its password, check both the old and new passwords before retrying')


def new_envelope(password: bytes, profile: str) -> crypto.Envelope:
    if not password:
        raise UsageError('An empty password is not allowed')
    return crypto.seal_envelope(crypto.random_key(), password, crypto.random_id(),
                                crypto.random_id(), crypto.KdfParams.from_profile(profile))


def rewrap(envelope: crypto.Envelope, old: bytes, new: bytes) -> crypto.Envelope:
    if not new:
        raise UsageError('An empty password is not allowed')
    secret = crypto.open_envelope(envelope, old)
    kdf = crypto.KdfParams(envelope.kdf.opslimit, envelope.kdf.memlimit, os.urandom(crypto.SALT_BYTES))
    return crypto.seal_envelope(secret, new, envelope.vault_id, crypto.random_id(), kdf)


def encode(envelope: crypto.Envelope) -> bytes:
    return sj.dumps({'format': KEY_FORMAT, 'version': 1,
                     'envelope': sj.loads(envelope.to_bytes(), max_bytes=limits.MAX_ENVELOPE_BYTES,
                                          what='key envelope')}) + b'\n'


def create(path: Path, password: bytes, profile: str = crypto.DEFAULT_PROFILE) -> None:
    path = canonical(path)
    if not password:
        raise UsageError('An empty password is not allowed')
    # Only create a single new private parent; never chmod existing directories.
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with key_lock(path):
        if os.path.lexists(path):
            raise UsageError(f'Key already exists; it has not been replaced: {path}')
        env = new_envelope(password, profile)
        durable.write_new_file(path, encode(env))
        durable.sync_dir(path.parent)


def open_key(path: Path, password: bytes) -> bytes:
    path = canonical(path)
    with key_lock(path):
        return crypto.open_envelope(read(path), password)


def change_password(path: Path, old: bytes, new: bytes) -> None:
    path = canonical(path)
    if not new:
        raise UsageError('An empty password is not allowed')
    with key_lock(path):
        env = read(path)
        replacement = rewrap(env, old, new)
        fd, tmp = tempfile.mkstemp(prefix='.key-', dir=path.parent)
        os.close(fd)
        temporary = Path(tmp)
        try:
            with temporary.open('wb') as f:
                f.write(encode(replacement))
                f.flush()
                durable.full_sync(f.fileno())
            os.replace(temporary, path)
            durable.sync_dir(path.parent)
        finally:
            temporary.unlink(missing_ok=True)
