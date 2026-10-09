"""Root-owned stdlib-only bridge. No project imports or 7z run with root IDs.

Compatible with macOS's /usr/bin/python3 (3.9). The encrypted key descriptor
is handed to the caller only after irreversible UID/GID/group changes. For
init/passwd a root parent accepts encrypted replacement bytes over a socket.
"""

import ctypes
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess
import sys
import tempfile

DEFAULT_KEY = Path('/usr/local/bin/key')
MAX_KEY_BYTES = 4096
ADMIN_GID = 80  # macOS "admin" group: members already have unrestricted sudo by default.
FIRST_REGULAR_UID = 501


def has_acl(path):
    lib = ctypes.CDLL(None, use_errno=True)
    lib.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.acl_get_link_np.restype = ctypes.c_void_p
    lib.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    lib.acl_free.argtypes = [ctypes.c_void_p]
    acl = lib.acl_get_link_np(os.fsencode(path), 0x100)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return False  # macOS reports no extended ACL this way.
        raise OSError(ctypes.get_errno(), 'Cannot inspect key ACL')
    try:
        entry = ctypes.c_void_p()
        return lib.acl_get_entry(acl, 0, ctypes.byref(entry)) == 0
    finally:
        lib.acl_free(acl)


def validate_encrypted(data):
    """Bound/check the envelope shape before privileged publication; no KDF."""
    if not 0 < len(data) <= MAX_KEY_BYTES:
        raise ValueError('Encrypted key exceeds size limit')

    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError('Duplicate key field')
            result[name] = value
        return result

    try:
        obj = json.loads(data, object_pairs_hook=unique)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError('Invalid encrypted key JSON') from exc
    if (not isinstance(obj, dict) or set(obj) != {'format', 'version', 'envelope'}
            or obj['format'] != 'docvault-7z-key' or type(obj['version']) is not int or obj['version'] != 1):
        raise ValueError('Not a DocVault encrypted 7z key')
    env = obj['envelope']
    fields = {'format', 'version', 'vault_id', 'envelope_id', 'kdf', 'nonce', 'wrapped_key'}
    if (not isinstance(env, dict) or set(env) != fields or env['format'] != 'docvault-envelope'
            or type(env['version']) is not int or env['version'] != 1):
        raise ValueError('Invalid key envelope')
    kdf = env['kdf']
    if (not isinstance(kdf, dict) or set(kdf) != {'alg', 'opslimit', 'memlimit', 'salt'}
            or kdf['alg'] != 'argon2id13' or type(kdf['opslimit']) is not int
            or not 2 <= kdf['opslimit'] <= 16 or type(kdf['memlimit']) is not int
            or not 64 * 1024**2 <= kdf['memlimit'] <= 4 * 1024**3 or kdf['memlimit'] % 1024):
        raise ValueError('Invalid password derivation parameters')
    for value, length in [(env['vault_id'], 16), (env['envelope_id'], 16),
                          (env['nonce'], 24), (env['wrapped_key'], 48), (kdf['salt'], 16)]:
        if (not isinstance(value, str) or len(value) != length * 2
                or any(c not in '0123456789abcdef' for c in value)):
            raise ValueError('Invalid encrypted key field')


def trusted_parent(path):
    parent = path.parent
    # Reject writable/symlink parent components before touching privileged data.
    for directory in (parent, *parent.parents):
        st = directory.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                or (st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX) or has_acl(directory)):
            raise ValueError('Root key must reside under administrator-owned directories without ACLs')


def open_key(path):
    trusted_parent(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                or stat.S_IMODE(st.st_mode) != 0o600 or has_acl(path)):
            raise ValueError('Key must be a root-owned 600 file without links or ACLs; rerun install.sh')
        validate_encrypted(os.read(fd, MAX_KEY_BYTES + 1))
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def caller():
    if os.geteuid() != 0:
        raise ValueError('This helper must be invoked through sudo')
    uid, gid = int(os.environ.get('SUDO_UID', '0')), int(os.environ.get('SUDO_GID', '-1'))
    if uid <= 0 or gid < 0:
        raise ValueError('Run sudo from your normal user account')
    account = pwd.getpwuid(uid)
    if gid not in os.getgrouplist(account.pw_name, account.pw_gid):
        raise ValueError('Sudo group does not belong to the invoking user')
    return account, gid


def key_argument(args):
    key = DEFAULT_KEY
    index = 1
    while index < len(args):
        arg = args[index]
        if arg == '--':
            break
        if arg in ('--key-fd', '--key-write-fd') or arg.startswith(('--key-fd=', '--key-write-fd=')):
            raise ValueError('Key descriptors are reserved for the privileged helper')
        if arg == '--key':
            index += 1
            if index >= len(args):
                raise ValueError('--key requires a file path')
            key = Path(args[index])
        elif arg.startswith('--key='):
            key = Path(arg.split('=', 1)[1])
        index += 1
    # Resolve parent aliases such as /tmp, but refuse a final key symlink.
    key = key.absolute()
    return key.parent.resolve() / key.name


def target_path(args):
    """The folder or archive a document command works on (default: current directory)."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('path', nargs='?')
    for flag in ('--key', '--password-fd', '--outer-password-fd', '--layer', '--new-password-fd',
                 '--new-outer-password-fd', '--new-key-password-fd', '--key-hint', '--outer-hint'):
        parser.add_argument(flag)
    try:
        parsed, _ = parser.parse_known_args(args[2:] if args[0] == 'bundle' else args[1:])
    except SystemExit:
        return Path.cwd()  # docvault itself reports the usage error.
    return Path(parsed.path).absolute() if parsed.path else Path.cwd()


def archive_candidates(folder, current=False):
    """Recognize public hint names using stdlib only; the worker validates them."""
    parent = folder if current else folder.parent
    if not parent.exists():
        return []
    candidates = []
    for path in parent.iterdir():
        if not path.name.endswith('.7z'):
            continue
        parts = path.name[:-3].rsplit('__', 2)
        if path.name == folder.name + '.7z' or (len(parts) == 3 and parts[0] == folder.name):
            candidates.append(path)
    return candidates


def document_account(account, gid, args):
    """An administrator working on another user's documents acts as that user.

    Staging, locks and restored files then live with the owner's permissions,
    instead of failing in folders the administrator cannot write. Admins can
    already become any user through sudo, so this grants nothing new; other
    callers always keep their own identity.
    """
    if ADMIN_GID not in os.getgrouplist(account.pw_name, account.pw_gid):
        return account, gid
    path = target_path(args)
    candidates = [path, path.with_name(path.name + '.7z')]
    if not os.path.lexists(path):
        candidates.extend(archive_candidates(path))
    for candidate in (*candidates, *path.parents):
        try:
            owner = candidate.lstat().st_uid
            break
        except FileNotFoundError:
            continue
    else:
        return account, gid
    if owner == account.pw_uid or owner < FIRST_REGULAR_UID:
        return account, gid
    target = pwd.getpwuid(owner)
    print(f'docvault sudo helper: acting as {target.pw_name}, the owner of {candidate}', file=sys.stderr)
    return target, target.pw_gid


def worker(runtime, args, account, gid, read_fd=None, write_fd=None):
    os.initgroups(account.pw_name, gid)
    os.setgid(gid)
    os.setuid(account.pw_uid)
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (account.pw_uid, account.pw_uid, gid, gid):
        raise ValueError('Could not permanently drop root privileges')
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith(('SUDO_', 'PYTHON', 'DYLD_')):
            environment.pop(name)
    environment.update(HOME=account.pw_dir, USER=account.pw_name, LOGNAME=account.pw_name,
                       SHELL=account.pw_shell, PATH='/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin')
    # Python does not expose Darwin's extension name in confstr_names.
    temp = os.confstr(65537)  # _CS_DARWIN_USER_TEMP_DIR in Darwin unistd.h
    if temp:
        environment['TMPDIR'] = temp
    inherited = []
    for fd, flag in ((read_fd, '--key-fd'), (write_fd, '--key-write-fd')):
        if fd is not None:
            os.set_inheritable(fd, True)
            inherited.extend([flag, str(fd)])
    split = 2 if args[0] == 'bundle' else 1
    command = [str(runtime), '-I', '-m', 'docvault', *args[:split], *inherited, *args[split:]]
    os.execve(str(runtime), command, environment)


def full_sync(fd):
    fcntl.fcntl(fd, fcntl.F_FULLFSYNC)


def publish_key(path, data, *, replace=False):
    validate_encrypted(data)
    trusted_parent(path)
    if not replace and os.path.lexists(path):
        raise ValueError('Existing key was not replaced')
    if replace:
        fd = open_key(path)
        os.close(fd)
    fd, temporary_name = tempfile.mkstemp(prefix='.docvault-key-', dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        subprocess.run(['/bin/chmod', '-N', str(temporary)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with os.fdopen(fd, 'wb') as output:
            fd = -1
            output.write(data)
            output.flush()
            full_sync(output.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)  # Exclusive publication.
            temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            full_sync(directory)
        finally:
            os.close(directory)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def writer(runtime, args, account, gid, path):
    trusted_parent(path)
    lock_fd = os.open(path.parent / '.docvault-key.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(lock_fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError('Invalid root key operation lock')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        read_fd = open_key(path) if args[0] == 'passwd' else None
        if args[0] == 'init' and os.path.lexists(path):
            raise ValueError('Key already exists; it has not been replaced')
        parent, child = socket.socketpair()
        pid = os.fork()
        if pid == 0:
            parent.close()
            os.close(lock_fd)
            try:
                worker(runtime, args, account, gid, read_fd, child.fileno())
            except BaseException:
                os._exit(1)
        child.close()
        if read_fd is not None:
            os.close(read_fd)
        with parent:
            chunks, total = [], 0
            while total <= MAX_KEY_BYTES:
                chunk = parent.recv(min(1024, MAX_KEY_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            data = b''.join(chunks)
            if data:
                try:
                    publish_key(path, data, replace=args[0] == 'passwd')
                    parent.sendall(b'OK')
                except (OSError, ValueError, subprocess.CalledProcessError):
                    parent.sendall(b'ERROR')
            # No data means the child declined, failed authentication or was interrupted.
        _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else 130
    finally:
        os.close(lock_fd)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        account, gid = caller()
        if len(args) < 2:
            raise ValueError('Installed launcher must supply its runtime and command')
        runtime, command_args = Path(args[0]), args[1:]
        option_args = command_args if '--' not in command_args else command_args[:command_args.index('--')]
        if (command_args[0] in ('--help', '-h', '--version')
                or any(arg in ('--help', '-h') for arg in option_args[1:])):
            worker(runtime, command_args, account, gid)
        path = key_argument(command_args)
        if command_args[0] in ('bundle', 'decrypt', 'verify', 'encrypt'):
            account, gid = document_account(account, gid, command_args)
        if command_args[0] in ('bundle', 'decrypt', 'verify'):
            worker(runtime, command_args, account, gid)
            return 1  # execve never returns in production
        if command_args[0] in ('init', 'passwd'):
            return writer(runtime, command_args, account, gid, path)
        if command_args[0] not in ('encrypt',):
            raise ValueError('Unsupported command')
        if command_args[0] == 'encrypt':
            parser = argparse.ArgumentParser(add_help=False)
            parser.add_argument('path', nargs='?')
            for flag in ('--key', '--password-fd', '--outer-password-fd', '--key-hint', '--outer-hint'):
                parser.add_argument(flag)
            for flag in ('--keep', '--generate-password', '--allow-kdf-cost'):
                parser.add_argument(flag, action='store_true')
            parsed, unknown = parser.parse_known_args(command_args[1:])
            folder = Path(parsed.path).absolute() if parsed.path else Path.cwd()
            current = folder.resolve() == Path.cwd()
            if not unknown and archive_candidates(Path.cwd() if current else folder, current):
                worker(runtime, command_args, account, gid)
                return 1
        fd = open_key(path)
        try:
            worker(runtime, command_args, account, gid, fd)
        finally:
            os.close(fd)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print('docvault sudo helper: ' + str(exc), file=sys.stderr)
        return 1
    return 1


if __name__ == '__main__':
    sys.exit(main())
