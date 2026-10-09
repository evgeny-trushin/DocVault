"""Install a root-owned sudo bridge and protect the default key; user runtime stays user-owned."""

import argparse
import importlib.util
import os
from pathlib import Path
import pwd
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

PROJECT = Path(__file__).resolve().parent.parent
COMMANDS = ('docvault', 'encrypt.sh', 'decrypt.sh')
DEFAULT_BIN_DIR = Path('/usr/local/bin')
DEFAULT_KEY = DEFAULT_BIN_DIR / 'key'
DEFAULT_HELPER_DIR = Path('/usr/local/libexec/docvault')


def load_helper():
    spec = importlib.util.spec_from_file_location('docvault_sudo_runner', PROJECT / 'scripts' / 'sudo_runner.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def owned_link(path: Path, source: Path) -> bool:
    return path.is_symlink() and path.resolve() == source.resolve()


def installed_launcher() -> bytes:
    runtime = shlex.quote(str(PROJECT / '.venv' / 'bin' / 'python'))
    helper = shlex.quote(str(DEFAULT_HELPER_DIR / 'sudo_runner.py'))
    return ('#!/bin/sh\n# DocVault installed sudo launcher.\nset -eu\n'
            'if [ "$(/usr/bin/id -u)" -eq 0 ]; then\n'
            f'    exec /usr/bin/python3 -I -S {helper} {runtime} "$@"\n'
            'fi\n'
            f'exec {runtime} -I -m docvault "$@"\n').encode()


def command_data(name: str) -> bytes:
    return installed_launcher() if name == 'docvault' else (PROJECT / 'bin' / name).read_bytes()


def owned_command(path: Path, source: Path, system: bool) -> bool:
    if not system and owned_link(path, source):
        return True
    if not system or path.is_symlink() or not path.is_file():
        return False
    st = path.lstat()
    return st.st_uid == 0 and not st.st_mode & 0o022 and path.read_bytes() == command_data(path.name)


def check_targets(bin_dir: Path, mode: str) -> None:
    system = bin_dir.resolve() == DEFAULT_BIN_DIR.resolve()
    for name in COMMANDS:
        target, source = bin_dir / name, PROJECT / 'bin' / name
        if os.path.lexists(target) and not owned_command(target, source, system):
            raise RuntimeError(f'Refusing to {mode} unrelated command: {target}')


def protect_bin_dir(helper) -> None:
    """Make the key's folder root-owned and sticky, so no other account can rename or replace
    root's key and launchers there. The group and its write access are kept (e.g. admin)."""
    st = DEFAULT_BIN_DIR.lstat()
    if not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f'{DEFAULT_BIN_DIR} must be a real directory')
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid != 0 or mode & 0o002 or (mode & 0o020 and not mode & stat.S_ISVTX):
        new_mode = (mode & ~0o002) | (stat.S_ISVTX if mode & 0o020 else 0)
        os.chown(DEFAULT_BIN_DIR, 0, -1)
        os.chmod(DEFAULT_BIN_DIR, new_mode)
        owner = pwd.getpwuid(st.st_uid).pw_name if st.st_uid else 'root'
        print(f'Protected {DEFAULT_BIN_DIR}: owner {owner} -> root, mode {mode:o} -> {new_mode:o}. '
              f'Undo with: sudo chown {owner} {DEFAULT_BIN_DIR} && sudo chmod {mode:o} {DEFAULT_BIN_DIR}')
    helper.trusted_parent(DEFAULT_KEY)


def adopt_existing_key(helper) -> None:
    """Re-protect a valid existing key in place (same bytes, root-owned 600, no ACL)."""
    try:
        fd = helper.open_key(DEFAULT_KEY)
    except (OSError, ValueError):
        pass
    else:
        os.close(fd)
        return  # Already protected.
    try:
        fd = os.open(DEFAULT_KEY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError('not a single-link regular file')
            data = os.read(fd, helper.MAX_KEY_BYTES + 1)
        finally:
            os.close(fd)
        helper.validate_encrypted(data)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f'{DEFAULT_KEY} is not a valid docvault key ({exc}); it was left unchanged. '
                           'Move it aside to create a new key, then rerun install.sh.') from None
    write_root_file(DEFAULT_KEY, data, helper, mode=0o600)
    print(f'Protected existing key {DEFAULT_KEY} (root-owned, mode 600); its contents and password are unchanged.')


def prepare_runtime(python: str) -> None:
    runtime = PROJECT / '.venv' / 'bin' / 'python'
    if runtime.exists():
        probe = ('import pathlib,sys,docvault,docvault.archive_cli; '
                 'sys.exit(sys.version_info < (3,12) or '
                 'pathlib.Path(docvault.__file__).resolve().parent != pathlib.Path(sys.argv[1]))')
        result = subprocess.run([str(runtime), '-I', '-c', probe, str(PROJECT / 'docvault')],
                                capture_output=True, text=True)
        if result.returncode == 0:
            return
    if os.geteuid() == 0:
        raise RuntimeError('Run install.sh as your normal user to prepare the Python environment.')
    uv = shutil.which('uv')
    if uv is None:
        raise RuntimeError('uv is required. Alternatively, create .venv with Python >=3.12 and install '
                           'this project into it, then rerun install.sh.')
    # A venv whose base interpreter was removed (e.g. a Homebrew upgrade) cannot start; rebuild it.
    if not runtime.exists() or subprocess.run([str(runtime), '-I', '-c', ''],
                                              capture_output=True).returncode != 0:
        subprocess.run([uv, 'venv', '--clear', '--python', python, str(PROJECT / '.venv')], check=True)
    subprocess.run([uv, 'pip', 'install', '--python', str(runtime), '--editable', str(PROJECT)], check=True)
    subprocess.run([str(runtime), '-I', '-m', 'docvault', '--version'], check=True)


def write_root_file(path: Path, data: bytes, helper, mode: int = 0o755) -> None:
    fd, name = tempfile.mkstemp(prefix='.docvault-install-', dir=path.parent)
    tmp = Path(name)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
        subprocess.run(['/bin/chmod', '-N', str(tmp)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with os.fdopen(fd, 'wb') as output:
            fd = -1
            output.write(data)
            output.flush()
            helper.full_sync(output.fileno())
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        tmp.unlink(missing_ok=True)


def publish(bin_dir: Path, mode: str) -> None:
    check_targets(bin_dir, mode)
    system = bin_dir.resolve() == DEFAULT_BIN_DIR.resolve()
    if mode == 'uninstall':
        for name in COMMANDS:
            target = bin_dir / name
            if owned_command(target, PROJECT / 'bin' / name, system):
                target.unlink()
                print(f'Removed {target}')
        return  # Keep the protected key, helper and archives.
    if system:
        if os.geteuid() != 0:
            raise PermissionError('Administrator access is required to protect the key and install sudo launchers')
        helper = load_helper()
        protect_bin_dir(helper)
        anchor = DEFAULT_HELPER_DIR
        while not os.path.lexists(anchor):
            anchor = anchor.parent
        helper.trusted_parent(anchor / '.installation-check')
        DEFAULT_HELPER_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
        helper_path = DEFAULT_HELPER_DIR / 'sudo_runner.py'
        helper.trusted_parent(helper_path)
        if os.path.lexists(helper_path):
            st = helper_path.lstat()
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022
                    or not helper_path.read_bytes().startswith(b'"""Root-owned stdlib-only bridge.')):
                raise RuntimeError(f'Unsafe privileged helper: {helper_path}')
        write_root_file(helper_path, (PROJECT / 'scripts' / 'sudo_runner.py').read_bytes(), helper)
        if os.path.lexists(DEFAULT_KEY):
            adopt_existing_key(helper)
        for name in COMMANDS:
            write_root_file(bin_dir / name, command_data(name), helper)
            print(f'Installed root-owned {bin_dir / name}')
        return
    bin_dir.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        for name in COMMANDS:
            target, source = bin_dir / name, PROJECT / 'bin' / name
            if owned_link(target, source):
                print(f'Already installed: {target}')
                continue
            target.symlink_to(source)
            created.append(target)
            print(f'Installed {target}')
    except BaseException:
        for target in reversed(created):
            if owned_link(target, PROJECT / 'bin' / target.name):
                target.unlink()
        raise


def initialize_default_key() -> None:
    if not os.path.lexists(DEFAULT_KEY):
        print(f'Choose the local password for the root-protected archive key ({DEFAULT_KEY}).', flush=True)
        # Installed root-owned bridge drops IDs before the user prompt and KDF.
        subprocess.run(['/usr/bin/sudo', str(DEFAULT_BIN_DIR / 'docvault'), 'init'], check=True)


def main() -> int:
    modes = ('install', 'uninstall', 'publish-install', 'publish-uninstall')
    if len(sys.argv) < 2 or sys.argv[1] not in modes:
        print('Use install.sh or uninstall.sh.', file=sys.stderr)
        return 2
    requested_mode = sys.argv[1]
    privileged = requested_mode.startswith('publish-')
    mode = requested_mode.removeprefix('publish-')
    parser = argparse.ArgumentParser(prog=f'{mode}.sh',
                                    description=f'{mode.capitalize()} docvault, encrypt.sh and decrypt.sh.')
    parser.add_argument('--bin-dir', type=Path, default=DEFAULT_BIN_DIR)
    if requested_mode == 'install':
        parser.add_argument('--python', default='3.12', help='Python version for a new uv environment')
    args = parser.parse_args(sys.argv[2:])
    bin_dir = args.bin_dir.expanduser().absolute()
    try:
        check_targets(bin_dir, mode)
        if requested_mode == 'install':
            if sys.platform != 'darwin':
                raise RuntimeError('This implementation currently supports macOS.')
            if os.geteuid() == 0:
                raise RuntimeError('Run ./install.sh as your normal user; it requests sudo for protected installation.')
            prepare_runtime(args.python)
            # Same check docvault uses: legacy p7zip reads passwords from the terminal and hangs.
            check = subprocess.run([str(PROJECT / '.venv' / 'bin' / 'python'), '-I', '-c',
                                    'from docvault import archive; print(archive.sevenzip())'],
                                   capture_output=True, text=True)
            if check.returncode:
                raise RuntimeError('7-Zip 21 or later is required (legacy p7zip is not supported). '
                                   'Install it with: brew install sevenzip')
        try:
            publish(bin_dir, mode)
        except PermissionError:
            if privileged or os.geteuid() == 0:
                raise
            sudo = shutil.which('sudo')
            if sudo is None:
                raise RuntimeError('Administrator access is needed; choose a writable --bin-dir.') from None
            print(f'Administrator access is needed to install protected commands in {bin_dir}.', flush=True)
            command = [sudo, sys.executable, '-I', '-S', str(Path(__file__).resolve()), f'publish-{mode}',
                       '--bin-dir', str(bin_dir)]
            subprocess.run(command, check=True)
        if requested_mode == 'install' and bin_dir.resolve() == DEFAULT_BIN_DIR.resolve():
            initialize_default_key()
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f'{mode}: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
