"""Privilege boundary, descriptor handoff and root-only key publication."""

import os
from pathlib import Path
import pwd
import socket
import subprocess
import threading
from types import SimpleNamespace

import pytest

from docvault import archive, archive_cli, keyfile
from docvault.errors import Unsupported, WrongPassword
from scripts import sudo_runner

from .conftest import PASSWORD, write


def root_descriptor(monkeypatch, path):
    """Model root ownership for one encrypted fixture; other FS objects are real."""
    inode = path.stat().st_ino
    original = os.fstat

    def fstat(fd):
        st = original(fd)
        if st.st_ino == inode:
            return SimpleNamespace(st_uid=0, st_mode=st.st_mode, st_nlink=st.st_nlink, st_size=st.st_size)
        return st

    monkeypatch.setattr(os, 'fstat', fstat)


@pytest.fixture
def protected_key(tmp_path, monkeypatch):
    path = tmp_path / 'private' / 'key'
    keyfile.create(path, PASSWORD, 'interactive')
    root_descriptor(monkeypatch, path)
    monkeypatch.setattr(sudo_runner, 'trusted_parent', lambda p: None)
    return path


@pytest.mark.parametrize('uid,gid', [('0', '0'), ('-1', '20'), ('bad', '20'), ('501', '-1')])
def test_sudo_identity_must_name_a_non_root_caller(monkeypatch, uid, gid):
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setenv('SUDO_UID', uid)
    monkeypatch.setenv('SUDO_GID', gid)
    with pytest.raises(ValueError):
        sudo_runner.caller()


def test_caller_restores_sudo_uid_and_valid_group(monkeypatch):
    account = pwd.getpwuid(os.getuid())
    gid = os.getgid()
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setenv('SUDO_UID', str(account.pw_uid))
    monkeypatch.setenv('SUDO_GID', str(gid))
    assert sudo_runner.caller() == (account, gid)


def test_helper_rejects_non_privileged_invocation():
    with pytest.raises(ValueError, match='sudo'):
        sudo_runner.caller()


def test_groups_gid_uid_are_dropped_before_exec_and_working_directory_is_preserved(tmp_path, monkeypatch):
    account = pwd.getpwuid(os.getuid())
    gid = os.getgid()
    calls = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('HOME', '/var/root')
    monkeypatch.setenv('SUDO_UID', str(account.pw_uid))
    monkeypatch.setenv('PYTHONPATH', '/untrusted')
    monkeypatch.setenv('DYLD_LIBRARY_PATH', '/untrusted')
    monkeypatch.setattr(os, 'initgroups', lambda name, group: calls.append(('groups', name, group)))
    monkeypatch.setattr(os, 'setgid', lambda group: calls.append(('gid', group)))
    monkeypatch.setattr(os, 'setuid', lambda user: calls.append(('uid', user)))
    captured = []

    def execve(runtime, args, env):
        captured.append((runtime, args, env, Path.cwd()))
        calls.append(('exec',))

    monkeypatch.setattr(os, 'execve', execve)
    fd = os.open(write(tmp_path / 'encrypted', b'fixture'), os.O_RDONLY)
    try:
        sudo_runner.worker('/user/runtime/python', ['encrypt', '--', 'folder'], account, gid, fd)
        assert os.get_inheritable(fd)
    finally:
        os.close(fd)
    assert calls == [('groups', account.pw_name, gid), ('gid', gid), ('uid', account.pw_uid), ('exec',)]
    runtime, args, env, cwd = captured[0]
    assert cwd == tmp_path
    assert args == [runtime, '-I', '-m', 'docvault', 'encrypt', '--key-fd', str(fd), '--', 'folder']
    assert env['HOME'] == account.pw_dir
    assert env['USER'] == env['LOGNAME'] == account.pw_name
    assert env['PATH'].startswith('/opt/homebrew/bin:')
    assert all(not name.startswith(('SUDO_', 'PYTHON', 'DYLD_')) for name in env)


def test_failed_privilege_drop_never_executes_user_runtime(monkeypatch):
    account = pwd.getpwuid(os.getuid())
    monkeypatch.setattr(os, 'initgroups', lambda *a: None)
    monkeypatch.setattr(os, 'setgid', lambda *a: None)
    monkeypatch.setattr(os, 'setuid', lambda *a: None)
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(os, 'execve', lambda *a: pytest.fail('Runtime executed with root credentials'))
    with pytest.raises(ValueError, match='drop root'):
        sudo_runner.worker('/user/runtime', ['encrypt'], account, os.getgid())


@pytest.mark.parametrize('option', ['--key-fd', '--key-write-fd', '--key-fd=4', '--key-write-fd=5'])
def test_users_cannot_override_internal_descriptor_options(option):
    with pytest.raises(ValueError, match='reserved'):
        sudo_runner.key_argument(['encrypt', option])


def test_key_option_uses_the_last_value_and_respects_literal_separator(tmp_path):
    assert sudo_runner.key_argument(['encrypt']) == Path('/usr/local/bin/key')
    assert sudo_runner.key_argument(['encrypt', '--key', '/first', '--key=' + str(tmp_path / 'key')]) == tmp_path / 'key'
    assert sudo_runner.key_argument(['encrypt', '--', '--key=other']) == Path('/usr/local/bin/key')


def test_readonly_key_descriptor_is_validated_and_closed(protected_key):
    fd = sudo_runner.open_key(protected_key)
    assert not os.get_inheritable(fd)
    env = keyfile.read_privileged_fd(fd)
    assert env.kdf.opslimit == 2
    with pytest.raises(OSError):
        os.fstat(fd)


@pytest.mark.parametrize('kind', ['user-owned', 'writable-fd', 'public-mode', 'symlink', 'hardlink'])
def test_bad_key_descriptor_or_file_is_rejected(tmp_path, monkeypatch, kind):
    path = tmp_path / 'private/key'
    keyfile.create(path, PASSWORD, 'interactive')
    monkeypatch.setattr(sudo_runner, 'trusted_parent', lambda p: None)
    if kind != 'user-owned':
        root_descriptor(monkeypatch, path)
    if kind == 'public-mode':
        path.chmod(0o644)
    if kind == 'hardlink':
        os.link(path, path.parent / 'another')
    if kind == 'symlink':
        link = path.parent / 'link'
        link.symlink_to(path)
        with pytest.raises(OSError):
            sudo_runner.open_key(link)
    elif kind == 'writable-fd':
        fd = os.open(path, os.O_RDWR)
        with pytest.raises(Unsupported):
            keyfile.read_privileged_fd(fd)
        with pytest.raises(OSError):
            os.fstat(fd)
    else:
        with pytest.raises(ValueError):
            sudo_runner.open_key(path)


def test_privileged_handoff_runs_real_7z_as_current_user_with_original_modes(tmp_path, protected_key, monkeypatch, ui):
    folder = tmp_path / 'documents'
    source = write(folder / 'document', 'private contents')
    source.chmod(0o640)
    monkeypatch.chdir(folder)
    owner = os.getuid()
    inode = folder.stat().st_ino
    normal_run = archive.run7z
    commands = []
    fd = sudo_runner.open_key(protected_key)

    def observe(args, *rest, **kwargs):
        assert os.getuid() == os.geteuid() == owner
        try:
            active = os.fstat(fd)
        except OSError:
            pass
        else:
            assert active.st_uid == owner  # A reused descriptor must not be the protected key.
        commands.append(args[0])
        return normal_run(args, *rest, **kwargs)

    monkeypatch.setattr(archive, 'run7z', observe)
    assert archive_cli.run(['encrypt', '--key', str(protected_key), '--key-fd', str(fd)], ui) == 0, ui.text
    encrypted = folder / 'documents.7z'
    assert encrypted.stat().st_uid == owner
    assert encrypted.stat().st_mode & 0o777 == 0o600
    assert folder.stat().st_ino == inode
    fd = sudo_runner.open_key(protected_key)
    assert archive_cli.run(['decrypt', '--key', str(protected_key), '--key-fd', str(fd)], ui) == 0, ui.text
    assert source.read_text() == 'private contents'
    assert source.stat().st_uid == owner
    assert source.stat().st_mode & 0o777 == 0o640
    assert folder.stat().st_ino == inode
    assert {'a', 't', 'x'}.issubset(commands)


def test_wrong_password_closes_both_privileged_channels_without_publication(protected_key, ui):
    reader = sudo_runner.open_key(protected_key)
    parent, child = socket.socketpair()
    ui.pw = b'wrong local password'
    try:
        fd = child.detach()
        result = archive_cli.run(['passwd', '--key', str(protected_key), '--key-fd', str(reader),
                                  '--key-write-fd', str(fd)], ui)
        assert result == WrongPassword.exit_code
        assert parent.recv(4096) == b''
        with pytest.raises(OSError):
            os.fstat(reader)
    finally:
        parent.close()


def test_password_writer_sends_only_encrypted_envelope_and_waits_for_ack(tmp_path):
    envelope = keyfile.new_envelope(PASSWORD, 'interactive')
    parent, child = socket.socketpair()
    received = []

    def broker():
        with parent:
            chunks = []
            while chunk := parent.recv(4096):
                chunks.append(chunk)
            data = b''.join(chunks)
            sudo_runner.validate_encrypted(data)
            received.append(data)
            parent.sendall(b'OK')

    thread = threading.Thread(target=broker)
    thread.start()
    keyfile.publish_privileged(child.detach(), envelope)
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert received == [keyfile.encode(envelope)]
    assert PASSWORD not in received[0]


def test_root_publication_creates_private_key_and_refuses_overwrite(tmp_path, monkeypatch):
    path = tmp_path / 'key'
    data = keyfile.encode(keyfile.new_envelope(PASSWORD, 'interactive'))
    owners = []
    monkeypatch.setattr(sudo_runner, 'trusted_parent', lambda p: None)
    monkeypatch.setattr(os, 'fchown', lambda fd, uid, gid: owners.append((uid, gid)))
    sudo_runner.publish_key(path, data)
    assert owners == [(0, 0)]
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == data
    assert not list(tmp_path.glob('.docvault-key-*'))
    with pytest.raises(ValueError, match='not replaced'):
        sudo_runner.publish_key(path, data)


def test_invalid_encrypted_bytes_are_rejected_before_privileged_write(tmp_path):
    for data in (b'plaintext-password', b'{}', b'x' * 4097):
        with pytest.raises(ValueError):
            sudo_runner.publish_key(tmp_path / 'key', data)
    assert not (tmp_path / 'key').exists()


def test_system_python_can_run_the_stdlib_helper_without_project_imports(tmp_path):
    helper = Path(sudo_runner.__file__).resolve()
    result = subprocess.run(['/usr/bin/python3', '-I', '-S', str(helper), '/untrusted/runtime', 'encrypt'],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 1
    assert 'must be invoked through sudo' in result.stderr
    assert 'ModuleNotFoundError' not in result.stderr


def test_root_archive_execution_is_refused_before_any_password_or_archive_work(monkeypatch, ui):
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    assert archive_cli.run(['encrypt'], ui) == 1
    assert 'must run as the invoking user' in ui.text


def test_password_change_can_share_one_descriptor_for_old_and_new_passwords():
    from docvault import passwords
    from docvault.ui import TerminalUI

    reader, writer = os.pipe()
    os.write(writer, b'old local password\nnew long local password\nnew long local password\n')
    os.close(writer)
    try:
        ui = TerminalUI(password_fd=reader)
        assert ui.password('old') == b'old local password'
        assert passwords.new_password(ui, 'New local key password: ', 'Confirm new local key password: ') == b'new long local password'
    finally:
        os.close(reader)


@pytest.mark.parametrize('args', [['decrypt'], ['verify'], ['bundle', 'passwd', '/missing.7z', '--layer', 'key']])
def test_portable_sudo_commands_drop_privileges_without_opening_key(monkeypatch, args):
    account = pwd.getpwuid(os.getuid())
    calls = []
    monkeypatch.setattr(sudo_runner, 'caller', lambda: (account, os.getgid()))
    monkeypatch.setattr(sudo_runner, 'open_key', lambda p: pytest.fail('Portable recovery opened the local key'))
    monkeypatch.setattr(sudo_runner, 'worker', lambda *a: calls.append(a))
    sudo_runner.main(['/runtime', *args])
    assert len(calls) == 1 and len(calls[0]) == 4


@pytest.mark.parametrize('name', ['docs.7z', 'docs__park__car.7z'])
@pytest.mark.parametrize('hint_args', [[], ['--key-hint', 'park', '--outer-hint', 'car']])
def test_sudo_bundle_update_does_not_require_local_key(tmp_path, monkeypatch, name, hint_args):
    account = pwd.getpwuid(os.getuid())
    folder = tmp_path / 'docs'
    write(folder / name, 'frozen by the unprivileged worker')
    monkeypatch.chdir(folder)
    calls = []
    monkeypatch.setattr(sudo_runner, 'caller', lambda: (account, os.getgid()))
    monkeypatch.setattr(sudo_runner, 'open_key', lambda p: pytest.fail('Bundle update opened the local key'))
    monkeypatch.setattr(sudo_runner, 'worker', lambda *a: calls.append(a))
    sudo_runner.main(['/runtime', 'encrypt', *hint_args])
    assert len(calls) == 1 and len(calls[0]) == 4


def test_hint_options_do_not_replace_sudo_document_path(tmp_path):
    assert sudo_runner.target_path(['encrypt', '--key-hint', 'park', '--outer-hint', 'car',
                                    str(tmp_path / 'Tax')]) == tmp_path / 'Tax'


def other_account(uid=os.getuid() + 1000):
    me = pwd.getpwuid(os.getuid())
    return SimpleNamespace(pw_name='otheradmin', pw_uid=uid, pw_gid=me.pw_gid, pw_dir='/Users/otheradmin',
                           pw_shell='/bin/zsh')


@pytest.mark.parametrize('args', [['decrypt'], ['verify'], ['encrypt'], ['decrypt', 'docs.7z'],
                                  ['decrypt', '--key', '/other/key', 'docs'],
                                  ['bundle', 'passwd', 'docs.7z', '--layer', 'key']])
def test_admin_acts_as_owner_of_another_users_documents(tmp_path, monkeypatch, capsys, args):
    owner = pwd.getpwuid(os.getuid())
    folder = tmp_path / 'docs'
    write(folder / 'docs.7z', 'archive owned by the current test user')
    monkeypatch.chdir(folder if args[-1] in ('decrypt', 'verify', 'encrypt') else tmp_path)
    monkeypatch.setattr(os, 'getgrouplist', lambda name, gid: [gid, sudo_runner.ADMIN_GID])
    admin = other_account()
    assert sudo_runner.document_account(admin, 20, args) == (owner, owner.pw_gid)
    assert f'acting as {owner.pw_name}' in capsys.readouterr().err


def test_non_admin_and_own_or_system_documents_keep_caller_identity(tmp_path, monkeypatch):
    write(tmp_path / 'docs' / 'docs.7z', 'archive')
    monkeypatch.chdir(tmp_path / 'docs')
    caller = other_account()
    monkeypatch.setattr(os, 'getgrouplist', lambda name, gid: [gid])
    assert sudo_runner.document_account(caller, 20, ['decrypt']) == (caller, 20)  # Not an administrator.
    monkeypatch.setattr(os, 'getgrouplist', lambda name, gid: [gid, sudo_runner.ADMIN_GID])
    me = other_account(os.getuid())
    assert sudo_runner.document_account(me, 20, ['decrypt']) == (me, 20)  # Own documents.
    assert sudo_runner.document_account(caller, 20, ['decrypt', '/usr/bin']) == (caller, 20)  # System owner.


def test_admin_sudo_decrypt_hands_owner_identity_to_worker(tmp_path, monkeypatch):
    owner = pwd.getpwuid(os.getuid())
    write(tmp_path / 'docs' / 'docs.7z', 'archive')
    monkeypatch.chdir(tmp_path / 'docs')
    admin = other_account()
    calls = []
    monkeypatch.setattr(sudo_runner, 'caller', lambda: (admin, 20))
    monkeypatch.setattr(os, 'getgrouplist', lambda name, gid: [gid, sudo_runner.ADMIN_GID])
    monkeypatch.setattr(sudo_runner, 'worker', lambda *a: calls.append(a))
    sudo_runner.main(['/runtime', 'decrypt'])
    assert calls[0][2:] == (owner, owner.pw_gid)
