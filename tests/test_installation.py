"""Installed command resolution, safe installation and real folder workflows."""

import os
from pathlib import Path
import subprocess

import pytest

from docvault import keyfile
from docvault.archive_cli import build_parser
from scripts import install_commands

from .conftest import OUTER, PASSWORD, write

PROJECT = Path(__file__).resolve().parent.parent
COMMANDS = ("docvault", "encrypt.sh", "decrypt.sh")


def script(name, bin_dir, cwd, *, check=True):
    return subprocess.run([str(PROJECT / name), "--bin-dir", str(bin_dir)], cwd=cwd,
                          capture_output=True, text=True, check=check)


def test_install_and_uninstall_from_any_directory(tmp_path):
    bin_dir = tmp_path / "commands with spaces"
    cwd = tmp_path / "unrelated working folder"
    cwd.mkdir()
    script("install.sh", bin_dir, cwd)
    for name in COMMANDS:
        assert (bin_dir / name).is_symlink()
        assert (bin_dir / name).resolve() == PROJECT / "bin" / name
    before = {name: (bin_dir / name).lstat().st_ino for name in COMMANDS}
    script("install.sh", bin_dir, cwd)
    assert before == {name: (bin_dir / name).lstat().st_ino for name in COMMANDS}
    sentinel = write(bin_dir / "other-tool", "preserve this tool")
    script("uninstall.sh", bin_dir, cwd)
    assert all(not os.path.lexists(bin_dir / name) for name in COMMANDS)
    assert sentinel.read_text() == "preserve this tool"
    assert (PROJECT / ".venv" / "bin" / "python").exists()
    script("uninstall.sh", bin_dir, cwd)  # repeat removal is harmless


@pytest.mark.parametrize("kind", ["file", "directory", "symlink", "broken-symlink"])
def test_installer_refuses_collisions_before_installing_anything(tmp_path, kind):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    collision = bin_dir / "encrypt.sh"
    if kind == "file":
        write(collision, "unrelated command")
    elif kind == "directory":
        collision.mkdir()
    else:
        target = tmp_path / "other-command"
        if kind == "symlink":
            write(target, "another tool")
        collision.symlink_to(target)
    result = script("install.sh", bin_dir, tmp_path, check=False)
    assert result.returncode == 1
    assert "unrelated command" in result.stderr
    assert os.path.lexists(collision)
    assert not os.path.lexists(bin_dir / "docvault")
    assert not os.path.lexists(bin_dir / "decrypt.sh")


def test_uninstaller_preserves_replaced_commands(tmp_path):
    bin_dir = tmp_path / "bin"
    script("install.sh", bin_dir, tmp_path)
    (bin_dir / "encrypt.sh").unlink()
    write(bin_dir / "encrypt.sh", "replacement command")
    result = script("uninstall.sh", bin_dir, tmp_path, check=False)
    assert result.returncode == 1
    assert (bin_dir / "encrypt.sh").read_text() == "replacement command"
    assert (bin_dir / "docvault").is_symlink()


def test_installed_launcher_is_isolated_and_resolves_relative_links(tmp_path):
    bin_dir = tmp_path / "bin"
    script("install.sh", bin_dir, tmp_path)
    evil = tmp_path / "evil"
    write(evil / "docvault/__init__.py", "")
    write(evil / "docvault/__main__.py", "print('HIJACKED')")
    alias = bin_dir / "relative-alias"
    alias.symlink_to("docvault")
    env = {**os.environ, "PYTHONPATH": str(evil)}
    result = subprocess.run([str(alias), "--version"], cwd=evil, env=env,
                            capture_output=True, text=True, check=True)
    assert result.stdout.startswith("docvault ")
    assert "HIJACKED" not in result.stdout + result.stderr


@pytest.mark.real_kdf
def test_installed_wrappers_work_with_paths_and_current_directory(tmp_path):
    bin_dir = tmp_path / "installed commands"
    cwd = tmp_path / "working directory"
    cwd.mkdir()
    script("install.sh", bin_dir, cwd)
    root = tmp_path / "documents with spaces"
    key = tmp_path / "private keys" / "key"
    pw = PASSWORD + b"\n"

    def run(command, args, working_directory=cwd):
        r, w = os.pipe()
        outer_r, outer_w = os.pipe()
        os.write(w, pw)
        os.write(outer_w, (OUTER + b'\n') * (2 if command == 'encrypt.sh' else 1))
        os.close(w)
        os.close(outer_w)
        try:
            return subprocess.run([str(bin_dir / command), *args, '--key', str(key), '--password-fd', str(r),
                                   '--outer-password-fd', str(outer_r)],
                                  pass_fds=(r, outer_r), cwd=working_directory, capture_output=True, text=True)
        finally:
            os.close(r)
            os.close(outer_r)

    # Installed commands accept descriptor options without a folder argument.
    r, w = os.pipe()
    os.write(w, pw * 2)
    os.close(w)
    try:
        init = subprocess.run([str(bin_dir / "docvault"), "init", "--key", str(key), "--password-fd", str(r),
                               "--kdf", "interactive"], cwd=cwd, pass_fds=(r,),
                              capture_output=True, text=True)
    finally:
        os.close(r)
    assert init.returncode == 0, init.stderr
    write(root / "passport.pdf", "encrypted document")
    encrypt = run("encrypt.sh", [str(root)])
    assert encrypt.returncode == 0, encrypt.stderr
    assert not root.exists()
    assert root.with_name(root.name + ".7z").is_file()
    decrypt = run("decrypt.sh", [str(root)])
    assert decrypt.returncode == 0, decrypt.stderr
    assert (root / "passport.pdf").read_text() == "encrypted document"
    inode = root.stat().st_ino
    encrypt = run("encrypt.sh", [], working_directory=root)
    assert encrypt.returncode == 0, encrypt.stderr
    assert root.stat().st_ino == inode
    assert list(root.iterdir()) == [root / (root.name + '.7z')]
    decrypt = run("decrypt.sh", [], working_directory=root)
    assert decrypt.returncode == 0, decrypt.stderr
    assert root.stat().st_ino == inode
    assert (root / "passport.pdf").read_text() == "encrypted document"
    script("uninstall.sh", bin_dir, cwd)
    assert key.exists()
    assert root.with_name(root.name + ".7z").is_file()


def test_cli_allows_omitted_document_path():
    for command in ("encrypt", "decrypt", "verify"):
        args = build_parser().parse_args([command])
        assert args.path is None
        assert args.key == Path("/usr/local/bin/key")


def test_cli_defaults_to_password_protected_key_file():
    for args in (["init"], ["encrypt", "folder"], ["decrypt", "folder.7z"]):
        assert build_parser().parse_args(args).key == Path("/usr/local/bin/key")


@pytest.mark.parametrize("wrapper,command", [("encrypt.sh", "encrypt"), ("decrypt.sh", "decrypt")])
def test_wrappers_forward_arguments_from_any_directory(tmp_path, wrapper, command):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / wrapper).symlink_to(PROJECT / "bin" / wrapper)
    stub = write(bin_dir / "docvault", '#!/bin/sh\nprintf "%s\\n" "$@"\n')
    stub.chmod(0o755)
    cwd = tmp_path / "unrelated folder"
    cwd.mkdir()
    result = subprocess.run([str(bin_dir / wrapper), "documents with spaces", "--key", "my-key"], cwd=cwd,
                            capture_output=True, text=True, check=True)
    assert result.stdout.splitlines() == [command, "documents with spaces", "--key", "my-key"]


def test_default_install_requires_root_before_publishing_anything(tmp_path, monkeypatch):
    bin_dir = tmp_path / "system bin"
    monkeypatch.setattr(install_commands, "DEFAULT_BIN_DIR", bin_dir)
    monkeypatch.setattr(install_commands, "DEFAULT_KEY", bin_dir / "key")
    with pytest.raises(PermissionError, match="Administrator"):
        install_commands.publish(bin_dir, "install")
    assert not bin_dir.exists()


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_invalid_existing_key_stops_install_and_is_never_changed(tmp_path, monkeypatch, kind):
    key = tmp_path / "bin" / "key"
    key.parent.mkdir()
    if kind == "directory":
        key.mkdir()
    elif kind == "file":
        write(key, "existing data")
    else:
        key.symlink_to(tmp_path / "somewhere-else")
    monkeypatch.setattr(install_commands, "DEFAULT_KEY", key)
    monkeypatch.setattr(install_commands, "write_root_file", lambda *a, **k: pytest.fail("Key was rewritten"))
    before = key.lstat()
    with pytest.raises(RuntimeError, match="not a valid docvault key"):
        install_commands.adopt_existing_key(install_commands.load_helper())
    assert key.lstat().st_ino == before.st_ino


def test_valid_unprotected_key_is_reprotected_in_place_with_same_bytes(tmp_path, monkeypatch):
    key = tmp_path / "bin" / "key"
    keyfile.create(key, PASSWORD, "interactive")
    data = key.read_bytes()
    monkeypatch.setattr(install_commands, "DEFAULT_KEY", key)
    written = []
    monkeypatch.setattr(install_commands, "write_root_file",
                        lambda path, payload, helper, mode=0o755: written.append((path, payload, mode)))
    install_commands.adopt_existing_key(install_commands.load_helper())
    assert written == [(key, data, 0o600)]


@pytest.mark.parametrize("mode,expected", [(0o775, 0o1775), (0o755, 0o755), (0o777, 0o1775)])
def test_user_owned_bin_dir_becomes_root_owned_and_sticky(tmp_path, monkeypatch, capsys, mode, expected):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    bin_dir.chmod(mode)
    monkeypatch.setattr(install_commands, "DEFAULT_BIN_DIR", bin_dir)
    monkeypatch.setattr(install_commands, "DEFAULT_KEY", bin_dir / "key")
    calls = []
    monkeypatch.setattr(install_commands.os, "chown", lambda path, uid, gid: calls.append(("chown", uid, gid)))
    monkeypatch.setattr(install_commands.os, "chmod", lambda path, m: calls.append(("chmod", m)))
    helper = install_commands.load_helper()
    monkeypatch.setattr(helper, "trusted_parent", lambda path: calls.append(("trusted", path)))
    install_commands.protect_bin_dir(helper)
    assert calls == [("chown", 0, -1), ("chmod", expected), ("trusted", bin_dir / "key")]
    assert "Undo with:" in capsys.readouterr().out


def test_default_key_initialization_uses_installed_sudo_bridge_and_is_not_repeated(tmp_path, monkeypatch):
    bin_dir = tmp_path / "system bin"
    bin_dir.mkdir()
    key = bin_dir / "key"
    monkeypatch.setattr(install_commands, "DEFAULT_KEY", key)
    monkeypatch.setattr(install_commands, "DEFAULT_BIN_DIR", bin_dir)
    calls = []

    def installed_init(argv, **kwargs):
        calls.append(argv)
        write(key, "encrypted key produced by the root broker")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(install_commands.subprocess, "run", installed_init)
    install_commands.initialize_default_key()
    assert calls == [["/usr/bin/sudo", str(bin_dir / "docvault"), "init"]]
    install_commands.initialize_default_key()
    assert len(calls) == 1


def test_installed_root_launcher_uses_system_python_and_separate_helper():
    text = install_commands.installed_launcher().decode()
    assert '/usr/bin/python3 -I -S' in text
    assert str(install_commands.DEFAULT_HELPER_DIR / 'sudo_runner.py') in text
    assert 'exec ' + str(PROJECT / '.venv/bin/python') + ' -I -m docvault' in text
