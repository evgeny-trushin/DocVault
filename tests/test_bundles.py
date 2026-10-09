"""Real encrypted wrapper operations and adversarial boundary checks."""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import zlib
from collections import deque

import pytest

from docvault import archive, archive_cli, bundle, crypto, durable, keyfile, passwords, strictjson as sj
from docvault.errors import IntegrityError, UsageError, WrongPassword
from docvault.ui import TerminalUI
from .conftest import ScriptedUI, write

OUTER = b'kX9#mQ2$vL7p'
LOCAL = b'unwashed-gauze-uncured-spinal-reclining-stucco'
NEW_OUTER = b'7hR!zW5@bN8t'
NEW_LOCAL = b'crumpled-sturdy-dwindle-handclap-unlovely-renounce'


class BundleUI(ScriptedUI):
    def __init__(self, outer=OUTER, local=LOCAL, new=()):
        super().__init__(local)
        self.outer = outer
        self.new = deque(new)
        self.password_prompts = []

    def password(self, prompt):
        self.password_prompts.append(prompt)
        return self.outer if prompt == 'Enter 7z password: ' else self.pw

    def new_secret(self, prompt):
        self.password_prompts.append(prompt)
        return super().new_secret(prompt)


@pytest.fixture
def local_key(tmp_path):
    key = tmp_path / 'private/key'
    keyfile.create(key, LOCAL, 'interactive')
    return key, keyfile.open_key(key, LOCAL)


@pytest.mark.parametrize('args', [
    ['legacy', 'unlock'],
    ['recovery', 'add', 'docs.7z'],
    ['encrypt', '--legacy-archive'],
    ['encrypt', '--with-recovery'],
    ['decrypt', '--legacy-archive'],
])
def test_removed_commands_and_flags_are_rejected(args):
    with pytest.raises(SystemExit) as exc:
        archive_cli.build_parser().parse_args(args)
    assert exc.value.code == 2


def test_bare_archive_is_rejected_without_document_publication(tmp_path):
    source = tmp_path / 'source'
    write(source / 'document', 'private document')
    output = tmp_path / 'docs.7z'
    # Even an archive with the correct outer encryption must satisfy the bundle
    # layout. There is no fallback to a single-layer document archive.
    archive.run7z(['a', '-t7z', '-p', '-m0=Copy', '-ms=off', '-mhe=on', '--',
                   str(output), 'document'], bundle.derive_outer(OUTER), cwd=source, creating=True)
    original = output.read_bytes()
    ui = BundleUI()
    assert archive_cli.run(['decrypt', str(output)], ui) == IntegrityError.exit_code
    assert 'Outer layout must contain exactly encrypted.7z and key' in ui.text
    assert ui.password_prompts == ['Local 7z key password: ', 'Enter 7z password: ']
    assert output.read_bytes() == original
    assert not (tmp_path / 'docs').exists()


def create(tmp_path, local_key, monkeypatch, *, current=False):
    key, secret = local_key
    folder = tmp_path / 'docs'
    write(folder / 'key', 'ordinary key document')
    write(folder / 'encrypted.7z', 'ordinary encrypted.7z document')
    write(folder / 'nested/document', 'private document')
    ui = BundleUI(new=[OUTER, OUTER])
    if current:
        monkeypatch.chdir(folder)
    args = ['encrypt', '--key', str(key)] + ([] if current else [str(folder)])
    assert archive_cli.run(args, ui) == 0, ui.text
    output = folder / 'docs.7z' if current else tmp_path / 'docs.7z'
    return folder, output, ui


def terminal_entries(monkeypatch, entries):
    """Exercise the real terminal UI without reading a person's terminal."""
    entries = iter(entries)
    prompts = []

    def getpass(prompt):
        prompts.append(prompt)
        value = next(entries)
        if isinstance(value, BaseException):
            raise value
        return value.decode()

    monkeypatch.setattr('docvault.ui.getpass.getpass', getpass)
    monkeypatch.setattr(TerminalUI, 'hint', lambda self, prompt: '')
    return prompts


def test_creation_retries_local_and_new_outer_until_valid(tmp_path, local_key, monkeypatch, capsys):
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original document')
    prompts = terminal_entries(monkeypatch, [
        *([b'incorrect local'] * 4), LOCAL,
        OUTER, b'mismatched confirmation', b'',
        b'weak', b'weak', LOCAL, LOCAL, OUTER, OUTER,
    ])
    assert archive_cli.run(['encrypt', str(folder), '--key', str(local_key[0])]) == 0
    assert prompts[:5] == ['Local 7z key password: '] * 5
    assert prompts[5:] == ['Enter 7z password: ', 'Confirm 7z password: ',
                          'Enter 7z password: ',
                          'Enter 7z password: ', 'Confirm 7z password: ',
                          'Enter 7z password: ', 'Confirm 7z password: ',
                          'Enter 7z password: ', 'Confirm 7z password: ']
    out, err = capsys.readouterr()
    assert 'Try again' in err and 'Ctrl-C' in err
    assert 'too weak' in err and 'close variant' in err and 'do not match' in err
    assert OUTER.decode() not in out + err and LOCAL.decode() not in out + err
    assert not folder.exists() and (tmp_path / 'docs.7z').exists()


@pytest.mark.parametrize('command', ['decrypt', 'verify', 'encrypt'])
def test_existing_bundle_retries_each_password_using_one_snapshot(tmp_path, local_key, monkeypatch, command):
    folder, output, _ = create(tmp_path, local_key, monkeypatch)
    if command == 'encrypt':
        assert archive_cli.run(['decrypt', str(output)], BundleUI()) == 0
    prompts = terminal_entries(monkeypatch, [
        b'wrong local', *([b'wrong outer'] * 4), OUTER, b'still wrong local', LOCAL,
    ])
    frozen = []
    freeze = bundle.freeze

    def observe(path, *args, **kwargs):
        if path == output:
            frozen.append(path)
        return freeze(path, *args, **kwargs)

    monkeypatch.setattr(bundle, 'freeze', observe)
    assert archive_cli.run([command, str(folder if command == 'encrypt' else output)]) == 0
    assert prompts == (['Local 7z key password: '] + ['Enter 7z password: '] * 5
                       + ['Local 7z key password: '] * 2)
    # Encryption also verifies the old bundle once inside its transaction.
    assert len(frozen) == (2 if command == 'encrypt' else 1)
    assert not list(tmp_path.glob('.docvault-7z-*'))


@pytest.mark.parametrize('entries', [
    [KeyboardInterrupt()],
    [LOCAL, KeyboardInterrupt()],
    [LOCAL, OUTER, KeyboardInterrupt()],
    [LOCAL, *([b'weak', b'weak'] * 4), KeyboardInterrupt()],
])
def test_creation_cancellation_preserves_plaintext(tmp_path, local_key, monkeypatch, entries):
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original document')
    terminal_entries(monkeypatch, entries)
    assert archive_cli.run(['encrypt', str(folder), '--key', str(local_key[0])]) == 130
    assert (folder / 'file').read_text() == 'original document'
    assert not (tmp_path / 'docs.7z').exists()
    assert not list(tmp_path.glob('.docvault-7z-*'))


@pytest.mark.parametrize('entries', [
    [LOCAL, *([b'wrong outer'] * 4), KeyboardInterrupt()],
    [b'wrong local', OUTER, KeyboardInterrupt()],
])
def test_decryption_cancellation_cleans_staging(tmp_path, local_key, monkeypatch, entries):
    folder, output, _ = create(tmp_path, local_key, monkeypatch)
    before = output.read_bytes()
    terminal_entries(monkeypatch, entries)
    assert archive_cli.run(['decrypt', str(output)]) == 130
    assert output.read_bytes() == before and not folder.exists()
    assert not list(tmp_path.glob('.docvault-7z-*'))


@pytest.mark.parametrize('layer,new', [('outer', NEW_OUTER), ('key', NEW_LOCAL)])
def test_bundle_password_change_retries_new_entries(tmp_path, local_key, monkeypatch, layer, new):
    _, output, _ = create(tmp_path, local_key, monkeypatch)
    similar = LOCAL if layer == 'outer' else OUTER
    terminal_entries(monkeypatch, [LOCAL, OUTER, new, b'mismatch', b'weak', b'weak',
                                   similar, similar, new, new])
    assert archive_cli.run(['bundle', 'passwd', str(output), '--layer', layer]) == 0
    ui = BundleUI(outer=new if layer == 'outer' else OUTER, local=new if layer == 'key' else LOCAL)
    assert archive_cli.run(['verify', str(output)], ui) == 0, ui.text


def test_terminal_eof_stops_instead_of_retrying(monkeypatch):
    terminal_entries(monkeypatch, [EOFError()])
    with pytest.raises(UsageError, match='no password was entered'):
        passwords.new_password(TerminalUI(), 'new', 'confirm')


def test_descriptor_eof_stops_instead_of_retrying():
    reader, writer = os.pipe()
    os.close(writer)
    try:
        with pytest.raises(UsageError, match='EOF'):
            passwords.new_password(TerminalUI(password_fd=reader), 'new', 'confirm')
    finally:
        os.close(reader)


@pytest.mark.parametrize('descriptor_role', ['outer', 'local'])
def test_invalid_descriptor_password_does_not_retry_terminal_role(tmp_path, local_key, monkeypatch, descriptor_role):
    folder, output, _ = create(tmp_path, local_key, monkeypatch)
    prompts = terminal_entries(monkeypatch, [LOCAL if descriptor_role == 'outer' else OUTER])
    reader, writer = os.pipe()
    os.write(writer, b'wrong password\n')
    os.close(writer)
    flag = '--outer-password-fd' if descriptor_role == 'outer' else '--password-fd'
    try:
        assert archive_cli.run(['decrypt', str(output), flag, str(reader)]) == WrongPassword.exit_code
    finally:
        os.close(reader)
    assert prompts == ['Local 7z key password: ' if descriptor_role == 'outer' else 'Enter 7z password: ']
    assert not folder.exists() and output.exists()
    assert not list(tmp_path.glob('.docvault-7z-*'))


@pytest.mark.real_kdf
def test_outer_derivation_vector():
    assert bundle.OUTER_SALT.hex() == 'b6b29a97b01ff79e2534f7f13a6531c4'
    assert bundle.derive_outer(b'correct horse battery staple').hex() == (
        '46ff9c2c74b641aaac53b10c2e468c25abcdfd901d398548b9c7621cd260e4da')


@pytest.mark.parametrize('current', [False, True])
def test_bundle_round_trip_without_local_key(tmp_path, local_key, monkeypatch, current):
    folder, output, ui = create(tmp_path, local_key, monkeypatch, current=current)
    assert ui.password_prompts == ['Local 7z key password: ', 'Enter 7z password: ', 'Confirm 7z password: ']
    assert output.stat().st_mode & 0o777 == 0o600
    assert not (folder / 'key').exists()
    assert b'encrypted.7z' not in output.read_bytes()
    key, _ = local_key
    key.unlink()
    ui = BundleUI()
    args = ['decrypt'] + ([] if current else [str(output)])
    assert archive_cli.run(args, ui) == 0, ui.text
    assert ui.password_prompts == ['Local 7z key password: ', 'Enter 7z password: ']
    assert (folder / 'key').read_text() == 'ordinary key document'
    assert (folder / 'encrypted.7z').read_text() == 'ordinary encrypted.7z document'
    assert output.exists() and not key.exists()
    assert not list(tmp_path.glob('.docvault-7z-*'))


def test_wrong_outer_never_publishes_documents(tmp_path, local_key, monkeypatch):
    folder, output, _ = create(tmp_path, local_key, monkeypatch)
    ui = BundleUI(outer=b'wrong outer password')
    assert archive_cli.run(['decrypt', str(output)], ui) == WrongPassword.exit_code
    assert ui.password_prompts == ['Local 7z key password: ', 'Enter 7z password: ']
    assert 'wrong 7z password or damaged outer archive' in ui.text
    assert not folder.exists()


def test_wrong_embedded_password_never_publishes_documents(tmp_path, local_key, monkeypatch):
    folder, output, _ = create(tmp_path, local_key, monkeypatch)
    ui = BundleUI(local=b'wrong local key password')
    assert archive_cli.run(['decrypt', str(output)], ui) == WrongPassword.exit_code
    assert 'wrong local 7z key password or damaged embedded key' in ui.text
    assert not folder.exists()


def test_bundle_update_preserves_format_without_machine_key(tmp_path, local_key, monkeypatch):
    folder, output, _ = create(tmp_path, local_key, monkeypatch)
    key, _ = local_key
    key.unlink()
    assert archive_cli.run(['decrypt', str(output)], BundleUI()) == 0
    write(folder / 'new document', 'updated')
    ui = BundleUI()
    assert archive_cli.run(['encrypt', str(folder)], ui) == 0, ui.text
    assert not folder.exists()
    opened = bundle.read(output, OUTER, tmp_path, ui)
    try:
        assert bundle.layout(opened.work / 'outer.7z', opened.outer_key).keys() == {'encrypted.7z', 'key'}
    finally:
        opened.close()
    assert archive_cli.run(['decrypt', str(output)], BundleUI()) == 0
    assert (folder / 'new document').read_text() == 'updated'


@pytest.mark.parametrize('layer,new', [('outer', NEW_OUTER), ('key', NEW_LOCAL)])
def test_password_changes_preserve_inner_ciphertext_and_other_credential(tmp_path, local_key, monkeypatch, layer, new):
    folder, output, _ = create(tmp_path, local_key, monkeypatch)
    ui = BundleUI()
    opened = bundle.read(output, OUTER, tmp_path, ui)
    inner, old_key = opened.inner.read_bytes(), (opened.work / 'key').read_bytes()
    opened.close()
    machine_bytes = local_key[0].read_bytes()
    backup = tmp_path / 'old-copy.7z'
    shutil.copyfile(output, backup)
    ui = BundleUI(new=[new, new])
    assert archive_cli.run(['bundle', 'passwd', str(output), '--layer', layer], ui) == 0, ui.text
    outer, local = (new, LOCAL) if layer == 'outer' else (OUTER, new)
    opened = bundle.read(output, outer, tmp_path, ui)
    try:
        assert opened.inner.read_bytes() == inner
        assert opened.unlock(local, ui) == local_key[1]
        assert ((opened.work / 'key').read_bytes() == old_key) == (layer == 'outer')
    finally:
        opened.close()
    assert local_key[0].read_bytes() == machine_bytes
    assert archive_cli.run(['verify', str(backup)], BundleUI()) == 0
    assert not folder.exists()




@pytest.mark.parametrize('second', [OUTER, OUTER.lower(), b' '+OUTER+b' ', OUTER+b'x', b'kX9#mQ2$vL7q'])
def test_duplicate_password_rejected_before_archive_lock(tmp_path, monkeypatch, second):
    folder = tmp_path / 'docs'
    write(folder / 'file', 'document')
    key = tmp_path / 'private/key'
    keyfile.create(key, second, 'interactive')
    monkeypatch.setattr(archive, 'archive_lock', lambda *a: pytest.fail('lock taken before duplicate refusal'))
    ui = BundleUI(local=second, new=[OUTER, OUTER])
    assert archive_cli.run(['encrypt', str(folder), '--key', str(key)], ui) == UsageError.exit_code
    assert 'One cracked password would open both layers' in ui.text
    assert (folder / 'file').exists() and not (tmp_path / 'docs.7z').exists()


@pytest.mark.parametrize('password', [b'', b'correct horse battery staple', b'Summer2026!Summer2026!'])
def test_weak_outer_refused_after_local_password(tmp_path, local_key, password):
    ui = BundleUI(new=[password, password])
    assert archive_cli.run(['encrypt', str(tmp_path / 'docs'), '--key', str(local_key[0])], ui) == UsageError.exit_code
    assert ui.password_prompts[0] == 'Local 7z key password: '
    assert not (tmp_path / 'docs.7z').exists()


def test_descriptor_passwords_reports_only_stderr(tmp_path, local_key, capsys):
    key, _ = local_key
    folder = tmp_path / 'docs'
    write(folder / 'file', 'document')
    outer_fd, out_write = os.pipe()
    key_fd, key_write = os.pipe()
    os.write(out_write, OUTER + b'\n' + OUTER + b'\n')
    os.write(key_write, LOCAL + b'\n')
    os.close(out_write)
    os.close(key_write)
    try:
        assert archive_cli.run(['encrypt', str(folder), '--key', str(key),
                                '--outer-password-fd', str(outer_fd), '--password-fd', str(key_fd)]) == 0
    finally:
        os.close(outer_fd)
        os.close(key_fd)
    out, err = capsys.readouterr()
    assert 'guesses needed' not in out and 'guesses needed' in err
    assert 'Whole bundle' in err
    assert OUTER.decode() not in out + err and LOCAL.decode() not in out + err


def test_generated_password_must_be_typed_back(monkeypatch):
    monkeypatch.setattr(passwords.secrets, 'choice', lambda values: values[0])
    ui = BundleUI(new=[b'wrong typeback'])
    displayed = []
    ui.show_generated = lambda password: displayed.append(password)
    with pytest.raises(UsageError, match='do not match'):
        passwords.new_password(ui, 'new', 'confirm', generate=True)
    assert len(displayed) == 1 and displayed[0].count(b'-') == 5
    assert displayed[0].decode() not in ui.text
    assert passwords.guesses(displayed[0], generated=True) == 7776**6 / 2


def test_strict_envelope_bounds_and_domain_separation(tmp_path, local_key, fast_kdf):
    key, secret = local_key
    inner = write(tmp_path / 'inner', b'ciphertext')
    env = bundle.seal(inner, secret, LOCAL, keyfile.read(key).kdf)
    assert env.kdf.opslimit == 3 and env.kdf.memlimit == 256 << 20
    assert env.open(LOCAL) == secret
    with pytest.raises(IntegrityError):
        keyfile.parse(env.encode())
    with pytest.raises(IntegrityError):
        bundle.Envelope.parse(key.read_bytes())
    for field, value in [('archive_bytes', True), ('archive_sha256', '00'), ('version', 2),
                          ('nonce', '00'), ('wrapped_secret', 'ff'), ('extra', 'bad')]:
        obj = sj.loads(env.encode(), max_bytes=16384, what='test')
        obj[field] = value
        with pytest.raises(IntegrityError):
            bundle.Envelope.parse(sj.dumps(obj))
    obj = sj.loads(env.encode(), max_bytes=16384, what='test')
    obj['kdf']['memlimit'] = (4 << 30) + 1024
    before = len(fast_kdf)
    with pytest.raises(IntegrityError):
        bundle.Envelope.parse(sj.dumps(obj))
    assert len(fast_kdf) == before
    obj = sj.loads(env.encode(), max_bytes=16384, what='test')
    obj['archive_sha256'] = '0' * 64
    with pytest.raises(WrongPassword):
        bundle.Envelope.parse(sj.dumps(obj)).open(LOCAL)


def test_embedded_costs_never_weaken_local_costs(tmp_path, local_key):
    _, secret = local_key
    inner = write(tmp_path / 'inner', b'ciphertext')
    for profile in crypto.PROFILES:
        params = crypto.KdfParams.from_profile(profile)
        env = bundle.seal(inner, secret, LOCAL, params)
        assert env.kdf.opslimit == max(3, params.opslimit)
        assert env.kdf.memlimit == max(256 << 20, params.memlimit)
    env = bundle.seal(inner, secret, LOCAL, crypto.KdfParams(5, 1024 << 20, os.urandom(16)))
    ui = BundleUI()
    ui.accept = False
    with pytest.raises(UsageError, match='not approved'):
        bundle.approve_cost(env, ui, False)
    assert '1024 MiB' in ui.prompts[0]
    bundle.approve_cost(env, ui, True)


@pytest.mark.parametrize('kind', ['unencrypted-headers', 'extra', 'directory', 'compressed', 'digest'])
def test_malformed_outer_rejected_without_document_publication(tmp_path, local_key, kind):
    _, secret = local_key
    members = tmp_path / 'members'
    members.mkdir()
    inner = write(members / 'encrypted.7z', b'inner ciphertext')
    env = bundle.seal(inner, secret, LOCAL, crypto.KdfParams.from_profile('interactive'))
    write(members / 'key', env.encode())
    names = ['encrypted.7z', 'key']
    if kind == 'extra':
        write(members / 'extra', b'extra')
        names.append('extra')
    if kind == 'directory':
        inner.unlink()
        inner.mkdir()
    if kind == 'digest':
        inner.write_bytes(b'other ciphertext')
    output = tmp_path / 'bad.7z'
    archive.run7z(['a', '-p', '-mhe=' + ('off' if kind == 'unencrypted-headers' else 'on'),
                   '-ms=off', '-mx=' + ('5' if kind == 'compressed' else '0'), '--', str(output), *names],
                  bundle.derive_outer(OUTER), cwd=members, creating=True)
    with pytest.raises(IntegrityError):
        bundle.read(output, OUTER, tmp_path, BundleUI())


def test_freeze_prevents_substitution_between_listing_and_extraction(tmp_path, local_key, monkeypatch):
    _, output, _ = create(tmp_path, local_key, monkeypatch)
    normal = bundle.layout
    def swap(path, secret):
        found = normal(path, secret)
        output.write_bytes(b'replaced original')
        return found
    monkeypatch.setattr(bundle, 'layout', swap)
    opened = bundle.read(output, OUTER, tmp_path, BundleUI())
    try:
        assert opened.unlock(LOCAL, BundleUI()) == local_key[1]
        checked, _, _ = bundle.verified(opened, local_key[1], tmp_path)
        shutil.rmtree(checked)
    finally:
        opened.close()


def test_publication_flush_failure_preserves_plaintext(tmp_path, local_key, monkeypatch):
    key, _ = local_key
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original')
    normal = durable.sync_dir
    def fail(path, **kw):
        if Path(path) == tmp_path and (tmp_path / 'docs.7z').exists():
            raise OSError('injected publication barrier')
        return normal(path, **kw)
    monkeypatch.setattr(durable, 'sync_dir', fail)
    ui = BundleUI(new=[OUTER, OUTER])
    assert archive_cli.run(['encrypt', str(folder), '--key', str(key)], ui) != 0
    assert (folder / 'file').read_text() == 'original'
    assert archive_cli.run(['verify', str(tmp_path / 'docs.7z')], BundleUI()) == 0


def test_unpassworded_or_typed_password_listing_does_not_open_bundle(tmp_path, local_key, monkeypatch):
    _, output, _ = create(tmp_path, local_key, monkeypatch)
    for typed in (b'\n', OUTER + b'\n'):
        result = subprocess.run([archive.sevenzip(), 'l', str(output)], input=typed,
                                capture_output=True, timeout=10)
        assert result.returncode != 0
        assert b'encrypted.7z' not in result.stdout and b'Path = key' not in result.stdout


def test_hostile_declared_header_size_rejected_before_7z(tmp_path, monkeypatch):
    header = struct.pack('<QQI', 0, bundle.ALLOWANCE + 1, 0)
    data = b'7z\xbc\xaf\x27\x1c\x00\x04' + struct.pack('<I', zlib.crc32(header)) + header
    path = write(tmp_path / 'bad.7z', data)
    monkeypatch.setattr(archive, 'run7z', lambda *a, **kw: pytest.fail('7z ran on oversized header'))
    with pytest.raises(IntegrityError, match='bounds'):
        bundle.read(path, OUTER, tmp_path, BundleUI())


@pytest.mark.parametrize('value,expected', [
    (b'correct horse battery staple', 5.7e12),
    (b'maple-orbit-tundra-velvet-clamp', 4.7e16),
    (b'q8fz2kd9x7mw', 2.4e18),
    (LOCAL, 5.4e22), (OUTER, 2.7e23),
])
def test_strength_calibration(value, expected):
    assert passwords.guesses(value) == pytest.approx(expected, rel=.02)


def test_shared_words_lower_estimate_and_sensitive_costs_slow_attacker():
    assert passwords.guesses(LOCAL, b'prefix-unwashed-gauze-other-independent-words') < passwords.guesses(LOCAL)
    assert passwords.speed(crypto.KdfParams.from_profile('sensitive')) < passwords.speed(bundle.OUTER_KDF) / 5
    assert passwords.similar('ＡＢＣＤrandompassword'.encode(), b'abcdrandompassword')


def test_terminal_refuses_echo_fallback(monkeypatch):
    import getpass
    import warnings
    def fallback(prompt):
        warnings.warn('cannot hide input', getpass.GetPassWarning)
        pytest.fail('echoed input')
    monkeypatch.setattr(getpass, 'getpass', fallback)
    with pytest.raises(UsageError, match='hidden input'):
        TerminalUI().password('Password: ')


@pytest.mark.parametrize('value,other,expected', [
    (b'Summer2026!Summer2026!', b'', 55_220_001),
    (b'Tr0ub4dor&4', b'Tr0ub4dor&3', 11_077_696_000_000),
])
def test_corrected_pinned_estimator_calibration(value, other, expected):
    assert passwords.guesses(value, other) == expected


def test_two_credentials_can_share_one_descriptor(tmp_path, local_key, monkeypatch):
    folder, output, _ = create(tmp_path, local_key, monkeypatch)
    reader, writer = os.pipe()
    os.write(writer, LOCAL + b'\n' + OUTER + b'\n')
    os.close(writer)
    try:
        assert archive_cli.run(['decrypt', str(output), '--outer-password-fd', str(reader),
                                '--password-fd', str(reader)]) == 0
    finally:
        os.close(reader)
    assert (folder / 'key').exists()


@pytest.mark.parametrize('layer,new', [('outer', NEW_OUTER), ('key', NEW_LOCAL)])
def test_password_change_descriptor_routes(tmp_path, local_key, monkeypatch, layer, new):
    _, output, _ = create(tmp_path, local_key, monkeypatch)
    reader, writer = os.pipe()
    os.write(writer, LOCAL + b'\n' + OUTER + b'\n' + new + b'\n' + new + b'\n')
    os.close(writer)
    try:
        assert archive_cli.run(['bundle', 'passwd', str(output), '--layer', layer,
                                '--outer-password-fd', str(reader), '--password-fd', str(reader),
                                '--new-' + layer + '-password-fd', str(reader)]) == 0
    finally:
        os.close(reader)
    ui = BundleUI(outer=new if layer == 'outer' else OUTER, local=new if layer == 'key' else LOCAL)
    assert archive_cli.run(['verify', str(output)], ui) == 0, ui.text


def test_bundle_processes_never_receive_typed_passwords(tmp_path, local_key, monkeypatch):
    normal = archive.run7z
    received = []
    def observe(args, secret, **kw):
        assert secret not in (OUTER, LOCAL)
        assert all(OUTER.decode() not in a and LOCAL.decode() not in a for a in args)
        received.append(secret)
        return normal(args, secret, **kw)
    monkeypatch.setattr(archive, 'run7z', observe)
    _, output, _ = create(tmp_path, local_key, monkeypatch)
    assert archive_cli.run(['verify', str(output)], BundleUI()) == 0
    assert bundle.derive_outer(OUTER) in received
    assert local_key[1] in received


def test_lock_is_shared_by_all_keys_and_keyless_recovery(tmp_path):
    from docvault.errors import Busy
    output = tmp_path / 'docs.7z'
    with archive.archive_lock(output, tmp_path / 'first/key'):
        with pytest.raises(Busy):
            with archive.archive_lock(output, tmp_path / 'missing/key'):
                pass
        with pytest.raises(Busy):
            with archive.archive_lock(output):
                pass


@pytest.mark.parametrize('layer', ['outer', 'key'])
def test_password_change_similarity_refusal_retains_output(tmp_path, local_key, monkeypatch, layer):
    _, output, _ = create(tmp_path, local_key, monkeypatch)
    before = output.read_bytes()
    value = LOCAL if layer == 'outer' else OUTER
    ui = BundleUI(new=[value, value])
    assert archive_cli.run(['bundle', 'passwd', str(output), '--layer', layer], ui) == UsageError.exit_code
    assert output.read_bytes() == before


def test_local_password_floor_applies_when_first_embedded(tmp_path):
    weak = b'correct horse battery staple'
    key = tmp_path / 'private/key'
    keyfile.create(key, weak, 'interactive')
    folder = tmp_path / 'docs'
    write(folder / 'file', 'document')
    ui = BundleUI(local=weak, new=[OUTER, OUTER])
    assert archive_cli.run(['encrypt', str(folder), '--key', str(key)], ui) == UsageError.exit_code
    assert 'sudo docvault passwd first' in ui.text
    assert not (tmp_path / 'docs.7z').exists()
    assert not (tmp_path / '.docvault-archive-locks').exists()
    assert (folder / 'file').exists()


def test_kdf_approval_precedes_embedded_password_derivation(tmp_path, local_key, monkeypatch):
    _, output, _ = create(tmp_path, local_key, monkeypatch)
    opened = bundle.read(output, OUTER, tmp_path, BundleUI())
    ui = BundleUI()
    env = bundle.seal(opened.inner, local_key[1], LOCAL, crypto.KdfParams(5, 256 << 20, os.urandom(16)))
    members = archive.workspace(tmp_path)
    try:
        shutil.copyfile(opened.inner, members / 'encrypted.7z')
        write(members / 'key', env.encode())
        output.unlink()
        archive.run7z(['a', '-p', '-mhe=on', '-mx=0', '-ms=off', '--', str(output), 'encrypted.7z', 'key'],
                      bundle.derive_outer(OUTER), cwd=members, creating=True)
    finally:
        opened.close()
        shutil.rmtree(members)
    ui.accept = False
    assert archive_cli.run(['verify', str(output)], ui) == UsageError.exit_code
    assert ui.password_prompts == ['Local 7z key password: ', 'Enter 7z password: ']
    assert 'Unlocking embedded key' not in ui.text
    assert archive_cli.run(['verify', str(output), '--allow-kdf-cost'], BundleUI()) == 0


def test_insufficient_disk_space_retains_plaintext(tmp_path, local_key, monkeypatch):
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original')
    from collections import namedtuple
    usage = namedtuple('usage', 'total used free')
    monkeypatch.setattr(shutil, 'disk_usage', lambda p: usage(1, 1, 0))
    ui = BundleUI(new=[OUTER, OUTER])
    assert archive_cli.run(['encrypt', str(folder), '--key', str(local_key[0])], ui) == UsageError.exit_code
    assert 'Insufficient disk space' in ui.text
    assert (folder / 'file').read_text() == 'original'
    assert not (tmp_path / 'docs.7z').exists()


@pytest.mark.real_kdf
def test_real_argon2_bundle_recovery_after_local_key_loss(tmp_path, local_key, monkeypatch):
    folder, output, _ = create(tmp_path, local_key, monkeypatch)
    local_key[0].unlink()
    ui = BundleUI()
    assert archive_cli.run(['decrypt', str(output)], ui) == 0, ui.text
    assert (folder / 'nested/document').read_text() == 'private document'


def test_password_change_verification_failure_retains_complete_old_bundle(tmp_path, local_key, monkeypatch):
    _, output, _ = create(tmp_path, local_key, monkeypatch)
    before = output.read_bytes()
    original = bundle.read
    def fail_candidate(path, *args, **kw):
        if Path(path) != output:
            raise IntegrityError('injected candidate verification failure')
        return original(path, *args, **kw)
    monkeypatch.setattr(bundle, 'read', fail_candidate)
    ui = BundleUI(new=[NEW_OUTER, NEW_OUTER])
    assert archive_cli.run(['bundle', 'passwd', str(output), '--layer', 'outer'], ui) == IntegrityError.exit_code
    assert output.read_bytes() == before
    assert 'preserve staging' in ui.text.lower()
    assert list(tmp_path.glob('.docvault-7z-*/*.7z'))




def test_transfer_and_rename_use_embedded_key_without_changing_receiver_key(tmp_path, local_key, monkeypatch):
    _, output, _ = create(tmp_path, local_key, monkeypatch)
    receiver = tmp_path / 'another laptop'
    receiver.mkdir()
    transferred = receiver / 'Renamed bundle.7z'
    shutil.copyfile(output, transferred)
    receiver_key = tmp_path / 'receiver-private/key'
    keyfile.create(receiver_key, b'unrelated receiver password', 'interactive')
    receiver_before = receiver_key.read_bytes()
    local_key[0].unlink()
    ui = BundleUI()
    assert archive_cli.run(['decrypt', str(transferred), '--key', str(receiver_key)], ui) == 0, ui.text
    assert (receiver / 'docs/nested/document').read_text() == 'private document'
    assert receiver_key.read_bytes() == receiver_before
    assert transferred.exists()
