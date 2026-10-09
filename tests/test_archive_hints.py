"""Filename hints survive creation, updates, renaming and keyless recovery."""

from collections import deque
import os
from pathlib import Path

import pytest

from docvault import archive_cli, archive_names, keyfile
from docvault.errors import UsageError
from docvault.ui import TerminalUI
from .conftest import write
from .test_bundles import BundleUI, LOCAL


class HintUI(BundleUI):
    def __init__(self, hints=()):
        super().__init__()
        self.hints = deque(hints)
        self.events = []

    def hint(self, prompt):
        self.events.append(('hint', prompt))
        return self.hints.popleft()

    def status(self, message):
        self.events.append(('status', message))
        super().status(message)

    def password(self, prompt):
        self.events.append(('password', prompt))
        return super().password(prompt)


@pytest.mark.parametrize('root,key,outer', [
    ('Tax', 'Hint1-Hint2-Hint-3', 'Hint4-Hint5-Hint6'),
    ('Tax__2026', 'childhood_park', 'first-car'),
    ('Tax_', 'clé été', '東京'),
    ('Tax', '', 'car'),
    ('Tax', 'park_', ''),
    ('Tax__', '', 'car'),
])
def test_filename_round_trip(root, key, outer):
    hints = archive_names.Hints(key, outer)
    name = archive_names.filename(root, hints)
    assert name == f'{root}__{key}__{outer}.7z'
    assert archive_names.parse(name) == (root, hints)
    assert archive_names.matches(name, root)


def test_no_hints_keep_legacy_name():
    assert archive_names.filename('Tax') == 'Tax.7z'
    assert archive_names.parse('Tax.7z') == ('Tax', None)


@pytest.mark.parametrize('hint', ['a__b', '_ambiguous', '../secret', 'a\\b', 'a:b', 'a\nforged', '\x1b[2J', '\u202e'])
def test_unsafe_hints_are_rejected(hint):
    with pytest.raises(UsageError):
        archive_names.filename('Tax', archive_names.Hints(hint, 'other'))


def test_filename_limit_counts_utf8_bytes():
    assert len(archive_names.filename('Tax', archive_names.Hints('é' * 122, 'x')).encode()) == 255
    with pytest.raises(UsageError, match='255 UTF-8 bytes'):
        archive_names.filename('Tax', archive_names.Hints('é' * 123, 'x'))


@pytest.mark.parametrize('current', [False, True])
def test_hinted_archive_create_update_decrypt_without_local_key(tmp_path, monkeypatch, current):
    key = tmp_path / 'private/key'
    keyfile.create(key, LOCAL, 'interactive')
    folder = tmp_path / 'Tax'
    write(folder / 'return.txt', 'tax return')
    if current:
        monkeypatch.chdir(folder)
    args = [] if current else [str(folder)]
    ui = HintUI(['Hint1-Hint2-Hint-3', 'Hint4-Hint5-Hint6'])
    assert archive_cli.run(['encrypt', *args, '--key', str(key)], ui) == 0, ui.text
    output = (folder if current else tmp_path) / 'Tax__Hint1-Hint2-Hint-3__Hint4-Hint5-Hint6.7z'
    assert output.is_file()
    assert [event[0] for event in ui.events if event[0] in ('hint', 'password')][:3] == [
        'hint', 'hint', 'password']
    assert not (folder / 'return.txt').exists()
    key.unlink()
    if current:
        # Re-encrypting an archive-only directory retains its saved documents.
        original = output.read_bytes()
        assert archive_cli.run(['encrypt'], HintUI()) == 0
        assert output.read_bytes() == original
        assert not (folder / '.docvault-archive-locks').exists()
    ui = HintUI()
    # No-argument or folder shorthand finds the hinted name automatically.
    assert archive_cli.run(['decrypt', *args], ui) == 0, ui.text
    events = [event for event in ui.events if event[0] in ('status', 'password')]
    before_password = [event[1] for event in events[:next(i for i, event in enumerate(events) if event[0] == 'password')]]
    assert any('Envelope/key password hint (level 1): Hint1-Hint2-Hint-3' in s for s in before_password)
    assert any('Outer 7z password hint (level 2): Hint4-Hint5-Hint6' in s for s in before_password)
    assert (folder / 'return.txt').read_text() == 'tax return'
    write(folder / 'return.txt', 'updated return')
    assert archive_cli.run(['encrypt', *args], HintUI()) == 0
    assert output.is_file()
    assert not (folder / 'return.txt').exists()
    assert archive_cli.run(['decrypt', str(output)], HintUI()) == 0
    assert (folder / 'return.txt').read_text() == 'updated return'


def test_explicit_hints_keep_plaintext_and_survive_transfer(tmp_path):
    key = tmp_path / 'private/key'
    keyfile.create(key, LOCAL, 'interactive')
    folder = tmp_path / 'Tax'
    write(folder / 'return.txt', 'tax return')
    assert archive_cli.run(['encrypt', str(folder), '--key', str(key), '--keep',
                            '--key-hint', 'park', '--outer-hint', 'car'], HintUI()) == 0
    assert (folder / 'return.txt').read_text() == 'tax return'
    receiver = tmp_path / 'receiver'
    receiver.mkdir()
    output = receiver / 'Renamed__park__car.7z'
    (tmp_path / 'Tax__park__car.7z').rename(output)
    key.unlink()
    ui = HintUI()
    assert archive_cli.run(['decrypt', str(output)], ui) == 0, ui.text
    assert (receiver / 'Tax/return.txt').read_text() == 'tax return'
    assert 'Envelope/key password hint (level 1): park' in ui.text
    assert 'Outer 7z password hint (level 2): car' in ui.text


def test_ambiguous_discovery_stops_before_passwords(tmp_path, monkeypatch):
    folder = tmp_path / 'Tax'
    write(folder / 'Tax.7z', 'legacy')
    write(folder / 'Tax__park__car.7z', 'hinted')
    monkeypatch.chdir(folder)
    for command in ['encrypt', 'decrypt', 'verify']:
        ui = HintUI()
        assert archive_cli.run([command], ui) == UsageError.exit_code
        assert 'Multiple archives match' in ui.text
        assert not ui.password_prompts


def test_untrusted_hints_are_escaped_before_display():
    ui = HintUI()
    archive_cli._show_hints(ui, Path('Tax__\x1b[2J__\nforged.7z'))
    assert '\x1b' not in ui.text
    assert '\\x1b[2J' in ui.text and '\\nforged' in ui.text


def test_invalid_hint_retries_but_eof_stops(tmp_path):
    args = archive_cli.build_parser().parse_args(['encrypt'])
    ui = HintUI(['../bad', 'park', 'car'])
    assert archive_cli._hints(args, ui, tmp_path / 'Tax') == archive_names.Hints('park', 'car')
    assert len([event for event in ui.events if event[0] == 'hint']) == 3
    assert ui.warnings
    ui.hint = lambda prompt: (_ for _ in ()).throw(UsageError('Hint input reached EOF'))
    with pytest.raises(UsageError, match='EOF'):
        archive_cli._hints(args, ui, tmp_path / 'Tax')


def test_hint_options_reject_unsafe_or_overlong_names_before_passwords(tmp_path):
    for hint in ['bad/name', 'é' * 128]:
        ui = HintUI()
        assert archive_cli.run(['encrypt', str(tmp_path / 'Tax'), '--key-hint', hint,
                                '--outer-hint', 'car'], ui) == UsageError.exit_code
        assert not ui.password_prompts
        assert not list(tmp_path.glob('.docvault-7z-*'))


def test_descriptor_passwords_do_not_prompt_for_hints(tmp_path):
    args = archive_cli.build_parser().parse_args(['encrypt', '--password-fd', '0', '--outer-password-fd', '0'])
    ui = HintUI()
    assert archive_cli._hints(args, ui, tmp_path / 'Tax') == archive_names.Hints()
    assert not any(event[0] == 'hint' for event in ui.events)


def test_terminal_hint_reads_public_text_separately(monkeypatch):
    master, slave = os.openpty()
    try:
        def open_tty(path, mode, **kwargs):
            assert path == '/dev/tty'
            return os.fdopen(os.dup(slave), mode, **kwargs)

        monkeypatch.setattr('builtins.open', open_tty)
        os.write(master, b'park\n')
        assert TerminalUI(password_fd=0).hint('Hint: ') == 'park'
    finally:
        os.close(slave)
        os.close(master)


def test_hint_cancellation_preserves_documents(tmp_path, monkeypatch):
    folder = tmp_path / 'Tax'
    write(folder / 'return.txt', 'tax return')
    ui = HintUI()

    def cancel(prompt):
        raise KeyboardInterrupt

    monkeypatch.setattr(ui, 'hint', cancel)
    assert archive_cli.run(['encrypt', str(folder)], ui) == 130
    assert (folder / 'return.txt').read_text() == 'tax return'
    assert not list(tmp_path.glob('*.7z'))
