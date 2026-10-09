"""Portable two-password bundle commands and local-key management."""

import argparse
import os
from pathlib import Path
import shutil
import sys

from . import __version__, archive, archive_names, bundle, crypto, keyfile, passwords
from .errors import PasswordError, UsageError, VaultError
from .ui import UI, TerminalUI, render


def _common(c):
    c.add_argument('--key', type=Path, default=keyfile.DEFAULT_KEY,
                   help=f'local encrypted key file (default: {keyfile.DEFAULT_KEY})')
    c.add_argument('--password-fd', type=int, metavar='FD', help='local/embedded-key password descriptor')
    c.add_argument('--outer-password-fd', type=int, metavar='FD', help='outer password descriptor')
    c.add_argument('--key-fd', type=int, help=argparse.SUPPRESS)
    c.add_argument('--key-write-fd', type=int, help=argparse.SUPPRESS)
    c.add_argument('--allow-kdf-cost', action='store_true', help='approve embedded KDF costs above sensitive')


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='docvault', description='Verified encrypted 7z archives and portable recovery bundles.')
    p.add_argument('--version', action='version', version=f'docvault {__version__}')
    sub = p.add_subparsers(dest='command', required=True)
    for name, help_text in [('init', 'create the password-protected local key'),
                            ('encrypt', 'create/update folder.7z, verify it, then remove plaintext'),
                            ('decrypt', 'restore documents from a bundle; keep the archive'),
                            ('verify', 'verify a bundle and its authenticated document metadata'),
                            ('passwd', 'change only the password protecting the machine-local key')]:
        c = sub.add_parser(name, help=help_text)
        _common(c)
        if name in ('encrypt', 'decrypt', 'verify'):
            c.add_argument('path', type=Path, nargs='?', help='folder/archive (default: current directory)')
        if name == 'encrypt':
            c.add_argument('--keep', action='store_true', help='retain plaintext after verification')
            c.add_argument('--generate-password', action='store_true', help='generate six EFF words; requires terminal typeback')
            c.add_argument('--key-hint', help='public envelope/key password hint in the archive filename')
            c.add_argument('--outer-hint', help='public outer 7z password hint in the archive filename')
        if name == 'init':
            c.add_argument('--kdf', choices=sorted(crypto.PROFILES), default=crypto.DEFAULT_PROFILE)
        if name == 'passwd':
            c.add_argument('--new-password-fd', type=int, metavar='FD')
    management = sub.add_parser('bundle', help='manage bundle credentials')
    bsub = management.add_subparsers(dest='action', required=True)
    change = bsub.add_parser('passwd')
    _common(change)
    change.add_argument('path', type=Path)
    change.add_argument('--layer', choices=['outer', 'key'], required=True)
    change.add_argument('--new-password-fd', type=int, metavar='FD', help='two matching entries for the selected layer')
    change.add_argument('--new-outer-password-fd', type=int, metavar='FD')
    change.add_argument('--new-key-password-fd', type=int, metavar='FD')
    change.add_argument('--generate-password', action='store_true')
    return p


def _read_local(args):
    key = keyfile.canonical(args.key)
    if args.key_fd is not None:
        fd, args.key_fd = args.key_fd, None
        return keyfile.read_privileged_fd(fd)
    if key.parent.exists() and key.parent.stat().st_uid == 0:
        raise UsageError('This key requires administrator access; use the installed sudo launcher')
    # Key writers publish complete envelopes with atomic replacement. A bounded
    # read-only snapshot needs no lock-file mutation before password checks.
    keyfile.private_directory(key.parent)
    return keyfile.read(key)


def _path(args):
    path = args.path if args.path is not None else Path.cwd()
    current = path.resolve() == Path.cwd()
    if current:
        path = Path.cwd()
        if args.command != 'encrypt':
            path = archive_names.find(path, preserve_root=True) or path / (path.name + '.7z')
    path = archive.location(path)
    if args.command != 'encrypt' and path.suffix != '.7z':
        path = archive_names.find(path) or path.with_name(path.name + '.7z')
    return path, current


def _hints(args, ui: UI, folder: Path) -> archive_names.Hints:
    ui.status('Password hints are public in the archive filename. Do not enter passwords here. '
              'Leave a hint empty to skip it.')

    def choose(value, prompt, scripted):
        if value is not None or scripted:
            return archive_names.validate_hint(value or '')
        while True:
            entered = ui.hint(prompt)
            try:
                return archive_names.validate_hint(entered)
            except UsageError as exc:
                # Only validation errors are retryable; EOF/cancellation must stop.
                ui.warn(str(exc))

    # Reading the terminal is independent of reading password descriptors.
    # Descriptor-based scripts can omit hints or supply them as public options.
    key = choose(args.key_hint, 'Envelope/key password hint (level 1): ', args.password_fd is not None)
    outer = choose(args.outer_hint, 'Outer 7z password hint (level 2): ', args.outer_password_fd is not None)
    hints = archive_names.Hints(key, outer)
    archive_names.filename(folder.name, hints)
    return hints


def _show_hints(ui: UI, path: Path) -> None:
    # A legacy filename may itself contain __; exact folder names take precedence.
    hints = None if path.name == path.parent.name + '.7z' else archive_names.parse(path.name)[1]
    if hints is not None:
        ui.status('Password hints from the public archive filename:')
        ui.status(f'  Envelope/key password hint (level 1): {render(hints.key) if hints.key else "(none)"}')
        ui.status(f'  Outer 7z password hint (level 2): {render(hints.outer) if hints.outer else "(none)"}')


def _new_outer(args, ui):
    value = passwords.new_password(ui, 'Enter 7z password: ', 'Confirm 7z password: ',
                                   generate=args.generate_password)
    result = passwords.report(ui, '7z password', value, bundle.OUTER_KDF,
                              enforce=True, generated=args.generate_password)
    return value, result


def _credentials(args, ui: UI, outer_ui: UI, path: Path, parent: Path) -> tuple[bundle.Opened, bytes, bytes, bytes]:
    # Freeze first. This closure is called only after the input is frozen.
    chosen: list[bytes] = []
    local = b''  # Filled by ask() after freezing, before the outer prompt.

    def ask() -> bytes:
        nonlocal local
        if not chosen:
            ui.status(passwords.DUPLICATION)
            _show_hints(ui, path)
            local = _local_password(ui)
        chosen[:] = [outer_ui.password('Enter 7z password: ')]
        return chosen[0]

    opened = bundle.read(path, ask, parent, ui, password_ui=outer_ui)
    try:
        bundle.approve_cost(opened.envelope, ui, args.allow_kdf_cost)
        first = True

        def unlock():
            nonlocal first, local
            if not first:
                local = _local_password(ui)
            first = False
            return opened.unlock(local, ui)

        secret = passwords.retry(ui, unlock)
        return opened, chosen[0], local, secret
    except BaseException:
        opened.close()
        raise


def _local_password(ui, prompt='Local 7z key password: '):
    def ask():
        value = ui.password(prompt)
        passwords.text(value)
        return value

    return passwords.retry(ui, ask)


def _fresh(args, ui, outer_ui):
    ui.status(passwords.DUPLICATION)
    envelope = _read_local(args)

    def unlock():
        local = _local_password(ui)
        ui.status('Unlocking local key with Argon2id…')
        return local, crypto.open_envelope(envelope, local)

    local, secret = passwords.retry(ui, unlock)
    kdf = bundle.raised_costs(envelope.kdf)
    # An existing weak local password needs rotation before a bundle can be made.
    passwords.report(ui, 'Local 7z key password', local, kdf, enforce=True, local=True)

    def choose_outer():
        outer, initial = _new_outer(args, outer_ui)
        passwords.distinct(ui, outer, local, bundle.OUTER_KDF)
        # Re-evaluate both with the other password as known input.
        first = passwords.estimate(outer, bundle.OUTER_KDF, local, generated=args.generate_password)
        if first.guesses != initial.guesses or first.guesses < passwords.FLOOR:
            first = passwords.report(ui, '7z password', outer, bundle.OUTER_KDF, local,
                                     enforce=True, generated=args.generate_password)
        second = passwords.report(ui, 'Local 7z key password', local, kdf, outer, enforce=True, local=True)
        passwords.whole(ui, first, second)
        return outer

    outer = passwords.retry(outer_ui, choose_outer, new=True)
    return outer, local, secret, kdf


def _change_bundle(args, ui, outer_ui, new_ui, path):
    opened, outer, local, secret = _credentials(args, ui, outer_ui, path, path.parent)
    success = False
    try:
        checked, _, _ = bundle.verified(opened, secret, opened.work)
        shutil.rmtree(checked)
        ui.status(passwords.DUPLICATION)
        label = '7z password' if args.layer == 'outer' else 'local 7z key password'
        kdf = (opened.envelope.kdf if args.layer == 'outer'
               else bundle.raised_costs(opened.envelope.kdf))

        def choose():
            new = passwords.new_password(new_ui, f'New {label}: ', f'Confirm new {label}: ',
                                         generate=args.generate_password)
            new_outer, new_local = (new, local) if args.layer == 'outer' else (outer, new)
            passwords.distinct(ui, new_outer, new_local, bundle.OUTER_KDF)
            result = passwords.report(ui, label.capitalize() if args.layer == 'key' else label,
                                      new, bundle.OUTER_KDF if args.layer == 'outer' else kdf,
                                      local if args.layer == 'outer' else outer, enforce=True,
                                      generated=args.generate_password)
            other = (passwords.estimate(local, kdf, new) if args.layer == 'outer'
                     else passwords.estimate(outer, bundle.OUTER_KDF, new))
            if other.guesses < passwords.FLOOR:
                raise PasswordError('The unchanged password is below the strength floor with the new password as known input; '
                                    'choose independent passwords. Nothing was changed.')
            passwords.whole(ui, result if args.layer == 'outer' else other, other if args.layer == 'outer' else result)
            return new_outer, new_local

        new_outer, new_local = passwords.retry(new_ui, choose, new=True)
        with archive.archive_lock(path):
            candidate = bundle.write(opened.inner, secret, new_outer, new_local, kdf, opened.work, ui,
                                     key_bytes=(opened.work / 'key').read_bytes() if args.layer == 'outer' else None)
            bundle.publish(candidate, path, opened.source_stat)
        success = True
        ui.info(f'Bundle {args.layer} password changed; inner ciphertext is unchanged: {render(str(path))}')
    finally:
        if success:
            opened.close()
        else:
            ui.warn(f'Password change failed; preserve staging in {render(str(opened.work))}.')


def run(argv: list[str] | None = None, ui: UI | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = build_parser().parse_args(argv)
    if ui is None:
        ui = TerminalUI(args.password_fd, getattr(args, 'new_password_fd', None))
        # Share descriptor readers across roles, even if both credentials use stdin.
        ui._fds['outer'] = args.outer_password_fd
        ui._fds['new_outer'] = args.outer_password_fd
        outer_ui = _RoleUI(ui, 'outer', 'new_outer')
        if args.command == 'bundle':
            new_fd = getattr(args, 'new_' + args.layer + '_password_fd', None)
            ui._fds['selected'] = new_fd if new_fd is not None else args.new_password_fd
            new_ui = _RoleUI(ui, 'selected', 'selected')
        else:
            new_ui = ui
    else:
        outer_ui = new_ui = ui
    opened = None
    try:
        if os.geteuid() == 0 or os.getuid() == 0:
            raise VaultError('Archive commands must run as the invoking user; use the installed sudo launcher')
        key = args.key
        if args.command == 'init':
            password = passwords.new_password(ui, 'Local key password: ', 'Confirm local key password: ')
            passwords.report(ui, 'Local 7z key password', password, crypto.KdfParams.from_profile(args.kdf))
            if args.key_write_fd is not None:
                envelope = keyfile.new_envelope(password, args.kdf)
                fd, args.key_write_fd = args.key_write_fd, None
                keyfile.publish_privileged(fd, envelope)
            else:
                keyfile.create(key, password, args.kdf)
            ui.info(f'Encrypted key created: {render(str(args.key))}. Back it up with your archives.')
        elif args.command == 'passwd':
            env = _read_local(args)
            # Authenticate before asking the user to choose a replacement.
            def unlock_local():
                old = _local_password(ui, 'Current local key password: ')
                crypto.open_envelope(env, old)
                return old

            old = passwords.retry(ui, unlock_local)
            new = passwords.new_password(ui, 'New local key password: ', 'Confirm new local key password: ')
            passwords.report(ui, 'Local 7z key password', new, env.kdf)
            replacement = keyfile.rewrap(env, old, new)
            if args.key_write_fd is not None:
                fd, args.key_write_fd = args.key_write_fd, None
                keyfile.publish_privileged(fd, replacement)
            else:
                keyfile.change_password(key, old, new)
            ui.info('Local key password changed; archives and embedded keys are unchanged.')
        else:
            archive.sevenzip()
            path, current = _path(args)
            portable = args.command in ('bundle', 'decrypt', 'verify')
            if portable and args.key_fd is not None:
                os.close(args.key_fd)
                args.key_fd = None
            if args.command == 'bundle':
                _change_bundle(args, ui, outer_ui, new_ui, path)
            elif args.command == 'encrypt':
                output = archive_names.find(path, preserve_root=current)
                if output is not None:
                    if args.generate_password:
                        raise UsageError('--generate-password chooses a new password; use bundle passwd to change an existing bundle')
                    if args.key_hint is not None or args.outer_hint is not None:
                        raise UsageError('Existing bundles retain their filename hints; rename the bundle to change hints')
                    if args.key_fd is not None:
                        os.close(args.key_fd)
                        args.key_fd = None
                    # Asked once, no confirmation: opening the existing archive proves it is correct.
                    opened, outer, local, secret = _credentials(args, ui, outer_ui, output, path.parent)
                    passwords.distinct(ui, outer, local, bundle.OUTER_KDF)
                    ui.status(f'7z password matches {render(str(output))}; re-encrypting with the same password.')
                    kdf = opened.envelope.kdf
                    key = None
                else:
                    hints = _hints(args, ui, path)
                    output = (path if current else path.parent) / archive_names.filename(path.name, hints)
                    outer, local, secret, kdf = _fresh(args, ui, outer_ui)
                    key = keyfile.canonical(key)
                archive.encrypt(path, key, secret, ui, keep=args.keep, preserve_root=current,
                                outer_password=outer, key_password=local, kdf=kdf,
                                source_stat=opened.source_stat if opened is not None else None,
                                archive_path=output)
            else:
                inside = archive_names.inside(path)
                opened, outer, local, secret = _credentials(args, ui, outer_ui, path,
                                                    path.parent.parent if inside else path.parent)
                archive.decrypt(path, secret, ui, opened=opened, verify_only=args.command == 'verify',
                                preserve_root=current)
        return 0
    except (VaultError, OSError) as exc:
        ui.warn(str(exc))
        return exc.exit_code if isinstance(exc, VaultError) else 1
    except KeyboardInterrupt:
        ui.warn('Interrupted; preserve any reported temporary folder before retrying.')
        return 130
    finally:
        if opened is not None:
            opened.close()
        for fd in (args.key_fd, args.key_write_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


class _RoleUI(UI):
    """Credential routing with one shared buffered reader per descriptor."""
    def __init__(self, terminal, current, new):
        self.terminal, self.current, self.new = terminal, current, new

    def password(self, prompt):
        return self.terminal._read(self.current, prompt)

    def new_secret(self, prompt):
        return self.terminal._read(self.new, prompt)

    def can_retry_password(self, *, new=False):
        return self.terminal._fds[self.new if new else self.current] is None

    def info(self, message):
        self.terminal.info(message)

    def status(self, message):
        self.terminal.status(message)

    def warn(self, message):
        self.terminal.warn(message)


def main() -> None:
    sys.exit(run())
