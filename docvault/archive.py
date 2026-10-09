"""Solid 7z archives. Stage, verify, publish durably, then remove exact originals."""

import functools
import hashlib
from typing import TYPE_CHECKING
import os
import resource
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unicodedata

from . import archive_names, crypto, durable, keyfile, limits, macos, strictjson as sj, tree
from .errors import CommitUncertain, IntegrityError, SourceChanged, Unsupported, UsageError
from .manifest import Entry, validate_entries, validate_path
from .oplock import OperationLock
from .ui import UI, render

if TYPE_CHECKING:
    from .bundle import Opened

METADATA = '.docvault-7z.json'
FORMAT = 'docvault-7z-metadata'


MIN_7Z_VERSION = (21, 0)  # Official 7-Zip with -sse and stdin passwords; never legacy p7zip.


def modern_7z(executable: str) -> bool:
    try:
        banner = subprocess.run([executable], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                errors='replace', timeout=10, start_new_session=True).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    found = re.search(r'^7-Zip(?: \([a-z]\))? (\d+)\.(\d+)', banner, re.MULTILINE)
    return found is not None and 'p7zip' not in banner and (int(found[1]), int(found[2])) >= MIN_7Z_VERSION


@functools.cache
def sevenzip() -> str:
    for command in ('7zz', '7z', '7za'):
        executable = shutil.which(command)
        if executable and modern_7z(executable):
            return executable
    raise Unsupported('7-Zip 21 or later is required (legacy p7zip is not supported). '
                      'On macOS install it with: brew install sevenzip')


def run7z(args: list[str], secret: bytes, *, cwd: Path | None = None, creating: bool = False,
          output_limit: int | None = None, output_file=None) -> str:
    # -p without a value prompts when creating. For reading, OMIT -p: an
    # explicit bare -p would select an empty password instead of prompting.
    # Only listings need output. An anonymous file avoids allocating unbounded
    # memory for a hostile listing before we can enforce the entry limits.
    maximum = output_limit if output_limit is not None else (limits.MAX_ENTRIES + 1) * (limits.MAX_PATH_BYTES + 1024)

    def bound_child():
        resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
        file_limit = output_limit if output_limit is not None else 2 * limits.MAX_TOTAL_SIZE + (2 << 20)
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run([sevenzip(), '-bd', '-bb0', '-bsp0', '-sccUTF-8', '-mmt=2', *args],
                                cwd=cwd, input=(secret.hex() + '\n') * (2 if creating else 1),
                                stdout=output_file if output_file is not None else
                                output if args[0] == 'l' else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='strict',
                                preexec_fn=bound_child, timeout=900,
                                # No controlling terminal: 7z can never wait on /dev/tty.
                                start_new_session=True)
        except subprocess.TimeoutExpired:
            raise IntegrityError('7z exceeded its time limit; original data was retained') from None
        if result.returncode:
            raise IntegrityError(f'7z {args[0]} failed (exit {result.returncode}); original data was retained')
        if output.tell() > maximum:
            raise IntegrityError('Archive listing exceeds size limit')
        output.seek(0)
        try:
            return output.read(maximum + 1).decode('utf-8')
        except UnicodeError:
            raise IntegrityError('Archive listing is not valid UTF-8') from None


def safe_name(path: str) -> None:
    validate_path(path)
    if '\\' in path or any(unicodedata.category(c) in ('Cc', 'Cf', 'Cs') for c in path):
        raise Unsupported(f'Archive paths cannot contain backslashes or control characters: {render(path)}')
    if any(':' in part for part in path.split('/')):
        raise Unsupported(f'Archive paths cannot contain colons: {render(path)}')


def location(path: Path) -> Path:
    path = path.expanduser().absolute()
    return path.parent.resolve() / path.name


def scan(root: Path, *, exclude_root_names: frozenset[str] = frozenset(),
          allow_metadata_cleanup: bool = False) -> tree.Scan:
    safe_name(root.name)
    if root.name == METADATA:
        raise UsageError(f'Reserved folder name: {METADATA}')
    if root.lstat().st_mode & 0o700 != 0o700:
        raise Unsupported(f'Folder needs owner read, write and execute permissions: {render(str(root))}')
    result = tree.scan_tree(root, prefix=root.name, include_root=True,
                            exclude_root_names=exclude_root_names,
                            allow_metadata_cleanup=allow_metadata_cleanup)
    if result.issues:
        raise Unsupported('\n'.join(issue.describe() for issue in result.issues))
    folded = set()
    for entry in result.entries:
        safe_name(entry.path)
        key = unicodedata.normalize('NFC', entry.path).casefold()
        if key in folded:
            raise Unsupported(f'Case-insensitive archive name collision: {render(entry.path)}')
        folded.add(key)
    validate_entries(result.entries)
    return result


def metadata(root: str, entries: list[Entry], secret: bytes) -> bytes:
    body = {'format': FORMAT, 'version': 1, 'root': root, 'entries': [e.to_json() for e in entries]}
    tag = crypto.mac(crypto.derive_subkey(secret, crypto.SUBKEY_ARCHIVE_METADATA), b'DOCVAULT-7Z-METADATA\0' + sj.dumps(body)).hex()
    return sj.dumps({**body, 'tag': tag})


def parse_metadata(data: bytes, secret: bytes) -> tuple[str, list[Entry]]:
    obj = sj.loads(data, max_bytes=limits.MAX_MANIFEST_BYTES, what='7z metadata')
    sj.require_object(obj, {'format', 'version', 'root', 'entries', 'tag'}, '7z metadata')
    tag = sj.require_hex(obj.pop('tag'), 'tag', 32)
    if not crypto.mac_matches(crypto.derive_subkey(secret, crypto.SUBKEY_ARCHIVE_METADATA), b'DOCVAULT-7Z-METADATA\0' + sj.dumps(obj), tag):
        raise IntegrityError('Archive metadata authentication failed')
    sj.require_header(obj, FORMAT, 1, '7z metadata')
    root = sj.require_str(obj['root'], 'root', limits.MAX_NAME_BYTES)
    safe_name(root)
    if '/' in root or root == METADATA:
        raise IntegrityError('Invalid archive root')
    if not isinstance(obj['entries'], list) or len(obj['entries']) > limits.MAX_ENTRIES:
        raise IntegrityError('Invalid archive entries')
    entries = [Entry.from_json(e) for e in obj['entries']]
    validate_entries(entries)
    if not entries or entries[0].path != root or entries[0].kind != 'dir':
        raise IntegrityError('Archive root missing')
    folded = set()
    for e in entries:
        safe_name(e.path)
        if e.path != root and not e.path.startswith(root + '/'):
            raise IntegrityError('Entry outside archive root')
        key = unicodedata.normalize('NFC', e.path).casefold()
        if key in folded:
            raise IntegrityError('Duplicate archive path')
        folded.add(key)
    return root, entries


def listing(archive: Path, secret: bytes) -> dict[str, tuple[str, int]]:
    output = run7z(['l', '-slt', '--', str(archive)], secret)
    if '\n----------\n' not in output:
        raise IntegrityError('7z listing is missing its entry section')
    header, contents = output.split('\n----------\n', 1)
    if '\nType = 7z\n' not in header:
        raise IntegrityError('Expected a 7z archive')
    found = {}
    folded = set()
    for record in contents.strip().split('\n\n'):
        fields = {}
        for line in record.splitlines():
            name, sep, value = line.partition(' = ')
            if not sep or name in fields:
                raise IntegrityError('Ambiguous archive listing')
            fields[name] = value
        path = fields.get('Path', '')
        safe_name(path)
        key = unicodedata.normalize('NFC', path).casefold()
        if key in folded:
            raise IntegrityError('Duplicate archive path')
        folded.add(key)
        attrs = fields.get('Attributes', '')
        if any(k in fields for k in ('Symbolic Link', 'Hard Link')) or 'l' in attrs.split(' ')[-1][:1]:
            raise IntegrityError('Archive links are unsupported')
        kind = 'dir' if attrs.startswith('D ') else 'file'
        if kind == 'file' and not attrs.split(' ')[-1].startswith('-'):
            raise IntegrityError('Archive special objects are unsupported')
        try:
            size = int(fields['Size'])
        except (KeyError, ValueError):
            raise IntegrityError('Invalid archive size') from None
        if not 0 <= size <= limits.MAX_FILE_SIZE:
            raise IntegrityError('Archive entry exceeds size limit')
        if kind == 'file' and size and fields.get('Encrypted') != '+':
            raise IntegrityError('Archive contains unencrypted file data')
        found[path] = (kind, size)
    if len(found) > limits.MAX_ENTRIES + 1 or sum(v[1] for v in found.values()) > limits.MAX_TOTAL_SIZE:
        raise IntegrityError('Archive exceeds extraction limits')
    # Every parent must be a directory: prevents a link/file parent ambiguity.
    for path in found:
        parent = path.rpartition('/')[0]
        if parent and found.get(parent, ('', 0))[0] != 'dir':
            raise IntegrityError('Archive parent directory is missing')
    if found.get(METADATA, ('', 0))[0] != 'file' or found[METADATA][1] > limits.MAX_MANIFEST_BYTES:
        raise IntegrityError('Not a DocVault 7z archive (metadata missing)')
    return found


def workspace(parent: Path) -> Path:
    work = Path(tempfile.mkdtemp(prefix='.docvault-7z-', dir=parent))
    try:
        if macos.has_extended_acl(work):
            raise Unsupported(f'Temporary folder inherited an ACL: {work}')
        macos.set_backup_excluded(work)
        return work
    except BaseException:
        work.rmdir()
        raise


def extract_verified(archive: Path, secret: bytes, parent: Path) -> tuple[Path, str, list[Entry]]:
    # Freeze the encrypted input to prevent listing/extraction from seeing
    # different archives. This copy never contains plaintext.
    work = workspace(parent)
    try:
        frozen = work / 'input.7z'
        fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise Unsupported('Archive must be a regular file')
            if st.st_size > limits.MAX_TOTAL_SIZE * 2:
                raise IntegrityError('Encrypted archive exceeds size limit')
            with os.fdopen(os.dup(fd), 'rb') as source, frozen.open('xb') as target:
                shutil.copyfileobj(source, target)
        finally:
            os.close(fd)
        paths = listing(frozen, secret)
        run7z(['t', '--', str(frozen)], secret)
        output = work / 'extracted'
        output.mkdir(mode=0o700)
        run7z(['x', '-y', f'-o{output}', '--', str(frozen)], secret)
        data_path = output / METADATA
        with data_path.open('rb') as f:
            root, entries = parse_metadata(f.read(limits.MAX_MANIFEST_BYTES + 1), secret)
        expected = {e.path: (e.kind, e.size) for e in entries}
        expected[METADATA] = ('file', data_path.stat().st_size)
        if paths != expected:
            raise IntegrityError('Archive entries do not match authenticated metadata')
        for e in entries:
            path = output / e.path
            st = path.lstat()
            if (e.kind == 'dir' and not stat.S_ISDIR(st.st_mode)) or (e.is_file and not stat.S_ISREG(st.st_mode)):
                raise IntegrityError('Extracted object type mismatch')
            if e.is_file and (st.st_size != e.size or tree.hash_file(path, st)[0] != e.sha256):
                raise IntegrityError('Extracted content checksum mismatch')
            tree.apply_metadata(path, e)
        if scan(output / root).entries != entries:
            raise IntegrityError('Extracted metadata mismatch')
        return work, root, entries
    except BaseException:
        shutil.rmtree(work)
        raise


def archive_lock(path: Path, key: Path | None = None) -> OperationLock:
    # Independent of key availability and --key selection. Keep the lock outside
    # a current-directory document root so it can never become a document.
    parent = path.parent.parent if archive_names.inside(path) else path.parent
    locks = parent / '.docvault-archive-locks'
    locks.mkdir(mode=0o700, exist_ok=True)
    keyfile.private_directory(locks)
    return OperationLock(locks / hashlib.sha256(os.fsencode(path)).hexdigest())


def encrypt(folder: Path, key: Path | None, secret: bytes, ui: UI, *, keep: bool = False,
            outer_password: bytes, key_password: bytes, kdf: crypto.KdfParams,
            preserve_root: bool = False, source_stat: os.stat_result | None = None,
            archive_path: Path | None = None) -> Path:
    from . import bundle
    folder = location(folder)
    parent = folder if preserve_root else folder.parent
    archive = location(archive_path) if archive_path is not None else parent / (folder.name + '.7z')
    if archive.parent != parent or not archive_names.matches(archive.name, folder.name):
        raise UsageError('Archive name or location does not match the document folder')
    excluded = frozenset({archive.name}) if preserve_root else frozenset()
    if key is not None and (key == folder or key.is_relative_to(folder)):
        raise UsageError('The key file must be outside the document folder')
    with archive_lock(archive, key):
        before = scan(folder, exclude_root_names=excluded, allow_metadata_cleanup=True)
        archive_before = None
        if os.path.lexists(archive):
            archive_before = archive.lstat()
            old_bundle = bundle.read(archive, outer_password, folder.parent, ui)
            try:
                recovered = old_bundle.unlock(key_password, ui)
                if recovered != secret or (source_stat is not None and
                        tree._identity(old_bundle.source_stat) != tree._identity(source_stat)):
                    raise SourceChanged('Bundle changed before update')
                old_work, old_root, _ = bundle.verified(old_bundle, secret, folder.parent)
                shutil.rmtree(old_work)
            finally:
                old_bundle.close()
            if old_root != folder.name:
                raise UsageError('Refusing to replace an archive of a different folder')
            if preserve_root and len(before.entries) == 1:
                # With only our archive left, a repeated invocation must not
                # replace the saved documents with an empty folder snapshot.
                ui.info(f'Already encrypted and verified: {render(str(archive))}')
                return archive
        estimate = sum(e.size for e in before.entries) + len(metadata(folder.name, before.entries, secret)) + (1 << 20)
        bundle.disk_space(folder.parent, estimate * 7 + (archive_before.st_size * 2 if archive_before else 0))
        work = workspace(folder.parent)
        staged = folder if preserve_root else work / folder.name
        source_parent = staged.parent
        deleting = False
        finished = False
        try:
            if not preserve_root:
                macos.rename_exclusive(folder, staged)
            approved = scan(staged, exclude_root_names=excluded, allow_metadata_cleanup=True)
            if approved.entries != before.entries or approved.identity != before.identity:
                raise SourceChanged('Folder changed before archiving')
            for path, name in approved.removable_xattrs:
                try:
                    macos.removexattr(source_parent / path, name)
                except OSError as exc:
                    raise Unsupported(f'Could not remove unsupported extended attribute {render(name)} '
                                      f'from {render(str(folder.parent / path))}: {exc}') from exc
                ui.warn(f'Removed unsupported extended attribute {render(name)} '
                        f'from {render(str(folder.parent / path))}')
            if approved.removable_xattrs:
                cleaned = scan(staged, exclude_root_names=excluded)
                if cleaned.entries != approved.entries or cleaned.identity != approved.identity:
                    raise SourceChanged('Folder changed during metadata cleanup; plaintext retained')
                approved = cleaned
            (work / METADATA).write_bytes(metadata(folder.name, approved.entries, secret))
            candidate = work / (crypto.random_id() + '.7z')
            while candidate.exists():
                candidate = work / (crypto.random_id() + '.7z')
            exclusions = [f'-x!{folder.name}/{archive.name}'] if preserve_root else []
            run7z(['a', '-t7z', '-p', '-mhe=on', '-ms=on', '-mx=5', '-sse', '-spd', *exclusions, '--',
                   str(candidate), str(staged), METADATA], secret, cwd=work, creating=True)
            checked, _, entries = extract_verified(candidate, secret, work)
            shutil.rmtree(checked)
            after = scan(staged, exclude_root_names=excluded)
            if after.entries != approved.entries or after.identity != approved.identity or entries != approved.entries:
                raise SourceChanged('Folder changed during archiving; plaintext retained')
            candidate = bundle.write(candidate, secret, outer_password, key_password, kdf, work, ui)
            os.chmod(candidate, 0o600)
            with candidate.open('rb') as f:
                durable.full_sync(f.fileno())
            if archive_before is None:
                macos.rename_exclusive(candidate, archive)
            else:
                if not os.path.lexists(archive) or tree._identity(archive.lstat()) != tree._identity(archive_before):
                    raise SourceChanged('Existing archive changed during encryption; plaintext retained')
                os.replace(candidate, archive)
            try:
                durable.sync_dir(archive.parent)
            except Exception as exc:
                raise CommitUncertain('Bundle published but directory flush failed; publication is uncertain. '
                                      'Plaintext and staging were retained.') from exc
            if keep:
                if not preserve_root:
                    macos.rename_exclusive(staged, folder)
                durable.sync_dir(folder.parent)
            else:
                # Recheck after the durability barrier, before deleting anything.
                final = scan(staged, exclude_root_names=excluded)
                if final.entries != approved.entries or final.identity != approved.identity:
                    raise SourceChanged('Folder changed after archive publication; plaintext retained')
                deleting = True
                for e in approved.entries:
                    if e.is_file:
                        path = source_parent / e.path
                        digest, st = tree.hash_file(path)
                        if digest != e.sha256 or tree._identity(st) != approved.identity[e.path]:
                            raise SourceChanged('A file changed during cleanup; remaining plaintext retained')
                        path.unlink()
                for e in reversed(approved.entries):
                    if e.kind == 'dir' and not (preserve_root and e.path == folder.name):
                        (source_parent / e.path).rmdir()
                if preserve_root:
                    if any(child.name not in excluded for child in folder.iterdir()):
                        raise SourceChanged('New files appeared during cleanup; remaining plaintext retained'
                                            ' in the current directory')
                    durable.sync_dir(folder)
                durable.sync_dir(folder.parent)
            ui.info(f'Encrypted and verified: {render(str(archive))}')
            finished = True
            return archive
        finally:
            retain_candidate = not finished
            if retain_candidate:
                ui.warn(f'Preserve failed bundle staging in {render(str(work))} before retrying.')
            if preserve_root:
                # The shell's working directory must retain its original inode.
                # Only scratch copies are inside work in this mode.
                if not retain_candidate:
                    shutil.rmtree(work)
            elif staged.exists():
                if not deleting and not os.path.lexists(folder):
                    macos.rename_exclusive(staged, folder)
                else:
                    ui.warn(f'Plaintext remains in {render(str(staged))}; preserve it before retrying.')
            if not preserve_root and not staged.exists() and not retain_candidate:
                shutil.rmtree(work)


def decrypt(archive: Path, secret: bytes, ui: UI, *, opened: "Opened", verify_only: bool = False,
            preserve_root: bool = False) -> Path:
    from . import bundle
    archive = location(archive)
    if archive.suffix != '.7z':
        archive = archive.with_name(archive.name + '.7z')
    with archive_lock(archive):
        # Keep scratch data outside an in-place destination so that its only
        # existing child may be the encrypted archive itself.
        inside = archive_names.inside(archive)
        work, root, entries = bundle.verified(
            opened, secret, archive.parent.parent if inside else archive.parent)
        inside = inside and archive.parent.name == root
        target = archive.parent if inside else archive.parent / root
        restore_in_place = preserve_root or inside
        try:
            if not verify_only:
                if restore_in_place:
                    if (preserve_root and target != Path.cwd()) or target.is_symlink() or not target.is_dir():
                        raise UsageError('Archive does not belong to the current directory')
                    if any(child != archive for child in target.iterdir()):
                        raise UsageError('Destination contains files other than its archive; nothing was overwritten')
                    if inside and any(e.path == f'{root}/{archive.name}' for e in entries):
                        raise UsageError('Archive contains a document with the archive’s own name; nothing was overwritten')
                    if macos.has_extended_acl(target):
                        raise Unsupported('Destination directory has an ACL')
                elif os.path.lexists(target):
                    raise UsageError(f'Destination already exists; nothing was overwritten: {render(str(target))}')
                for e in entries:
                    if e.is_file:
                        with (work / 'extracted' / e.path).open('rb') as f:
                            durable.full_sync(f.fileno())
                for e in reversed(entries):
                    if e.kind == 'dir':
                        durable.sync_dir(work / 'extracted' / e.path)
                if restore_in_place:
                    # Publish beside the archive, using exclusive moves for
                    # every top-level item to protect concurrent files.
                    for child in (work / 'extracted' / root).iterdir():
                        macos.rename_exclusive(child, target / child.name)
                    tree.apply_metadata(target, entries[0])
                    durable.sync_dir(target)
                else:
                    macos.rename_exclusive(work / 'extracted' / root, target)
                durable.sync_dir(target.parent)
                ui.info(f'Decrypted: {render(str(target))}; archive retained.')
            else:
                ui.info(f'Archive verified: {render(str(archive))}')
            return target
        finally:
            shutil.rmtree(work)
