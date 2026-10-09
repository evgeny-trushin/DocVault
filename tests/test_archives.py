"""Real 7z round trips and failure paths guarding plaintext and the shared key."""

import os
from pathlib import Path
import subprocess

import pytest

from docvault import archive, archive_cli, bundle, crypto, durable, keyfile, macos
from docvault.errors import CommitUncertain, IntegrityError, SourceChanged, Unsupported, UsageError, WrongPassword
from .conftest import OUTER, PASSWORD, write


def encrypt(folder, key, secret, ui, **options):
    return archive.encrypt(folder, key, secret, ui, outer_password=OUTER,
                           key_password=PASSWORD, kdf=crypto.KdfParams.from_profile('moderate'), **options)


def decrypt(output, key, secret, ui, **options):
    parent = output.parent.parent if output.name == output.parent.name + '.7z' else output.parent
    opened = bundle.read(output, OUTER, parent, ui)
    try:
        assert opened.unlock(PASSWORD, ui) == secret
        return archive.decrypt(output, secret, ui, opened=opened, **options)
    finally:
        opened.close()


def inner_listing(output, secret, ui):
    parent = output.parent.parent if output.name == output.parent.name + '.7z' else output.parent
    opened = bundle.read(output, OUTER, parent, ui)
    try:
        return archive.listing(opened.inner, secret)
    finally:
        opened.close()


@pytest.fixture
def archive_key(tmp_path):
    key = tmp_path / 'private keys' / 'key'
    keyfile.create(key, PASSWORD, 'interactive')
    return key, keyfile.open_key(key, PASSWORD)


def test_solid_archive_headers_metadata_and_round_trip(tmp_path, archive_key, ui):
    key, secret = archive_key
    folder = tmp_path / 'Documents with spaces'
    first = write(folder / 'identity.pdf', b'private data' * 100)
    write(folder / 'nested/empty.txt', b'')
    write(folder / '.DS_Store', b'finder data')
    (folder / 'empty directory').mkdir()
    os.chmod(first, 0o600)
    os.utime(first, ns=(1234567890123456789, 1234567890123456789))
    macos.setxattr(first, 'com.apple.metadata:_kMDItemUserTags', b'example tag')
    expected = archive.scan(folder).entries
    encrypted = encrypt(folder, key, secret, ui)
    assert encrypted.name == folder.name + '.7z'
    assert not folder.exists()
    assert encrypted.stat().st_mode & 0o777 == 0o600
    assert b'identity.pdf' not in encrypted.read_bytes()
    opened = bundle.read(encrypted, OUTER, tmp_path, ui)
    try:
        listing = archive.run7z(['l', '-slt', '--', str(opened.inner)], secret)
    finally:
        opened.close()
    assert 'Solid = +' in listing
    assert '7zAES' in listing
    assert secret.hex().encode() not in key.read_bytes()
    decrypt(encrypted, key, secret, ui)
    assert archive.scan(folder).entries == expected
    assert encrypted.exists()
    write(folder / 'another.txt', 'new content')
    encrypt(folder, key, secret, ui)
    decrypt(encrypted, key, secret, ui)
    assert (folder / 'another.txt').read_text() == 'new content'


@pytest.mark.parametrize('preserve_root', [False, True])
@pytest.mark.parametrize('keep', [False, True])
def test_unsupported_apple_metadata_is_removed_before_7z(tmp_path, archive_key, ui, monkeypatch,
                                                       preserve_root, keep):
    key, secret = archive_key
    folder = tmp_path / 'Documents with spaces'
    document = write(folder / 'nested/file', 'private contents')
    paths = [folder, document.parent, document]
    unwanted = ['com.apple.metadata:kMDItemComment', 'com.apple.metadata:custom']
    for path in paths:
        for name in unwanted:
            macos.setxattr(path, name, b'optional metadata')
    preserved = {
        'com.apple.metadata:_kMDItemUserTags': b'example tag',
        'com.apple.metadata:kMDItemWhereFroms': b'download information',
        'com.apple.metadata:kMDItemDownloadedDate': b'download date',
        'com.apple.quarantine': b'0081;12345678;DocVault;',
    }
    for name, value in preserved.items():
        macos.setxattr(document, name, value)
    macos.set_backup_excluded(folder)
    if preserve_root:
        monkeypatch.chdir(folder)
    with pytest.raises(Unsupported, match='unsupported extended attribute'):
        archive.scan(folder)
    expected = archive.scan(folder, allow_metadata_cleanup=True).entries
    # Both kinds of scan are read-only; encryption performs the cleanup.
    assert all(set(unwanted) <= set(macos.listxattr(path)) for path in paths)
    original_run = archive.run7z
    creations = []

    def observe(args, *a, **kw):
        if args[0] == 'a' and archive.METADATA in args:
            staged = Path(args[-2])
            creations.append(staged)
            for path in (staged, staged / 'nested', staged / 'nested/file'):
                assert not set(unwanted) & set(macos.listxattr(path))
        return original_run(args, *a, **kw)

    monkeypatch.setattr(archive, 'run7z', observe)
    encrypted = encrypt(folder, key, secret, ui, preserve_root=preserve_root, keep=keep)
    assert len(creations) == 1
    for path in paths:
        for name in unwanted:
            assert any(name in warning and str(path) in warning for warning in ui.warnings)
    if not keep:
        assert not document.exists()
        decrypt(encrypted, key, secret, ui, preserve_root=preserve_root)
    excluded = frozenset({encrypted.name}) if preserve_root else frozenset()
    assert archive.scan(folder, exclude_root_names=excluded).entries == expected
    assert document.read_text() == 'private contents'
    assert all(not set(unwanted) & set(macos.listxattr(path)) for path in paths)
    assert all(macos.getxattr(document, name) == value for name, value in preserved.items())
    assert macos.has_own_backup_exclusion(folder)


@pytest.mark.parametrize('kind', ['unsupported-xattr', 'hardlink', 'symlink'])
def test_metadata_cleanup_waits_for_source_validation(tmp_path, archive_key, ui, kind):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    name = 'com.apple.metadata:custom'
    macos.setxattr(original, name, b'optional metadata')
    if kind == 'unsupported-xattr':
        macos.setxattr(original, 'com.example.unsupported', b'important data')
    elif kind == 'hardlink':
        os.link(original, tmp_path / 'outside')
    else:
        (folder / 'link').symlink_to(original)
    with pytest.raises(Unsupported):
        encrypt(folder, key, secret, ui)
    assert macos.getxattr(original, name) == b'optional metadata'
    assert original.read_text() == 'original'
    assert not (tmp_path / 'docs.7z').exists()


def test_metadata_removal_failure_stops_before_7z(tmp_path, archive_key, ui, monkeypatch):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    name = 'com.apple.metadata:custom'
    macos.setxattr(original, name, b'optional metadata')

    def fail(*a, **kw):
        raise PermissionError('attribute removal denied')

    monkeypatch.setattr(macos, 'removexattr', fail)
    monkeypatch.setattr(archive, 'run7z', lambda *a, **kw: pytest.fail('7z ran before cleanup'))
    with pytest.raises(Unsupported, match='Could not remove unsupported extended attribute'):
        encrypt(folder, key, secret, ui)
    assert original.read_text() == 'original'
    assert macos.getxattr(original, name) == b'optional metadata'
    assert not (tmp_path / 'docs.7z').exists()


def test_source_changed_during_metadata_cleanup_is_retained(tmp_path, archive_key, ui, monkeypatch):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    macos.setxattr(original, 'com.apple.metadata:custom', b'optional metadata')
    remove = macos.removexattr

    def mutate(path, name):
        remove(path, name)
        write(Path(path), 'changed during cleanup')

    monkeypatch.setattr(macos, 'removexattr', mutate)
    monkeypatch.setattr(archive, 'run7z', lambda *a, **kw: pytest.fail('7z ran after source changed'))
    with pytest.raises(SourceChanged, match='during metadata cleanup'):
        encrypt(folder, key, secret, ui)
    assert original.read_text() == 'changed during cleanup'
    assert not (tmp_path / 'docs.7z').exists()


def test_one_key_for_two_archives_and_local_password_rotation(tmp_path, archive_key, ui):
    key, secret = archive_key
    files = []
    for name in ('first', 'second'):
        folder = tmp_path / name
        write(folder / 'file.txt', name)
        files.append(encrypt(folder, key, secret, ui))
    before = [f.read_bytes() for f in files]
    replacement = b'a different long local password'
    keyfile.change_password(key, PASSWORD, replacement)
    with pytest.raises(WrongPassword):
        keyfile.open_key(key, PASSWORD)
    assert keyfile.open_key(key, replacement) == secret
    assert [f.read_bytes() for f in files] == before
    for f in files:
        target = decrypt(f, key, secret, ui)
        assert (target / 'file.txt').read_text() == target.name


def test_keep_option_and_decrypt_refuses_existing_destination(tmp_path, archive_key, ui):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'preserve me')
    encrypted = encrypt(folder, key, secret, ui, keep=True)
    assert original.read_text() == 'preserve me'
    with pytest.raises(UsageError, match='already exists'):
        decrypt(encrypted, key, secret, ui)
    assert original.read_text() == 'preserve me'
    decrypt(encrypted, key, secret, ui, verify_only=True)
    assert original.exists()


@pytest.mark.parametrize('failure', ['create', 'verify', 'flush'])
def test_failure_preserves_original_folder_and_prior_archive(tmp_path, archive_key, ui, monkeypatch, failure):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    write(folder / 'file', 'old content')
    encrypted = encrypt(folder, key, secret, ui, keep=True)
    old = encrypted.read_bytes()
    write(folder / 'file', 'new content')
    original_run = archive.run7z
    calls = []

    def fail(args, *rest, **kwargs):
        calls.append(args)
        if (failure == 'create' and args[0] == 'a') or (failure == 'verify' and args[0] == 't' and
                '.docvault-7z-' in args[-1] and sum(c[0] == 'a' for c in calls)):
            raise IntegrityError('injected 7z failure')
        return original_run(args, *rest, **kwargs)

    monkeypatch.setattr(archive, 'run7z', fail)
    if failure == 'flush':
        monkeypatch.setattr(durable, 'full_sync', lambda *a, **k: (_ for _ in ()).throw(OSError('flush failed')))
    with pytest.raises((IntegrityError, OSError)):
        encrypt(folder, key, secret, ui)
    assert (folder / 'file').read_text() == 'new content'
    assert encrypted.read_bytes() == old


def test_source_changed_during_compression_is_retained(tmp_path, archive_key, ui, monkeypatch):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original')
    original_run = archive.run7z

    def mutate(args, *rest, **kwargs):
        result = original_run(args, *rest, **kwargs)
        if args[0] == 'a':
            write(kwargs['cwd'] / 'docs/new.txt', 'appeared during compression')
        return result

    monkeypatch.setattr(archive, 'run7z', mutate)
    with pytest.raises(SourceChanged):
        encrypt(folder, key, secret, ui)
    assert (folder / 'file').read_text() == 'original'
    assert (folder / 'new.txt').exists()
    assert not (tmp_path / 'docs.7z').exists()


def test_source_changed_after_publication_is_retained(tmp_path, archive_key, ui, monkeypatch):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original')
    original_sync = durable.sync_dir

    def mutate(path, **kwargs):
        result = original_sync(path, **kwargs)
        if Path(path) == tmp_path and (tmp_path / 'docs.7z').exists():
            staged = next(tmp_path.glob('.docvault-7z-*/docs'))
            write(staged / 'file', 'changed after publication')
        return result

    monkeypatch.setattr(durable, 'sync_dir', mutate)
    with pytest.raises(SourceChanged):
        encrypt(folder, key, secret, ui)
    assert (folder / 'file').read_text() == 'changed after publication'
    assert (tmp_path / 'docs.7z').exists()


def test_durability_failure_after_publication_preserves_plaintext(tmp_path, archive_key, ui, monkeypatch):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original')
    original_sync = durable.sync_dir

    def fail(path, **kwargs):
        if Path(path) == tmp_path and (tmp_path / 'docs.7z').exists():
            raise OSError('publication sync failed')
        return original_sync(path, **kwargs)

    monkeypatch.setattr(durable, 'sync_dir', fail)
    with pytest.raises(CommitUncertain):
        encrypt(folder, key, secret, ui)
    assert (folder / 'file').read_text() == 'original'
    assert (tmp_path / 'docs.7z').exists()


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'unsupported-xattr', 'newline', 'key-inside'])
def test_unsupported_source_is_never_deleted(tmp_path, archive_key, ui, kind):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    if kind == 'symlink':
        (folder / 'link').symlink_to(original)
    elif kind == 'hardlink':
        os.link(original, folder / 'link')
    elif kind == 'unsupported-xattr':
        macos.setxattr(original, 'com.example.unsupported', b'data')
    elif kind == 'newline':
        write(folder / 'bad\nname', 'data')
    else:
        key = folder / 'private/key'
    with pytest.raises((Unsupported, UsageError)):
        encrypt(folder, key, secret, ui)
    assert original.read_text() == 'original'
    assert not (tmp_path / 'docs.7z').exists()


def test_unrelated_archive_not_replaced(tmp_path, archive_key, ui):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    prior = write(tmp_path / 'docs.7z', 'unrelated file')
    with pytest.raises(IntegrityError):
        encrypt(folder, key, secret, ui)
    assert prior.read_text() == 'unrelated file'
    assert original.read_text() == 'original'


def test_tampered_archive_metadata_rejected(tmp_path, archive_key, ui):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original')
    encrypted = encrypt(folder, key, secret, ui)
    work = tmp_path / 'tamper'
    work.mkdir()
    data = archive.metadata('docs', [], secret).replace(b'"root":"docs"', b'"root":"evil"')
    write(work / archive.METADATA, data)
    write(work / 'docs/file', 'tampered')
    replacement = tmp_path / 'bad.7z'
    archive.run7z(['a', '-p', '-mhe=on', '-ms=on', '--', str(replacement), 'docs', archive.METADATA],
                  secret, cwd=work, creating=True)
    with pytest.raises(IntegrityError, match='authentication'):
        archive.extract_verified(replacement, secret, tmp_path)
    assert not folder.exists()
    assert encrypted.exists()


@pytest.mark.parametrize('path', ['../outside', '/absolute', 'docs/../escape', 'docs\\escape', 'docs/file\nPath = bad'])
def test_listing_rejects_unsafe_paths_before_extraction(tmp_path, monkeypatch, path):
    listing = '\nType = 7z\n----------\nPath = ' + path + '\nSize = 1\nAttributes = A -rw-------\nEncrypted = +\n'
    monkeypatch.setattr(archive, 'run7z', lambda *a, **k: listing)
    with pytest.raises((IntegrityError, Unsupported)):
        archive.listing(tmp_path / 'bad.7z', b'x' * 32)


def test_no_archive_password_in_process_arguments(tmp_path, archive_key, ui, monkeypatch):
    key, secret = archive_key
    original = subprocess.run
    observed = []

    def capture(args, **kwargs):
        observed.append(args)
        return original(args, **kwargs)

    monkeypatch.setattr(archive.subprocess, 'run', capture)
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original')
    encrypted = encrypt(folder, key, secret, ui)
    decrypt(encrypted, key, secret, ui)
    assert observed
    assert all(secret.hex() not in ' '.join(args) for args in observed)
    assert all(PASSWORD.decode() not in ' '.join(args) for args in observed)


def test_wrong_local_password_changes_nothing(tmp_path, archive_key, ui):
    key, _ = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    ui.pw = b'wrong local password'
    assert archive_cli.run(['encrypt', str(folder), '--key', str(key)], ui) == WrongPassword.exit_code
    assert original.read_text() == 'original'
    assert not (tmp_path / 'docs.7z').exists()


def test_key_create_refuses_existing_and_change_refuses_wrong_password(archive_key):
    key, secret = archive_key
    before = key.read_bytes()
    with pytest.raises(UsageError):
        keyfile.create(key, PASSWORD)
    with pytest.raises(WrongPassword):
        keyfile.change_password(key, b'wrong', b'new')
    assert key.read_bytes() == before
    assert keyfile.open_key(key, PASSWORD) == secret


def test_metadata_limit_and_checksums(archive_key):
    _, secret = archive_key
    with pytest.raises(IntegrityError):
        archive.parse_metadata(archive.metadata('docs', [], secret), secret)
    with pytest.raises(IntegrityError):
        archive.parse_metadata(archive.metadata('docs', [], secret), crypto.random_key())


def test_new_archive_created_concurrently_is_not_overwritten(tmp_path, archive_key, ui, monkeypatch):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original')
    original_sync = durable.full_sync

    def appear(fd, **kwargs):
        result = original_sync(fd, **kwargs)
        write(tmp_path / 'docs.7z', 'a concurrent unrelated archive')
        return result

    monkeypatch.setattr(durable, 'full_sync', appear)
    with pytest.raises(FileExistsError):
        encrypt(folder, key, secret, ui)
    assert (folder / 'file').read_text() == 'original'
    assert (tmp_path / 'docs.7z').read_text() == 'a concurrent unrelated archive'


def test_modified_file_during_partial_cleanup_is_retained(tmp_path, archive_key, ui, monkeypatch):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    write(folder / 'a', 'first original')
    write(folder / 'b', 'second original')
    original_unlink = Path.unlink

    def mutate(path, *args, **kwargs):
        original_unlink(path, *args, **kwargs)
        if path.name == 'a' and path.parent.name == 'docs' and '.docvault-7z-' in str(path):
            write(path.parent / 'b', 'new unsaved content')

    monkeypatch.setattr(Path, 'unlink', mutate)
    with pytest.raises(SourceChanged):
        encrypt(folder, key, secret, ui)
    staged = next(tmp_path.glob('.docvault-7z-*/docs'))
    assert (staged / 'b').read_text() == 'new unsaved content'
    assert ui.warnings and str(staged) in ui.warnings[-1]
    # Restoring the verified archive recovers originals alongside the preserved change.
    decrypt(tmp_path / 'docs.7z', key, secret, ui)
    assert (folder / 'a').read_text() == 'first original'
    assert (folder / 'b').read_text() == 'second original'
    assert (staged / 'b').read_text() == 'new unsaved content'


def test_workspace_acl_is_rejected_before_plaintext_moves(tmp_path, archive_key, ui, monkeypatch):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    original_acl = macos.has_extended_acl
    monkeypatch.setattr(macos, 'has_extended_acl', lambda p: Path(p).name.startswith('.docvault-7z-') or original_acl(p))
    with pytest.raises(Unsupported, match='inherited an ACL'):
        encrypt(folder, key, secret, ui)
    assert original.read_text() == 'original'
    assert not list(tmp_path.glob('.docvault-7z-*'))


@pytest.mark.parametrize('operation', ['create', 'open', 'passwd'])
def test_key_symlink_is_refused_without_changing_target(tmp_path, archive_key, operation):
    key, secret = archive_key
    default = tmp_path / 'system-bin/key'
    default.parent.mkdir()
    default.symlink_to(key)
    original = key.read_bytes()
    with pytest.raises(Unsupported, match='regular file'):
        if operation == 'create':
            keyfile.create(default, PASSWORD)
        elif operation == 'open':
            keyfile.open_key(default, PASSWORD)
        else:
            keyfile.change_password(default, PASSWORD, b'another long local password')
    assert default.is_symlink()
    assert key.read_bytes() == original
    assert keyfile.open_key(key, PASSWORD) == secret


def test_folder_named_like_an_archive_round_trips(tmp_path, archive_key, ui):
    key, secret = archive_key
    folder = tmp_path / 'candidate.7z'
    write(folder / 'file', 'ordinary folder despite its suffix')
    encrypted = encrypt(folder, key, secret, ui)
    assert encrypted.name == 'candidate.7z.7z'
    decrypt(encrypted, key, secret, ui)
    assert (folder / 'file').read_text() == 'ordinary folder despite its suffix'


def test_no_arguments_use_cwd_and_default_key_without_changing_directory_inode(tmp_path, archive_key, ui, monkeypatch):
    key, _ = archive_key
    monkeypatch.setattr(keyfile, 'DEFAULT_KEY', key)
    folder = tmp_path / 'current documents'
    write(folder / 'document', 'private contents')
    write(folder / 'nested/file', 'nested contents')
    monkeypatch.chdir(folder)
    inode = folder.stat().st_ino
    assert archive_cli.run(['encrypt'], ui) == 0, ui.text
    assert Path.cwd() == folder
    assert folder.stat().st_ino == inode
    encrypted = folder / (folder.name + '.7z')
    assert list(folder.iterdir()) == [encrypted]
    assert not folder.with_name(folder.name + '.7z').exists()
    assert archive_cli.run(['decrypt'], ui) == 0, ui.text
    assert Path.cwd() == folder
    assert folder.stat().st_ino == inode
    assert (folder / 'document').read_text() == 'private contents'
    assert (folder / 'nested/file').read_text() == 'nested contents'
    # Updates follow the same argument-free workflow.
    write(folder / 'document', 'updated contents')
    assert archive_cli.run(['encrypt'], ui) == 0, ui.text
    assert archive_cli.run(['decrypt'], ui) == 0, ui.text
    assert (folder / 'document').read_text() == 'updated contents'


def test_default_decrypt_never_overwrites_current_directory_contents(tmp_path, archive_key, ui, monkeypatch):
    key, _ = archive_key
    monkeypatch.setattr(keyfile, 'DEFAULT_KEY', key)
    folder = tmp_path / 'docs'
    write(folder / 'file', 'original')
    monkeypatch.chdir(folder)
    assert archive_cli.run(['encrypt'], ui) == 0, ui.text
    sentinel = write(folder / 'file', 'new content')
    assert archive_cli.run(['decrypt'], ui) == UsageError.exit_code
    assert sentinel.read_text() == 'new content'


@pytest.mark.parametrize('name', ['docs', 'docs ? [x]*'])
def test_in_place_archive_excludes_only_itself_on_repeated_encryption(tmp_path, archive_key, ui, monkeypatch, name):
    key, secret = archive_key
    folder = tmp_path / name
    encrypted = folder / (name + '.7z')
    nested = write(folder / 'nested' / encrypted.name, 'ordinary nested archive document')
    write(folder / 'file', 'original')
    monkeypatch.chdir(folder)
    for version in ('original', 'updated'):
        write(folder / 'file', version)
        assert encrypt(folder, key, secret, ui, preserve_root=True) == encrypted
        assert list(folder.iterdir()) == [encrypted]
        members = inner_listing(encrypted, secret, ui)
        assert f'{name}/{encrypted.name}' not in members
        assert f'{name}/nested/{encrypted.name}' in members
        assert decrypt(encrypted, key, secret, ui, preserve_root=True) == folder
        assert nested.read_text() == 'ordinary nested archive document'
        assert (folder / 'file').read_text() == version
        assert encrypted.exists()


@pytest.mark.parametrize('kind', ['file', 'directory', 'symlink'])
def test_in_place_encryption_refuses_conflicting_archive_name(tmp_path, archive_key, ui, kind):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'keep plaintext')
    conflict = folder / 'docs.7z'
    if kind == 'file':
        conflict.write_text('unrelated existing data')
    elif kind == 'directory':
        write(conflict / 'file', 'unrelated existing data')
    else:
        conflict.symlink_to(original)
    with pytest.raises((IntegrityError, Unsupported, OSError)):
        encrypt(folder, key, secret, ui, preserve_root=True)
    assert original.read_text() == 'keep plaintext'
    if kind == 'file':
        assert conflict.read_text() == 'unrelated existing data'
    elif kind == 'directory':
        assert (conflict / 'file').read_text() == 'unrelated existing data'
    else:
        assert conflict.is_symlink()


def test_failed_in_place_update_retains_old_archive_and_updated_plaintext(tmp_path, archive_key, ui, monkeypatch):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    encrypted = encrypt(folder, key, secret, ui, preserve_root=True)
    decrypt(encrypted, key, secret, ui)
    old_bytes = encrypted.read_bytes()
    original.write_text('updated')
    original_run = archive.run7z

    def fail(args, *rest, **kwargs):
        if args[0] == 'a':
            raise IntegrityError('injected compression failure')
        return original_run(args, *rest, **kwargs)

    monkeypatch.setattr(archive, 'run7z', fail)
    with pytest.raises(IntegrityError, match='injected'):
        encrypt(folder, key, secret, ui, preserve_root=True)
    assert encrypted.read_bytes() == old_bytes
    assert original.read_text() == 'updated'


def test_explicit_in_place_archive_path_restores_beside_archive(tmp_path, archive_key, ui):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    encrypted = encrypt(folder, key, secret, ui, preserve_root=True)
    assert decrypt(encrypted, key, secret, ui) == folder
    assert original.read_text() == 'original'
    assert encrypted.exists()
    assert not (folder / folder.name).exists()


def test_repeated_encryption_of_archive_only_folder_retains_documents(tmp_path, archive_key, ui):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    encrypted = encrypt(folder, key, secret, ui, preserve_root=True)
    encrypted_bytes = encrypted.read_bytes()
    assert encrypt(folder, key, secret, ui, preserve_root=True) == encrypted
    assert encrypted.read_bytes() == encrypted_bytes
    decrypt(encrypted, key, secret, ui)
    assert original.read_text() == 'original'


def test_sibling_bundle_can_be_moved_inside_for_default_decryption(tmp_path, archive_key, ui, monkeypatch):
    key, _ = archive_key
    monkeypatch.setattr(keyfile, 'DEFAULT_KEY', key)
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    assert archive_cli.run(['encrypt', str(folder)], ui) == 0, ui.text
    folder.mkdir()
    folder.with_name('docs.7z').rename(folder / 'docs.7z')
    monkeypatch.chdir(folder)
    assert archive_cli.run(['decrypt'], ui) == 0, ui.text
    assert original.read_text() == 'original'


def test_moved_bundle_refuses_to_restore_over_itself(tmp_path, archive_key, ui):
    key, secret = archive_key
    folder = tmp_path / 'docs'
    write(folder / 'another-file', 'original')
    write(folder / 'docs.7z', 'ordinary document with the bundle name')
    encrypted = encrypt(folder, key, secret, ui)
    folder.mkdir()
    encrypted = encrypted.rename(folder / encrypted.name)
    encrypted_bytes = encrypted.read_bytes()
    with pytest.raises(UsageError, match='own name'):
        decrypt(encrypted, key, secret, ui)
    assert list(folder.iterdir()) == [encrypted]
    assert encrypted.read_bytes() == encrypted_bytes


def test_current_directory_named_with_7z_suffix_round_trips(tmp_path, archive_key, ui, monkeypatch):
    key, _ = archive_key
    monkeypatch.setattr(keyfile, 'DEFAULT_KEY', key)
    folder = tmp_path / 'docs.7z'
    write(folder / 'file', 'original')
    monkeypatch.chdir(folder)
    assert archive_cli.run(['encrypt'], ui) == 0, ui.text
    assert (folder / 'docs.7z.7z').is_file()
    assert archive_cli.run(['decrypt'], ui) == 0, ui.text
    assert (folder / 'file').read_text() == 'original'


def test_current_directory_compression_failure_preserves_plaintext_and_inode(tmp_path, archive_key, ui, monkeypatch):
    key, _ = archive_key
    monkeypatch.setattr(keyfile, 'DEFAULT_KEY', key)
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    monkeypatch.chdir(folder)
    inode = folder.stat().st_ino
    original_run = archive.run7z

    def fail(args, *rest, **kwargs):
        if args[0] == 'a':
            raise IntegrityError('injected compression failure')
        return original_run(args, *rest, **kwargs)

    monkeypatch.setattr(archive, 'run7z', fail)
    assert archive_cli.run(['encrypt'], ui) == IntegrityError.exit_code
    assert original.read_text() == 'original'
    assert folder.stat().st_ino == inode
    assert not (folder / (folder.name + '.7z')).exists()
    assert 'Preserve failed bundle staging' in ui.text


def test_new_file_during_current_directory_cleanup_is_preserved_and_reported(tmp_path, archive_key, ui, monkeypatch):
    key, _ = archive_key
    monkeypatch.setattr(keyfile, 'DEFAULT_KEY', key)
    folder = tmp_path / 'docs'
    original = write(folder / 'file', 'original')
    monkeypatch.chdir(folder)
    original_unlink = Path.unlink

    def appear(path, *args, **kwargs):
        original_unlink(path, *args, **kwargs)
        if path == original:
            write(folder / 'new-file', 'new unarchived plaintext')

    monkeypatch.setattr(Path, 'unlink', appear)
    assert archive_cli.run(['encrypt'], ui) == SourceChanged.exit_code
    assert (folder / 'new-file').read_text() == 'new unarchived plaintext'
    assert 'current directory' in ui.warnings[-1]
    assert (folder / (folder.name + '.7z')).exists()
    assert archive_cli.run(['verify'], ui) == 0, ui.text
