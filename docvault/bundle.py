"""Version 1 encrypted recovery bundles. One wrapper, two independent passwords."""

from dataclasses import dataclass
from collections.abc import Callable
import hashlib
import hmac
import os
from pathlib import Path
import shutil
import stat
import struct
import zlib

import nacl.exceptions
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt as aead_encrypt
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as aead_decrypt

from . import archive, crypto, durable, limits, passwords, strictjson as sj, tree
from .errors import IntegrityError, UsageError, WrongPassword, SourceChanged, CommitUncertain
from .ui import UI

FORMAT = 'docvault-7z-recovery'
KEY_LIMIT = 16 * 1024
ALLOWANCE = 1024 * 1024
OUTER_SALT = hashlib.sha256(b'DOCVAULT-7Z-OUTER-v1').digest()[:16]
OUTER_KDF = crypto.KdfParams(3, 256 << 20, OUTER_SALT)


def derive_outer(password: bytes) -> bytes:
    passwords.text(password)
    return crypto.derive_wrapping_key(password, OUTER_KDF)


def raised_costs(kdf: crypto.KdfParams) -> crypto.KdfParams:
    return crypto.KdfParams(max(3, kdf.opslimit), max(256 << 20, kdf.memlimit), os.urandom(16))


def disk_space(parent: Path, required: int):
    if shutil.disk_usage(parent).free < required + ALLOWANCE:
        raise UsageError('Insufficient disk space for staging and verification; originals were retained')


def freeze(source: Path, target: Path, maximum: int) -> os.stat_result:
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise IntegrityError('Archive must be a regular file within the encrypted size limit')
        disk_space(target.parent, before.st_size)
        with os.fdopen(os.dup(fd), 'rb') as src, target.open('xb') as dst:
            os.chmod(target, 0o600)
            total = 0
            while chunk := src.read(min(1024 * 1024, maximum + 1 - total)):
                total += len(chunk)
                if total > maximum:
                    raise IntegrityError('Encrypted archive exceeds size limit')
                dst.write(chunk)
        if total != before.st_size or tree._identity(os.fstat(fd)) != tree._identity(before):
            raise SourceChanged('Archive changed while freezing its bytes')
        return before
    finally:
        os.close(fd)


def digest(path: Path) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    with path.open('rb') as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
            size += len(chunk)
            if size > 2 * limits.MAX_TOTAL_SIZE:
                raise IntegrityError('Inner archive exceeds size limit')
    return h.hexdigest(), size


@dataclass(frozen=True)
class Envelope:
    archive_sha256: str
    archive_bytes: int
    envelope_id: str
    kdf: crypto.KdfParams
    nonce: bytes
    wrapped_secret: bytes

    def body(self):
        return dict(format=FORMAT, version=1, archive_sha256=self.archive_sha256,
                    archive_bytes=self.archive_bytes, envelope_id=self.envelope_id, kdf=self.kdf.to_json())

    def aad(self):
        return b'DOCVAULT-7Z-RECOVERY\0' + sj.dumps(self.body())

    def encode(self):
        return sj.dumps(dict(self.body(), nonce=self.nonce.hex(), wrapped_secret=self.wrapped_secret.hex())) + b'\n'

    @classmethod
    def parse(cls, data: bytes):
        obj = sj.loads(data, max_bytes=KEY_LIMIT, what='embedded key')
        sj.require_object(obj, {'format', 'version', 'archive_sha256', 'archive_bytes',
                                'envelope_id', 'kdf', 'nonce', 'wrapped_secret'}, 'embedded key')
        sj.require_header(obj, FORMAT, 1, 'embedded key')
        return cls(sj.require_hex(obj['archive_sha256'], 'archive_sha256', 32).hex(),
                   sj.require_int(obj['archive_bytes'], 'archive_bytes', 1, 2 * limits.MAX_TOTAL_SIZE),
                   sj.require_id(obj['envelope_id'], 'envelope_id'), crypto.KdfParams.from_json(obj['kdf']),
                   sj.require_hex(obj['nonce'], 'nonce', crypto.NONCE_BYTES),
                   sj.require_hex(obj['wrapped_secret'], 'wrapped_secret', crypto.WRAPPED_BYTES))

    def open(self, password: bytes) -> bytes:
        passwords.text(password)
        wrapping = crypto.derive_wrapping_key(password, self.kdf)
        try:
            return aead_decrypt(self.wrapped_secret, self.aad(), self.nonce, wrapping)
        except nacl.exceptions.CryptoError:
            raise WrongPassword('wrong local 7z key password or damaged embedded key') from None


def seal(inner: Path, secret: bytes, password: bytes, kdf: crypto.KdfParams) -> Envelope:
    passwords.text(password)
    if len(secret) != 32:
        raise UsageError('Invalid archive secret')
    sha, size = digest(inner)
    env = Envelope(sha, size, crypto.random_id(), raised_costs(kdf), os.urandom(crypto.NONCE_BYTES), b'')
    wrapped = aead_encrypt(secret, env.aad(), env.nonce, crypto.derive_wrapping_key(password, env.kdf))
    return Envelope(sha, size, env.envelope_id, env.kdf, env.nonce, wrapped)


class Header:
    """Bounded reader for 7z EncodedHeader StreamsInfo (7zip/DOC/7zFormat.txt).

    Accept only a single packed stream, one folder and a simple AES -> optional
    LZMA chain. Every header byte must pass through AES; a passworded listing
    alone cannot establish this. Unknown structures fail closed.
    """
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise IntegrityError('Malformed encrypted outer header')
        value = self.data[self.pos:self.pos + n]
        self.pos += n
        return value

    def byte(self):
        return self.take(1)[0]

    def expect(self, value):
        if self.byte() != value:
            raise IntegrityError('Unsupported or unencrypted outer header')

    def number(self):
        first, value, mask = self.byte(), 0, 0x80
        for i in range(8):
            if not first & mask:
                return value | ((first & (mask - 1)) << (8 * i))
            value |= self.byte() << (8 * i)
            mask >>= 1
        return value

    def crc(self):
        # Exactly one stream. Require a canonical defined CRC.
        self.expect(1)
        self.take(4)


def encrypted_headers(path: Path):
    with path.open('rb') as f:
        start = f.read(32)
        if len(start) != 32 or start[:8] != b'7z\xbc\xaf\x27\x1c\x00\x04':
            raise IntegrityError('Expected a version 0.4 7z outer archive')
        if zlib.crc32(start[12:]) != struct.unpack('<I', start[8:12])[0]:
            raise IntegrityError('Damaged outer start header')
        offset, size, crc = struct.unpack('<QQI', start[12:])
        if not 0 < size <= ALLOWANCE or 32 + offset + size != path.stat().st_size:
            raise IntegrityError('Outer header exceeds bounds or has trailing data')
        f.seek(32 + offset)
        data = f.read(size)
    if zlib.crc32(data) != crc:
        raise IntegrityError('Damaged outer header')
    p = Header(data)
    p.expect(0x17)  # EncodedHeader, never a plaintext Header (0x01).
    p.expect(6)
    position = p.number()
    if p.number() != 1:
        raise IntegrityError('Outer headers must have one packed stream')
    p.expect(9)
    packed = p.number()
    if not 0 < packed <= ALLOWANCE or position + packed > offset:
        raise IntegrityError('Encrypted header stream exceeds bounds')
    marker = p.byte()
    if marker == 10:
        p.crc()
        marker = p.byte()
    if marker != 0:
        raise IntegrityError('Malformed outer header pack info')
    p.expect(7)
    p.expect(11)
    if p.number() != 1:
        raise IntegrityError('Outer headers must have one folder')
    p.expect(0)  # no external folder definitions
    coders = p.number()
    if coders not in (1, 2):
        raise IntegrityError('Unsupported outer header coders')
    for i in range(coders):
        flags = p.byte()
        if flags & 0xd0 or not 1 <= (flags & 15) <= 4:
            raise IntegrityError('Unsupported outer header coder flags')
        method = p.take(flags & 15)
        props = p.take(p.number()) if flags & 0x20 else b''
        if i == 0:
            if method != b'\x06\xf1\x07\x01' or len(props) != 18 or props[:2] != b'\x53\x0f':
                raise IntegrityError('Outer headers must use standard 7zAES:19 encryption')
        elif method == b'\x03\x01\x01':
            if len(props) != 5 or props[0] >= 225 or int.from_bytes(props[1:], 'little') > 64 << 20:
                raise IntegrityError('Outer LZMA header exceeds resource limits')
        elif method == b'\x21':
            if len(props) != 1 or props[0] > 26:
                raise IntegrityError('Outer LZMA2 header exceeds resource limits')
        else:
            raise IntegrityError('Unsupported outer header compression')
    if coders == 2 and (p.number(), p.number()) != (1, 0):
        raise IntegrityError('Invalid outer header stream binding')
    p.expect(12)
    for _ in range(coders):
        if not 0 < p.number() <= ALLOWANCE:
            raise IntegrityError('Decoded outer header exceeds bounds')
    marker = p.byte()
    if marker == 10:
        p.crc()
        marker = p.byte()
    if marker != 0:
        raise IntegrityError('Malformed outer header unpack info')
    marker = p.byte()
    if marker == 8:  # empty substreams info only
        p.expect(0)
        marker = p.byte()
    if marker != 0 or p.pos != len(data):
        raise IntegrityError('Unsupported outer header streams')


def layout(path: Path, outer_key: bytes) -> dict[str, int]:
    output = archive.run7z(['l', '-slt', '--', str(path)], outer_key, output_limit=64 * 1024)
    if '\n----------\n' not in output:
        raise IntegrityError('Outer listing is missing its entry section')
    head, contents = output.split('\n----------\n', 1)
    if '\nType = 7z\n' not in head or '\nSolid = -\n' not in head:
        raise IntegrityError('Outer bundle must be a non-solid 7z archive')
    result, blocks = {}, set()
    allowed = {'Path', 'Size', 'Packed Size', 'Modified', 'Created', 'Accessed',
               'Attributes', 'CRC', 'Encrypted', 'Method', 'Block'}
    for record in contents.strip().split('\n\n'):
        fields = {}
        for line in record.splitlines():
            name, sep, value = line.partition(' = ')
            if not sep or name in fields or name not in allowed:
                raise IntegrityError('Ambiguous or unsupported outer member header')
            fields[name] = value
        name = fields.get('Path')
        if name not in ('encrypted.7z', 'key') or name in result:
            raise IntegrityError('Outer layout must contain exactly encrypted.7z and key at its root')
        attrs = fields.get('Attributes', '')
        if (attrs.startswith('D') or not attrs.split(' ')[-1].startswith('-')
                or fields.get('Encrypted') != '+' or fields.get('Method') != 'Copy 7zAES:19'):
            raise IntegrityError('Outer members must be regular files using encrypted Copy')
        maximum = KEY_LIMIT if name == 'key' else 2 * limits.MAX_TOTAL_SIZE
        try:
            size, packed, block = int(fields['Size']), int(fields['Packed Size']), int(fields['Block'])
        except (KeyError, ValueError):
            raise IntegrityError('Invalid outer member size or block') from None
        if not 0 < size <= maximum or packed != (size + 15) // 16 * 16 or block in blocks:
            raise IntegrityError('Outer member size or block exceeds limits')
        result[name] = size
        blocks.add(block)
    if set(result) != {'encrypted.7z', 'key'} or blocks != {0, 1}:
        raise IntegrityError('Outer layout must contain exactly encrypted.7z and key at its root')
    if path.stat().st_size > sum(result.values()) + ALLOWANCE:
        raise IntegrityError('Outer archive overhead exceeds the fixed allowance')
    return result


@dataclass
class Opened:
    work: Path
    inner: Path
    envelope: Envelope
    outer_key: bytes
    source_stat: os.stat_result

    def unlock(self, password: bytes, ui: UI):
        ui.status('Unlocking embedded key with Argon2id…')
        return self.envelope.open(password)

    def close(self):
        shutil.rmtree(self.work)


def read(path: Path, outer_password: bytes | Callable[[], bytes], parent: Path, ui: UI,
         *, password_ui: UI | None = None) -> Opened:
    work = archive.workspace(parent)
    try:
        frozen = work / 'outer.7z'
        original = freeze(path, frozen, 2 * limits.MAX_TOTAL_SIZE + KEY_LIMIT + ALLOWANCE)
        encrypted_headers(frozen)

        def open_headers():
            password = outer_password() if callable(outer_password) else outer_password
            ui.status('Opening 7z headers with Argon2id…')
            outer_key = derive_outer(password)
            try:
                return outer_key, layout(frozen, outer_key)
            except IntegrityError as exc:
                if str(exc).startswith('7z l failed'):
                    raise WrongPassword('wrong 7z password or damaged outer archive') from None
                raise

        outer_key, sizes = (passwords.retry(password_ui or ui, open_headers)
                            if callable(outer_password) else open_headers())
        disk_space(work, sum(sizes.values()))
        for name, size in sizes.items():
            target = work / name
            with target.open('xb') as out:
                os.chmod(target, 0o600)
                try:
                    archive.run7z(['x', '-so', '-spd', '--', str(frozen), name], outer_key,
                                  output_file=out, output_limit=size)
                except IntegrityError:
                    raise IntegrityError('wrong 7z password or damaged outer archive') from None
            if target.stat().st_size != size:
                raise IntegrityError('Outer materialized member size mismatch')
        env = Envelope.parse((work / 'key').read_bytes())
        if digest(work / 'encrypted.7z') != (env.archive_sha256, env.archive_bytes):
            raise IntegrityError('Embedded key digest or size does not match encrypted.7z')
        return Opened(work, work / 'encrypted.7z', env, outer_key, original)
    except BaseException:
        shutil.rmtree(work)
        raise


def approve_cost(env: Envelope, ui: UI, allow: bool):
    ops, mem = crypto.PROFILES['sensitive']
    if not allow and (env.kdf.opslimit > ops or env.kdf.memlimit > mem):
        if not ui.confirm('Embedded key requests ' + env.kdf.describe() + '.', 'ACCEPT'):
            raise UsageError('Embedded KDF cost was not approved; scripts may use --allow-kdf-cost')


def verified(opened: Opened, secret: bytes, parent: Path):
    paths = archive.listing(opened.inner, secret)
    disk_space(parent, sum(size for _, size in paths.values()) + opened.envelope.archive_bytes)
    return archive.extract_verified(opened.inner, secret, parent)


def write(inner: Path, secret: bytes, outer_password: bytes, key_password: bytes,
          kdf: crypto.KdfParams, parent: Path, ui: UI, *, key_bytes: bytes | None = None) -> Path:
    members = archive.workspace(parent)
    try:
        staged = members / 'encrypted.7z'
        freeze(inner, staged, 2 * limits.MAX_TOTAL_SIZE)
        env = seal(staged, secret, key_password, kdf) if key_bytes is None else Envelope.parse(key_bytes)
        if digest(staged) != (env.archive_sha256, env.archive_bytes) or not hmac.compare_digest(env.open(key_password), secret):
            raise IntegrityError('Embedded key self-check failed')
        durable.write_new_file(members / 'key', env.encode() if key_bytes is None else key_bytes)
        candidate = parent / (crypto.random_id() + '.7z')
        while os.path.lexists(candidate):
            candidate = parent / (crypto.random_id() + '.7z')
        contents = archive.listing(staged, secret)
        disk_space(parent, staged.stat().st_size * 4 + sum(size for _, size in contents.values()))
        archive.run7z(['a', '-t7z', '-p', '-mhe=on', '-mx=0', '-ms=off', '-sse', '-spd', '--',
                       str(candidate), 'encrypted.7z', 'key'], derive_outer(outer_password),
                      cwd=members, creating=True)
        os.chmod(candidate, 0o600)
        opened = read(candidate, outer_password, parent, ui)
        try:
            if not hmac.compare_digest(opened.unlock(key_password, ui), secret):
                raise IntegrityError('Bundle secret self-check failed')
            checked, _, _ = verified(opened, secret, parent)
            shutil.rmtree(checked)
        finally:
            opened.close()
        return candidate
    finally:
        shutil.rmtree(members)


def publish(candidate: Path, output: Path, original: os.stat_result):
    with candidate.open('rb') as f:
        durable.full_sync(f.fileno())
    if not os.path.lexists(output) or tree._identity(output.lstat()) != tree._identity(original):
        raise SourceChanged('Existing archive changed; replacement was not published')
    os.replace(candidate, output)
    try:
        durable.sync_dir(output.parent)
    except Exception as exc:
        raise CommitUncertain('Bundle replaced but directory flush failed; publication is uncertain. '
                              'Preserve the output and remaining staging files.') from exc
