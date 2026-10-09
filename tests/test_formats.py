"""Strict parsing of every stored format, key handling and KDF bounds."""

import ctypes
import json

import nacl._sodium
import pytest
from nacl.bindings import crypto_generichash_blake2b_salt_personal

from docvault import crypto, limits
from docvault import strictjson as sj
from docvault.errors import FormatError, WrongPassword
from docvault.manifest import Entry, validate_entries

ID = "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize("raw, message", [
    (b'{"a":1,"a":2}', "duplicate"),
    (b'{"a":NaN}', "non-finite"),
    (b'{"a":Infinity}', "non-finite"),
    (b'{"a":1.5}', "floating"),
    (b'\xef\xbb\xbf{"a":1}', "strict JSON"),
    (b'{"a":1} {"b":2}', "strict JSON"),
    (b'{"a":"\xff"}', "strict JSON"),
    (b"[" * 100_000 + b"]" * 100_000, "larger"),
])
def test_strict_json_rejects(raw, message):
    with pytest.raises(FormatError, match=message):
        sj.loads(raw, max_bytes=1000 if message == "larger" else 10_000, what="x")


def test_strict_json_rejects_deep_nesting():
    with pytest.raises(FormatError):
        sj.loads(b"[" * 5000 + b"]" * 5000, max_bytes=20_000, what="x")










def _envelope_json(**kdf) -> bytes:
    params = {"alg": "argon2id13", "opslimit": 2, "memlimit": 64 * limits.MiB, "salt": "00" * 16}
    params.update(kdf)
    return json.dumps({"format": "docvault-envelope", "version": 1, "vault_id": ID, "envelope_id": ID,
                       "kdf": params, "nonce": "00" * 24, "wrapped_key": "00" * 48}).encode()


@pytest.mark.parametrize("kdf", [
    {"memlimit": 1 << 40},
    {"memlimit": 8 * limits.KiB},
    {"opslimit": 1},
    {"opslimit": 10_000},
    {"opslimit": 2.0},
    {"opslimit": True},
    {"memlimit": 64 * limits.MiB + 1},
    {"alg": "argon2i13"},
    {"salt": "00" * 8},
])
def test_kdf_parameters_rejected_before_derivation(kdf, fast_kdf):
    with pytest.raises(FormatError):
        env = crypto.Envelope.parse(_envelope_json(**kdf))
        crypto.open_envelope(env, b"pw")
    assert fast_kdf == [], "password derivation ran on malformed parameters"


def test_envelope_round_trip_and_wrong_password():
    master = crypto.random_key()
    env = crypto.seal_envelope(master, b"pw", ID, ID, crypto.KdfParams.from_profile("interactive"))
    parsed = crypto.Envelope.parse(env.to_bytes())
    assert crypto.open_envelope(parsed, b"pw") == master
    with pytest.raises(WrongPassword):
        crypto.open_envelope(parsed, b"wrong")


def test_envelope_kdf_parameters_are_authenticated():
    master = crypto.random_key()
    env = crypto.seal_envelope(master, b"pw", ID, ID, crypto.KdfParams(3, 256 * limits.MiB, bytes(16)))
    weakened = crypto.Envelope(env.vault_id, env.envelope_id, crypto.KdfParams(2, 64 * limits.MiB, bytes(16)),
                               env.nonce, env.wrapped)
    with pytest.raises(WrongPassword):
        crypto.open_envelope(weakened, b"pw")


@pytest.mark.real_kdf
def test_real_argon2id_profile():
    params = crypto.KdfParams.from_profile("interactive")
    assert params.memlimit == 64 * limits.MiB
    key = crypto.derive_wrapping_key(b"pw", params)
    assert len(key) == 32 and key == crypto.derive_wrapping_key(b"pw", params)


def test_subkeys_match_libsodium_crypto_kdf():
    """crypto_kdf_derive_from_key is BLAKE2b keyed with the master key, salt =
    subkey id (LE64, zero padded) and personal = context (zero padded)."""
    master = bytes(range(32))
    for subkey_id in (crypto.SUBKEY_ARCHIVE_METADATA, crypto.SUBKEY_ARCHIVE_METADATA + 1):
        expected = crypto_generichash_blake2b_salt_personal(
            b"", digest_size=32, key=master, salt=subkey_id.to_bytes(8, "little") + bytes(8),
            person=crypto.KDF_CONTEXT + bytes(8))
        assert crypto.derive_subkey(master, subkey_id) == expected
    lib = ctypes.CDLL(nacl._sodium.__file__)
    fn = getattr(lib, "crypto_kdf_derive_from_key", None)
    if fn is not None:
        out = ctypes.create_string_buffer(32)
        assert fn(out, ctypes.c_size_t(32), ctypes.c_uint64(1), crypto.KDF_CONTEXT, master) == 0
        assert out.raw == crypto.derive_subkey(master, 1)
    assert crypto.derive_subkey(master, 1) != crypto.derive_subkey(master, 2)




def _file(path, **kw):
    entry = {"path": path, "type": "file", "mode": 0o644, "size": 0,
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "mtime_ns": 0,
             "xattrs": {}}
    entry.update(kw)
    return entry


@pytest.mark.parametrize("entries", [
    [_file("../escape")],
    [_file("/abs")],
    [_file("a//b")],
    [_file("a/b")],                                  # parent missing
    [_file("x"), _file("x")],                        # duplicate
    [_file("._x")],
    [_file("x", sha256="00" * 32)],                  # an empty file must have the empty hash
    [_file("x", mode=0o4755)],
    [_file("x", xattrs={"com.example.unknown": ""})],
    [_file("x", xattrs={"com.apple.quarantine": "!!"})],
    [{"path": "d", "type": "symlink", "mode": 0o755, "xattrs": {}}],
])
def test_archive_entries_strict_validation(entries):
    with pytest.raises(FormatError):
        validate_entries([Entry.from_json(e) for e in entries])
