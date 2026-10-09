"""The actual salted, iterated derivation protecting the shared 7z password."""

import pytest

from docvault import crypto, keyfile, limits, strictjson as sj
from docvault.errors import WrongPassword

from .conftest import PASSWORD


@pytest.mark.real_kdf
def test_default_key_uses_real_salted_argon2id_output_to_open_cipher(tmp_path, monkeypatch):
    path = tmp_path / 'private' / 'key'
    keyfile.create(path, PASSWORD)
    envelope = keyfile.read(path)
    assert envelope.kdf.opslimit == 3
    assert envelope.kdf.memlimit == 256 * limits.MiB
    assert len(envelope.kdf.salt) == 16
    derived = crypto.derive_wrapping_key(PASSWORD, envelope.kdf)
    assert len(derived) == 32
    cipher_keys = []
    decrypt = crypto.crypto_aead_xchacha20poly1305_ietf_decrypt

    def record_key(ciphertext, associated_data, nonce, cipher_key):
        cipher_keys.append(cipher_key)
        return decrypt(ciphertext, associated_data, nonce, cipher_key)

    monkeypatch.setattr(crypto, 'crypto_aead_xchacha20poly1305_ietf_decrypt', record_key)
    secret = keyfile.open_key(path, PASSWORD)
    assert len(secret) == 32
    assert cipher_keys == [derived]
    data = path.read_bytes()
    for sensitive in (PASSWORD, derived, secret):
        assert sensitive not in data
        assert sensitive.hex().encode() not in data
    obj = sj.loads(data, max_bytes=limits.MAX_ENVELOPE_BYTES, what='test key file')
    assert obj['envelope']['kdf']['alg'] == 'argon2id13'
    assert obj['envelope']['kdf']['salt'] == envelope.kdf.salt.hex()


@pytest.mark.real_kdf
def test_same_password_gets_distinct_salts_and_derived_keys(tmp_path):
    first, second = tmp_path / 'private' / 'first', tmp_path / 'private' / 'second'
    keyfile.create(first, PASSWORD)
    keyfile.create(second, PASSWORD)
    a, b = keyfile.read(first), keyfile.read(second)
    assert a.kdf.salt != b.kdf.salt
    assert crypto.derive_wrapping_key(PASSWORD, a.kdf) != crypto.derive_wrapping_key(PASSWORD, b.kdf)


def test_password_change_refreshes_salt_and_preserves_archive_secret(tmp_path):
    path = tmp_path / 'private' / 'key'
    keyfile.create(path, PASSWORD)
    before = keyfile.read(path)
    archive_secret = keyfile.open_key(path, PASSWORD)
    replacement = b'a new long local password'
    keyfile.change_password(path, PASSWORD, replacement)
    after = keyfile.read(path)
    assert after.kdf.salt != before.kdf.salt
    assert (after.kdf.opslimit, after.kdf.memlimit) == (before.kdf.opslimit, before.kdf.memlimit)
    assert keyfile.open_key(path, replacement) == archive_secret
    with pytest.raises(WrongPassword):
        keyfile.open_key(path, PASSWORD)


def test_stored_salt_is_authenticated(tmp_path):
    path = tmp_path / 'private' / 'key'
    keyfile.create(path, PASSWORD)
    obj = sj.loads(path.read_bytes(), max_bytes=limits.MAX_ENVELOPE_BYTES, what='test key file')
    salt = bytearray.fromhex(obj['envelope']['kdf']['salt'])
    salt[0] ^= 1
    obj['envelope']['kdf']['salt'] = salt.hex()
    path.write_bytes(sj.dumps(obj))
    with pytest.raises(WrongPassword):
        keyfile.open_key(path, PASSWORD)
