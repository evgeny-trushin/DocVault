"""Argon2id password wrapping and domain-separated archive metadata MACs."""

import hashlib
import hmac
import os
from dataclasses import dataclass

import nacl.exceptions
import nacl.pwhash.argon2id as argon2id
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)

from . import limits
from . import strictjson as sj
from .errors import FormatError, WrongPassword

KEY_BYTES = 32
SALT_BYTES = argon2id.SALTBYTES
NONCE_BYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
WRAPPED_BYTES = KEY_BYTES + 16
KDF_ALG = "argon2id13"

ENVELOPE_FORMAT = "docvault-envelope"
ENVELOPE_VERSION = 1

KDF_CONTEXT = b"DOCVAULT"
SUBKEY_ARCHIVE_METADATA = 3

PROFILES = {
    "interactive": (argon2id.OPSLIMIT_INTERACTIVE, argon2id.MEMLIMIT_INTERACTIVE),
    "moderate": (argon2id.OPSLIMIT_MODERATE, argon2id.MEMLIMIT_MODERATE),
    "sensitive": (argon2id.OPSLIMIT_SENSITIVE, argon2id.MEMLIMIT_SENSITIVE),
}
DEFAULT_PROFILE = "moderate"


def random_id() -> str:
    return os.urandom(16).hex()


def random_key() -> bytes:
    return os.urandom(KEY_BYTES)


@dataclass(frozen=True)
class KdfParams:
    opslimit: int
    memlimit: int
    salt: bytes

    @classmethod
    def from_profile(cls, profile: str) -> "KdfParams":
        ops, mem = PROFILES[profile]
        return cls(ops, mem, os.urandom(SALT_BYTES))

    @classmethod
    def from_json(cls, obj) -> "KdfParams":
        sj.require_object(obj, {"alg", "opslimit", "memlimit", "salt"}, "KDF parameters")
        if obj["alg"] != KDF_ALG:
            raise FormatError(f"unsupported KDF {obj['alg']!r}")
        ops = sj.require_int(obj["opslimit"], "opslimit", limits.KDF_OPSLIMIT_MIN, limits.KDF_OPSLIMIT_MAX)
        mem = sj.require_int(obj["memlimit"], "memlimit", limits.KDF_MEMLIMIT_MIN, limits.KDF_MEMLIMIT_MAX)
        if mem % 1024:
            raise FormatError("memlimit must be a whole number of KiB")
        return cls(ops, mem, sj.require_hex(obj["salt"], "salt", SALT_BYTES))

    def to_json(self) -> dict:
        return {"alg": KDF_ALG, "opslimit": self.opslimit, "memlimit": self.memlimit, "salt": self.salt.hex()}

    def describe(self) -> str:
        return f"Argon2id, {self.memlimit // limits.MiB} MiB, {self.opslimit} passes"


def derive_wrapping_key(password: bytes, params: KdfParams) -> bytes:
    # Bounds were enforced when ``params`` was constructed from stored JSON.
    return argon2id.kdf(KEY_BYTES, password, params.salt, opslimit=params.opslimit, memlimit=params.memlimit)


def derive_subkey(master: bytes, subkey_id: int) -> bytes:
    """Equivalent to libsodium ``crypto_kdf_derive_from_key(32, id, "DOCVAULT", master)``."""
    return hashlib.blake2b(
        b"", digest_size=KEY_BYTES, key=master, salt=subkey_id.to_bytes(8, "little"), person=KDF_CONTEXT
    ).digest()


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def mac_matches(key: bytes, data: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(mac(key, data), tag)


@dataclass(frozen=True)
class Envelope:
    """The master key wrapped by a password-derived key.

    The associated data authenticates the vault ID, envelope ID and the KDF
    parameters, so none of them can be swapped or silently weakened.
    """

    vault_id: str
    envelope_id: str
    kdf: KdfParams
    nonce: bytes
    wrapped: bytes

    def associated_data(self) -> bytes:
        return sj.dumps({
            "format": ENVELOPE_FORMAT,
            "version": ENVELOPE_VERSION,
            "vault_id": self.vault_id,
            "envelope_id": self.envelope_id,
            "kdf": self.kdf.to_json(),
        })

    def to_bytes(self) -> bytes:
        return sj.dumps({
            "format": ENVELOPE_FORMAT,
            "version": ENVELOPE_VERSION,
            "vault_id": self.vault_id,
            "envelope_id": self.envelope_id,
            "kdf": self.kdf.to_json(),
            "nonce": self.nonce.hex(),
            "wrapped_key": self.wrapped.hex(),
        }) + b"\n"

    @classmethod
    def parse(cls, data: bytes) -> "Envelope":
        obj = sj.loads(data, max_bytes=limits.MAX_ENVELOPE_BYTES, what="key envelope")
        sj.require_object(
            obj, {"format", "version", "vault_id", "envelope_id", "kdf", "nonce", "wrapped_key"}, "key envelope")
        sj.require_header(obj, ENVELOPE_FORMAT, ENVELOPE_VERSION, "key envelope")
        return cls(
            vault_id=sj.require_id(obj["vault_id"], "vault_id"),
            envelope_id=sj.require_id(obj["envelope_id"], "envelope_id"),
            kdf=KdfParams.from_json(obj["kdf"]),
            nonce=sj.require_hex(obj["nonce"], "nonce", NONCE_BYTES),
            wrapped=sj.require_hex(obj["wrapped_key"], "wrapped_key", WRAPPED_BYTES),
        )


def seal_envelope(master: bytes, password: bytes, vault_id: str, envelope_id: str, kdf: KdfParams) -> Envelope:
    template = Envelope(vault_id, envelope_id, kdf, os.urandom(NONCE_BYTES), b"")
    wrapping_key = derive_wrapping_key(password, kdf)
    wrapped = crypto_aead_xchacha20poly1305_ietf_encrypt(
        master, template.associated_data(), template.nonce, wrapping_key)
    return Envelope(vault_id, envelope_id, kdf, template.nonce, wrapped)


def open_envelope(envelope: Envelope, password: bytes) -> bytes:
    wrapping_key = derive_wrapping_key(password, envelope.kdf)
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            envelope.wrapped, envelope.associated_data(), envelope.nonce, wrapping_key)
    except nacl.exceptions.CryptoError:
        raise WrongPassword("wrong password, or the key envelope is damaged") from None
