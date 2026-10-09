"""Hard bounds applied when scanning plaintext and when parsing any stored file.

Every parser checks these before allocating or deriving anything, so a
malformed or hostile archive cannot make the program do unbounded work.
"""

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

MAX_ENTRIES = 100_000
MAX_DEPTH = 64
MAX_NAME_BYTES = 255
MAX_PATH_BYTES = 1024
MAX_FILE_SIZE = 16 * GiB
MAX_TOTAL_SIZE = 64 * GiB

MAX_MANIFEST_BYTES = 32 * MiB
MAX_ENVELOPE_BYTES = 4 * KiB

MAX_XATTRS_PER_ENTRY = 16
MAX_XATTR_VALUE_BYTES = 64 * KiB
MAX_XATTR_TOTAL_BYTES = 256 * KiB

# Argon2id bounds, enforced before any password derivation is attempted.
KDF_OPSLIMIT_MIN = 2
KDF_OPSLIMIT_MAX = 16
KDF_MEMLIMIT_MIN = 64 * MiB
KDF_MEMLIMIT_MAX = 4 * GiB
