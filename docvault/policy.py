"""Which filesystem objects and metadata document archives accept.

Unsupported Apple metadata can be removed before encryption. Anything else not
explicitly handled here is refused, naming the specific file and attribute.
"""

import stat

from .macos import BACKUP_EXCLUDE_XATTR

APPLEDOUBLE_PREFIX = "._"

# System-managed attributes that carry no document data. Not stored or compared.
IGNORED_XATTRS = frozenset({
    "com.apple.provenance",
    "com.apple.lastuseddate#PS",
    "com.apple.macl",
})

# Attributes stored in the authenticated manifest and restored on decryption.
# Quarantine is security metadata: keeping it means Gatekeeper still treats a
# restored download as downloaded.
PRESERVED_XATTRS = frozenset({
    "com.apple.quarantine",
    "com.apple.FinderInfo",
    "com.apple.TextEncoding",
    "com.apple.metadata:_kMDItemUserTags",
    "com.apple.metadata:kMDItemWhereFroms",
    "com.apple.metadata:kMDItemDownloadedDate",
    BACKUP_EXCLUDE_XATTR,
})

# Encryption may discard unsupported attributes in this namespace. Supported
# attributes above (including Finder tags and backup exclusions) take precedence.
REMOVABLE_METADATA_PREFIX = "com.apple.metadata:"

RESOURCE_FORK_XATTR = "com.apple.ResourceFork"
FINDER_INFO_XATTR = "com.apple.FinderInfo"

# BSD file flags that carry no data and do not block deletion. Anything else
# (immutable, append-only, restricted, dataless cloud placeholders, ...) is refused.
# stat.UF_TRACKED only exists on Python >= 3.13; 0x40 is its <sys/stat.h> value.
ALLOWED_FLAGS = (stat.UF_NODUMP | stat.UF_COMPRESSED | getattr(stat, "UF_TRACKED", 0x00000040)
                 | stat.UF_HIDDEN | stat.SF_ARCHIVED)

SPECIAL_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
