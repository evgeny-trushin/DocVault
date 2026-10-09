"""Strict entries and path validation for authenticated archive metadata."""

import base64
import binascii
import hashlib
from dataclasses import dataclass

from . import limits
from . import strictjson as sj
from .errors import FormatError
from .policy import APPLEDOUBLE_PREFIX, PRESERVED_XATTRS

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
INT64 = (-(2**63), 2**63 - 1)


def name_problem(name: str) -> str | None:
    """Return why ``name`` cannot be a path component, or None."""
    if name in ("", ".", ".."):
        return "is a reserved name"
    if "/" in name or "\0" in name:
        return "contains '/' or NUL"
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError:
        return "is not valid UTF-8"
    if len(encoded) > limits.MAX_NAME_BYTES:
        return f"is longer than {limits.MAX_NAME_BYTES} bytes"
    return None


def validate_path(path: str) -> tuple[str, ...]:
    if not isinstance(path, str) or not path:
        raise FormatError("entry path must be a non-empty string")
    try:
        if len(path.encode("utf-8")) > limits.MAX_PATH_BYTES:
            raise FormatError(f"entry path longer than {limits.MAX_PATH_BYTES} bytes")
    except UnicodeEncodeError:
        raise FormatError("entry path is not valid UTF-8") from None
    parts = tuple(path.split("/"))
    if len(parts) > limits.MAX_DEPTH:
        raise FormatError(f"entry path deeper than {limits.MAX_DEPTH} levels")
    for part in parts:
        problem = name_problem(part)
        if problem:
            raise FormatError(f"entry path component {part!r} {problem}")
        if part.startswith(APPLEDOUBLE_PREFIX):
            raise FormatError("entry path component begins with '._'")
    return parts


def sort_key(path: str) -> tuple[str, ...]:
    return tuple(path.split("/"))


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str  # "dir" or "file"
    mode: int
    size: int = 0
    sha256: str = EMPTY_SHA256
    mtime_ns: int = 0
    xattrs: tuple[tuple[str, bytes], ...] = ()

    @property
    def is_file(self) -> bool:
        return self.kind == "file"

    def same_content(self, other: "Entry") -> bool:
        return (self.kind, self.size, self.sha256) == (other.kind, other.size, other.sha256)

    def same_metadata(self, other: "Entry") -> bool:
        return (self.mode, self.mtime_ns, self.xattrs) == (other.mode, other.mtime_ns, other.xattrs)

    def to_json(self) -> dict:
        obj = {
            "path": self.path,
            "type": self.kind,
            "mode": self.mode,
            "xattrs": {name: base64.b64encode(value).decode("ascii") for name, value in self.xattrs},
        }
        if self.is_file:
            obj.update(size=self.size, sha256=self.sha256, mtime_ns=self.mtime_ns)
        return obj

    @classmethod
    def from_json(cls, obj) -> "Entry":
        if not isinstance(obj, dict):
            raise FormatError("manifest entry must be an object")
        kind = obj.get("type")
        if kind == "dir":
            sj.require_object(obj, {"path", "type", "mode", "xattrs"}, "directory entry")
        elif kind == "file":
            sj.require_object(obj, {"path", "type", "mode", "xattrs", "size", "sha256", "mtime_ns"}, "file entry")
        else:
            raise FormatError(f"unsupported entry type {kind!r}")
        path = obj["path"]
        validate_path(path)
        mode = sj.require_int(obj["mode"], "mode", 0, 0o777)
        required_bits = 0o700 if kind == "dir" else 0o400
        if mode & required_bits != required_bits:
            raise FormatError(f"entry mode {mode:o} lacks required owner permissions")
        xattrs = _parse_xattrs(obj["xattrs"])
        if kind == "dir":
            return cls(path, kind, mode, xattrs=xattrs)
        size = sj.require_int(obj["size"], "size", 0, limits.MAX_FILE_SIZE)
        digest = obj["sha256"]
        if not isinstance(digest, str) or not sj.HEX64.fullmatch(digest):
            raise FormatError("sha256 must be 64 lowercase hex characters")
        if size == 0 and digest != EMPTY_SHA256:
            raise FormatError("empty file has a non-empty checksum")
        mtime = sj.require_int(obj["mtime_ns"], "mtime_ns", *INT64)
        return cls(path, kind, mode, size, digest, mtime, xattrs)


def _parse_xattrs(obj) -> tuple[tuple[str, bytes], ...]:
    if not isinstance(obj, dict) or len(obj) > limits.MAX_XATTRS_PER_ENTRY:
        raise FormatError("xattrs must be an object with a bounded number of attributes")
    total = 0
    out = []
    for name in sorted(obj):
        if name not in PRESERVED_XATTRS:
            raise FormatError(f"extended attribute {name!r} is not in the preserved set")
        encoded = obj[name]
        if not isinstance(encoded, str) or len(encoded) > 2 * limits.MAX_XATTR_VALUE_BYTES:
            raise FormatError(f"extended attribute {name!r} has an invalid value")
        try:
            value = base64.b64decode(encoded, validate=True)
        except binascii.Error:
            raise FormatError(f"extended attribute {name!r} is not valid base64") from None
        if len(value) > limits.MAX_XATTR_VALUE_BYTES:
            raise FormatError(f"extended attribute {name!r} is too large")
        total += len(value)
        out.append((name, value))
    if total > limits.MAX_XATTR_TOTAL_BYTES:
        raise FormatError("extended attributes exceed the per-entry limit")
    return tuple(out)


def validate_entries(entries: list[Entry]) -> None:
    """Unique paths, every parent listed earlier as a directory, global bounds."""
    if len(entries) > limits.MAX_ENTRIES:
        raise FormatError(f"more than {limits.MAX_ENTRIES} entries")
    kinds: dict[str, str] = {}
    total = 0
    for entry in entries:
        if entry.path in kinds:
            raise FormatError(f"duplicate entry path {entry.path!r}")
        parent, _, _ = entry.path.rpartition("/")
        if parent and kinds.get(parent) != "dir":
            raise FormatError(f"entry {entry.path!r} appears before its parent directory")
        kinds[entry.path] = entry.kind
        total += entry.size
    if total > limits.MAX_TOTAL_SIZE:
        raise FormatError("total content size exceeds the limit")
