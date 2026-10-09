"""Strict JSON parsing and canonical serialisation.

``json.loads`` on its own accepts repeated object names, NaN/Infinity and
arbitrarily large documents, so it does not satisfy the format rules. Every
stored JSON document goes through :func:`loads` instead.
"""

import json
import re

from .errors import FormatError

HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")

MAX_DEPTH = 8  # deepest stored format (manifest entry xattrs) needs 4
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)
_BRACKET = re.compile(r"[\[\]{}]")


def _no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise FormatError(f"duplicate JSON key {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name):
    raise FormatError(f"non-finite number {name} is not allowed")


def _reject_float(_text):
    raise FormatError("floating-point numbers are not allowed")


_DECODER = json.JSONDecoder(
    object_pairs_hook=_no_duplicates,
    parse_constant=_reject_constant,
    parse_float=_reject_float,
)


def loads(data: bytes, *, max_bytes: int, what: str):
    if len(data) > max_bytes:
        raise FormatError(f"{what} is larger than {max_bytes} bytes")
    try:
        text = data.decode("utf-8")
        _check_depth(text, what)
        return _DECODER.decode(text)
    except FormatError as e:
        raise FormatError(f"{what}: {e}") from None
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise FormatError(f"{what} is not valid strict JSON: {e}") from None


def _check_depth(text: str, what: str) -> None:
    depth = 0
    for m in _BRACKET.finditer(_STRING.sub("", text)):
        depth += 1 if m.group() in "[{" else -1
        if depth > MAX_DEPTH:
            raise FormatError(f"{what} is nested more than {MAX_DEPTH} levels deep")


def dumps(obj) -> bytes:
    """Canonical encoding: sorted keys, no whitespace, ASCII only."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


# --- field validators shared by every format -------------------------------


def require_object(obj, keys: set[str], what: str) -> dict:
    if not isinstance(obj, dict):
        raise FormatError(f"{what} must be a JSON object")
    if set(obj) != keys:
        missing = sorted(keys - set(obj))
        extra = sorted(set(obj) - keys)
        raise FormatError(f"{what} has missing keys {missing} or unexpected keys {extra}")
    return obj


def require_int(value, what: str, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise FormatError(f"{what} must be an integer in [{lo}, {hi}]")
    return value


def require_str(value, what: str, max_len: int = 256) -> str:
    if not isinstance(value, str) or len(value) > max_len:
        raise FormatError(f"{what} must be a string of at most {max_len} characters")
    return value


def require_id(value, what: str) -> str:
    if not isinstance(value, str) or not HEX32.fullmatch(value):
        raise FormatError(f"{what} must be 32 lowercase hex characters")
    return value


def require_hex(value, what: str, nbytes: int) -> bytes:
    if not isinstance(value, str) or len(value) != 2 * nbytes or not re.fullmatch(r"[0-9a-f]*", value):
        raise FormatError(f"{what} must be {2 * nbytes} lowercase hex characters")
    return bytes.fromhex(value)


def require_header(obj: dict, fmt: str, version: int, what: str) -> None:
    if obj.get("format") != fmt:
        raise FormatError(f"{what} has format {obj.get('format')!r}, expected {fmt!r}")
    if type(obj.get("version")) is not int or obj["version"] != version:
        raise FormatError(f"{what} version {obj.get('version')!r} is not supported (expected {version})")
