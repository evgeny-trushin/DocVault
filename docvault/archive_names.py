"""Public password hints in NAME__KEY-HINT__7Z-HINT.7z filenames."""

from dataclasses import dataclass
from pathlib import Path
import unicodedata

from . import limits
from .errors import UsageError
from .ui import render


@dataclass(frozen=True)
class Hints:
    key: str = ''
    outer: str = ''


def validate_hint(value: str) -> str:
    value = value.strip()
    if value.startswith('_') or '__' in value or any(c in '/\\:' or unicodedata.category(c).startswith('C')
                            or unicodedata.category(c) in ('Zl', 'Zp') for c in value):
        raise UsageError('Hints cannot start with _ or contain __, slashes, colons or control characters')
    return value


def filename(root: str, hints: Hints = Hints()) -> str:
    key, outer = validate_hint(hints.key), validate_hint(hints.outer)
    name = f'{root}__{key}__{outer}.7z' if key or outer else root + '.7z'
    if len(name.encode('utf-8')) > limits.MAX_NAME_BYTES:
        raise UsageError('Archive name with hints exceeds 255 UTF-8 bytes; shorten the hints or folder name')
    return name


def parse(name: str) -> tuple[str, Hints | None]:
    if not name.endswith('.7z'):
        return name, None
    stem = name[:-3]
    parts = stem.rsplit('__', 2)
    if len(parts) == 3 and parts[0]:
        return parts[0], Hints(parts[1], parts[2])
    return stem, None


def matches(name: str, root: str) -> bool:
    return name == root + '.7z' or (name.endswith('.7z') and parse(name)[0] == root)


def inside(path: Path) -> bool:
    return matches(path.name, path.parent.name)


def find(folder: Path, *, preserve_root: bool = False) -> Path | None:
    """Find one legacy or hinted bundle, refusing ambiguous automatic selection."""
    parent = folder if preserve_root else folder.parent
    if not parent.exists():
        return None
    candidates = [p for p in parent.iterdir() if matches(p.name, folder.name)]
    if len(candidates) > 1:
        raise UsageError(f'Multiple archives match {render(str(folder))}; move extra archives aside '
                         'or decrypt/verify using an explicit .7z path')
    return candidates[0] if candidates else None
