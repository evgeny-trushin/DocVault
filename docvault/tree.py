"""Scanning plaintext trees under the metadata policy, and restoring them."""

import errno
import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from . import limits, macos
from .errors import SourceChanged
from .manifest import Entry, name_problem, sort_key
from .policy import (
    ALLOWED_FLAGS, APPLEDOUBLE_PREFIX, FINDER_INFO_XATTR, IGNORED_XATTRS,
    PRESERVED_XATTRS, REMOVABLE_METADATA_PREFIX, RESOURCE_FORK_XATTR, SPECIAL_MODE_BITS,
)
from .ui import render

READ_SIZE = 1 << 20


@dataclass(frozen=True)
class Issue:
    path: str
    problem: str
    remedy: str

    def describe(self) -> str:
        return f"{render(self.path)}: {self.problem}\n      fix: {self.remedy}"


@dataclass
class Scan:
    entries: list[Entry] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    # Planned removals only; scanning never changes the source tree.
    removable_xattrs: list[tuple[str, str]] = field(default_factory=list)
    # Not stored: (st_dev, st_ino, st_size, st_mtime_ns) per file, used to
    # confirm that the file streamed for encryption is the one that was approved.
    identity: dict[str, tuple[int, int, int, int]] = field(default_factory=dict)

    @property
    def total_size(self) -> int:
        return sum(e.size for e in self.entries)


def _identity(st: os.stat_result) -> tuple[int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _xattrs(path: Path, rel: str, issues: list[Issue],
            removable_xattrs: list[tuple[str, str]] | None = None) -> tuple[tuple[str, bytes], ...]:
    """Classify extended attributes: ignore, preserve, or report an issue."""
    kept = []
    total = 0
    for name in sorted(macos.listxattr(path)):
        if name in IGNORED_XATTRS:
            continue
        if (removable_xattrs is not None and name.startswith(REMOVABLE_METADATA_PREFIX)
                and name not in PRESERVED_XATTRS):
            removable_xattrs.append((rel, name))
            continue
        value = macos.getxattr(path, name)
        if name == RESOURCE_FORK_XATTR:
            if value:
                issues.append(Issue(rel, "has a non-empty resource fork, which docvault does not store",
                                    f"copy the data elsewhere, then: xattr -d {name} {render(str(path))}"))
            continue
        if name == FINDER_INFO_XATTR and not any(value):
            continue
        if name not in PRESERVED_XATTRS:
            issues.append(Issue(rel, f"has unsupported extended attribute {render(name)}",
                                f"if it is not needed: xattr -d {render(name)} {render(str(path))}"))
            continue
        if len(value) > limits.MAX_XATTR_VALUE_BYTES:
            issues.append(Issue(rel, f"extended attribute {render(name)} is larger than supported",
                                f"if it is not needed: xattr -d {render(name)} {render(str(path))}"))
            continue
        total += len(value)
        kept.append((name, value))
    if total > limits.MAX_XATTR_TOTAL_BYTES or len(kept) > limits.MAX_XATTRS_PER_ENTRY:
        issues.append(Issue(rel, "has more extended-attribute data than supported",
                            "remove attributes that are not needed, naming each one with xattr -d"))
    return tuple(kept)


def _common_checks(path: Path, rel: str, st: os.stat_result, issues: list[Issue]) -> bool:
    ok = True
    if st.st_flags & ~ALLOWED_FLAGS:
        issues.append(Issue(rel, f"has unsupported file flags 0x{st.st_flags & ~ALLOWED_FLAGS:x}"
                                 " (for example locked, append-only or a cloud placeholder)",
                            f"inspect with: ls -lO {render(str(path))}; clear with chflags"))
        ok = False
    if st.st_mode & SPECIAL_MODE_BITS:
        issues.append(Issue(rel, "has setuid, setgid or sticky permission bits",
                            f"chmod ug-s,-t {render(str(path))}"))
        ok = False
    if st.st_uid != os.getuid():
        issues.append(Issue(rel, "is owned by another user", "copy it so that you own the copy"))
        ok = False
    if macos.has_extended_acl(path):
        issues.append(Issue(rel, "has an access control list", f"chmod -N {render(str(path))}"))
        ok = False
    return ok


def hash_file(path: Path, expected: os.stat_result | None = None) -> tuple[str, os.stat_result]:
    """SHA-256 of a regular file, refusing if it changes while being read."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SourceChanged(f"{render(str(path))} is no longer a regular file")
        if expected is not None and _identity(before)[:2] != _identity(expected)[:2]:
            raise SourceChanged(f"{render(str(path))} was replaced while being scanned")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, READ_SIZE):
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        if total != before.st_size or _identity(after) != _identity(before):
            raise SourceChanged(f"{render(str(path))} changed while being read; close it and try again")
        return digest.hexdigest(), before
    finally:
        os.close(fd)




def scan_tree(root: Path, *, prefix: str = "", include_root: bool = False,
              exclude_root_names: frozenset[str] = frozenset(),
              allow_metadata_cleanup: bool = False) -> Scan:
    """Describe every object below ``root`` (the root itself is not an entry).

    Every name is an entry or an issue, except explicitly excluded root children.
    Archive scans set ``include_root`` and a
    ``prefix`` to preserve and check the source folder's own metadata too.
    ``allow_metadata_cleanup`` collects unsupported Apple metadata for the caller
    to remove after validation, rather than reporting those attributes as issues.
    """
    scan = Scan()
    removable_xattrs = scan.removable_xattrs if allow_metadata_cleanup else None
    root_st = os.lstat(root)
    if not stat.S_ISDIR(root_st.st_mode):
        raise NotADirectoryError(errno.ENOTDIR, "not a directory", str(root))
    if include_root:
        if not prefix:
            raise ValueError("include_root requires a prefix")
        _common_checks(root, prefix, root_st, scan.issues)
        xattrs = _xattrs(root, prefix, scan.issues, removable_xattrs)
        # The top-level folder must remain accessible during restoration.
        scan.entries.append(Entry(prefix, "dir", stat.S_IMODE(root_st.st_mode) | 0o700, xattrs=xattrs))
    total = 0
    stack: list[tuple[Path, str, int]] = [(root, prefix, 0)]
    while stack:
        directory, rel_dir, depth = stack.pop()
        children = []
        with os.scandir(directory) as it:
            names = sorted(e.name for e in it)
        for name in names:
            if directory == root and name in exclude_root_names:
                continue
            path = directory / name
            rel = f"{rel_dir}/{name}" if rel_dir else name
            problem = name_problem(name)
            if problem:
                scan.issues.append(Issue(rel, f"name {problem}", "rename it"))
                continue
            st = os.lstat(path)
            if st.st_dev != root_st.st_dev:
                scan.issues.append(Issue(rel, "is on a different filesystem (a mount point)", "unmount or move it"))
                continue
            if name.startswith(APPLEDOUBLE_PREFIX):
                scan.issues.append(Issue(
                    rel, "begins with '._': it may be a document or an AppleDouble sidecar holding"
                         " resource forks and attributes, so docvault neither stores nor deletes it",
                    "if it is a document, rename it; if it is a sidecar, check what it holds and remove it yourself"))
                continue
            if depth + 1 > limits.MAX_DEPTH or len((rel).encode("utf-8")) > limits.MAX_PATH_BYTES:
                scan.issues.append(Issue(rel, "path is too deep or too long", "shorten the folder structure"))
                continue
            if stat.S_ISLNK(st.st_mode):
                scan.issues.append(Issue(rel, "is a symbolic link, which is not supported",
                                         "replace it with a copy of the file it points to, or remove it"))
                continue
            if stat.S_ISDIR(st.st_mode):
                ok = _common_checks(path, rel, st, scan.issues)
                if st.st_mode & 0o700 != 0o700:
                    scan.issues.append(Issue(rel, "is a folder you cannot read, write and enter",
                                             f"chmod u+rwx {render(str(path))}"))
                    ok = False
                xattrs = _xattrs(path, rel, scan.issues, removable_xattrs)
                if ok:
                    scan.entries.append(Entry(rel, "dir", stat.S_IMODE(st.st_mode), xattrs=xattrs))
                    children.append((path, rel, depth + 1))
                continue
            if not stat.S_ISREG(st.st_mode):
                scan.issues.append(Issue(rel, "is not a regular file or folder (device, socket or pipe)",
                                         "remove it"))
                continue
            ok = _common_checks(path, rel, st, scan.issues)
            if st.st_nlink != 1:
                scan.issues.append(Issue(rel, "has more than one hard link", "replace it with an independent copy"))
                ok = False
            if not st.st_mode & stat.S_IRUSR:
                scan.issues.append(Issue(rel, "is not readable by you", f"chmod u+r {render(str(path))}"))
                ok = False
            if st.st_size > limits.MAX_FILE_SIZE:
                scan.issues.append(Issue(rel, "is larger than the supported maximum", "store it elsewhere"))
                ok = False
            xattrs = _xattrs(path, rel, scan.issues, removable_xattrs)
            if not ok:
                continue
            digest, opened = hash_file(path, st)
            total += opened.st_size
            scan.entries.append(Entry(rel, "file", stat.S_IMODE(opened.st_mode), opened.st_size, digest,
                                      opened.st_mtime_ns, xattrs))
            scan.identity[rel] = _identity(opened)
        stack.extend(children)
        if len(scan.entries) > limits.MAX_ENTRIES:
            scan.issues.append(Issue(rel_dir or ".", f"more than {limits.MAX_ENTRIES} items", "split the folder"))
            break
    if total > limits.MAX_TOTAL_SIZE:
        scan.issues.append(Issue(".", "total size exceeds the supported maximum", "store fewer files"))
    # Component-wise order: a parent always precedes its children.
    scan.entries.sort(key=lambda e: sort_key(e.path))
    return scan




def apply_metadata(path: Path, entry: Entry) -> None:
    for name, value in entry.xattrs:
        macos.setxattr(path, name, value)
    os.chmod(path, entry.mode, follow_symlinks=False)
    if entry.is_file:
        os.utime(path, ns=(entry.mtime_ns, entry.mtime_ns), follow_symlinks=False)
