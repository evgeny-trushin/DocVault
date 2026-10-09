"""macOS system interfaces that Python's standard library does not expose.

``os.listxattr``/``os.getxattr`` are Linux-only, so extended attributes go
through libc directly. Everything here uses the no-follow variants: the
archive workflow never follows symbolic links.
"""

import ctypes
import errno
import os
import subprocess
import sys

from .errors import Unsupported

IS_DARWIN = sys.platform == "darwin"

XATTR_NOFOLLOW = 0x0001
RENAME_EXCL = 0x0000_0004
ACL_TYPE_EXTENDED = 0x0000_0100
ACL_FIRST_ENTRY = 0

BACKUP_EXCLUDE_XATTR = "com.apple.metadata:com_apple_backup_excludeItem"

_libc = None
_cs = None  # (CoreServices, CoreFoundation) once loaded


def _lib():
    global _libc
    if not IS_DARWIN:
        raise Unsupported("docvault currently supports macOS only")
    if _libc is None:
        lib = ctypes.CDLL(None, use_errno=True)
        c_ssize, c_size, c_char_p, c_void_p, c_int = (
            ctypes.c_ssize_t, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int)
        lib.listxattr.argtypes = [c_char_p, c_void_p, c_size, c_int]
        lib.listxattr.restype = c_ssize
        lib.getxattr.argtypes = [c_char_p, c_char_p, c_void_p, c_size, ctypes.c_uint32, c_int]
        lib.getxattr.restype = c_ssize
        lib.setxattr.argtypes = [c_char_p, c_char_p, c_void_p, c_size, ctypes.c_uint32, c_int]
        lib.setxattr.restype = c_int
        lib.removexattr.argtypes = [c_char_p, c_char_p, c_int]
        lib.removexattr.restype = c_int
        lib.renamex_np.argtypes = [c_char_p, c_char_p, ctypes.c_uint]
        lib.renamex_np.restype = c_int
        lib.acl_get_link_np.argtypes = [c_char_p, c_int]
        lib.acl_get_link_np.restype = c_void_p
        lib.acl_get_entry.argtypes = [c_void_p, c_int, ctypes.POINTER(c_void_p)]
        lib.acl_get_entry.restype = c_int
        lib.acl_free.argtypes = [c_void_p]
        lib.acl_free.restype = c_int
        _libc = lib
    return _libc


def _raise_errno(path) -> None:
    e = ctypes.get_errno()
    raise OSError(e, os.strerror(e), os.fspath(path))


# --- extended attributes ---------------------------------------------------


def listxattr(path) -> list[str]:
    lib, p = _lib(), os.fsencode(path)
    for _ in range(8):
        n = lib.listxattr(p, None, 0, XATTR_NOFOLLOW)
        if n < 0:
            _raise_errno(path)
        if n == 0:
            return []
        buf = ctypes.create_string_buffer(n)
        m = lib.listxattr(p, buf, n, XATTR_NOFOLLOW)
        if m < 0:
            if ctypes.get_errno() == errno.ERANGE:
                continue  # attributes were added between the two calls
            _raise_errno(path)
        return [os.fsdecode(name) for name in buf.raw[:m].split(b"\0") if name]
    raise OSError(errno.ERANGE, "extended attributes kept changing", os.fspath(path))


def getxattr(path, name: str) -> bytes:
    lib, p, nm = _lib(), os.fsencode(path), os.fsencode(name)
    for _ in range(8):
        n = lib.getxattr(p, nm, None, 0, 0, XATTR_NOFOLLOW)
        if n < 0:
            _raise_errno(path)
        buf = ctypes.create_string_buffer(max(n, 1))
        m = lib.getxattr(p, nm, buf, n, 0, XATTR_NOFOLLOW)
        if m < 0:
            if ctypes.get_errno() == errno.ERANGE:
                continue
            _raise_errno(path)
        return buf.raw[:m]
    raise OSError(errno.ERANGE, "extended attribute kept changing", os.fspath(path))


def setxattr(path, name: str, value: bytes) -> None:
    lib = _lib()
    if lib.setxattr(os.fsencode(path), os.fsencode(name), value, len(value), 0, XATTR_NOFOLLOW) < 0:
        _raise_errno(path)


def removexattr(path, name: str) -> None:
    if _lib().removexattr(os.fsencode(path), os.fsencode(name), XATTR_NOFOLLOW) < 0:
        _raise_errno(path)


def has_extended_acl(path) -> bool:
    lib = _lib()
    acl = lib.acl_get_link_np(os.fsencode(path), ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return False
        _raise_errno(path)
    try:
        entry = ctypes.c_void_p()
        return lib.acl_get_entry(acl, ACL_FIRST_ENTRY, ctypes.byref(entry)) == 0
    finally:
        lib.acl_free(acl)


# --- filesystem capabilities -----------------------------------------------


def rename_exclusive(src, dst) -> None:
    """Rename that fails with FileExistsError instead of replacing ``dst``."""
    if _lib().renamex_np(os.fsencode(src), os.fsencode(dst), RENAME_EXCL) != 0:
        e = ctypes.get_errno()
        if e == errno.EEXIST:
            raise FileExistsError(e, os.strerror(e), os.fspath(dst))
        raise OSError(e, os.strerror(e), os.fspath(src))


# --- Time Machine ------------------------------------------------------------


def _coreservices():
    global _cs
    if _cs is None:
        cs = ctypes.CDLL("/System/Library/Frameworks/CoreServices.framework/CoreServices")
        cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        cf.CFURLCreateFromFileSystemRepresentation.restype = ctypes.c_void_p
        cf.CFURLCreateFromFileSystemRepresentation.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long, ctypes.c_bool]
        cf.CFRelease.argtypes = [ctypes.c_void_p]
        cs.CSBackupSetItemExcluded.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_bool]
        cs.CSBackupSetItemExcluded.restype = ctypes.c_int32
        _cs = (cs, cf)
    return _cs


def has_own_backup_exclusion(path) -> bool:
    """True only if ``path`` itself carries a sticky Time Machine exclusion.

    ``CSBackupIsItemExcluded``/``tmutil isexcluded`` also report true when an
    ancestor is excluded, which says nothing about whether the exclusion
    survives moving the item elsewhere. The per-item exclusion is stored on
    the item as an extended attribute, so that is what is checked.
    """
    return BACKUP_EXCLUDE_XATTR in listxattr(path)


def set_backup_excluded(path) -> None:
    """Apply a per-item (not path-based) Time Machine exclusion to ``path``."""
    _lib()
    try:
        cs, cf = _coreservices()
        raw = os.fsencode(os.path.abspath(path))
        url = cf.CFURLCreateFromFileSystemRepresentation(None, raw, len(raw), True)
        if not url:
            raise OSError("CFURLCreateFromFileSystemRepresentation failed")
        try:
            status = cs.CSBackupSetItemExcluded(url, True, False)
        finally:
            cf.CFRelease(url)
        if status != 0:
            raise OSError(f"CSBackupSetItemExcluded returned {status}")
    except (OSError, AttributeError):
        subprocess.run(["/usr/bin/tmutil", "addexclusion", os.fspath(path)],
                       check=False, capture_output=True)
    if not has_own_backup_exclusion(path):
        raise Unsupported(f"could not attach a Time Machine exclusion to {os.fspath(path)}")
