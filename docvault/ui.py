"""Terminal interaction and safe rendering of untrusted names."""

import getpass
import os
import sys
import unicodedata
import warnings

from .errors import UsageError

# Control, format (includes bidi overrides and zero-width characters),
# surrogate, private-use, unassigned and line/paragraph separators.
_UNSAFE_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def render(text: str) -> str:
    """Make a filename safe to print.

    Escapes control characters, newlines and direction-control characters so a
    name cannot forge a status line or another summary entry. Names that needed
    escaping, or have leading/trailing spaces, are shown in double quotes.
    """
    out = []
    quote = text == "" or text != text.strip(" ")
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in '\\"':
            out.append("\\" + ch)
            quote = True
        elif cat in _UNSAFE_CATEGORIES or (cat == "Zs" and ch != " "):
            quote = True
            code = ord(ch)
            out.append(_NAMED.get(ch) or (
                f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"))
        else:
            out.append(ch)
    body = "".join(out)
    return f'"{body}"' if quote else body


class UI:
    """Interface archive commands use for interactions with the person."""

    def info(self, message: str) -> None:
        raise NotImplementedError

    def warn(self, message: str) -> None:
        raise NotImplementedError

    def status(self, message: str) -> None:
        # Test/embedded interfaces may collect status alongside other messages.
        self.info(message)

    def show_generated(self, password: bytes) -> None:
        try:
            with open('/dev/tty', 'w', encoding='utf-8') as tty:
                tty.write('Generated password (save it now): ' + password.decode('utf-8') + '\n')
                tty.flush()
        except OSError:
            raise UsageError('--generate-password requires a controlling terminal') from None

    def password(self, prompt: str) -> bytes:
        """Read an existing password."""
        raise NotImplementedError

    def new_secret(self, prompt: str) -> bytes:
        """Read one entry of a password being chosen."""
        raise NotImplementedError

    def hint(self, prompt: str) -> str:
        """Read an optional public hint; embedded interfaces default to no hint."""
        return ''

    def can_retry_password(self, *, new: bool = False) -> bool:
        """Embedded/scripted interfaces opt in to interactive password retries."""
        return False

    def confirm(self, prompt: str, token: str = "ACCEPT") -> bool:
        raise NotImplementedError

class TerminalUI(UI):
    """Prompts on the terminal, or reads newline-terminated passwords from file descriptors.

    A password being chosen is read from ``new_password_fd`` if given, otherwise
    from ``password_fd`` (so ``init --password-fd`` works); changing a password
    non-interactively can share one descriptor for the old/new entries.
    """

    def __init__(self, password_fd: int | None = None, new_password_fd: int | None = None):
        self._fds = {"current": password_fd, "new": new_password_fd if new_password_fd is not None else password_fd}
        self._files = {}

    def info(self, message: str) -> None:
        print(message, file=sys.stdout, flush=True)

    def warn(self, message: str) -> None:
        print(f"warning: {message}", file=sys.stderr, flush=True)

    def status(self, message: str) -> None:
        print(message, file=sys.stderr, flush=True)

    def _read_fd_line(self, which: str) -> bytes:
        f = self._files.get(which)
        if f is None:
            fd = self._fds[which]
            assert fd is not None
            # sudo usually preserves only stdin/stdout/stderr. Sharing stdin
            # for old/new passwords must also share its buffered reader.
            f = next((reader for role, reader in self._files.items() if self._fds[role] == fd), None)
            if f is None:
                f = os.fdopen(fd, "rb", closefd=False)
            self._files[which] = f
        line = f.readline(4098)
        if len(line) > 4097:
            raise UsageError('Password input exceeds the size limit')
        if not line:
            raise UsageError('Password input reached EOF')
        return line[:-1] if line.endswith(b"\n") else line

    def _read(self, which: str, prompt: str) -> bytes:
        if self._fds[which] is not None:
            return self._read_fd_line(which)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                return getpass.getpass(prompt).encode("utf-8")
        except getpass.GetPassWarning:
            raise UsageError('A terminal with hidden input is required; use password descriptors in scripts') from None
        except EOFError:
            raise UsageError("no password was entered") from None

    def password(self, prompt: str) -> bytes:
        return self._read("current", prompt)

    def new_secret(self, prompt: str) -> bytes:
        return self._read("new", prompt)

    def can_retry_password(self, *, new: bool = False) -> bool:
        return self._fds['new' if new else 'current'] is None

    def hint(self, prompt: str) -> str:
        # Keep public hints separate from password descriptors and piped stdin.
        try:
            # Terminals cannot seek, so TextIO's r+ (BufferedRandom) is unsuitable.
            with open('/dev/tty', 'w', encoding='utf-8') as output, \
                    open('/dev/tty', 'r', encoding='utf-8') as input_stream:
                output.write(prompt)
                output.flush()
                line = input_stream.readline(4098)
                if not line:
                    raise UsageError('Hint input reached EOF')
                if len(line) > 4097:
                    raise UsageError('Hint input exceeds the size limit')
                return line.rstrip('\n')
        except OSError:
            raise UsageError('Hint entry requires a terminal; use --key-hint and --outer-hint in scripts') from None

    def confirm(self, prompt: str, token: str = "ACCEPT") -> bool:
        try:
            with open("/dev/tty", "r+", encoding="utf-8") as tty:
                tty.write(f"{prompt} Type {token} to continue: ")
                tty.flush()
                return tty.readline().strip("\n") == token
        except OSError:
            return False
