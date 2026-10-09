"""Exception hierarchy. Each class carries the process exit code the CLI uses."""


class VaultError(Exception):
    exit_code = 1


class UsageError(VaultError):
    exit_code = 2


class PasswordError(UsageError):
    """A password entry can be corrected without restarting the command."""


class WrongPassword(VaultError):
    exit_code = 3


class IntegrityError(VaultError):
    """Encrypted data, a checksum or a control file failed verification."""

    exit_code = 4


class FormatError(IntegrityError):
    """A file does not follow its strict format (bounds, keys, types)."""


class PlaintextPreserved(VaultError):
    """The operation stopped before deleting any plaintext."""

    exit_code = 6


class SourceChanged(PlaintextPreserved):
    """A plaintext file changed while it was being read or after approval."""


class CommitUncertain(VaultError):
    """An archive or key was replaced but the persistence barrier after it failed."""

    exit_code = 7


class Busy(VaultError):
    exit_code = 8


class Unsupported(VaultError):
    """Unsupported platform, filesystem, object type or metadata."""

    exit_code = 9


class DurabilityError(VaultError):
    """A flush failed before the commit point; nothing was published."""
