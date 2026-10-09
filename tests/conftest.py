import hashlib
import sys
from collections import deque
from pathlib import Path

import pytest

if sys.platform != "darwin":
    pytest.skip("docvault is macOS-only", allow_module_level=True)

from docvault import crypto  # noqa: E402
from docvault.ui import UI  # noqa: E402

PASSWORD = b"unwashed-gauze-uncured-spinal-reclining-stucco"
OUTER = b"kX9#mQ2$vL7p"


class ScriptedUI(UI):
    """Non-interactive UI. ``on_confirm`` runs when approval is requested."""

    def __init__(self, password: bytes = PASSWORD, accept: bool = True):
        self.pw = password
        self.new = deque()
        self.accept = accept
        self.on_confirm = None
        self.out: list[str] = []
        self.warnings: list[str] = []
        self.prompts: list[str] = []

    def info(self, message):
        self.out.append(message)

    def warn(self, message):
        self.warnings.append(message)

    def password(self, prompt):
        return OUTER if prompt == "Enter 7z password: " else self.pw

    def new_secret(self, prompt):
        return self.new.popleft() if self.new else OUTER if "7z password" in prompt else self.pw

    def confirm(self, prompt, token="ACCEPT"):
        self.prompts.append(prompt)
        if self.on_confirm:
            self.on_confirm()
        return self.accept

    @property
    def text(self) -> str:
        return "\n".join(self.out + self.warnings)


@pytest.fixture(autouse=True)
def fast_kdf(request, monkeypatch):
    """Replace Argon2id with a cheap deterministic function except where the
    test is about the KDF itself (marked ``real_kdf``)."""
    if request.node.get_closest_marker("real_kdf"):
        return
    calls = []

    def fake(password, params):
        calls.append(params)
        return hashlib.blake2b(password + params.salt + bytes([params.opslimit]) +
                               params.memlimit.to_bytes(8, "little"), digest_size=32).digest()

    monkeypatch.setattr(crypto, "derive_wrapping_key", fake)
    return calls


def pytest_configure(config):
    config.addinivalue_line("markers", "real_kdf: use the real Argon2id derivation")


@pytest.fixture
def ui():
    return ScriptedUI()


def write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path
