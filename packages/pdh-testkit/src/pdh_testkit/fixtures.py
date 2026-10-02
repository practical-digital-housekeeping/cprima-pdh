"""pytest plugin (registered via the `pytest11` entry point): fixtures for synthetic vaults."""
from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from .vault import Entry, synthetic_vault


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "e2e: end-to-end test on a genuine vault file made by a real client")
    # Tests must never read, write or lock the owner's real session cache (pdh reads this at import time).
    if "PDH_SESSION_FILE" not in os.environ:
        os.environ["PDH_SESSION_FILE"] = str(Path(tempfile.gettempdir()) / f"pdh-test-session-{os.getpid()}.bin")


@pytest.fixture(autouse=True)
def _isolated_pdh_environment(monkeypatch, tmp_path_factory):
    """No test sees the owner's config files, vault variables or current folder."""
    home = tmp_path_factory.mktemp("pdh-env")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "xdg"))
    for name in ("PDH_CONFIG", "PDH_VAULT", "PDH_SCHEMAS", "KDBX_FILE", "KDBX_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(home)


@pytest.fixture
def make_synthetic_vault(tmp_path: Path) -> Callable[..., Path]:
    """Factory: `make_synthetic_vault(entries, name="vault.kdbx", **kw)` -> path of a fast synthetic vault."""

    def make(entries: list[Entry] | tuple[Entry, ...] = (), name: str = "vault.kdbx", **kw) -> Path:
        return synthetic_vault(tmp_path / name, entries, **kw)

    return make
