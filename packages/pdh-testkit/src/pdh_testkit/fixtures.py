"""pytest plugin (registered via the `pytest11` entry point): fixtures for synthetic vaults."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from .vault import Entry, synthetic_vault


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "e2e: end-to-end test on a genuine vault file made by a real client")


@pytest.fixture
def make_synthetic_vault(tmp_path: Path) -> Callable[..., Path]:
    """Factory: `make_synthetic_vault(entries, name="vault.kdbx", **kw)` -> path of a fast synthetic vault."""

    def make(entries: list[Entry] | tuple[Entry, ...] = (), name: str = "vault.kdbx", **kw) -> Path:
        return synthetic_vault(tmp_path / name, entries, **kw)

    return make
