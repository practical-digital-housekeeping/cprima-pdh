"""Backends are plugins in the entry-point group `pdh.backends`; the entry-point name is the extra name."""
from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path

GROUP = "pdh.backends"


class BackendMissing(Exception):
    pass


@dataclass(frozen=True)
class BackendInfo:
    name: str
    available: bool  # its dependencies are installed
    detail: str


def _eps():
    return {ep.name: ep for ep in entry_points(group=GROUP)}


def install_hint(name: str) -> str:
    return f'uvx --from "cprima-pdh[{name}]" pdh ...'


def load(name: str):
    """The backend class for `name`; its dependencies are imported only now."""
    eps = _eps()
    if name not in eps:
        raise BackendMissing(f'no backend "{name}"; install it with: {install_hint(name)}')
    backend = eps[name].load()
    missing = backend.missing_dependencies()
    if missing:
        raise BackendMissing(f'backend "{name}" needs {", ".join(missing)}; install it with: {install_hint(name)}')
    return backend


def for_path(path: Path) -> str:
    """The backend name for a source path, from its suffix (`vault.kdbx` -> `kdbx`)."""
    suffix = path.suffix.lstrip(".").lower()
    if not suffix:
        raise BackendMissing(f"cannot tell the backend of {path.name!r}; use --source <backend>:<location>")
    return suffix


def available() -> list[BackendInfo]:
    out = []
    for name, ep in sorted(_eps().items()):
        backend = ep.load()
        missing = backend.missing_dependencies()
        out.append(BackendInfo(name, not missing, "ready" if not missing else f"missing: {', '.join(missing)}"))
    return out
