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
    detection: str = ""  # how a file of this kind is recognised
    capabilities: tuple[str, ...] = ()  # what its vault can do (see `cprima_pdh.vault.CAPABILITIES`)


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


class BackendMismatch(BackendMissing):
    """A backend was chosen explicitly, but the file is of another kind."""


class BackendUndetected(BackendMissing):
    """The file is not recognised by any backend and nothing chose one."""


@dataclass(frozen=True)
class Selection:
    name: str
    source: str  # where the choice came from: "--backend", "PDH_BACKEND", a config entry, "file content", ...


def detect(path: Path) -> str | None:
    """The name of the backend that recognises the content of `path` (extensions lie); None when none does.
    A backend decides for itself, in `Backend.detects`; exactly one may claim a file."""
    claims = []
    for name, ep in sorted(_eps().items()):
        if ep.load().detects(path):
            claims.append(name)
    if len(claims) > 1:
        raise BackendUndetected(f"{path.name} is claimed by more than one backend ({', '.join(claims)}); choose one with --backend")
    return claims[0] if claims else None


def _is_empty(path: Path) -> bool:
    try:
        return Path(path).stat().st_size == 0
    except OSError:
        return True  # missing or unreadable: the opener reports the real problem


BUILT_IN_DEFAULT = "kdbx"


def select(path: Path, chosen: list[tuple[str, str]] | tuple[tuple[str, str], ...] = ()) -> Selection:
    """Which backend works on `path`. `chosen` holds the explicit choices as (backend, source), highest priority first
    (`--backend`, `PDH_BACKEND`, the vault's config entry, the config default); the first one wins. The file content is
    always looked at: a choice that contradicts it is refused, and without any choice the content decides.

    An empty file has no content to look at and gets the built-in default; any other unrecognised file is an error."""
    found = detect(path)
    if chosen:
        name, source = chosen[0]
        if name not in _eps():
            raise BackendMissing(f'no backend "{name}" (chosen by {source}); known: {", ".join(sorted(_eps())) or "none"}')
        if found is not None and found != name:
            raise BackendMismatch(f"{Path(path).name} is a {found} file, not {name} (chosen by {source})")
        return Selection(name, source)
    if found is not None:
        return Selection(found, "file content")
    if _is_empty(path):
        return Selection(BUILT_IN_DEFAULT, "built-in default (the file is empty)")
    raise BackendUndetected(
        f"cannot tell what kind of vault {Path(path).name!r} is (tried: {', '.join(sorted(_eps()))}); say so with --backend NAME")


def available() -> list[BackendInfo]:
    out = []
    for name, ep in sorted(_eps().items()):
        backend = ep.load()
        missing = backend.missing_dependencies()
        out.append(BackendInfo(name, not missing, "ready" if not missing else f"missing: {', '.join(missing)}",
                               getattr(backend, "detection", ""), tuple(sorted(backend.capabilities()))))
    return out
