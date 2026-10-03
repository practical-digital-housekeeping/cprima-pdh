"""Shared CLI plumbing: global state, opening the vault, loading the taxonomy, rendering, error mapping."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from pydantic import BaseModel

from .. import backends, profiles, schema, source
from ..render import Format, get_renderer

NOT_IMPLEMENTED = 3  # exit code of a planned command: the surface exists, the behaviour does not yet
Fmt = Annotated[Format, typer.Option("--format", "-f", help="Output format.")]
Apply = Annotated[bool, typer.Option("--apply", help="Write. Without it: dry run.")]


class LevelName(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


@dataclass
class AppState:
    db: Path | None = None
    key: Path | None = None
    schemas: Path | None = None
    profile: str = profiles.DEFAULT
    profile_origin: str = ""  # where the profile came from; empty = the built-in default
    vault_source: str = "none"  # where the vault came from (--db, KDBX_FILE, config, session)


def state(ctx: typer.Context) -> AppState:
    root = ctx.find_root()
    if not isinstance(root.obj, AppState):
        root.obj = AppState()
    return root.obj


def fail(message: str, code: int = 2) -> NoReturn:
    typer.echo(message, err=True)
    raise typer.Exit(code)


def _has_console() -> bool:
    """True only for a real console. On Windows isatty() is also True for NUL, which hung background runs."""
    try:
        import ctypes
        import msvcrt

        mode = ctypes.c_uint32()
        return bool(ctypes.windll.kernel32.GetConsoleMode(msvcrt.get_osfhandle(0), ctypes.byref(mode)))
    except Exception:
        return sys.stdin.isatty()


def prompt_password() -> str | None:
    if not _has_console():  # scripts and background runs must not hang on a hidden prompt
        fail("database is locked and there is no terminal to ask on; run `pdh session unlock` first")
    return typer.prompt("Master password (empty for none)", hide_input=True, default="", show_default=False, err=True) or None


def require_db(st: AppState) -> Path:
    if st.db is None:
        fail("no vault: pass --db or --vault before the command, set KDBX_FILE, or configure one (pdh.toml)")
    return st.db


def require_backend(name: str = "kdbx") -> None:
    try:
        backends.load(name)
    except backends.BackendMissing as exc:
        fail(f"pdh: {exc}")


def open_db(db: Path, key: Path | None):
    """Open the vault (session cache first, else prompt). Tests replace this function."""
    require_backend("kdbx")
    try:
        return source.open_db(db, key, prompt_password)
    except source.OpenError as exc:
        fail(f"open failed: {exc}", 1)


def taxonomy_source(st: AppState) -> str:
    return str(st.schemas) if st.schemas is not None else f"profile {st.profile!r}"


def taxonomy_origin(st: AppState) -> str:
    """Where the profile was chosen, for `doctor`: '--schemas', 'from --profile', 'from config ...' or ''."""
    if st.schemas is not None:
        return "--schemas"
    return f"from {st.profile_origin}" if st.profile_origin else ""


def read_taxonomy(st: AppState):
    """Load the taxonomy: the --schemas file if given, else the selected packaged profile.

    Raises SchemaError (callers decide how to report it)."""
    if st.schemas is not None:
        return schema.load_schemas(st.schemas)
    return profiles.load(st.profile)


def load_taxonomy(st: AppState):
    try:
        return read_taxonomy(st)
    except schema.SchemaError as exc:
        fail(f"schema error: {exc}")


def emit(data: BaseModel, fmt: Format, ascii_only: bool = False) -> None:
    get_renderer(fmt, ascii_only).render(data, sys.stdout)
