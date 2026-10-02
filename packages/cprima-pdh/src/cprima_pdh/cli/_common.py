"""Shared CLI plumbing: global state, opening the vault, loading the taxonomy, rendering, error mapping."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from importlib.resources import files
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from pydantic import BaseModel

from .. import backends, schema, source
from ..render import Format, get_renderer

DEFAULT_TAXONOMY = files("cprima_pdh") / "data" / "schemas.toml"

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
        fail("no vault: pass --db before the command or set KDBX_FILE")
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


def load_taxonomy(st: AppState):
    try:
        if st.schemas is not None:
            return schema.load_schemas(st.schemas)
        return schema.parse_schemas(DEFAULT_TAXONOMY.read_text(encoding="utf-8"), "packaged taxonomy")
    except schema.SchemaError as exc:
        fail(f"schema error: {exc}")


def emit(data: BaseModel, fmt: Format, ascii_only: bool = False) -> None:
    get_renderer(fmt, ascii_only).render(data, sys.stdout)
