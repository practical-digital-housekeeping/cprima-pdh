"""`pdh db`: the database itself. Dry run unless --apply; new passwords come from an environment variable or a hidden prompt."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Optional

import typer

from .. import database as database_mod
from .. import session as session_mod
from .. import write as write_mod
from ..render import Format
from . import _common as c

app = typer.Typer(no_args_is_help=True, help="The database itself: create, key, settings, recycle bin. Dry run unless --apply.")

PasswordEnv = Annotated[str, typer.Option("--password-env", help="Environment variable holding the new master password.")]


def _vault(ctx: typer.Context):
    st = c.state(ctx)
    db = c.require_db(st)
    return db, (lambda: c.open_kdbx(st, db))


def _refused(exc: Exception) -> None:
    c.fail(f"write refused: {exc}")


def _new_password(env_name: str) -> str:
    """The new master password: the environment variable, else a hidden prompt (twice) on a real console."""
    value = os.environ.get(env_name, "")
    if value:
        return value
    if not c._has_console():
        c.fail(f"write refused: environment variable {env_name} is empty and there is no terminal to ask on")
    first = typer.prompt("New master password", hide_input=True, err=True)
    if first != typer.prompt("Repeat it", hide_input=True, err=True):
        c.fail("write refused: the two passwords differ")
    return first


@app.command("create")
def create(
    file: Annotated[Path, typer.Argument(help="The new vault file; must not exist.")],
    fmt: c.Fmt = Format.text,
    apply: c.Apply = False,
    keyfile: Annotated[Optional[Path], typer.Option("--keyfile", help="Also require this key file.")] = None,
    password_env: PasswordEnv = "PDH_NEW_PASSWORD",
) -> None:
    """Create a new, empty KDBX 4 vault (KeePass' default key derivation)."""
    password = _new_password(password_env) if apply else "x"  # a dry run needs no password
    try:
        change = database_mod.create_vault(file, password, keyfile, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("password")
def password(ctx: typer.Context, fmt: c.Fmt = Format.text, apply: c.Apply = False,
             password_env: PasswordEnv = "PDH_NEW_PASSWORD") -> None:
    """Change the master password; the cached session is discarded."""
    new = _new_password(password_env) if apply else os.environ.get(password_env, "") or "x"
    db, opener = _vault(ctx)
    try:
        change = database_mod.change_password(opener, db, new, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    if apply and change.applied:
        session_mod.lock()
    c.emit(change, fmt)


@app.command("keyfile")
def keyfile(
    ctx: typer.Context, fmt: c.Fmt = Format.text, apply: c.Apply = False,
    set_: Annotated[Optional[Path], typer.Option("--set", help="Use this key file.")] = None,
    remove: Annotated[bool, typer.Option("--remove", help="Stop using a key file.")] = False,
) -> None:
    """Set, change or remove the key file."""
    if (set_ is None) == (not remove):
        c.fail("give exactly one of --set FILE and --remove")
    db, opener = _vault(ctx)
    try:
        change = database_mod.set_keyfile(opener, db, set_, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("settings")
def settings(
    ctx: typer.Context, fmt: c.Fmt = Format.text, apply: c.Apply = False,
    name: Annotated[Optional[str], typer.Option("--name", help="Database name.")] = None,
    description: Annotated[Optional[str], typer.Option("--description")] = None,
    history_max_items: Annotated[Optional[int], typer.Option("--history-max-items", help="Snapshots per entry; -1 unlimited.")] = None,
    history_max_size: Annotated[Optional[int], typer.Option("--history-max-size", help="Bytes of history per entry; -1 unlimited.")] = None,
    recycle_bin: Annotated[Optional[bool], typer.Option("--recycle-bin/--no-recycle-bin")] = None,
) -> None:
    """Show the database settings; with options, change them."""
    db, opener = _vault(ctx)
    try:
        result = database_mod.database_settings(opener, db, {
            "name": name, "description": description, "history_max_items": history_max_items,
            "history_max_size": history_max_size, "recycle_bin": recycle_bin}, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(result, fmt)


@app.command("kdf")
def kdf(
    ctx: typer.Context, fmt: c.Fmt = Format.text, apply: c.Apply = False,
    iterations: Annotated[Optional[int], typer.Option("--iterations")] = None,
    memory: Annotated[Optional[int], typer.Option("--memory", help="KiB.")] = None,
    parallelism: Annotated[Optional[int], typer.Option("--parallelism")] = None,
) -> None:
    """Show the Argon2 key derivation parameters; with options, change them (not below a safe minimum)."""
    db, opener = _vault(ctx)
    try:
        result = database_mod.key_derivation(opener, db, iterations, memory, parallelism, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(result, fmt)


@app.command("empty-bin")
def empty_bin(ctx: typer.Context, fmt: c.Fmt = Format.text, apply: c.Apply = False) -> None:
    """Delete everything in the recycle bin permanently."""
    db, opener = _vault(ctx)
    try:
        result = database_mod.empty_bin(opener, db, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(result, fmt)
