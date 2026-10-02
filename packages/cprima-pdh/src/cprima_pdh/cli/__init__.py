"""The `pdh` command: Practical Digital Housekeeping.

Global options (vault, key file, taxonomy) are given once, before the command group:
    pdh --db vault.kdbx check conform -f json
They also come from the environment: KDBX_FILE, KDBX_KEY, PDH_SCHEMAS.
"""
from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from .. import __version__, backends
from . import _common as c
from . import check, edit, inspect, method, session

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="Practical Digital Housekeeping. Keep it tidy. Keep it trustworthy.")
app.add_typer(session.app, name="session")
app.add_typer(inspect.app, name="inspect")
app.add_typer(check.app, name="check")
app.add_typer(edit.app, name="edit")
app.add_typer(method.app, name="method")


def _version(value: bool) -> None:
    if value:
        typer.echo(f"pdh {__version__} (cprima-pdh, Practical Digital Housekeeping)")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    db: Annotated[Optional[Path], typer.Option("--db", envvar="KDBX_FILE", exists=True, dir_okay=False,
                                               help="Vault file (env KDBX_FILE).")] = None,
    key: Annotated[Optional[Path], typer.Option("--key", envvar="KDBX_KEY", help="Key file (env KDBX_KEY).")] = None,
    schemas: Annotated[Optional[Path], typer.Option("--schemas", envvar="PDH_SCHEMAS", exists=True, dir_okay=False,
                                                    help="Taxonomy TOML (env PDH_SCHEMAS); default: the packaged one.")] = None,
    version: Annotated[Optional[bool], typer.Option("--version", callback=_version, is_eager=True,
                                                    help="Show the version.")] = None,
) -> None:
    """Practical Digital Housekeeping: keep your digital life in order, starting with your password database."""
    ctx.obj = c.AppState(db=db, key=key, schemas=schemas)


@app.command("backends")
def list_backends() -> None:
    """List the installed backends and whether their dependencies are present."""
    for b in backends.available():
        typer.echo(f"{b.name:10} {b.detail}")
