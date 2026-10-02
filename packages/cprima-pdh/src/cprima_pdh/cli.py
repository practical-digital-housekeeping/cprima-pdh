"""The `pdh` command. 0.0.x is a placeholder: final shape, no operation on any vault."""
from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from . import __version__, backends

app = typer.Typer(no_args_is_help=True, help="Practical Digital Housekeeping. Keep it tidy. Keep it trustworthy.")


def _version(value: bool) -> None:
    if value:
        typer.echo(f"pdh {__version__} (cprima-pdh, Practical Digital Housekeeping)")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool], typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")
    ] = None,
) -> None:
    """Practical Digital Housekeeping: keep your digital life in order, starting with your password database."""


@app.command("backends")
def list_backends() -> None:
    """List the installed backends and whether their dependencies are present."""
    for b in backends.available():
        typer.echo(f"{b.name:10} {b.detail}")


@app.command()
def check(
    path: Annotated[Path, typer.Argument(help="The store to check, e.g. vault.kdbx.")],
) -> None:
    """Check a store against the method. Not implemented yet: the store is never opened."""
    try:
        name = backends.for_path(path)
        backends.load(name)
    except backends.BackendMissing as exc:
        typer.echo(f"pdh: {exc}", err=True)
        raise typer.Exit(2)
    typer.echo(f"pdh {__version__}: backend {name} is ready; check is not implemented yet. {path.name} was not opened.")
