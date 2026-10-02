"""`pdh method`: the methodology itself. No vault and no backend needed."""
from __future__ import annotations

import typer

from .. import schema
from .. import taxonomy as taxonomy_mod
from ..render import Format
from . import _common as c

app = typer.Typer(no_args_is_help=True, help="The method: taxonomy, record types, vocabulary. No vault needed.")


@app.command()
def show(ctx: typer.Context, fmt: c.Fmt = Format.markdown) -> None:
    """The taxonomy document (principles, areas, record types, field kinds, vocabulary, decisions)."""
    c.emit(taxonomy_mod.build(c.load_taxonomy(c.state(ctx))), fmt)


@app.command()
def schemas(ctx: typer.Context, fmt: c.Fmt = Format.text) -> None:
    """The rules compiled from the taxonomy, per record type, and the vocabulary."""
    c.emit(schema.describe(c.load_taxonomy(c.state(ctx))), fmt)
