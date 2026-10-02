"""`pdh inspect`: read-only views of a vault. Nothing here saves the vault or writes files."""
from __future__ import annotations

from collections import Counter
from typing import Annotated, Optional

import typer

from .. import infer as infer_mod
from .. import schema, source
from ..models import EntryList, TagCounts
from ..render import Format
from . import _common as c

app = typer.Typer(no_args_is_help=True, help="Read-only views of a vault.")


def _kp(ctx: typer.Context):
    st = c.state(ctx)
    return c.open_db(c.require_db(st), st.key)


@app.command()
def inventory(ctx: typer.Context, fmt: c.Fmt = Format.text) -> None:
    """Counts and quality metrics for the whole vault (no secrets)."""
    c.emit(source.inventory(_kp(ctx), c.state(ctx).db), fmt)


@app.command()
def tree(
    ctx: typer.Context,
    fmt: c.Fmt = Format.text,
    entries: Annotated[bool, typer.Option("--entries", help="Also list entry titles.")] = False,
    ascii_only: Annotated[bool, typer.Option("--ascii", help="ASCII tree characters.")] = False,
) -> None:
    """Group hierarchy with entry counts."""
    c.emit(source.tree(_kp(ctx), entries), fmt, ascii_only)


@app.command("entries")
def list_entries(ctx: typer.Context, fmt: c.Fmt = Format.text) -> None:
    """List all entries."""
    c.emit(EntryList(entries=source.records(_kp(ctx))), fmt)


@app.command()
def tags(ctx: typer.Context, fmt: c.Fmt = Format.text) -> None:
    """All tags with entry counts."""
    recs = source.records(_kp(ctx))
    counts = Counter(t for r in recs for t in r.tags)
    c.emit(TagCounts(tags=dict(counts), untagged_entries=sum(1 for r in recs if not r.tags)), fmt)


@app.command()
def totp(ctx: typer.Context, fmt: c.Fmt = Format.text) -> None:
    """Entries with TOTP/HOTP configured (secrets not shown)."""
    c.emit(EntryList(entries=[r for r in source.records(_kp(ctx)) if r.totp_style]), fmt)


@app.command()
def find(ctx: typer.Context, text: str, fmt: c.Fmt = Format.text) -> None:
    """Entries whose title, username, URL or notes contain TEXT."""
    needle = text.lower()

    def match(e) -> bool:
        return any(needle in (v or "").lower() for v in (e.title, e.username, e.url, e.notes))

    c.emit(EntryList(entries=source.records(_kp(ctx), match)), fmt)


@app.command()
def show(
    ctx: typer.Context,
    title: str,
    fmt: c.Fmt = Format.text,
    show_password: Annotated[bool, typer.Option("--show-password")] = False,
) -> None:
    """One entry in full; password masked unless --show-password."""
    d = source.detail(_kp(ctx), title, show_password)
    if d is None:
        c.fail("not found", 1)
    c.emit(d, fmt)


@app.command("read")
def read_typed(
    ctx: typer.Context,
    fmt: c.Fmt = Format.text,
    only: Annotated[Optional[str], typer.Option("--schema", help="Only this schema.")] = None,
) -> None:
    """Entries as typed records of their schema (protected values not shown)."""
    c.emit(schema.read(_kp(ctx), c.load_taxonomy(c.state(ctx)), only), fmt)


@app.command()
def links(ctx: typer.Context, fmt: c.Fmt = Format.text) -> None:
    """Every link between entries with its status, and how many links each target receives."""
    c.emit(schema.links_report(_kp(ctx), c.load_taxonomy(c.state(ctx))), fmt)


@app.command()
def unclassified(
    ctx: typer.Context,
    fmt: c.Fmt = Format.text,
    entries: Annotated[bool, typer.Option("--entries", help="Also list every entry.")] = False,
) -> None:
    """Entries without a valid `_schema` field (the seeding to-do list), counted per group."""
    c.emit(schema.unclassified(_kp(ctx), c.load_taxonomy(c.state(ctx)), entries), fmt)


@app.command()
def fields(ctx: typer.Context, fmt: c.Fmt = Format.text) -> None:
    """Per-group field profile (names and counts only)."""
    c.emit(infer_mod.infer(_kp(ctx)), fmt)
