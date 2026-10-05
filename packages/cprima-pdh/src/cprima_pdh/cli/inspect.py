"""`pdh inspect`: read-only views of a vault. Nothing here saves the vault or writes files."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

import typer

from .. import attachments as attachments_mod
from .. import history as history_mod
from .. import infer as infer_mod
from .. import schema, source
from .. import tree as tree_mod
from ..models import EntryList, TagCounts
from ..render import Format
from . import _common as c

app = typer.Typer(no_args_is_help=True, help="Read-only views of a vault.")


def _guarded(action):
    from ..write import WriteError

    try:
        return action()
    except WriteError as exc:
        c.fail(f"not found: {exc}", 1)


def _kp(ctx: typer.Context):
    """The vault of the command (any backend); the engine reads it through its snapshots."""
    st = c.state(ctx)
    return c.open_vault(st, c.require_db(st), st.key)


def _kdbx(ctx: typer.Context, capability: str):
    """The KeePass database behind the vault, for what the engine cannot yet do on snapshots; refuses other backends."""
    from cprima_pdh_vault.vault import Unsupported, require

    vault = _kp(ctx)
    try:
        require(vault, capability)
    except Unsupported as exc:
        c.fail(str(exc), 2)
    return vault.kp


@app.command()
def inventory(ctx: typer.Context, fmt: c.Fmt = Format.text) -> None:
    """Counts and quality metrics for the whole vault (no secrets)."""
    c.emit(source.inventory(_kp(ctx), c.state(ctx).db), fmt)


@app.command()
def tree(
    ctx: typer.Context,
    fmt: c.Fmt = Format.text,
    entries: Annotated[bool, typer.Option("--entries", help="Also list entries with their record types.")] = False,
    ascii_only: Annotated[bool, typer.Option("--ascii", help="ASCII tree characters.")] = False,
    depth: Annotated[Optional[int], typer.Option("--depth", min=1, help="Levels below the root to show.")] = None,
) -> None:
    """The groups seen through the method: owner (level 1), area (level 2), total entries and how many are typed,
    and what the method would not expect (an entry outside an owner, a group that is not an area). The recycle bin
    is shown last and not counted."""
    c.emit(tree_mod.build(_kp(ctx), c.load_taxonomy(c.state(ctx)), entries, depth), fmt, ascii_only)


@app.command("entries")
def list_entries(
    ctx: typer.Context,
    fmt: c.Fmt = Format.text,
    expired: Annotated[bool, typer.Option("--expired", help="Entries past their expiry date.")] = False,
    expiring: Annotated[Optional[int], typer.Option("--expiring", min=0, help="Entries expiring within this many days.")] = None,
) -> None:
    """List all entries, or only those that have expired and/or expire soon."""
    records = source.records(_kp(ctx))
    if expired or expiring is not None:
        now = datetime.now(timezone.utc)
        horizon = now + timedelta(days=expiring) if expiring is not None else None

        def wanted(r) -> bool:
            if r.expires is None:
                return False
            return (expired and r.expires < now) or (horizon is not None and now <= r.expires <= horizon)

        records = [r for r in records if wanted(r)]
    c.emit(EntryList(entries=records), fmt)


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
def find(
    ctx: typer.Context, text: str, fmt: c.Fmt = Format.text,
    in_fields: Annotated[bool, typer.Option("--in-fields", help="Search custom field names and values instead "
                                            "(protected ones too; values are never printed).")] = False,
) -> None:
    """Entries whose title, username, URL or notes contain TEXT (or, with --in-fields, a custom field does)."""
    needle = text.lower()

    def match(e) -> bool:
        if in_fields:
            return any(needle in k.lower() or needle in f.value.lower() for k, f in e.fields.items())
        return any(needle in v.lower() for v in (e.title, e.username, e.url, e.notes))

    c.emit(EntryList(entries=source.records(_kp(ctx), match)), fmt)


@app.command("history")
def history(ctx: typer.Context, path: Annotated[str, typer.Argument(help="Entry as `group/path/title`.")],
            fmt: c.Fmt = Format.text,
            username: Annotated[Optional[str], typer.Option("--username", help="Pick among entries sharing the path.")] = None) -> None:
    """The history of an entry: when it changed and which fields, never the values."""
    c.emit(_guarded(lambda: history_mod.history_report(_kdbx(ctx, "history"), path, username)), fmt)


@app.command("otp")
def otp_code(ctx: typer.Context, path: Annotated[str, typer.Argument(help="Entry as `group/path/title`.")],
             fmt: c.Fmt = Format.text,
             username: Annotated[Optional[str], typer.Option("--username", help="Pick among entries sharing the path.")] = None) -> None:
    """The current one-time password of an entry: the code and its remaining seconds, never the secret."""
    from .. import otp as otp_mod
    from cprima_pdh_vault.vault import as_vault

    try:
        e = as_vault(_kp(ctx)).find_entry(path, username)
    except LookupError as exc:  # no such entry, or several: say so
        c.fail(f"not found: {exc.args[0] if exc.args else exc}", 1)
    params = None
    try:
        if e.otp:
            params = otp_mod.parse(e.otp)
        else:
            params = otp_mod.from_plugin_fields({k: f.value for k, f in e.fields.items()})
    except ValueError as exc:
        c.fail(f"{path}: {exc}", 1)
    if params is None:
        c.fail(f"{path} has no one-time password", 1)
    c.emit(otp_mod.code(params), fmt)


@app.command("attachments")
def attachments(ctx: typer.Context, path: Annotated[str, typer.Argument(help="Entry as `group/path/title`.")],
                fmt: c.Fmt = Format.text,
                username: Annotated[Optional[str], typer.Option("--username", help="Pick among entries sharing the path.")] = None) -> None:
    """The attachments of an entry: name and size, never the content."""
    c.emit(_guarded(lambda: attachments_mod.attachments_report(_kdbx(ctx, "attachments"), path, username)), fmt)


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
