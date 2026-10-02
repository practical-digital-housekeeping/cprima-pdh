"""`pdh edit`: changes to the vault. Every command is a dry run unless --apply; backups are the owner's job."""
from __future__ import annotations

import os
from typing import Annotated, Optional

import typer

from .. import fix as fix_mod
from .. import organize as organize_mod
from .. import write as write_mod
from ..render import Format
from . import _common as c

app = typer.Typer(no_args_is_help=True, help="Change the vault. Dry run unless --apply.")

EntryPath = Annotated[str, typer.Argument(help="Entry as `group/path/title` (as printed by check).")]
Username = Annotated[Optional[str], typer.Option("--username", help="Pick among entries sharing the path.")]


def _vault(ctx: typer.Context):
    st = c.state(ctx)
    db = c.require_db(st)
    return db, (lambda: c.open_db(db, st.key))


def _refused(exc: Exception) -> None:
    c.fail(f"write refused: {exc}")


@app.command("set")
def set_field(
    ctx: typer.Context,
    path: EntryPath,
    field: Annotated[str, typer.Argument(help="Title, UserName, Password, URL, Notes, otp or a custom field.")],
    value: Annotated[str, typer.Argument(help="New value; `-` prompts (hidden) instead.")],
    fmt: c.Fmt = Format.text,
    apply: c.Apply = False,
    overwrite: Annotated[bool, typer.Option("--overwrite", help="Replace a non-empty value.")] = False,
    protect: Annotated[bool, typer.Option("--protect", help="Mark a custom field as protected.")] = False,
    username: Username = None,
) -> None:
    """Set one field on one entry."""
    if value == "-":
        value = typer.prompt("Value", hide_input=True, err=True)
    db, opener = _vault(ctx)
    try:
        if apply:
            change = write_mod.apply_set(opener, db, path, field, value, overwrite, protect, username)
        else:
            change = write_mod.plan_set(opener(), path, field, value, overwrite, protect, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)
    if change.action.startswith("skipped"):
        raise typer.Exit(1)


@app.command()
def link(
    ctx: typer.Context,
    account: Annotated[str, typer.Argument(help="The entry that gets the link, as `group/path/title`.")],
    target: Annotated[str, typer.Argument(help="The entry it points to (a device, for example).")],
    fmt: c.Fmt = Format.text,
    field: Annotated[str, typer.Option("--field", help="The link field.")] = "device",
    plain: Annotated[bool, typer.Option("--plain", help="Store the bare UUID instead of a KeePass reference.")] = False,
    overwrite: Annotated[bool, typer.Option("--overwrite", help="Replace an existing, different link.")] = False,
    apply: c.Apply = False,
    account_username: Annotated[Optional[str], typer.Option("--account-username", help="Pick the account by username.")] = None,
    target_username: Annotated[Optional[str], typer.Option("--target-username", help="Pick the target by username.")] = None,
) -> None:
    """Link an entry to another one by UUID (a KeePass reference)."""
    db, opener = _vault(ctx)
    try:
        if apply:
            change = write_mod.apply_link(opener, db, account, target, field, plain, overwrite,
                                          account_username, target_username)
        else:
            change = write_mod.plan_link(opener(), account, target, field, plain, overwrite,
                                         account_username, target_username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)
    if change.action.startswith("skipped"):
        raise typer.Exit(1)


@app.command("rename-field")
def rename_field(
    ctx: typer.Context,
    names: Annotated[list[str], typer.Argument(
        help="PATH OLD NEW for one entry (`group/path/title`, as printed by check); with --all just OLD NEW.")],
    fmt: c.Fmt = Format.text,
    apply: c.Apply = False,
    username: Username = None,
    all_entries: Annotated[bool, typer.Option("--all", help="Every live entry that has the field, not one entry.")] = False,
    under: Annotated[Optional[str], typer.Option(
        "--under", help="With --all: only entries below this group (e.g. one owner).")] = None,
) -> None:
    """Rename a custom field, keeping value and protection: on one entry, or with --all on every entry."""
    wanted = 2 if all_entries else 3
    if len(names) != wanted:
        c.fail(f"expected {'OLD NEW' if all_entries else 'PATH OLD NEW'}, got {len(names)} argument(s)")
    if (under is not None and not all_entries) or (username is not None and all_entries):
        c.fail("--under belongs to --all; --username to a single entry")
    db, opener = _vault(ctx)
    try:
        if all_entries:
            plan = fix_mod.rename_field_all(opener, db, names[0], names[1], apply, under)
        else:
            plan = fix_mod.rename_field(opener, db, names[0], names[1], names[2], apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(plan, fmt)


@app.command()
def vocabulary(
    ctx: typer.Context,
    fmt: c.Fmt = Format.text,
    apply: c.Apply = False,
    renames: Annotated[bool, typer.Option("--renames/--no-renames", help="Rename aliases to the canonical name.")] = True,
    protection: Annotated[bool, typer.Option("--protection/--no-protection", help="Set each term's fixed protection.")] = True,
) -> None:
    """Apply the vocabulary to every entry: canonical names and fixed protection."""
    db, opener = _vault(ctx)
    try:
        plan = fix_mod.run_fix(opener, db, c.load_taxonomy(c.state(ctx)), apply, renames, protection)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(plan, fmt)


@app.command("new-entry")
def new_entry(
    ctx: typer.Context,
    group: Annotated[str, typer.Argument(help="Group path as shown by `pdh inspect tree`.")],
    title: Annotated[str, typer.Argument(help="Title of the new entry.")],
    username: Annotated[str, typer.Argument(help="UserName.")],
    fmt: c.Fmt = Format.text,
    password_env: Annotated[str, typer.Option("--password-env", help="Environment variable holding the password.")] = "PDH_NEW_PASSWORD",
    apply: c.Apply = False,
) -> None:
    """Create an entry with standard fields. The password comes from an environment variable, never from argv."""
    password = os.environ.get(password_env, "")
    if not password:
        c.fail(f"write refused: environment variable {password_env} is empty")
    db, opener = _vault(ctx)
    try:
        change = organize_mod.new_entry(opener, db, group, title, username, password, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("new-group")
def new_group(
    ctx: typer.Context,
    parent: Annotated[str, typer.Argument(help="Parent group path as shown by `pdh inspect tree`; '/' is the root.")],
    name: Annotated[str, typer.Argument(help="Name of the new group.")],
    fmt: c.Fmt = Format.text,
    apply: c.Apply = False,
) -> None:
    """Create a group."""
    db, opener = _vault(ctx)
    try:
        change = organize_mod.new_group(opener, db, parent, name, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command()
def move(
    ctx: typer.Context,
    path: EntryPath,
    dest: Annotated[str, typer.Argument(help="Destination group path, as shown by `pdh inspect tree`.")],
    fmt: c.Fmt = Format.text,
    apply: c.Apply = False,
    username: Username = None,
    cross_top_level: Annotated[
        bool, typer.Option("--cross-top-level", help="Allow moving between top-level groups (owners).")
    ] = False,
) -> None:
    """Move one entry to another group (its UUID is kept). Stays inside one top-level group by default."""
    db, opener = _vault(ctx)
    try:
        change = organize_mod.move_entry(opener, db, path, dest, apply, username, cross_top_level)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)
