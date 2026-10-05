"""`pdh edit`: changes to the vault. Every command is a dry run unless --apply; backups are the owner's job."""
from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from .. import attachments as attachments_mod
from .. import entries as entries_mod
from .. import history as history_mod
from .. import secret_fields as secret_fields_mod
from .. import fix as fix_mod
from .. import groups as groups_mod
from .. import organize as organize_mod
from .. import write as write_mod
from ..models import FillItem, FillReport
from ..render import Format
from cprima_pdh_vault.vault import as_vault
from .. import generate as generate_mod
from . import _common as c
from . import _generator as g

app = typer.Typer(no_args_is_help=True, help="Change the vault. Dry run unless --apply.")

EntryPath = Annotated[str, typer.Argument(help="Entry as `group/path/title` (as printed by check).")]
Username = Annotated[Optional[str], typer.Option("--username", help="Pick among entries sharing the path.")]


def _vault(ctx: typer.Context):
    st = c.state(ctx)
    db = c.require_db(st)
    return db, (lambda: c.open_kdbx(st, db))


def _refused(exc: Exception) -> None:
    c.fail(f"write refused: {exc}")


@app.command("set")
def set_field(
    ctx: typer.Context,
    path: EntryPath,
    field: Annotated[str, typer.Argument(help="Title, UserName, Password, URL, Notes, otp or a custom field.")],
    value: Annotated[str, typer.Argument(help="New value; `-` prompts (hidden) instead, and is the only way to give a secret.")],
    fmt: c.Fmt = Format.text,
    apply: c.Apply = False,
    overwrite: Annotated[bool, typer.Option("--overwrite", help="Replace a non-empty value.")] = False,
    protect: Annotated[bool, typer.Option("--protect", help="Mark a custom field as protected.")] = False,
    unprotect: Annotated[bool, typer.Option("--unprotect", help="Remove the protection of a custom field.")] = False,
    username: Username = None,
) -> None:
    """Set one field on one entry. An existing protection is kept unless --unprotect; the old state goes to the history."""
    if protect and unprotect:
        c.fail("--protect and --unprotect exclude each other")
    literal = value != "-"
    if not literal:
        value = typer.prompt("Value", hide_input=True, err=True)
    sset = c.load_taxonomy(c.state(ctx))
    db, opener = _vault(ctx)
    try:
        change = write_mod.set_field(opener, db, path, field, value, overwrite, protect, username, unprotect, literal, sset,
                                     apply)
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
        change = write_mod.link_entries(opener, db, account, target, field, plain, overwrite, account_username,
                                        target_username, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)
    if change.action.startswith("skipped"):
        raise typer.Exit(1)


@app.command("delete")
def delete(ctx: typer.Context, path: EntryPath, fmt: c.Fmt = Format.text, apply: c.Apply = False,
           username: Username = None) -> None:
    """Move an entry to the recycle bin (never a permanent delete)."""
    db, opener = _vault(ctx)
    try:
        change = entries_mod.delete_entry(opener, db, path, apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("restore")
def restore(
    ctx: typer.Context, path: EntryPath, fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None,
    to: Annotated[Optional[str], typer.Option("--to", help="Group to restore into (else where a client recorded it).")] = None,
) -> None:
    """Move an entry out of the recycle bin."""
    db, opener = _vault(ctx)
    try:
        change = entries_mod.restore_entry(opener, db, path, apply, to, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("purge")
def purge(ctx: typer.Context, path: EntryPath, fmt: c.Fmt = Format.text, apply: c.Apply = False,
          username: Username = None) -> None:
    """Delete an entry permanently; only entries already in the recycle bin."""
    db, opener = _vault(ctx)
    try:
        change = entries_mod.purge_entry(opener, db, path, apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("tags")
def tags(
    ctx: typer.Context, path: EntryPath, fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None,
    add: Annotated[Optional[list[str]], typer.Option("--add", help="Tag to add (repeat for several).")] = None,
    remove: Annotated[Optional[list[str]], typer.Option("--remove", help="Tag to remove (repeat for several).")] = None,
) -> None:
    """Add or remove tags on an entry (the previous state is kept in its history)."""
    if not add and not remove:
        c.fail("nothing to do: give --add and/or --remove")
    db, opener = _vault(ctx)
    try:
        change = entries_mod.change_tags(opener, db, path, add or [], remove or [], apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("expiry")
def expiry(
    ctx: typer.Context, path: EntryPath,
    date: Annotated[Optional[str], typer.Argument(help="YYYY-MM-DD (midnight UTC).")] = None,
    fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None,
    clear: Annotated[bool, typer.Option("--clear", help="Remove the expiry.")] = False,
) -> None:
    """Set or clear the expiry date of an entry."""
    db, opener = _vault(ctx)
    try:
        change = entries_mod.set_expiry(opener, db, path, date, clear, apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("clone")
def clone(
    ctx: typer.Context, path: EntryPath, fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None,
    title: Annotated[Optional[str], typer.Option("--title", help="Title of the copy (default: '<title> - copy').")] = None,
) -> None:
    """Duplicate an entry next to the original (new UUID; fields, tags, expiry and attachments are copied)."""
    db, opener = _vault(ctx)
    try:
        change = entries_mod.clone_entry(opener, db, path, title, apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("icon")
def icon(ctx: typer.Context, path: EntryPath,
         icon_number: Annotated[int, typer.Argument(help="Standard icon number, 0..68.")],
         fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None) -> None:
    """Set the icon of an entry."""
    db, opener = _vault(ctx)
    try:
        change = entries_mod.set_icon(opener, db, path, icon_number, apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("color")
def color(
    ctx: typer.Context, path: EntryPath, fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None,
    fg: Annotated[Optional[str], typer.Option("--fg", help="Foreground, #RRGGBB.")] = None,
    bg: Annotated[Optional[str], typer.Option("--bg", help="Background, #RRGGBB.")] = None,
    clear: Annotated[bool, typer.Option("--clear", help="Remove both colours.")] = False,
) -> None:
    """Set the colours of an entry."""
    db, opener = _vault(ctx)
    try:
        change = entries_mod.set_color(opener, db, path, fg, bg, clear, apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("override-url")
def override_url(ctx: typer.Context, path: EntryPath,
                 url: Annotated[str, typer.Argument(help="URL (or command) to open instead; empty removes it.")],
                 fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None) -> None:
    """Set the URL override of an entry."""
    db, opener = _vault(ctx)
    try:
        change = entries_mod.set_override_url(opener, db, path, url, apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("autotype")
def autotype(
    ctx: typer.Context, path: EntryPath, fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None,
    enabled: Annotated[Optional[bool], typer.Option("--enabled/--disabled", help="Switch auto-type on or off.")] = None,
    sequence: Annotated[Optional[str], typer.Option("--sequence", help="Auto-type keystroke sequence.")] = None,
) -> None:
    """Enable, disable or set the auto-type sequence of an entry."""
    db, opener = _vault(ctx)
    try:
        change = entries_mod.set_autotype(opener, db, path, enabled, sequence, apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("history-restore")
def history_restore(ctx: typer.Context, path: EntryPath,
                    index: Annotated[int, typer.Argument(help="Which snapshot, from `inspect history` (0 is the oldest).")],
                    fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None) -> None:
    """Restore an entry to one of its history snapshots (the current state goes to the history first)."""
    db, opener = _vault(ctx)
    try:
        change = history_mod.restore_history(opener, db, path, index, apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("history-prune")
def history_prune(
    ctx: typer.Context, fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None,
    path: Annotated[Optional[str], typer.Argument(help="One entry; default every entry.")] = None,
    keep: Annotated[int, typer.Option("--keep", help="Snapshots to keep per entry (the newest).")] = 0,
) -> None:
    """Remove old history snapshots: old values (passwords included) live there."""
    db, opener = _vault(ctx)
    try:
        plan = history_mod.prune_history(opener, db, keep, apply, path, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(plan, fmt)


@app.command("attach")
def attach(ctx: typer.Context, path: EntryPath, file: Annotated[Path, typer.Argument(help="The file to attach.")],
           fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None,
           name: Annotated[Optional[str], typer.Option("--name", help="Attachment name (default: the file name).")] = None) -> None:
    """Attach a file to an entry."""
    db, opener = _vault(ctx)
    try:
        change = attachments_mod.attach_file(opener, db, path, file, apply, name, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("detach")
def detach(ctx: typer.Context, path: EntryPath, name: Annotated[str, typer.Argument(help="Attachment name.")],
           fmt: c.Fmt = Format.text, apply: c.Apply = False, username: Username = None) -> None:
    """Remove an attachment from an entry."""
    db, opener = _vault(ctx)
    try:
        change = attachments_mod.detach_file(opener, db, path, name, apply, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


GroupPath = Annotated[str, typer.Argument(help="Group path as shown by `pdh inspect tree`.")]


@app.command("rename-group")
def rename_group(ctx: typer.Context, group: GroupPath, name: Annotated[str, typer.Argument(help="New name.")],
                 fmt: c.Fmt = Format.text, apply: c.Apply = False) -> None:
    """Rename a group."""
    db, opener = _vault(ctx)
    try:
        change = groups_mod.rename_group(opener, db, group, name, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("move-group")
def move_group(ctx: typer.Context, group: GroupPath, dest: Annotated[str, typer.Argument(help="New parent group.")],
               fmt: c.Fmt = Format.text, apply: c.Apply = False,
               cross_top_level: Annotated[bool, typer.Option("--cross-top-level", help="Allow moving between top-level groups.")] = False) -> None:
    """Move a group, with everything in it, below another group."""
    db, opener = _vault(ctx)
    try:
        change = groups_mod.move_group(opener, db, group, dest, apply, cross_top_level)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("delete-group")
def delete_group(ctx: typer.Context, group: GroupPath, fmt: c.Fmt = Format.text, apply: c.Apply = False) -> None:
    """Move a group, with everything in it, to the recycle bin."""
    db, opener = _vault(ctx)
    try:
        change = groups_mod.delete_group(opener, db, group, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("group-notes")
def group_notes(ctx: typer.Context, group: GroupPath, text: Annotated[str, typer.Argument(help="The notes of the group.")],
                fmt: c.Fmt = Format.text, apply: c.Apply = False) -> None:
    """Set the notes of a group."""
    db, opener = _vault(ctx)
    try:
        change = groups_mod.set_group_notes(opener, db, group, text, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("group-icon")
def group_icon(ctx: typer.Context, group: GroupPath, icon_number: Annotated[int, typer.Argument(help="Standard icon number, 0..68.")],
               fmt: c.Fmt = Format.text, apply: c.Apply = False) -> None:
    """Set the icon of a group."""
    db, opener = _vault(ctx)
    try:
        change = groups_mod.set_group_icon(opener, db, group, icon_number, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


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
    """Rename a custom field, keeping value and protection: on one entry, or with --all on every entry. Each changed
    entry keeps its previous state in the history."""
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
    """Apply the vocabulary to every entry: canonical names and fixed protection. Each changed entry keeps its
    previous state in the history (undo with history-restore, trim with history-prune)."""
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
    apply: c.Apply = False,
    url: Annotated[Optional[str], typer.Option("--url", help="The entry's URL.")] = None,
    notes: Annotated[Optional[str], typer.Option("--notes", help="The entry's notes.")] = None,
    tag: Annotated[Optional[list[str]], typer.Option("--tag", help="A tag (repeat for several).")] = None,
    expires: Annotated[Optional[str], typer.Option("--expires", help="Expiry date, YYYY-MM-DD.")] = None,
    field: Annotated[Optional[list[str]], typer.Option("--field", help="A custom field NAME=VALUE (repeat); a field that "
                                                       "holds a secret is refused: add it with `pdh edit set PATH FIELD -`.")] = None,
) -> None:
    """Create an entry in one call: structure only. Its password is asked for with a hidden prompt when there is a terminal
    (Enter leaves it empty); without a terminal the entry is created without one. A secret is never an argument: add it with
    `pdh edit set PATH FIELD -`."""
    password = ""
    if apply and c._has_console():
        password = typer.prompt("Password (empty for none)", hide_input=True, default="", show_default=False,
                                confirmation_prompt=True, err=True)

    def pairs(items: list[str] | None, what: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for item in items or []:
            name, sep, value = item.partition("=")
            if not sep or not name:
                c.fail(f"{what} needs NAME=VALUE, got {item!r}")
            out[name] = value
        return out

    fields = pairs(field, "--field")
    db, opener = _vault(ctx)
    try:
        change = organize_mod.new_entry(opener, db, group, title, username, password, apply, url, notes, tag, expires,
                                        fields, c.load_taxonomy(c.state(ctx)))
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(change, fmt)


@app.command("fill")
def fill(
    ctx: typer.Context,
    path: Annotated[str, typer.Argument(help="An entry (`group/title`) or a group: every entry below it is filled.")],
    fmt: c.Fmt = Format.text,
    apply: c.Apply = False,
    generate: Annotated[bool, typer.Option("--generate", help="Generate the fields the taxonomy allows to be generated "
                                           "(passwords, made-up keys) and store them without showing them; ask for the "
                                           "rest.")] = False,
    length: g.Length = g.DEFAULTS.length,
    lower: g.Lower = True,
    upper: g.Upper = True,
    numeric: g.Numeric = True,
    special: g.Special = False,
    extended: g.Extended = False,
    space: g.Space = False,
    include: g.Include = "",
    exclude: g.Exclude = "",
    exclude_similar: g.ExcludeSimilar = g.DEFAULTS.exclude_similar,
    every_group: g.EveryGroup = g.DEFAULTS.every_group,
    username: Username = None,
) -> None:
    """Fill the secret fields that an entry (or every entry below a group) still lacks. The taxonomy decides which fields
    are secret and in what order they come. Without --apply it only lists what is missing and asks nothing. With --apply each
    field is asked for with a hidden prompt (Enter skips it); with --generate the ones that may be generated are generated
    and stored without being shown, so you read them in your KeePass client, for example to paste into a registration form.
    A secret is never an argument, and everything is written in one go, one history snapshot per entry. The options that
    shape a generated password are those of `pdh generate`."""
    try:
        settings = g.password_settings(length, lower, upper, numeric, special, extended, space, include, exclude,
                                       exclude_similar, every_group)
        generate_mod.check(settings)  # a setting that cannot make a password is refused before anything is opened or asked
    except ValueError as exc:
        c.fail(f"write refused: {exc}", 2)
    st = c.state(ctx)
    db = c.require_db(st)
    sset = c.load_taxonomy(st)
    kp = c.open_kdbx(st, db)
    try:
        targets = secret_fields_mod.fill_targets(as_vault(kp), path, sset, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    pairs = [(t, f) for t in targets for f in t.fields]

    def report(items: list[FillItem], applied: bool) -> FillReport:
        count = lambda how: sum(1 for i in items if i.how == how)  # noqa: E731
        return FillReport(target=path, entries=len(targets), fields=len(pairs), generated=count("generated"),
                          typed=count("typed"), skipped=count("skipped"), items=items, applied=applied)

    if not apply:
        c.emit(report([FillItem(entry=t.entry.path, field=f.name,
                                how="to generate" if generate and f.generatable else "to type") for t, f in pairs], False), fmt)
        return
    if not pairs:
        c.emit(report([], False), fmt)
        return
    console = c._has_console()
    if not console and not (generate and any(f.generatable for _, f in pairs)):
        c.fail("write refused: there is no terminal to ask on; --generate fills the fields that may be generated", 2)
    ask = (lambda t, f: typer.prompt(f"{t.entry.path}: {f.name} (Enter to skip)", hide_input=True, default="",
                                     show_default=False, err=True)) if console else None
    values, items = secret_fields_mod.collect(pairs, generate, settings, ask)
    applied = False
    if values:
        try:
            applied = secret_fields_mod.fill_entries(lambda: kp, db, values, True, sset).applied
        except write_mod.WriteError as exc:
            _refused(exc)
    c.emit(report(items, applied), fmt)


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
