"""`pdh io`: moving data in and out. The exports are the only commands that write outside the vault (only to --out)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Optional

import typer

from .. import export as export_mod
from .. import source as source_mod
from .. import transfer as transfer_mod
from .. import write as write_mod
from ..render import Format
from . import _common as c

app = typer.Typer(no_args_is_help=True, help="Import, merge and export.")

Out = Annotated[Path, typer.Option("--out", help="The file to write; an existing file is never overwritten.")]
Username = Annotated[Optional[str], typer.Option("--username", help="Pick among entries sharing the path.")]


def _kp(ctx: typer.Context):
    st = c.state(ctx)
    return c.open_kdbx(st, c.require_db(st))


def _refused(exc: Exception) -> None:
    c.fail(f"write refused: {exc}")


def _vault(ctx: typer.Context):
    st = c.state(ctx)
    db = c.require_db(st)
    return db, (lambda: c.open_kdbx(st, db))


IMPORT_PASSWORD = "PDH_IMPORT_PASSWORD"  # the other vault's master passphrase: one fixed variable per role, no pointer option
NEW_PASSWORD = "PDH_NEW_PASSWORD"  # the master passphrase of a vault being written (a copy)


def _other(path: Path, keyfile: Optional[Path], fallback=None):
    """An opener for another vault: its passphrase from PDH_IMPORT_PASSWORD, else its sidecar, else what
    `fallback()` offers (the local vault's own credentials, for a merge), else a hidden prompt."""
    if not path.is_file():
        c.fail(f"write refused: {path} is not a file")
    password = os.environ.get(IMPORT_PASSWORD, "") or source_mod.sidecar_password(path)
    key = str(keyfile) if keyfile else None
    if not password and fallback is not None:
        password, key = fallback()
    if not password:
        if not c._has_console():
            c.fail(f"write refused: {IMPORT_PASSWORD} is empty and there is no terminal to ask on")
        password = typer.prompt(f"Master password of {path.name}", hide_input=True, err=True)

    def opener():
        try:
            return source_mod.pykeepass_open(path, password, key)
        except Exception as exc:  # noqa: BLE001 - a wrong password or a damaged file: say so, never a traceback
            c.fail(f"write refused: cannot open {path.name}: {exc}")

    return opener


OtherKeyfile = Annotated[Optional[Path], typer.Option("--keyfile", help="Key file of the other vault.")]


@app.command("import-csv")
def import_csv(
    ctx: typer.Context, file: Annotated[Path, typer.Argument(help="CSV file to read (UTF-8, with a header row).")],
    fmt: c.Fmt = Format.text, apply: c.Apply = False,
    group: Annotated[str, typer.Option("--group", help="Group the rows go below (created if missing).")] = "Imported",
) -> None:
    """Add the rows of a CSV file as entries. Columns: Group, Title (required), UserName, URL, Notes, Tags (`a;b`),
    Expires (YYYY-MM-DD); any other column becomes a custom field. A column for a secret (a password, an otp, anything the
    taxonomy marks protected) is refused: secrets are never read from a file; add them afterwards with `pdh edit set`. The
    report says how many secret fields the new entries still lack. A workbook is read with `import-xlsx`."""
    db, opener = _vault(ctx)
    try:
        result = transfer_mod.import_csv(opener, db, file, group, apply, c.load_taxonomy(c.state(ctx)))
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(result, fmt)


@app.command("import-xlsx")
def import_xlsx(
    ctx: typer.Context, file: Annotated[Path, typer.Argument(help="The .xlsx workbook to read (its first visible sheet, "
                                                                   "header in row 1).")],
    fmt: c.Fmt = Format.text, apply: c.Apply = False,
    group: Annotated[str, typer.Option("--group", help="Group the rows go below (created if missing).")] = "Imported",
) -> None:
    """Add the rows of an .xlsx workbook as entries: the same columns and rules as `import-csv` (Group, Title, UserName, URL,
    Notes, Tags, Expires, any other column as a custom field; a column for a secret is refused). A date cell in Expires is read
    as a date. The workbook is read as data only: formulas are not evaluated (their stored value is read), and a workbook with
    macros or links to other workbooks is refused, as are .xls, .xlsb, .xlsm and .ods files."""
    db, opener = _vault(ctx)
    try:
        result = transfer_mod.import_xlsx(opener, db, file, group, apply, c.load_taxonomy(c.state(ctx)))
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(result, fmt)


@app.command("import-kdbx")
def import_kdbx(
    ctx: typer.Context, file: Annotated[Path, typer.Argument(help="The vault to read.")],
    fmt: c.Fmt = Format.text, apply: c.Apply = False,
    group: Annotated[str, typer.Option("--group", help="Group the entries go below (created if missing).")] = "Imported",
    keyfile: OtherKeyfile = None,
) -> None:
    """Copy the entries of another vault (new UUIDs, group structure kept) below a group; its recycle bin is left out."""
    db, opener = _vault(ctx)
    other = _other(file, keyfile)()
    try:
        result = transfer_mod.import_vault(opener, db, other, str(file), group, apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(result, fmt)


@app.command("merge")
def merge(
    ctx: typer.Context, other: Annotated[Path, typer.Argument(help="The other copy of this vault.")],
    fmt: c.Fmt = Format.text, apply: c.Apply = False,
    keyfile: OtherKeyfile = None,
) -> None:
    """Merge another copy of this vault (a sync conflict): by UUID and modification time, nothing is deleted.
    Without a password for the other copy, this vault's own credentials are tried."""
    db, opener = _vault(ctx)
    local = opener()

    result_opener = _other(other, keyfile, fallback=lambda: (local.password, local.keyfile))
    try:
        result = transfer_mod.merge_vaults(opener, db, result_opener, str(other), apply)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(result, fmt)


@app.command("export-attachment")
def export_attachment(
    ctx: typer.Context,
    path: Annotated[str, typer.Argument(help="Entry as `group/path/title`.")],
    name: Annotated[str, typer.Argument(help="Attachment name.")],
    out: Out,
    fmt: c.Fmt = Format.text,
    username: Username = None,
) -> None:
    """Write one attachment to a file."""
    try:
        result = export_mod.export_attachment(_kp(ctx), path, name, out, username)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(result, fmt)


@app.command("export-csv")
def export_csv(
    ctx: typer.Context, out: Out, fmt: c.Fmt = Format.text,
) -> None:
    """Write the entries (not the recycle bin) to a CSV file for review in a spreadsheet. A secret (a password, an otp, a
    protected field) has no column: pdh never writes a secret to a plaintext file."""
    try:
        result = export_mod.export_csv(_kp(ctx), out, c.load_taxonomy(c.state(ctx)))
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(result, fmt)


@app.command("export-kdbx")
def export_kdbx(
    ctx: typer.Context, out: Out, fmt: c.Fmt = Format.text,
) -> None:
    """Write a copy of the vault under a new master passphrase, from PDH_NEW_PASSWORD or a hidden prompt (the original is not
    touched)."""
    password = os.environ.get(NEW_PASSWORD, "")
    if not password:
        if not c._has_console():
            c.fail(f"write refused: {NEW_PASSWORD} is empty and there is no terminal to ask on")
        password = typer.prompt("Master password of the copy", hide_input=True, confirmation_prompt=True, err=True)
    try:
        result = export_mod.export_kdbx(_kp(ctx), out, password)
    except write_mod.WriteError as exc:
        _refused(exc)
    c.emit(result, fmt)
