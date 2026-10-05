"""Exports: the only things pdh writes outside the vault, and only to the file the owner names with --out.

An existing file is never overwritten. Secrets (passwords, one-time-password secrets, protected custom fields) are in
a CSV export never. Reports name the file and count entries; they never contain a value.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path

from .models import FileWritten
from cprima_pdh_vault.vault import as_vault, require
from .write import WriteError, find_data


def _create_exclusive(out: Path):
    """Open `out` for writing only if it does not exist yet."""
    out = Path(out)
    if not out.parent.is_dir():
        raise WriteError(f"the folder {out.parent} does not exist")
    try:
        return open(out, "xb")
    except FileExistsError:
        raise WriteError(f"{out} exists; pdh never overwrites a file") from None


def export_attachment(source, path: str, name: str, out: Path, username: str | None = None) -> FileWritten:
    """Write one attachment of an entry, byte for byte."""
    vault = as_vault(source)
    require(vault, "attachments")
    e = find_data(vault, path, username)
    if not any(n == name for n, _ in e.attachments):
        raise WriteError(f"{path!r} has no attachment named {name!r}")
    content = vault.attachment(e.id, name)
    with _create_exclusive(out) as f:
        f.write(content)
    return FileWritten(kind="attachment", path=str(out), entries=1, bytes=len(content))


def _live(source):
    return [e for e in as_vault(source).entries() if not e.in_bin]


def export_csv(source, out: Path, sset=None) -> FileWritten:
    """Write the live entries (not the recycle bin) as CSV, for review in a spreadsheet. A secret has no column at all, not an
    empty one: a column for a secret is what `import-csv` refuses (see `boundary`), so the export must be something it
    accepts back. Secret: a field the file protects in any entry, or one `boundary` names (the KDBX ecosystem's, the taxonomy's).
    Cells a spreadsheet would run as a formula (they start with =, +, - or @) are written as text."""
    from . import boundary

    entries = _live(source)
    custom = sorted({k for e in entries for k in e.fields})
    secret = set(boundary.secret_columns(custom, sset)) | {k for e in entries for k, f in e.fields.items() if f.protected}
    custom = [k for k in custom if k not in secret]
    head = ["Group", "Title", "UserName", "URL", "Notes", "Tags", "Expires", *custom]
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(head)
    for e in entries:
        row = [e.group_path, e.title, e.username, e.url, e.notes, ";".join(e.tags),
               e.expiry.date().isoformat() if e.expires and e.expiry else ""]
        row += [e.fields[k].value if k in e.fields else "" for k in custom]
        writer.writerow([_as_text(cell) for cell in row])
    data = buffer.getvalue().encode("utf-8")
    with _create_exclusive(out) as f:
        f.write(data)
    return FileWritten(kind="csv", path=str(out), entries=len(entries), bytes=len(data))


_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _as_text(cell: str) -> str:
    """A cell as text: one that starts like a formula gets a leading apostrophe, so a spreadsheet shows it and does not run it
    (CSV injection). A value that merely starts with a minus sign is rare in these columns, and a visible apostrophe is the
    safe side."""
    return "'" + cell if cell.startswith(_FORMULA_START) else cell


def export_kdbx(source, out: Path, new_password: str) -> FileWritten:
    """Write a copy of the vault under a new master password; the original file is not touched."""
    if not new_password:
        raise WriteError("an empty master password is not accepted")
    if Path(out).exists():
        raise WriteError(f"{out} exists; pdh never overwrites a file")
    vault = as_vault(source)
    require(vault, "credentials")
    total = len(vault.entries())
    vault.set_password(new_password)
    vault.set_keyfile(None)  # the copy needs only its own password
    with _create_exclusive(out):
        pass  # reserve the name atomically; the vault is then written over it
    try:
        vault.save(out)
        again = vault.reopen(out)
        if again.file_problems(out):
            raise WriteError("verification failed: the copy's header does not match its stored hash")
        if len(again.entries()) != total:
            raise WriteError("verification failed: the copy has a different number of entries")
    except Exception:
        Path(out).unlink(missing_ok=True)  # never leave a half-written copy of a vault behind
        raise
    return FileWritten(kind="kdbx", path=str(out), entries=total, bytes=Path(out).stat().st_size)
