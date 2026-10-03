"""Exports: the only things pdh writes outside the vault, and only to the file the owner names with --out.

An existing file is never overwritten. Secrets (passwords, one-time-password secrets, protected custom fields) are in
a CSV export only with `with_secrets`. Reports name the file and count entries; they never contain a value.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path

from .models import FileWritten
from .vault import as_vault, require
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


def export_csv(source, out: Path, with_secrets: bool = False) -> FileWritten:
    """Write the live entries (not the recycle bin) as CSV; secrets only with `with_secrets`."""
    entries = _live(source)
    custom = sorted({k for e in entries for k in e.fields})
    head = ["Group", "Title", "UserName", *(["Password", "OTP"] if with_secrets else []), "URL", "Notes", "Tags",
            "Expires", *custom]
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(head)
    for e in entries:
        row = [e.group_path, e.title, e.username]
        if with_secrets:
            row += [e.password, e.otp]
        row += [e.url, e.notes, ";".join(e.tags), e.expiry.date().isoformat() if e.expires and e.expiry else ""]
        for k in custom:
            field = e.fields.get(k)
            row.append("" if field is None or (field.protected and not with_secrets) else field.value)
        writer.writerow(row)
    data = buffer.getvalue().encode("utf-8")
    with _create_exclusive(out) as f:
        f.write(data)
    return FileWritten(kind="csv", path=str(out), entries=len(entries), bytes=len(data))


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
