"""Exports: the only things pdh writes outside the vault, and only to the file the owner names with --out.

An existing file is never overwritten. Secrets (passwords, one-time-password secrets, protected custom fields) are in
a CSV export only with `with_secrets`. Reports name the file and count entries; they never contain a value.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import TYPE_CHECKING

from .models import FileWritten
from .source import _gpath, _in_bin, pykeepass_open
from .write import WriteError, find_entry

if TYPE_CHECKING:
    from pykeepass import PyKeePass


def _create_exclusive(out: Path):
    """Open `out` for writing only if it does not exist yet."""
    out = Path(out)
    if not out.parent.is_dir():
        raise WriteError(f"the folder {out.parent} does not exist")
    try:
        return open(out, "xb")
    except FileExistsError:
        raise WriteError(f"{out} exists; pdh never overwrites a file") from None


def export_attachment(kp: PyKeePass, path: str, name: str, out: Path, username: str | None = None) -> FileWritten:
    """Write one attachment of an entry, byte for byte."""
    e = find_entry(kp, path, username)
    match = next((a for a in e.attachments if a.filename == name), None)
    if match is None:
        raise WriteError(f"{path!r} has no attachment named {name!r}")
    content = match.data
    with _create_exclusive(out) as f:
        f.write(content)
    return FileWritten(kind="attachment", path=str(out), entries=1, bytes=len(content))


def _live(kp: PyKeePass):
    rb = kp.recyclebin_group
    return [e for e in kp.entries if rb is None or not _in_bin(e.group, rb.uuid)]


def export_csv(kp: PyKeePass, out: Path, with_secrets: bool = False) -> FileWritten:
    """Write the live entries (not the recycle bin) as CSV; secrets only with `with_secrets`."""
    entries = _live(kp)
    custom = sorted({k for e in entries for k in (e.custom_properties or {})})
    head = ["Group", "Title", "UserName", *(["Password", "OTP"] if with_secrets else []), "URL", "Notes", "Tags",
            "Expires", *custom]
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(head)
    for e in entries:
        props = e.custom_properties or {}
        row = [_gpath(e.group), e.title or "", e.username or ""]
        if with_secrets:
            row += [e.password or "", e.otp or ""]
        row += [e.url or "", e.notes or "", ";".join(e.tags or []),
                e.expiry_time.date().isoformat() if e.expires and e.expiry_time else ""]
        for k in custom:
            hidden = k in props and not with_secrets and e.is_custom_property_protected(k)
            row.append("" if hidden or k not in props else props[k])
        writer.writerow(row)
    data = buffer.getvalue().encode("utf-8")
    with _create_exclusive(out) as f:
        f.write(data)
    return FileWritten(kind="csv", path=str(out), entries=len(entries), bytes=len(data))


def export_kdbx(kp: PyKeePass, out: Path, new_password: str) -> FileWritten:
    """Write a copy of the vault under a new master password; the original file is not touched."""
    if not new_password:
        raise WriteError("an empty master password is not accepted")
    if Path(out).exists():
        raise WriteError(f"{out} exists; pdh never overwrites a file")
    total = len(list(kp.entries))
    kp.password = new_password
    kp.keyfile = None  # the copy needs only its own password
    with _create_exclusive(out):
        pass  # reserve the name atomically; the vault is then written over it
    try:
        kp.save(filename=str(out))
        again = pykeepass_open(out, new_password, None)
        if len(list(again.entries)) != total:
            raise WriteError("verification failed: the copy has a different number of entries")
    except Exception:
        Path(out).unlink(missing_ok=True)  # never leave a half-written copy of a vault behind
        raise
    return FileWritten(kind="kdbx", path=str(out), entries=total, bytes=Path(out).stat().st_size)
