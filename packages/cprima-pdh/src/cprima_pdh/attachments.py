"""Attachments: list (name and size), attach a file, detach one. The content is never reported or printed."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .models import AttachmentItem, AttachmentsReport, OrgChange
from .txn import Plan, execute, snapshot
from .write import WriteError, find_entry

if TYPE_CHECKING:
    from pykeepass import PyKeePass


def _contents(entry) -> dict[str, bytes]:
    return {a.filename: a.data for a in entry.attachments}


def attachments_report(kp: PyKeePass, path: str, username: str | None = None) -> AttachmentsReport:
    e = find_entry(kp, path, username)
    return AttachmentsReport(entry=path, attachments=[AttachmentItem(name=a.filename, size=len(a.data))
                                                       for a in e.attachments])


def attach_file(open_db: Callable[[], PyKeePass], db: Path, path: str, file: Path, apply: bool,
                name: str | None = None, username: str | None = None) -> OrgChange:
    """Attach a file to an entry under `name` (default: the file's own name)."""
    try:
        content = Path(file).read_bytes()
    except OSError as exc:
        raise WriteError(f"cannot read {file}: {exc.strerror or exc}") from exc
    label = name or Path(file).name

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        if label in _contents(e):
            raise WriteError(f"{path!r} already has an attachment named {label!r}")
        uid, others = str(e.uuid), _contents(e)
        change = OrgChange(kind="attach", target=path, dest=label)

        def mutate(k: PyKeePass) -> None:
            target = next(x for x in k.entries if str(x.uuid) == uid)
            snapshot(target)
            target.add_attachment(k.add_binary(content), label)

        def verify(again: PyKeePass) -> list[str]:
            x = next((y for y in again.entries if str(y.uuid) == uid), None)
            if x is None or _contents(x) != {**others, label: content}:
                return ["the attachments are not as planned"]
            return []

        return Plan(change=change, mutate=mutate, touched={uid}, verify=verify)

    return execute(open_db, db, build, apply)


def detach_file(open_db: Callable[[], PyKeePass], db: Path, path: str, name: str, apply: bool,
                username: str | None = None) -> OrgChange:
    """Remove one attachment from an entry; its content goes too when no other entry uses it."""

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        have = _contents(e)
        if name not in have:
            raise WriteError(f"{path!r} has no attachment named {name!r}")
        uid = str(e.uuid)
        left = {k: v for k, v in have.items() if k != name}
        change = OrgChange(kind="detach", target=path, dest=name)

        def mutate(k: PyKeePass) -> None:
            target = next(x for x in k.entries if str(x.uuid) == uid)
            snapshot(target)
            att = next(a for a in target.attachments if a.filename == name)
            ident = att.id
            target.delete_attachment(att)
            if not any(a.id == ident for x in k.entries for a in x.attachments):
                k.delete_binary(ident)

        def verify(again: PyKeePass) -> list[str]:
            x = next((y for y in again.entries if str(y.uuid) == uid), None)
            return [] if x is not None and _contents(x) == left else ["the attachments are not as planned"]

        return Plan(change=change, mutate=mutate, touched={uid}, verify=verify)

    return execute(open_db, db, build, apply)
