"""Attachments: list (name and size), attach a file, detach one. The content is never reported or printed."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from .models import AttachmentItem, AttachmentsReport, OrgChange
from .txn import Plan, execute_vault
from cprima_pdh_vault.vault import Vault, as_vault, require
from .write import WriteError, find_data


def _contents(vault: Vault, eid: str, names) -> dict[str, bytes]:
    return {name: vault.attachment(eid, name) for name, _ in names}


def attachments_report(source, path: str, username: str | None = None) -> AttachmentsReport:
    vault = as_vault(source)
    require(vault, "attachments")
    e = find_data(vault, path, username)
    return AttachmentsReport(entry=path, attachments=[AttachmentItem(name=n, size=s) for n, s in e.attachments])


def attach_file(open_db: Callable[[], object], db: Path, path: str, file: Path, apply: bool,
                name: str | None = None, username: str | None = None) -> OrgChange:
    """Attach a file to an entry under `name` (default: the file's own name)."""
    try:
        content = Path(file).read_bytes()
    except OSError as exc:
        raise WriteError(f"cannot read {file}: {exc.strerror or exc}") from exc
    label = name or Path(file).name

    def build(vault: Vault) -> Plan:
        require(vault, "attachments")
        e = find_data(vault, path, username)
        if any(n == label for n, _ in e.attachments):
            raise WriteError(f"{path!r} already has an attachment named {label!r}")
        uid, others = e.id, _contents(vault, e.id, e.attachments)
        change = OrgChange(kind="attach", target=path, dest=label)

        def mutate(v: Vault) -> None:
            v.snapshot_history(uid)
            v.attach(uid, label, content)

        def verify(again: Vault) -> list[str]:
            x = next((y for y in again.entries() if y.id == uid), None)
            if x is None or _contents(again, uid, x.attachments) != {**others, label: content}:
                return ["the attachments are not as planned"]
            return []

        return Plan(change=change, mutate=mutate, touched={uid}, verify=verify)

    return execute_vault(open_db, db, build, apply)


def detach_file(open_db: Callable[[], object], db: Path, path: str, name: str, apply: bool,
                username: str | None = None) -> OrgChange:
    """Remove one attachment from an entry; its content goes too when no other entry uses it."""

    def build(vault: Vault) -> Plan:
        require(vault, "attachments")
        e = find_data(vault, path, username)
        have = _contents(vault, e.id, e.attachments)
        if name not in have:
            raise WriteError(f"{path!r} has no attachment named {name!r}")
        uid = e.id
        left = {k: v for k, v in have.items() if k != name}
        change = OrgChange(kind="detach", target=path, dest=name)

        def mutate(v: Vault) -> None:
            v.snapshot_history(uid)
            v.detach(uid, name)

        def verify(again: Vault) -> list[str]:
            x = next((y for y in again.entries() if y.id == uid), None)
            ok = x is not None and _contents(again, uid, x.attachments) == left
            return [] if ok else ["the attachments are not as planned"]

        return Plan(change=change, mutate=mutate, touched={uid}, verify=verify)

    return execute_vault(open_db, db, build, apply)
