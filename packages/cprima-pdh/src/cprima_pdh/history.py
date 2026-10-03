"""Entry history: what changed (names only), restore an earlier state, prune old snapshots.

KeePass keeps an entry's earlier states in its `History`. Old values live there, which makes pruning a privacy lever.
Reports name fields and counts, never values.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .backends.kdbx import STANDARD_ATTR
from .models import HistoryPrune, HistoryReport, HistorySnapshot, OrgChange
from .source import _aware
from .txn import Plan, execute, snapshot
from .write import WriteError, find_entry

if TYPE_CHECKING:
    from pykeepass import PyKeePass

_NAME_OF = {attr: name for name, attr in STANDARD_ATTR.items()}


def set_otp(entry, value: str | None) -> None:
    """Set the one-time-password secret of an entry, or remove it when `value` is empty (pykeepass cannot set None)."""
    if value:
        entry.otp = value
        return
    for element in entry._element.xpath("String[Key='otp']"):
        entry._element.remove(element)


def _state(e) -> dict[str, object]:
    """Everything a snapshot can differ in, by name: standard fields, custom fields, tags, icon, expiry."""
    out: dict[str, object] = {name: getattr(e, attr, None) or "" for name, attr in STANDARD_ATTR.items()}
    out.update({k: (v, bool(e.is_custom_property_protected(k))) for k, v in (e.custom_properties or {}).items()})
    out["tags"] = ",".join(sorted(e.tags or []))
    out["icon"] = str(e.icon or "0")
    out["expiry"] = (bool(e.expires), e.expiry_time if e.expires else None)
    return out


def _differences(older, newer) -> list[str]:
    a, b = _state(older), _state(newer)
    return sorted(k for k in {*a, *b} if a.get(k) != b.get(k))


def history_report(kp: PyKeePass, path: str, username: str | None = None) -> HistoryReport:
    e = find_entry(kp, path, username)
    states = [*e.history, e]
    return HistoryReport(entry=path, snapshots=[
        HistorySnapshot(index=i, modified=_aware(h.mtime), changed=_differences(h, states[i + 1]))
        for i, h in enumerate(e.history)])


def restore_history(open_db: Callable[[], PyKeePass], db: Path, path: str, index: int, apply: bool,
                    username: str | None = None) -> OrgChange:
    """Make the entry look as it did in snapshot `index`; the state it had before goes to the history first."""

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        if not 0 <= index < len(e.history):
            raise WriteError(f"{path!r} has {len(e.history)} history snapshot(s); there is no index {index}")
        uid, change = str(e.uuid), OrgChange(kind="history-restore", target=path, dest=str(index))
        goal = _state(e.history[index])
        before = len(e.history)

        def mutate(k: PyKeePass) -> None:
            target = next(x for x in k.entries if str(x.uuid) == uid)
            snap = target.history[index]
            snapshot(target)
            for attr in ("title", "username", "password", "url", "notes"):
                setattr(target, attr, getattr(snap, attr) or "")
            if (snap.otp or None) != (target.otp or None):
                set_otp(target, snap.otp)
            for key in list(target.custom_properties or {}):
                if key not in (snap.custom_properties or {}):
                    target.delete_custom_property(key)
            for key, value in (snap.custom_properties or {}).items():
                target.set_custom_property(key, value, protect=bool(snap.is_custom_property_protected(key)))
            target.tags = list(snap.tags or [])
            target.icon = snap.icon or "0"
            target.expires = bool(snap.expires)
            if snap.expires:
                target.expiry_time = snap.expiry_time

        def verify(again: PyKeePass) -> list[str]:
            x = next((y for y in again.entries if str(y.uuid) == uid), None)
            if x is None:
                return ["the entry is missing"]
            problems = []
            if _state(x) != goal:
                problems.append("the entry does not match the snapshot")
            if len(x.history) != before + 1:
                problems.append("the replaced state was not added to the history")
            return problems

        return Plan(change=change, mutate=mutate, touched={uid}, verify=verify)

    return execute(open_db, db, build, apply)


def prune_history(open_db: Callable[[], PyKeePass], db: Path, keep: int, apply: bool, path: str | None = None,
                  username: str | None = None) -> HistoryPrune:
    """Keep only the newest `keep` snapshots, of one entry or of every entry."""
    if keep < 0:
        raise WriteError("--keep must be zero or more")

    def build(kp: PyKeePass) -> Plan:
        targets = [find_entry(kp, path, username)] if path else list(kp.entries)
        excess = {str(e.uuid): len(e.history) - keep for e in targets if len(e.history) > keep}
        report = HistoryPrune(keep=keep, entries=len(excess), removed=sum(excess.values()))
        if not excess:
            return Plan(change=report)

        def mutate(k: PyKeePass) -> None:
            for e in k.entries:
                n = excess.get(str(e.uuid))
                for old in list(e.history)[:n] if n else []:
                    e.delete_history(old)

        def verify(again: PyKeePass) -> list[str]:
            left = {str(e.uuid): len(e.history) for e in again.entries}
            return [] if all(left.get(uid) == keep for uid in excess) else ["history was not pruned as planned"]

        return Plan(change=report, mutate=mutate, touched=set(excess), verify=verify, stamp="none")  # not an edit

    return execute(open_db, db, build, apply)
