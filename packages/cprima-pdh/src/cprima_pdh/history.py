"""Entry history: what changed (names only), restore an earlier state, prune old snapshots.

KeePass keeps an entry's earlier states in its `History`. Old values live there, which makes pruning a privacy lever.
Reports name fields and counts, never values.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from .models import HistoryPrune, HistoryReport, HistorySnapshot, OrgChange
from .txn import Plan, execute_vault
from .vault import STANDARD, EntryData, Vault, as_vault, require
from .write import WriteError, find_data


def _state(e: EntryData) -> dict[str, object]:
    """Everything a snapshot can differ in, by name: standard fields, custom fields, tags, icon, expiry."""
    out: dict[str, object] = {name: e.value(name) for name in STANDARD}
    out.update({k: (f.value, f.protected) for k, f in e.fields.items()})
    out["tags"] = ",".join(sorted(e.tags))
    out["icon"] = str(e.icon or "0")
    out["expiry"] = (bool(e.expires), e.expiry if e.expires else None)
    return out


def _differences(older: EntryData, newer: EntryData) -> list[str]:
    a, b = _state(older), _state(newer)
    return sorted(k for k in {*a, *b} if a.get(k) != b.get(k))


def history_report(source, path: str, username: str | None = None) -> HistoryReport:
    vault = as_vault(source)
    require(vault, "history")
    e = find_data(vault, path, username)
    old = vault.history(e.id)
    states = [*old, e]
    return HistoryReport(entry=path, snapshots=[
        HistorySnapshot(index=i, modified=h.mtime, changed=_differences(h, states[i + 1])) for i, h in enumerate(old)])


def restore_history(open_db: Callable[[], object], db: Path, path: str, index: int, apply: bool,
                    username: str | None = None) -> OrgChange:
    """Make the entry look as it did in snapshot `index`; the state it had before goes to the history first."""

    def build(vault: Vault) -> Plan:
        require(vault, "history")
        e = find_data(vault, path, username)
        old = vault.history(e.id)
        if not 0 <= index < len(old):
            raise WriteError(f"{path!r} has {len(old)} history snapshot(s); there is no index {index}")
        uid, change = e.id, OrgChange(kind="history-restore", target=path, dest=str(index))
        snap = old[index]
        goal = _state(snap)
        before = len(old)

        def mutate(v: Vault) -> None:
            v.snapshot_history(uid)
            v.overwrite_entry(uid, snap)

        def verify(again: Vault) -> list[str]:
            x = next((y for y in again.entries() if y.id == uid), None)
            if x is None:
                return ["the entry is missing"]
            problems = []
            if _state(x) != goal:
                problems.append("the entry does not match the snapshot")
            if x.history_count != before + 1:
                problems.append("the replaced state was not added to the history")
            return problems

        return Plan(change=change, mutate=mutate, touched={uid}, verify=verify)

    return execute_vault(open_db, db, build, apply)


def prune_history(open_db: Callable[[], object], db: Path, keep: int, apply: bool, path: str | None = None,
                  username: str | None = None) -> HistoryPrune:
    """Keep only the newest `keep` snapshots, of one entry or of every entry."""
    if keep < 0:
        raise WriteError("--keep must be zero or more")

    def build(vault: Vault) -> Plan:
        require(vault, "history")
        targets = [find_data(vault, path, username)] if path else vault.entries()
        excess = {e.id: e.history_count - keep for e in targets if e.history_count > keep}
        report = HistoryPrune(keep=keep, entries=len(excess), removed=sum(excess.values()))
        if not excess:
            return Plan(change=report)

        def mutate(v: Vault) -> None:
            for uid in excess:
                v.prune_history(uid, keep)

        def verify(again: Vault) -> list[str]:
            left = {e.id: e.history_count for e in again.entries()}
            return [] if all(left.get(uid) == keep for uid in excess) else ["history was not pruned as planned"]

        return Plan(change=report, mutate=mutate, touched=set(excess), verify=verify, stamp="none")  # not an edit

    return execute_vault(open_db, db, build, apply)
