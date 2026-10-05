"""What merging another copy of a vault into this one would do, worked out as data.

The way git does it: what loses nothing is done by itself, and where one copy's change would be dropped by the other's there is a
conflict and a person decides. Nothing here writes, prints or asks; the result is a `MergeSituation` that a renderer shows and
that `transfer.merge_apply` acts on once every conflict has an answer.

A merge has a direction: `target` is the vault that changes, `source` is only read. Which copy is newer is not taken from the
clocks but from the entries' own history, the way git uses a common ancestor: if one copy's current state is among the other's
earlier states, the other has gone on from it. A deletion is only known from its record in `DeletedObjects` (a delete needs a
record, otherwise a merge cannot tell a deleted entry from one that never arrived); the records of the other copy apply to this
vault's entries, and this vault's records apply to the other copy's. A clock is used for one question only, whether an entry was
changed after it was deleted, as KeePassXC does.
"""
from __future__ import annotations

from datetime import datetime, timezone

from cprima_pdh_vault.vault import EntryData, Unsupported, Vault, as_vault

from .history import _differences, _state
from .models import MergeChange, MergeConflict, MergeSituation

_EARLIEST = datetime.min.replace(tzinfo=timezone.utc)


def _when(moment: datetime | None) -> datetime:
    return moment or _EARLIEST


def _history(vault: Vault, entry_id: str) -> list[EntryData]:
    try:
        return vault.history(entry_id)
    except (Unsupported, KeyError):
        return []


def _deletions(vault: Vault) -> dict[str, datetime]:
    try:
        return dict(vault.deletions())
    except Unsupported:
        return {}


def _order(target: Vault, source: Vault, mine: EntryData, theirs: EntryData) -> str:
    """For two different states of one entry: `mine-newer`, `theirs-newer`, or `diverged` (neither can be shown to come from the other)."""
    wanted = _state(theirs)
    if any(_state(old) == wanted for old in _history(target, mine.id)):
        return "mine-newer"
    have = _state(mine)
    if any(_state(old) == have for old in _history(source, theirs.id)):
        return "theirs-newer"
    return "diverged"


def merge_situation(target: Vault, source: Vault, source_name: str = "") -> MergeSituation:
    """What merging `source` into `target` does by itself (`clean`) and where a person has to decide (`conflicts`)."""
    target, source = as_vault(target), as_vault(source)
    mine_by_id = {e.id: e for e in target.entries()}
    theirs_by_id = {e.id: e for e in source.entries()}
    deleted_here, deleted_there = _deletions(target), _deletions(source)
    clean: list[MergeChange] = []
    conflicts: list[MergeConflict] = []
    unchanged = skipped = 0
    deleting: set[str] = set()

    for theirs in sorted(theirs_by_id.values(), key=lambda e: (e.path, e.id)):
        mine = mine_by_id.get(theirs.id)
        if mine is None:  # only the other copy has it
            if theirs.in_bin:
                skipped += 1
                continue
            when = deleted_here.get(theirs.id)
            if when is None:
                clean.append(MergeChange(kind="add", id=theirs.id, path=theirs.path))
            elif _when(theirs.mtime) <= when:
                skipped += 1  # deleted here and not changed since
            else:
                conflicts.append(MergeConflict(
                    id=theirs.id, path=theirs.path, kind="deleted-here-modified-there", theirs_modified=theirs.mtime,
                    deleted_at=when, choices=["keep", "delete"],
                    reason="deleted in this vault, but the other copy changed it afterwards"))
            continue

        decided = False  # in both: a record on either side is moot, the entry is alive in both copies
        if _state(theirs) != _state(mine):
            decided = True
            order = _order(target, source, mine, theirs)
            if order == "theirs-newer":
                clean.append(MergeChange(kind="update", id=mine.id, path=mine.path))
            elif order == "diverged":
                conflicts.append(MergeConflict(
                    id=mine.id, path=mine.path, kind="both-modified", fields=_differences(mine, theirs),
                    mine_modified=mine.mtime, theirs_modified=theirs.mtime, choices=["mine", "theirs"],
                    reason="changed in both copies: neither copy's earlier states include the other's current state"))
            else:
                decided = False  # this copy has gone on from the other's state: nothing to take
        newer_place = _when(theirs.location_changed) > _when(mine.location_changed)  # a move or a bin move loses nothing
        if theirs.in_bin and not mine.in_bin and newer_place:
            decided = True
            clean.append(MergeChange(kind="trash", id=mine.id, path=mine.path))
        elif not theirs.in_bin and newer_place and mine.group_id != theirs.group_id:
            decided = True
            clean.append(MergeChange(kind="move", id=mine.id, path=mine.path))
        if not decided:
            unchanged += 1

    for mine in sorted(mine_by_id.values(), key=lambda e: (e.path, e.id)):
        if mine.id in theirs_by_id or mine.id not in deleted_there:
            continue  # (an entry the other copy lacks is not removed because of that; only its record removes it)
        when = deleted_there[mine.id]
        if _when(mine.mtime) <= when:
            deleting.add(mine.id)
            clean.append(MergeChange(kind="delete", id=mine.id, path=mine.path))
        else:
            conflicts.append(MergeConflict(
                id=mine.id, path=mine.path, kind="deleted-there-modified-here", mine_modified=mine.mtime, deleted_at=when,
                choices=["keep", "delete"], reason="deleted in the other copy, but changed here afterwards"))

    groups_kept = _group_deletions(target, deleted_there, set(mine_by_id) - deleting, clean)
    copy = sum(1 for uid, when in deleted_there.items() if uid not in deleted_here or when < deleted_here[uid])
    return MergeSituation(source=source_name, clean=clean, conflicts=conflicts, unchanged=unchanged, skipped=skipped,
                          groups_kept=groups_kept, records_to_copy=copy)


def _group_deletions(target: Vault, deleted_there: dict[str, datetime], remaining: set[str], clean: list[MergeChange]) -> int:
    """The groups the other copy deleted that can go: nothing left in them (or below them) and all of them deleted there too.
    Adds a `delete-group` for each topmost one and returns how many deleted groups stay. (KeePassXC also keeps a group changed
    after the deletion; a group has no modification time here, so only the emptiness decides.)"""
    groups = {g.id: g for g in target.groups()}
    kids: dict[str, list[str]] = {}
    for g in groups.values():
        if g.parent_id:
            kids.setdefault(g.parent_id, []).append(g.id)
    held = {e.group_id for e in target.entries() if e.id in remaining}
    candidates = {gid for gid in deleted_there if gid in groups and not groups[gid].is_root and not groups[gid].is_bin}

    def subtree(gid: str) -> set[str]:
        found = {gid}
        for child in kids.get(gid, []):
            found |= subtree(child)
        return found

    goes = {gid for gid in candidates if subtree(gid) <= candidates and not (subtree(gid) & held)}
    for gid in sorted(goes, key=lambda g: groups[g].path):
        if groups[gid].parent_id not in goes:  # the topmost one takes the rest with it
            clean.append(MergeChange(kind="delete-group", id=gid, path=groups[gid].path))
    return len(candidates - goes)
