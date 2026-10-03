"""Group commands: rename, move, delete (into the recycle bin), notes, icon.

Entries below a group keep their UUIDs and data; `txn.execute_vault` checks that every entry is unchanged afterwards.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from .models import OrgChange
from .organize import _top, find_group
from .txn import Plan, execute_vault
from .vault import GroupData, Vault
from .write import WriteError

_ICONS = range(0, 69)  # KeePass' standard icon set


def _editable(g: GroupData, what: str) -> None:
    if g.is_root:
        raise WriteError(f"the root group cannot be {what}")
    if g.is_bin:
        raise WriteError(f"the recycle bin cannot be {what}")


def _is_below(vault: Vault, group: GroupData, ancestor: GroupData) -> bool:
    """Whether `group` is `ancestor` or sits inside it."""
    by_id = {g.id: g for g in vault.groups()}
    current: GroupData | None = group
    while current is not None:
        if current.id == ancestor.id:
            return True
        current = by_id.get(current.parent_id) if current.parent_id else None
    return False


def _group_plan(change: OrgChange, uid: str, mutate: Callable[[Vault], None], check: Callable[[GroupData], list[str]]) -> Plan:
    """A change to one group's own properties (stamps its modification time)."""

    def verify(again: Vault) -> list[str]:
        x = next((g for g in again.groups() if g.id == uid), None)
        return check(x) if x is not None else ["the group is missing"]

    return Plan(change=change, mutate=mutate, touched_groups={uid}, verify=verify)


def rename_group(open_db: Callable[[], object], db: Path, path: str, name: str, apply: bool) -> OrgChange:
    """Rename a group; its UUID, entries and subgroups stay."""

    def build(vault: Vault) -> Plan:
        g = find_group(vault, path)
        _editable(g, "renamed")
        if not name or "/" in name:
            raise WriteError("group name must be non-empty and must not contain '/'")
        siblings = [s for s in vault.groups() if s.parent_id == g.parent_id and s.id != g.id]
        if any(s.name == name for s in siblings):
            parent = next(p for p in vault.groups() if p.id == g.parent_id)
            raise WriteError(f"{parent.path!r} already has a group {name!r}")
        change = OrgChange(kind="rename-group", target=path, dest=name)
        if g.name == name:
            return Plan(change=change)
        return _group_plan(change, g.id, lambda v: v.rename_group(g.id, name),
                           lambda x: [] if x.name == name else ["the name is not as planned"])

    return execute_vault(open_db, db, build, apply)


def move_group(open_db: Callable[[], object], db: Path, path: str, dest: str, apply: bool,
               cross_top_level: bool = False) -> OrgChange:
    """Move a group, with everything in it, below another group (inside one top-level group by default)."""

    def build(vault: Vault) -> Plan:
        g, target = find_group(vault, path), find_group(vault, dest)
        _editable(g, "moved")
        if _is_below(vault, target, g):
            raise WriteError(f"{dest!r} is {path!r} itself or inside it")
        if not cross_top_level and _top(g.path) != _top(target.path):
            raise WriteError(f"{path!r} is under {_top(g.path)!r} but {dest!r} is under {_top(target.path)!r}; "
                             f"moves stay inside one top-level group (use --cross-top-level to override)")
        if any(s.name == g.name and s.parent_id == target.id for s in vault.groups()):
            raise WriteError(f"{dest!r} already has a group {g.name!r}")
        change = OrgChange(kind="move-group", target=path, dest=target.path)
        if g.parent_id == target.id:
            return Plan(change=change)

        def verify(again: Vault) -> list[str]:
            x = next((y for y in again.groups() if y.id == g.id), None)
            return [] if x is not None and x.parent_id == target.id else ["the group is not where planned"]

        return Plan(change=change, mutate=lambda v: v.move_group(g.id, target.id), verify=verify,
                    touched_groups={g.id}, stamp="location")

    return execute_vault(open_db, db, build, apply)


def delete_group(open_db: Callable[[], object], db: Path, path: str, apply: bool) -> OrgChange:
    """Move a group, with everything in it, to the recycle bin. Never a permanent delete."""

    def build(vault: Vault) -> Plan:
        g = find_group(vault, path)
        _editable(g, "deleted")
        if not vault.bin_enabled():
            raise WriteError("the recycle bin is switched off in this database; pdh deletes only into the bin")
        if g.in_bin:
            raise WriteError(f"{path!r} is already in the recycle bin")
        rb = next((x for x in vault.groups() if x.is_bin), None)
        change = OrgChange(kind="delete-group", target=path, dest=rb.path if rb is not None else "Recycle Bin")

        def verify(again: Vault) -> list[str]:
            x = next((y for y in again.groups() if y.id == g.id), None)
            bin_ = next((y for y in again.groups() if y.is_bin), None)
            ok = x is not None and bin_ is not None and x.parent_id == bin_.id
            return [] if ok else ["the group is not in the recycle bin"]

        return Plan(change=change, mutate=lambda v: v.trash_group(g.id), verify=verify, touched_groups={g.id},
                    stamp="location")

    return execute_vault(open_db, db, build, apply)


def set_group_notes(open_db: Callable[[], object], db: Path, path: str, text: str, apply: bool) -> OrgChange:
    def build(vault: Vault) -> Plan:
        g = find_group(vault, path)
        change = OrgChange(kind="group-notes", target=path, dest=f"{len(text)} characters")
        if g.notes == text:
            return Plan(change=change)
        return _group_plan(change, g.id, lambda v: v.set_group_notes(g.id, text),
                           lambda x: [] if x.notes == text else ["notes differ"])

    return execute_vault(open_db, db, build, apply)


def set_group_icon(open_db: Callable[[], object], db: Path, path: str, icon: int, apply: bool) -> OrgChange:
    if icon not in _ICONS:
        raise WriteError(f"icon {icon} is not one of the standard icons ({_ICONS[0]}..{_ICONS[-1]})")

    def build(vault: Vault) -> Plan:
        g = find_group(vault, path)
        change = OrgChange(kind="group-icon", target=path, dest=str(icon))
        if str(g.icon) == str(icon):
            return Plan(change=change)
        return _group_plan(change, g.id, lambda v: v.set_group_icon(g.id, str(icon)),
                           lambda x: [] if str(x.icon) == str(icon) else ["icon differs"])

    return execute_vault(open_db, db, build, apply)
