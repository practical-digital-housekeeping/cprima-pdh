"""Group commands: rename, move, delete (into the recycle bin), notes, icon.

Entries below a group keep their UUIDs and data; `txn.execute` checks that every entry is unchanged afterwards.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .entries import _bin_enabled, record_origin
from .models import OrgChange
from .organize import _top, find_group
from .source import _gpath, _in_bin
from .txn import Plan, execute
from .write import WriteError

if TYPE_CHECKING:
    from pykeepass import PyKeePass

_ICONS = range(0, 69)  # KeePass' standard icon set


def _editable(kp: PyKeePass, g, what: str) -> None:
    if g.is_root_group:
        raise WriteError(f"the root group cannot be {what}")
    rb = kp.recyclebin_group
    if rb is not None and g.uuid == rb.uuid:
        raise WriteError(f"the recycle bin cannot be {what}")


def _is_below(group, ancestor) -> bool:
    while group is not None:
        if group.uuid == ancestor.uuid:
            return True
        group = group.parentgroup
    return False


def _group_plan(change: OrgChange, uid, mutate: Callable[[PyKeePass], None], check: Callable[[object], list[str]]) -> Plan:
    """A change to one group's own properties (stamps its modification time)."""
    def run(kp: PyKeePass) -> None:
        mutate(next(g for g in kp.groups if g.uuid == uid))
        # (mutate receives the group; moves need the database, so they close over `kp` through the plan below)

    return Plan(change=change, mutate=run, touched_groups={uid}, verify=lambda again: (
        check(next((g for g in again.groups if g.uuid == uid), None)) if any(g.uuid == uid for g in again.groups)
        else ["the group is missing"]))


def rename_group(open_db: Callable[[], PyKeePass], db: Path, path: str, name: str, apply: bool) -> OrgChange:
    """Rename a group; its UUID, entries and subgroups stay."""

    def build(kp: PyKeePass) -> Plan:
        g = find_group(kp, path)
        _editable(kp, g, "renamed")
        if not name or "/" in name:
            raise WriteError("group name must be non-empty and must not contain '/'")
        if any(s.name == name for s in g.parentgroup.subgroups if s.uuid != g.uuid):
            raise WriteError(f"{_gpath(g.parentgroup)!r} already has a group {name!r}")
        change = OrgChange(kind="rename-group", target=path, dest=name)
        if g.name == name:
            return Plan(change=change)

        def set_name(group) -> None:
            group.name = name

        return _group_plan(change, g.uuid, set_name, lambda x: [] if x.name == name else ["the name is not as planned"])

    return execute(open_db, db, build, apply)


def move_group(open_db: Callable[[], PyKeePass], db: Path, path: str, dest: str, apply: bool,
               cross_top_level: bool = False) -> OrgChange:
    """Move a group, with everything in it, below another group (inside one top-level group by default)."""

    def build(kp: PyKeePass) -> Plan:
        g, target = find_group(kp, path), find_group(kp, dest)
        _editable(kp, g, "moved")
        if _is_below(target, g):
            raise WriteError(f"{dest!r} is {path!r} itself or inside it")
        if not cross_top_level and _top(_gpath(g)) != _top(_gpath(target)):
            raise WriteError(f"{path!r} is under {_top(_gpath(g))!r} but {dest!r} is under {_top(_gpath(target))!r}; "
                             f"moves stay inside one top-level group (use --cross-top-level to override)")
        if any(s.name == g.name for s in target.subgroups):
            raise WriteError(f"{dest!r} already has a group {g.name!r}")
        change = OrgChange(kind="move-group", target=path, dest=_gpath(target))
        if g.parentgroup.uuid == target.uuid:
            return Plan(change=change)
        uid, target_uid = g.uuid, target.uuid

        def mutate(k: PyKeePass) -> None:
            k.move_group(next(x for x in k.groups if x.uuid == uid), next(x for x in k.groups if x.uuid == target_uid))

        def verify(again: PyKeePass) -> list[str]:
            x = next((y for y in again.groups if y.uuid == uid), None)
            return [] if x is not None and x.parentgroup.uuid == target_uid else ["the group is not where planned"]

        return Plan(change=change, mutate=mutate, verify=verify, touched_groups={uid}, stamp="location")

    return execute(open_db, db, build, apply)


def delete_group(open_db: Callable[[], PyKeePass], db: Path, path: str, apply: bool) -> OrgChange:
    """Move a group, with everything in it, to the recycle bin. Never a permanent delete."""

    def build(kp: PyKeePass) -> Plan:
        g = find_group(kp, path)
        _editable(kp, g, "deleted")
        if not _bin_enabled(kp):
            raise WriteError("the recycle bin is switched off in this database; pdh deletes only into the bin")
        rb = kp.recyclebin_group
        if rb is not None and _in_bin(g, rb.uuid):
            raise WriteError(f"{path!r} is already in the recycle bin")
        uid = g.uuid
        change = OrgChange(kind="delete-group", target=path, dest=_gpath(rb) if rb is not None else "Recycle Bin")

        def mutate(k: PyKeePass) -> None:
            target = next(x for x in k.groups if x.uuid == uid)
            origin = target.parentgroup
            k.trash_group(target)
            record_origin(k, target, origin)

        def verify(again: PyKeePass) -> list[str]:
            x = next((y for y in again.groups if y.uuid == uid), None)
            ok = x is not None and again.recyclebin_group is not None and x.parentgroup.uuid == again.recyclebin_group.uuid
            return [] if ok else ["the group is not in the recycle bin"]

        return Plan(change=change, mutate=mutate, verify=verify, touched_groups={uid}, stamp="location")

    return execute(open_db, db, build, apply)


def set_group_notes(open_db: Callable[[], PyKeePass], db: Path, path: str, text: str, apply: bool) -> OrgChange:
    def build(kp: PyKeePass) -> Plan:
        g = find_group(kp, path)
        change = OrgChange(kind="group-notes", target=path, dest=f"{len(text)} characters")
        if (g.notes or "") == text:
            return Plan(change=change)

        def set_notes(group) -> None:
            group.notes = text

        return _group_plan(change, g.uuid, set_notes, lambda x: [] if (x.notes or "") == text else ["notes differ"])

    return execute(open_db, db, build, apply)


def set_group_icon(open_db: Callable[[], PyKeePass], db: Path, path: str, icon: int, apply: bool) -> OrgChange:
    if icon not in _ICONS:
        raise WriteError(f"icon {icon} is not one of the standard icons ({_ICONS[0]}..{_ICONS[-1]})")

    def build(kp: PyKeePass) -> Plan:
        g = find_group(kp, path)
        change = OrgChange(kind="group-icon", target=path, dest=str(icon))
        if str(g.icon) == str(icon):
            return Plan(change=change)

        def set_icon(group) -> None:
            group.icon = str(icon)

        return _group_plan(change, g.uuid, set_icon, lambda x: [] if str(x.icon) == str(icon) else ["icon differs"])

    return execute(open_db, db, build, apply)
