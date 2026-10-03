"""The group tree of a vault, seen through the method: owner, area, record types, and what looks out of place.

Read-only. Counts are totals (every entry below a group); the recycle bin is shown last and counts nowhere else.
Level 1 below the root is an owner and level 2 an area of the profile; deeper folders are for browsing and carry no rule.
"""
from __future__ import annotations

from .models import GroupNode, TreeEntry
from .schema import SchemaSet
from .validation import typing_of
from .vault import as_vault


def _plural(n: int) -> str:
    return "entry" if n == 1 else "entries"


def build(source, sset: SchemaSet, with_entries: bool = False, depth: int | None = None) -> GroupNode:
    """The tree; `depth` limits the levels shown below the root (totals stay true), `with_entries` lists entries."""
    vault = as_vault(source)
    groups, entries = vault.groups(), vault.entries()
    label = sset.profile.full_name if sset.profile else "the taxonomy"
    children: dict[str | None, list] = {}
    for g in groups:
        children.setdefault(g.parent_id, []).append(g)
    own_of: dict[str, list] = {}
    for e in entries:
        if not e.in_bin:
            own_of.setdefault(e.group_id, []).append(e)
    typing = {e.id: typing_of(e, sset) for e in entries if not e.in_bin}

    def walk(g, level: int) -> GroupNode:
        if g.is_bin:
            return GroupNode(name=g.name or "Recycle Bin", kind="recycle-bin", total=sum(1 for e in entries if e.in_bin))
        kids = [walk(c, level + 1) for c in sorted(children.get(g.id, []), key=lambda x: (x.is_bin, x.name or ""))]
        own = own_of.get(g.id, [])
        counted = [k for k in kids if k.kind != "recycle-bin"]
        total = len(own) + sum(k.total for k in counted)
        typed = sum(1 for e in own if typing[e.id].names) + sum(k.typed for k in counted)
        kind = {0: "root", 1: "owner"}.get(level, "group")
        note = ""
        if level == 2 and (g.name or "") in sset.areas:
            kind = "area"
        elif level == 2:
            note = f"not an area of {label}"
        elif level == 0 and own:
            note = f"{len(own)} {_plural(len(own))} directly at the root, outside an owner"
        elif level == 1 and own:
            note = f"{len(own)} {_plural(len(own))} directly at the owner, outside an area"
        return GroupNode(
            name=g.name or "/", kind=kind, total=total, typed=typed, entry_count=len(own), note=note,
            entries=[TreeEntry(title=e.title, schemas=typing[e.id].explicit, by_fields=typing[e.id].by_fields)
                     for e in sorted(own, key=lambda x: x.title)] if with_entries else [],
            children=kids)

    def prune(node: GroupNode, level: int) -> GroupNode:
        if depth is not None and level >= depth:
            hidden = bool(node.children or node.entries)
            return node.model_copy(update={"children": [], "entries": [], "collapsed": hidden})
        return node.model_copy(update={"children": [prune(c, level + 1) for c in node.children]})

    root = next(g for g in groups if g.is_root)
    return prune(walk(root, 0), 0)
