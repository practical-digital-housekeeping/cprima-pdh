"""The group tree of a vault, seen through the method: owner, area, record types, and what looks out of place.

Read-only. Counts are totals (every entry below a group); the recycle bin is shown last and counts nowhere else.
Level 1 below the root is an owner and level 2 an area of the profile; deeper folders are for browsing and carry no rule.
"""
from __future__ import annotations

from .models import GroupNode, TreeEntry
from .schema import SchemaSet, typing_of
from .source import _in_bin


def _plural(n: int) -> str:
    return "entry" if n == 1 else "entries"


def build(kp, sset: SchemaSet, with_entries: bool = False, depth: int | None = None) -> GroupNode:
    """The tree; `depth` limits the levels shown below the root (totals stay true), `with_entries` lists entries."""
    rb = kp.recyclebin_group
    bin_uuid = rb.uuid if rb is not None else None
    label = sset.profile.full_name if sset.profile else "the taxonomy"

    def typed_names(e) -> list[str]:  # every record type that applies: written (`_schema`) and/or from the fields
        return typing_of(e, sset).names

    def walk(g, level: int) -> GroupNode:
        if bin_uuid is not None and g.uuid == bin_uuid:
            held = sum(1 for e in kp.entries if _in_bin(e.group, bin_uuid))
            return GroupNode(name=g.name or "Recycle Bin", kind="recycle-bin", total=held)
        kids = [walk(c, level + 1) for c in sorted(g.subgroups, key=lambda x: (x.uuid == bin_uuid, x.name or ""))]
        own = list(g.entries)
        counted = [k for k in kids if k.kind != "recycle-bin"]
        total = len(own) + sum(k.total for k in counted)
        typed = sum(1 for e in own if typed_names(e)) + sum(k.typed for k in counted)
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
            entries=[TreeEntry(title=e.title or "", schemas=(t := typing_of(e, sset)).explicit, by_fields=t.by_fields)
                     for e in sorted(own, key=lambda x: x.title or "")] if with_entries else [],
            children=kids)

    def prune(node: GroupNode, level: int) -> GroupNode:
        if depth is not None and level >= depth:
            hidden = bool(node.children or node.entries)
            return node.model_copy(update={"children": [], "entries": [], "collapsed": hidden})
        return node.model_copy(update={"children": [prune(c, level + 1) for c in node.children]})

    return prune(walk(kp.root_group, 0), 0)
