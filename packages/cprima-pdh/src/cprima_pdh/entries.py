"""Entry lifecycle: move to the recycle bin, restore, delete for good (only from the bin).

All of it runs through `txn.execute`: dry run unless `apply`, one save, reopened and verified.
"""
from __future__ import annotations

import base64
import re
import uuid as uuidlib
from datetime import date as _date
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .fix import _base, _custom
from .models import OrgChange
from .organize import find_group
from .source import _gpath, _in_bin
from .txn import Plan, execute, snapshot
from .write import WriteError, find_entry

if TYPE_CHECKING:
    from pykeepass import PyKeePass

BIN_NAME = "Recycle Bin"  # what pykeepass names a recycle bin it has to create


def _root(kp: PyKeePass):
    tree = kp.tree
    return tree.getroot() if hasattr(tree, "getroot") else tree


def _bin_enabled(kp: PyKeePass) -> bool:
    return _root(kp).findtext("Meta/RecycleBinEnabled", default="True").strip().lower() != "false"


def record_origin(kp: PyKeePass, element_owner, origin_group) -> None:
    """Remember the group something was deleted from, where the format has a place for it (KDBX 4.1 and later).

    Older vaults get nothing: an element their clients do not know could confuse them."""
    if tuple(kp.version) < (4, 1):
        return
    from lxml import etree

    el = element_owner._element.find("PreviousParentGroup")
    if el is None:
        el = etree.SubElement(element_owner._element, "PreviousParentGroup")
    el.text = base64.b64encode(origin_group.uuid.bytes).decode()


def _in_the_bin(kp: PyKeePass, entry) -> bool:
    rb = kp.recyclebin_group
    return rb is not None and _in_bin(entry.group, rb.uuid)


def _previous_group(kp: PyKeePass, entry):
    """The group a client recorded as the entry's origin (KDBX 4.1 `PreviousParentGroup`), if it still exists."""
    raw = entry._element.findtext("PreviousParentGroup")
    if not raw:
        return None
    try:
        wanted = uuidlib.UUID(bytes=base64.b64decode(raw))
    except ValueError:
        return None
    return next((g for g in kp.groups if g.uuid == wanted), None)


def _same_data(entry, expect: tuple[str, str]) -> bool:
    return (_base(entry, with_group=False), _custom(entry)) == expect


def _moved_plan(entry, dest, change: OrgChange, expect_group_uuid: Callable[[PyKeePass], object]) -> Plan:
    uid = str(entry.uuid)
    expect = (_base(entry, with_group=False), _custom(entry))

    def verify(again: PyKeePass) -> list[str]:
        e = next((x for x in again.entries if str(x.uuid) == uid), None)
        if e is None:
            return ["the entry is missing"]
        problems = []
        if e.group.uuid != expect_group_uuid(again):
            problems.append("the entry is not in the expected group")
        if not _same_data(e, expect):
            problems.append("the entry's data changed")
        return problems

    return Plan(change=change, touched={uid}, verify=verify)


def delete_entry(open_db: Callable[[], PyKeePass], db: Path, path: str, apply: bool,
                 username: str | None = None) -> OrgChange:
    """Move an entry to the recycle bin (created if the vault has none yet). Never deletes for good."""

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        if not _bin_enabled(kp):
            raise WriteError("the recycle bin is switched off in this database; pdh deletes only into the bin")
        if _in_the_bin(kp, e):
            raise WriteError(f"{path!r} is already in the recycle bin; `pdh edit purge` deletes it for good")
        rb = kp.recyclebin_group
        change = OrgChange(kind="delete", target=path, dest=_gpath(rb) if rb is not None else BIN_NAME)
        plan = _moved_plan(e, None, change, lambda again: again.recyclebin_group.uuid)

        def trash(k: PyKeePass) -> None:
            target = find_entry(k, path, username)
            origin = target.group
            k.trash_entry(target)
            record_origin(k, target, origin)

        plan.mutate = trash
        return plan

    return execute(open_db, db, build, apply)


def restore_entry(open_db: Callable[[], PyKeePass], db: Path, path: str, apply: bool, to: str | None = None,
                  username: str | None = None) -> OrgChange:
    """Move an entry out of the recycle bin: into `to`, else where a client recorded it came from."""

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        if not _in_the_bin(kp, e):
            raise WriteError(f"{path!r} is not in the recycle bin")
        dest = find_group(kp, to) if to else _previous_group(kp, e)
        if dest is None:
            raise WriteError(f"{path!r}: the vault does not say where it came from; give a group with --to")
        if any(x.title == e.title for x in dest.entries):
            raise WriteError(f"{_gpath(dest)!r} already has an entry titled {e.title!r}; rename one first")
        dest_uid = dest.uuid
        change = OrgChange(kind="restore", target=path, dest=_gpath(dest))
        plan = _moved_plan(e, dest, change, lambda again: dest_uid)
        plan.mutate = lambda k: k.move_entry(find_entry(k, path, username), next(g for g in k.groups if g.uuid == dest_uid))
        return plan

    return execute(open_db, db, build, apply)


def purge_entry(open_db: Callable[[], PyKeePass], db: Path, path: str, apply: bool,
                username: str | None = None) -> OrgChange:
    """Delete an entry for good. Only an entry that is already in the recycle bin."""

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        if not _in_the_bin(kp, e):
            raise WriteError(f"{path!r} is not in the recycle bin; `pdh edit delete` moves it there first")
        uid = str(e.uuid)

        def verify(again: PyKeePass) -> list[str]:
            return ["the entry still exists"] if any(str(x.uuid) == uid for x in again.entries) else []

        return Plan(change=OrgChange(kind="purge", target=path, dest=""), touched={uid}, count_delta=-1, verify=verify,
                    mutate=lambda k: k.delete_entry(find_entry(k, path, username)))

    return execute(open_db, db, build, apply)


# --- attributes that are not fields: tags, expiry, and copies ---------------------------------------------------

def _core(entry) -> tuple:
    """The fields of an entry that an attribute change must leave alone."""
    return (entry.title, entry.username, entry.password, entry.url, entry.notes, entry.otp, _custom(entry))


def _attribute_plan(kp: PyKeePass, e, change: OrgChange, mutate: Callable, check: Callable[[object], list[str]]) -> Plan:
    uid, core = str(e.uuid), _core(e)

    def verify(again: PyKeePass) -> list[str]:
        x = next((y for y in again.entries if str(y.uuid) == uid), None)
        if x is None:
            return ["the entry is missing"]
        problems = check(x)
        if _core(x) != core:
            problems.append("the entry's fields changed")
        if x.group.uuid != e.group.uuid:
            problems.append("the entry moved")
        return problems

    def run(k: PyKeePass) -> None:
        target = next(y for y in k.entries if str(y.uuid) == uid)
        snapshot(target)  # the previous state stays in the entry's history
        mutate(target)

    return Plan(change=change, mutate=run, touched={uid}, verify=verify)


def _tag_ok(tag: str) -> str:
    if not tag or not tag.strip() or ";" in tag or "," in tag:
        raise WriteError(f"tag {tag!r} must be non-empty and contain no ';' or ','")
    return tag.strip()


def change_tags(open_db: Callable[[], PyKeePass], db: Path, path: str, add: list[str], remove: list[str], apply: bool,
                username: str | None = None) -> OrgChange:
    """Add and remove tags on one entry (the previous state goes to its history)."""
    add, remove = [_tag_ok(t) for t in add], [_tag_ok(t) for t in remove]

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        have = list(e.tags or [])
        want = [t for t in have if t not in remove] + [t for t in add if t not in have]
        change = OrgChange(kind="tags", target=path, dest=",".join(want))
        if sorted(want) == sorted(have):
            return Plan(change=change)  # nothing to do: no save, no history

        def mutate(entry) -> None:
            entry.tags = want

        return _attribute_plan(kp, e, change, mutate, lambda x: [] if sorted(x.tags or []) == sorted(want)
                               else ["the tags are not as planned"])

    return execute(open_db, db, build, apply)


def set_expiry(open_db: Callable[[], PyKeePass], db: Path, path: str, date: str | None, clear: bool, apply: bool,
               username: str | None = None) -> OrgChange:
    """Set the expiry date of an entry (YYYY-MM-DD, midnight UTC) or clear it."""
    if clear == (date is not None):
        raise WriteError("give a date (YYYY-MM-DD) or --clear, not both and not neither")
    day = None
    if date is not None:
        try:
            day = _date.fromisoformat(date)
        except ValueError:
            raise WriteError(f"{date!r} is not a date (YYYY-MM-DD)") from None

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        current = e.expiry_time.astimezone(timezone.utc).date() if e.expires and e.expiry_time else None
        change = OrgChange(kind="expiry", target=path, dest="" if clear else date)
        if current == day:  # same date, or nothing to clear
            return Plan(change=change)

        def mutate(entry) -> None:
            if day is None:
                entry.expires = False
            else:
                entry.expiry_time = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
                entry.expires = True

        def check(x) -> list[str]:
            ok = (not x.expires) if day is None else (x.expires and x.expiry_time.astimezone(timezone.utc).date() == day)
            return [] if ok else ["the expiry is not as planned"]

        return _attribute_plan(kp, e, change, mutate, check)

    return execute(open_db, db, build, apply)


def clone_entry(open_db: Callable[[], PyKeePass], db: Path, path: str, title: str | None, apply: bool,
                username: str | None = None) -> OrgChange:
    """Duplicate an entry next to the original: a new UUID, the same fields, tags, icon, expiry and attachments."""

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        new_title = title or f"{e.title} - copy"
        if any(x.title == new_title for x in e.group.entries):
            raise WriteError(f"{_gpath(e.group)!r} already has an entry titled {new_title!r}")
        src_uid, group_uid = str(e.uuid), e.group.uuid
        change = OrgChange(kind="clone", target=path, dest=f"{_gpath(e.group)}/{new_title}")
        expect = (e.username, e.password, e.url, e.notes, e.otp, _custom(e), sorted(e.tags or []))

        def mutate(k: PyKeePass) -> None:
            src = next(y for y in k.entries if str(y.uuid) == src_uid)
            copy = k.add_entry(src.group, new_title, src.username or "", src.password or "", url=src.url, notes=src.notes,
                               tags=list(src.tags or []) or None, otp=src.otp, icon=src.icon)
            for key, value in (src.custom_properties or {}).items():
                copy.set_custom_property(key, value, protect=src.is_custom_property_protected(key))
            if src.expires:
                copy.expiry_time, copy.expires = src.expiry_time, True
            for a in src.attachments:
                copy.add_attachment(a.id, a.filename)
            for tag in ("ForegroundColor", "BackgroundColor", "OverrideURL"):
                text = src._element.findtext(tag)
                if text:
                    el = copy._element.find(tag)
                    if el is not None:
                        el.text = text

        def verify(again: PyKeePass) -> list[str]:
            twins = [x for x in again.entries if x.title == new_title and x.group.uuid == group_uid]
            if len(twins) != 1 or str(twins[0].uuid) == src_uid:
                return ["the copy is missing or not a new entry"]
            x = twins[0]
            got = (x.username, x.password, x.url, x.notes, x.otp, _custom(x), sorted(x.tags or []))
            return [] if got == expect else ["the copy differs from the original"]

        return Plan(change=change, mutate=mutate, touched=set(), count_delta=1, verify=verify)

    return execute(open_db, db, build, apply)


# --- appearance and behaviour in a client: icon, colours, URL override, auto-type ------------------------------------

_HEX = re.compile(r"#[0-9A-Fa-f]{6}")
_ICONS = range(0, 69)  # KeePass' standard icon set


def _element_text(entry, tag: str) -> str:
    return entry._element.findtext(tag) or ""


def _set_element(entry, tag: str, value: str) -> None:
    el = entry._element.find(tag)
    if el is None:
        from lxml import etree
        el = etree.SubElement(entry._element, tag)
    el.text = value or None


def _one_attribute(open_db, db, path, username, apply, kind, goal: str, current: Callable, mutate: Callable,
                   check: Callable) -> OrgChange:
    """The shape every single-attribute change shares: a no-op when nothing differs, else history + mutate + verify."""

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        change = OrgChange(kind=kind, target=path, dest=goal)
        if current(e) == goal:
            return Plan(change=change)
        return _attribute_plan(kp, e, change, mutate, check)

    return execute(open_db, db, build, apply)


def set_icon(open_db: Callable[[], PyKeePass], db: Path, path: str, icon: int, apply: bool,
             username: str | None = None) -> OrgChange:
    """Set the standard icon number of an entry."""
    if icon not in _ICONS:
        raise WriteError(f"icon {icon} is not one of the standard icons ({_ICONS[0]}..{_ICONS[-1]})")
    return _one_attribute(open_db, db, path, username, apply, "icon", str(icon), lambda e: str(e.icon),
                          lambda e: setattr(e, "icon", str(icon)),
                          lambda x: [] if str(x.icon) == str(icon) else ["the icon is not as planned"])


def set_color(open_db: Callable[[], PyKeePass], db: Path, path: str, fg: str | None, bg: str | None, clear: bool,
              apply: bool, username: str | None = None) -> OrgChange:
    """Set the foreground and/or background colour (#RRGGBB) of an entry, or clear both."""
    if clear == (fg is not None or bg is not None):
        raise WriteError("give --fg and/or --bg (#RRGGBB), or --clear, not both and not neither")
    for value in (fg, bg):
        if value is not None and not _HEX.fullmatch(value):
            raise WriteError(f"{value!r} is not a colour (#RRGGBB)")

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        have = (_element_text(e, "ForegroundColor"), _element_text(e, "BackgroundColor"))
        goal = ("", "") if clear else (fg if fg is not None else have[0], bg if bg is not None else have[1])
        change = OrgChange(kind="color", target=path, dest=f"{goal[0] or '-'} {goal[1] or '-'}")
        if have == goal:
            return Plan(change=change)

        def mutate(entry) -> None:
            _set_element(entry, "ForegroundColor", goal[0])
            _set_element(entry, "BackgroundColor", goal[1])

        return _attribute_plan(kp, e, change, mutate, lambda x: [] if (
            _element_text(x, "ForegroundColor"), _element_text(x, "BackgroundColor")) == goal else ["colours differ"])

    return execute(open_db, db, build, apply)


def set_override_url(open_db: Callable[[], PyKeePass], db: Path, path: str, url: str, apply: bool,
                     username: str | None = None) -> OrgChange:
    """Set the URL (or command) a client opens instead of the entry's URL; an empty value removes it."""
    return _one_attribute(open_db, db, path, username, apply, "override-url", url,
                          lambda e: _element_text(e, "OverrideURL"), lambda e: _set_element(e, "OverrideURL", url),
                          lambda x: [] if _element_text(x, "OverrideURL") == url else ["the URL override differs"])


def set_autotype(open_db: Callable[[], PyKeePass], db: Path, path: str, enabled: bool | None, sequence: str | None,
                 apply: bool, username: str | None = None) -> OrgChange:
    """Switch auto-type on or off and/or set its keystroke sequence."""
    if enabled is None and sequence is None:
        raise WriteError("nothing to change: give --enabled/--disabled and/or --sequence")

    def build(kp: PyKeePass) -> Plan:
        e = find_entry(kp, path, username)
        goal = (e.autotype_enabled if enabled is None else enabled,
                (e.autotype_sequence or "") if sequence is None else sequence)
        change = OrgChange(kind="autotype", target=path, dest=f"{'on' if goal[0] else 'off'} {goal[1]}".strip())
        if (e.autotype_enabled, e.autotype_sequence or "") == goal:
            return Plan(change=change)

        def mutate(entry) -> None:
            entry.autotype_enabled = goal[0]
            entry.autotype_sequence = goal[1] or None

        return _attribute_plan(kp, e, change, mutate, lambda x: [] if (
            x.autotype_enabled, x.autotype_sequence or "") == goal else ["auto-type is not as planned"])

    return execute(open_db, db, build, apply)
