"""Entry lifecycle: move to the recycle bin, restore, delete for good (only from the bin).

All of it runs through `txn.execute_vault`: dry run unless `apply`, one save, reopened and verified.
"""
from __future__ import annotations

import re
from dataclasses import replace
from datetime import date as _date
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .models import OrgChange
from .organize import find_group
from .txn import Plan, execute_vault
from cprima_pdh_vault.vault import EntryData, Vault, require
from .write import WriteError, find_data

BIN_NAME = "Recycle Bin"  # what a store names a recycle bin it has to create



def _the_bin(vault: Vault):
    return next((g for g in vault.groups() if g.is_bin), None)


def _same_data(e: EntryData) -> EntryData:
    """An entry minus where it is and when it was moved: what a move must leave alone."""
    return replace(e, group_path="", group_id="", in_bin=False, location_changed=None)


def _moved_plan(e: EntryData, change: OrgChange, expect_group: Callable[[Vault], str | None]) -> Plan:
    uid, expect = e.id, _same_data(e)

    def verify(again: Vault) -> list[str]:
        x = next((y for y in again.entries() if y.id == uid), None)
        if x is None:
            return ["the entry is missing"]
        problems = []
        if x.group_id != expect_group(again):
            problems.append("the entry is not in the expected group")
        if _same_data(x) != expect:
            problems.append("the entry's data changed")
        return problems

    return Plan(change=change, touched={uid}, verify=verify, stamp="location")


def delete_entry(open_db: Callable[[], object], db: Path, path: str, apply: bool,
                 username: str | None = None) -> OrgChange:
    """Move an entry to the recycle bin (created if the vault has none yet). Never deletes for good."""

    def build(vault: Vault) -> Plan:
        require(vault, "recycle_bin")
        e = find_data(vault, path, username)
        if not vault.bin_enabled():
            raise WriteError("the recycle bin is switched off in this database; pdh deletes only into the bin")
        if e.in_bin:
            raise WriteError(f"{path!r} is already in the recycle bin; `pdh edit purge` deletes it for good")
        rb = _the_bin(vault)
        change = OrgChange(kind="delete", target=path, dest=rb.path if rb is not None else BIN_NAME)
        plan = _moved_plan(e, change, lambda again: getattr(_the_bin(again), "id", None))
        plan.mutate = lambda v: v.trash_entry(e.id)
        return plan

    return execute_vault(open_db, db, build, apply)


def restore_entry(open_db: Callable[[], object], db: Path, path: str, apply: bool, to: str | None = None,
                  username: str | None = None) -> OrgChange:
    """Move an entry out of the recycle bin: into `to`, else where a client recorded it came from."""

    def build(vault: Vault) -> Plan:
        require(vault, "recycle_bin")
        e = find_data(vault, path, username)
        if not e.in_bin:
            raise WriteError(f"{path!r} is not in the recycle bin")
        if to:
            dest = find_group(vault, to)
        else:
            origin = vault.origin_group(e.id)
            dest = next((g for g in vault.groups() if g.id == origin), None)
        if dest is None:
            raise WriteError(f"{path!r}: the vault does not say where it came from; give a group with --to")
        if any(x.title == e.title and x.group_id == dest.id for x in vault.entries()):
            raise WriteError(f"{dest.path!r} already has an entry titled {e.title!r}; rename one first")
        plan = _moved_plan(e, OrgChange(kind="restore", target=path, dest=dest.path), lambda again: dest.id)
        plan.mutate = lambda v: v.restore_entry(e.id, dest.id)
        return plan

    return execute_vault(open_db, db, build, apply)


def purge_entry(open_db: Callable[[], object], db: Path, path: str, apply: bool,
                username: str | None = None) -> OrgChange:
    """Delete an entry for good. Only an entry that is already in the recycle bin."""

    def build(vault: Vault) -> Plan:
        e = find_data(vault, path, username)
        if not e.in_bin:
            raise WriteError(f"{path!r} is not in the recycle bin; `pdh edit delete` moves it there first")
        uid = e.id

        def verify(again: Vault) -> list[str]:
            return ["the entry still exists"] if any(x.id == uid for x in again.entries()) else []

        return Plan(change=OrgChange(kind="purge", target=path, dest=""), touched={uid}, count_delta=-1, verify=verify,
                    mutate=lambda v: v.purge_entry(uid))

    return execute_vault(open_db, db, build, apply)


# --- attributes that are not fields: tags, expiry, and copies ---------------------------------------------------

def _core(e: EntryData) -> tuple:
    """The fields of an entry that an attribute change must leave alone."""
    return (e.title, e.username, e.password, e.url, e.notes, e.otp, e.fields)


def _attribute_plan(e: EntryData, change: OrgChange, mutate: Callable[[Vault, str], None],
                    check: Callable[[EntryData], list[str]]) -> Plan:
    """The previous state goes to the entry's history, then `mutate(vault, id)`; afterwards `check` and the core must hold."""
    uid, core = e.id, _core(e)

    def verify(again: Vault) -> list[str]:
        x = next((y for y in again.entries() if y.id == uid), None)
        if x is None:
            return ["the entry is missing"]
        problems = check(x)
        if _core(x) != core:
            problems.append("the entry's fields changed")
        if x.group_id != e.group_id:
            problems.append("the entry moved")
        return problems

    def run(v: Vault) -> None:
        v.snapshot_history(uid)
        mutate(v, uid)

    return Plan(change=change, mutate=run, touched={uid}, verify=verify)


def _tag_ok(tag: str) -> str:
    if not tag or not tag.strip() or ";" in tag or "," in tag:
        raise WriteError(f"tag {tag!r} must be non-empty and contain no ';' or ','")
    return tag.strip()


def change_tags(open_db: Callable[[], object], db: Path, path: str, add: list[str], remove: list[str], apply: bool,
                username: str | None = None) -> OrgChange:
    """Add and remove tags on one entry (the previous state goes to its history)."""
    add, remove = [_tag_ok(t) for t in add], [_tag_ok(t) for t in remove]

    def build(vault: Vault) -> Plan:
        require(vault, "tags")
        e = find_data(vault, path, username)
        have = list(e.tags)
        want = [t for t in have if t not in remove] + [t for t in add if t not in have]
        change = OrgChange(kind="tags", target=path, dest=",".join(want))
        if sorted(want) == sorted(have):
            return Plan(change=change)  # nothing to do: no save, no history

        return _attribute_plan(e, change, lambda v, uid: v.set_tags(uid, want),
                               lambda x: [] if sorted(x.tags) == sorted(want) else ["the tags are not as planned"])

    return execute_vault(open_db, db, build, apply)


def set_expiry(open_db: Callable[[], object], db: Path, path: str, date: str | None, clear: bool, apply: bool,
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

    def build(vault: Vault) -> Plan:
        require(vault, "expiry")
        e = find_data(vault, path, username)
        current = e.expiry.astimezone(timezone.utc).date() if e.expires and e.expiry else None
        change = OrgChange(kind="expiry", target=path, dest="" if clear else date)
        if current == day:  # same date, or nothing to clear
            return Plan(change=change)
        moment = None if day is None else datetime(day.year, day.month, day.day, tzinfo=timezone.utc)

        def check(x: EntryData) -> list[str]:
            ok = (not x.expires) if day is None else (x.expires and x.expiry.astimezone(timezone.utc).date() == day)
            return [] if ok else ["the expiry is not as planned"]

        return _attribute_plan(e, change, lambda v, uid: v.set_expiry(uid, moment), check)

    return execute_vault(open_db, db, build, apply)


def clone_entry(open_db: Callable[[], object], db: Path, path: str, title: str | None, apply: bool,
                username: str | None = None) -> OrgChange:
    """Duplicate an entry next to the original: a new UUID, the same fields, tags, icon, expiry and attachments."""

    def build(vault: Vault) -> Plan:
        e = find_data(vault, path, username)
        new_title = title or f"{e.title} - copy"
        if any(x.title == new_title and x.group_id == e.group_id for x in vault.entries()):
            raise WriteError(f"{e.group_path!r} already has an entry titled {new_title!r}")
        change = OrgChange(kind="clone", target=path, dest=f"{e.group_path}/{new_title}")
        expect = (e.username, e.password, e.url, e.notes, e.otp, e.fields, sorted(e.tags))

        def mutate(v: Vault) -> None:
            content = {name: v.attachment(e.id, name) for name, _ in e.attachments}
            v.add_entry(e.group_id, replace(e, title=new_title, history_count=0), content)

        def verify(again: Vault) -> list[str]:
            twins = [x for x in again.entries() if x.title == new_title and x.group_id == e.group_id]
            if len(twins) != 1 or twins[0].id == e.id:
                return ["the copy is missing or not a new entry"]
            x = twins[0]
            got = (x.username, x.password, x.url, x.notes, x.otp, x.fields, sorted(x.tags))
            return [] if got == expect else ["the copy differs from the original"]

        return Plan(change=change, mutate=mutate, touched=set(), count_delta=1, verify=verify)

    return execute_vault(open_db, db, build, apply)


# --- appearance and behaviour in a client: icon, colours, URL override, auto-type ------------------------------------

_HEX = re.compile(r"#[0-9A-Fa-f]{6}")
_ICONS = range(0, 69)  # KeePass' standard icon set


def _one_attribute(open_db, db, path, username, apply, kind, goal: str, current: Callable[[EntryData], str],
                   mutate: Callable[[Vault, str], None], check: Callable[[EntryData], list[str]],
                   capability: str) -> OrgChange:
    """The shape every single-attribute change shares: a no-op when nothing differs, else history + mutate + verify."""

    def build(vault: Vault) -> Plan:
        require(vault, capability)
        e = find_data(vault, path, username)
        change = OrgChange(kind=kind, target=path, dest=goal)
        if current(e) == goal:
            return Plan(change=change)
        return _attribute_plan(e, change, mutate, check)

    return execute_vault(open_db, db, build, apply)


def set_icon(open_db: Callable[[], object], db: Path, path: str, icon: int, apply: bool,
             username: str | None = None) -> OrgChange:
    """Set the standard icon number of an entry."""
    if icon not in _ICONS:
        raise WriteError(f"icon {icon} is not one of the standard icons ({_ICONS[0]}..{_ICONS[-1]})")
    return _one_attribute(open_db, db, path, username, apply, "icon", str(icon), lambda e: str(e.icon),
                          lambda v, uid: v.set_icon(uid, str(icon)),
                          lambda x: [] if str(x.icon) == str(icon) else ["the icon is not as planned"], "icons")


def set_color(open_db: Callable[[], object], db: Path, path: str, fg: str | None, bg: str | None, clear: bool,
              apply: bool, username: str | None = None) -> OrgChange:
    """Set the foreground and/or background colour (#RRGGBB) of an entry, or clear both."""
    if clear == (fg is not None or bg is not None):
        raise WriteError("give --fg and/or --bg (#RRGGBB), or --clear, not both and not neither")
    for value in (fg, bg):
        if value is not None and not _HEX.fullmatch(value):
            raise WriteError(f"{value!r} is not a colour (#RRGGBB)")

    def build(vault: Vault) -> Plan:
        require(vault, "colours")
        e = find_data(vault, path, username)
        have = (e.fg_color, e.bg_color)
        goal = ("", "") if clear else (fg if fg is not None else have[0], bg if bg is not None else have[1])
        change = OrgChange(kind="color", target=path, dest=f"{goal[0] or '-'} {goal[1] or '-'}")
        if have == goal:
            return Plan(change=change)
        return _attribute_plan(e, change, lambda v, uid: v.set_colours(uid, *goal),
                               lambda x: [] if (x.fg_color, x.bg_color) == goal else ["colours differ"])

    return execute_vault(open_db, db, build, apply)


def set_override_url(open_db: Callable[[], object], db: Path, path: str, url: str, apply: bool,
                     username: str | None = None) -> OrgChange:
    """Set the URL (or command) a client opens instead of the entry's URL; an empty value removes it."""
    return _one_attribute(open_db, db, path, username, apply, "override-url", url, lambda e: e.override_url,
                          lambda v, uid: v.set_override_url(uid, url),
                          lambda x: [] if x.override_url == url else ["the URL override differs"], "colours")


def set_autotype(open_db: Callable[[], object], db: Path, path: str, enabled: bool | None, sequence: str | None,
                 apply: bool, username: str | None = None) -> OrgChange:
    """Switch auto-type on or off and/or set its keystroke sequence."""
    if enabled is None and sequence is None:
        raise WriteError("nothing to change: give --enabled/--disabled and/or --sequence")

    def build(vault: Vault) -> Plan:
        require(vault, "autotype")
        e = find_data(vault, path, username)
        goal = (e.autotype_enabled if enabled is None else enabled, e.autotype_sequence if sequence is None else sequence)
        change = OrgChange(kind="autotype", target=path, dest=f"{'on' if goal[0] else 'off'} {goal[1]}".strip())
        if (e.autotype_enabled, e.autotype_sequence) == goal:
            return Plan(change=change)
        return _attribute_plan(e, change, lambda v, uid: v.set_autotype(uid, goal[0], goal[1]),
                               lambda x: [] if (x.autotype_enabled, x.autotype_sequence) == goal
                               else ["auto-type is not as planned"])

    return execute_vault(open_db, db, build, apply)
