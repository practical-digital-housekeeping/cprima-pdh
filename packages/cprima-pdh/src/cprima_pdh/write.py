"""Write operations. Everything here is dry-run unless `apply` is set."""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .backends.kdbx import STANDARD_ATTR, STANDARD_PROTECTED
from .models import Change
from .schema import make_ref, uuid_key
from .source import _gpath

if TYPE_CHECKING:
    from pykeepass import PyKeePass

_HIDDEN = "(hidden)"


class WriteError(Exception):
    pass


def find_entry(kp: PyKeePass, path: str, username: str | None = None):
    """The single entry whose `group/path/title` equals path (as printed by validate).

    `username` narrows down entries that share the same path.
    """
    hits = [e for e in kp.entries if f"{_gpath(e.group)}/{e.title}" == path]
    if username is not None:
        hits = [e for e in hits if (e.username or "") == username]
    if not hits:
        raise WriteError(f"no entry at {path!r}" + (f" with username {username!r}" if username else ""))
    if len(hits) > 1:
        raise WriteError(f"{len(hits)} entries at {path!r}; narrow it down with --username or rename one")
    return hits[0]


def effective_protection(e, field: str, protect: bool, unprotect: bool = False) -> bool:
    """Whether the field ends up protected: asked for, else asked against, else as it already is.

    Setting a custom field replaces its XML element, so the flag has to be carried over explicitly; otherwise every
    edit of a protected field would silently unprotect it."""
    if field in STANDARD_ATTR:
        return field in STANDARD_PROTECTED
    if protect:
        return True
    if unprotect:
        return False
    return bool(e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=field))


def _get(e, field: str) -> str:
    if field in STANDARD_ATTR:
        return getattr(e, STANDARD_ATTR[field]) or ""
    return e.get_custom_property(field) or ""


def _put(e, field: str, value: str, protect: bool) -> None:
    if field in STANDARD_ATTR:
        setattr(e, STANDARD_ATTR[field], value)
    else:
        e.set_custom_property(field, value, protect=protect)


def plan_set(
    kp: PyKeePass,
    path: str,
    field: str,
    value: str | Callable[[PyKeePass], str],
    overwrite: bool,
    protect: bool,
    username: str | None = None,
    unprotect: bool = False,
) -> Change:
    if protect and unprotect:
        raise WriteError("--protect and --unprotect exclude each other")
    if callable(value):  # a value that needs the opened database, such as a link to another entry
        value = value(kp)
    e = find_entry(kp, path, username)
    old = _get(e, field)
    hide = effective_protection(e, field, protect, unprotect)
    shown = (lambda v: _HIDDEN if v and hide else v)
    if old == value:
        action = "unchanged"
    elif old and not overwrite:
        action = "skipped: field not empty (use --overwrite)"
    else:
        action = "set"
    return Change(entry=path, field=field, old=shown(old), new=shown(value), action=action)


def _fingerprint(db: Path) -> tuple[int, int]:
    st = os.stat(db)
    return st.st_mtime_ns, st.st_size


def _lock_files(db: Path) -> list[Path]:
    return [p for p in (db.with_name(db.name + ".lock"), db.with_name("." + db.name + ".lock")) if p.exists()]


def apply_set(
    open_db: Callable[[], PyKeePass],
    db: Path,
    path: str,
    field: str,
    value: str,
    overwrite: bool,
    protect: bool,
    username: str | None = None,
    unprotect: bool = False,
) -> Change:
    """Set one field on one entry: history snapshot, one save, reopened and verified (see `txn.execute`)."""
    from .txn import Plan, execute, snapshot

    def build(kp: PyKeePass) -> Plan:
        wanted = value(kp) if callable(value) else value
        change = plan_set(kp, path, field, wanted, overwrite, protect, username, unprotect)
        if change.action != "set":
            return Plan(change=change)
        e = find_entry(kp, path, username)
        uid = str(e.uuid)
        keep = effective_protection(e, field, protect, unprotect)

        def mutate(k: PyKeePass) -> None:
            target = next(x for x in k.entries if str(x.uuid) == uid)
            snapshot(target)
            _put(target, field, wanted, keep)

        def verify(again: PyKeePass) -> list[str]:
            target = next((x for x in again.entries if str(x.uuid) == uid), None)  # by uuid: Title changes the path
            if target is None or _get(target, field) != wanted:
                return [f"{field} not set as expected"]
            if field not in STANDARD_ATTR and bool(target.is_custom_property_protected(field)) != keep:
                return [f"{field} does not have the expected protection"]
            return []

        return Plan(change=change, mutate=mutate, touched={uid}, verify=verify)

    return execute(open_db, db, build, True)  # the caller decided to write


def _link_value(kp: PyKeePass, account: str, target: str, plain: bool, account_username: str | None,
                target_username: str | None) -> str:
    """The value to store in the link field: a KeePass reference to the target by UUID (or the bare UUID)."""
    t = find_entry(kp, target, target_username)
    a = find_entry(kp, account, account_username)
    if str(t.uuid) == str(a.uuid):
        raise WriteError("an entry cannot link to itself")
    return uuid_key(t.uuid) if plain else make_ref(t.uuid)


def plan_link(
    kp: PyKeePass,
    account: str,
    target: str,
    field: str = "device",
    plain: bool = False,
    overwrite: bool = False,
    account_username: str | None = None,
    target_username: str | None = None,
) -> Change:
    """Dry run: what would be written into `field` of `account` so that it links to `target`."""
    value = _link_value(kp, account, target, plain, account_username, target_username)
    return plan_set(kp, account, field, value, overwrite, False, account_username)


def apply_link(
    open_db: Callable[[], PyKeePass],
    db: Path,
    account: str,
    target: str,
    field: str = "device",
    plain: bool = False,
    overwrite: bool = False,
    account_username: str | None = None,
    target_username: str | None = None,
) -> Change:
    """Write the link, with the same safeguards as `set` (lock file, change detection, verification)."""
    return apply_set(
        open_db, db, account, field,
        lambda kp: _link_value(kp, account, target, plain, account_username, target_username),
        overwrite, False, account_username,
    )
