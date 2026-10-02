"""Write operations. Everything here is dry-run unless `apply` is set."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .backends.kdbx import STANDARD_ATTR, STANDARD_PROTECTED
from .models import Change
from .schema import make_ref, uuid_key
from .source import _gpath, pykeepass_open

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


def _is_protected(e, field: str, protect: bool) -> bool:
    return (
        protect
        or field in STANDARD_PROTECTED
        or bool(e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=field))
    )


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
) -> Change:
    if callable(value):  # a value that needs the opened database, such as a link to another entry
        value = value(kp)
    e = find_entry(kp, path, username)
    old = _get(e, field)
    hide = _is_protected(e, field, protect)
    shown = (lambda v: _HIDDEN if v and hide else v)
    if old == value:
        action = "unchanged"
    elif old and not overwrite:
        action = "skipped: field not empty (use --overwrite)"
    else:
        action = "set"
    return Change(entry=path, field=field, old=shown(old), new=shown(value), action=action)


def _snapshot(kp: PyKeePass) -> dict[str, str]:
    """uuid -> digest of everything user-visible about the entry (compared in memory only)."""
    out = {}
    for e in kp.entries:
        parts = [e.title, e.username, e.password, e.url, e.notes, e.otp, ",".join(sorted(e.tags or [])),
                 repr(sorted((e.custom_properties or {}).items())), _gpath(e.group), str(e.expires)]
        out[str(e.uuid)] = hashlib.sha256("\x1f".join(p or "" for p in parts).encode()).hexdigest()
    return out


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
) -> Change:
    before = _fingerprint(db)
    kp = open_db()
    if callable(value):
        value = value(kp)
    change = plan_set(kp, path, field, value, overwrite, protect, username)
    if change.action != "set":
        return change

    if locks := _lock_files(db):
        raise WriteError(f"database seems open elsewhere (lock file {locks[0].name}); close it first")

    e = find_entry(kp, path, username)
    target_uuid = e.uuid
    expect = _snapshot(kp)
    _put(e, field, value, protect)
    expect[str(e.uuid)] = None  # the target entry is verified separately
    if _fingerprint(db) != before:
        raise WriteError("database file changed while working; nothing written")
    kp.save()

    again = pykeepass_open(db, kp.password, kp.keyfile)
    after = _snapshot(again)
    target = again.find_entries(uuid=target_uuid, first=True)  # by uuid: a Title change alters the path
    problems = []
    if target is None or _get(target, field) != value:
        problems.append(f"{field} not set as expected")
    if len(after) != len(expect):
        problems.append(f"entry count changed ({len(expect)} -> {len(after)})")
    changed = [u for u, d in expect.items() if d is not None and after.get(u) != d]
    if changed:
        problems.append(f"{len(changed)} other entries differ after save")
    if problems:
        raise WriteError("verification failed: " + "; ".join(problems) + ". Restore from your own backup.")
    return change.model_copy(update={"applied": True})


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
