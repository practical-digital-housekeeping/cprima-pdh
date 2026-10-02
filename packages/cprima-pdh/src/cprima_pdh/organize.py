"""Group structure changes: create a group, move an entry. Dry run unless `apply`.

Entries keep their UUID when moved. Nothing but the group of the moved entry (or the
existence of the new group) may change; this is verified by reopening the saved file.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .fix import _base, _custom
from .models import OrgChange
from .source import _gpath, pykeepass_open

if TYPE_CHECKING:
    from pykeepass import PyKeePass
from .write import WriteError, _fingerprint, _lock_files, find_entry


def find_group(kp: PyKeePass, path: str):
    """The single group whose path (as shown by `tree`/validate) equals path; '/' is the root."""
    wanted = "/" if path in ("", "/") else path.strip("/")
    hits = [g for g in kp.groups if _gpath(g) == wanted]
    if not hits:
        raise WriteError(f"no group {path!r}")
    if len(hits) > 1:
        raise WriteError(f"{len(hits)} groups match {path!r}; rename one first")
    return hits[0]


def _digests(kp: PyKeePass, skip: set[str] = frozenset()) -> dict[str, tuple[str, str]]:
    return {str(e.uuid): (_base(e), _custom(e)) for e in kp.entries if str(e.uuid) not in skip}


def _guard(db: Path) -> None:
    if locks := _lock_files(db):
        raise WriteError(f"database seems open elsewhere (lock file {locks[0].name}); close it first")


def _check_untouched(again: PyKeePass, before: dict[str, tuple[str, str]], total: int, problems: list[str]) -> None:
    entries = {str(e.uuid): e for e in again.entries}
    if len(entries) != total:
        problems.append(f"entry count changed ({total} -> {len(entries)})")
    for uid, digest in before.items():
        e = entries.get(uid)
        if e is None or (_base(e), _custom(e)) != digest:
            problems.append("an entry that should be unchanged differs")
            break


def new_group(open_db: Callable[[], PyKeePass], db: Path, parent: str, name: str, apply: bool) -> OrgChange:
    before_fp = _fingerprint(db)
    kp = open_db()
    p = find_group(kp, parent)
    if not name or "/" in name:
        raise WriteError("group name must be non-empty and must not contain '/'")
    if any(g.name == name for g in p.subgroups):
        raise WriteError(f"{parent!r} already has a group {name!r}")
    parent_path = _gpath(p)
    target = name if parent_path == "/" else f"{parent_path}/{name}"
    change = OrgChange(kind="new-group", target=target, dest=parent_path)
    if not apply:
        return change

    _guard(db)
    before = _digests(kp)
    total, n_groups = len(before), len(list(kp.groups))
    kp.add_group(p, name)
    if _fingerprint(db) != before_fp:
        raise WriteError("database file changed while working; nothing written")
    kp.save()

    again = pykeepass_open(db, kp.password, kp.keyfile)
    problems: list[str] = []
    _check_untouched(again, before, total, problems)
    if len(list(again.groups)) != n_groups + 1:
        problems.append("group count did not grow by one")
    try:
        find_group(again, target)
    except WriteError:
        problems.append("the new group is missing")
    if problems:
        raise WriteError("verification failed: " + "; ".join(sorted(set(problems))) + ". Restore from your own backup.")
    return change.model_copy(update={"applied": True})


def new_entry(open_db: Callable[[], PyKeePass], db: Path, group: str, title: str, username: str, password: str,
              apply: bool) -> OrgChange:
    """Create an entry with standard fields only. The password is written, never shown or returned."""
    before_fp = _fingerprint(db)
    kp = open_db()
    g = find_group(kp, group)
    if not title or "/" in title:
        raise WriteError("title must be non-empty and must not contain '/'")
    if any(e.title == title for e in g.entries):
        raise WriteError(f"{group!r} already has an entry {title!r}")
    group_path = _gpath(g)
    change = OrgChange(kind="new-entry", target=f"{group_path}/{title}", dest=group_path)
    if not apply:
        return change

    _guard(db)
    before = _digests(kp)
    total = len(before)
    kp.add_entry(g, title, username, password)
    if _fingerprint(db) != before_fp:
        raise WriteError("database file changed while working; nothing written")
    kp.save()

    again = pykeepass_open(db, kp.password, kp.keyfile)
    problems: list[str] = []
    entries = {str(e.uuid) for e in again.entries}
    if len(entries) != total + 1:
        problems.append("entry count did not grow by one")
    for uid, digest in before.items():
        e = again.find_entries(uuid=__import__("uuid").UUID(uid), first=True)
        if e is None or (_base(e), _custom(e)) != digest:
            problems.append("an entry that should be unchanged differs")
            break
    made = find_entry(again, change.target, username)
    if made.password != password:
        problems.append("the stored password differs")
    if problems:
        raise WriteError("verification failed: " + "; ".join(sorted(set(problems))) + ". Restore from your own backup.")
    return change.model_copy(update={"applied": True})


def _top(group_path: str) -> str:
    """First path segment of a group path ('' for the root group)."""
    return "" if group_path == "/" else group_path.split("/", 1)[0]


def move_entry(
    open_db: Callable[[], PyKeePass],
    db: Path,
    path: str,
    dest: str,
    apply: bool,
    username: str | None = None,
    cross_top_level: bool = False,
) -> OrgChange:
    before_fp = _fingerprint(db)
    kp = open_db()
    e = find_entry(kp, path, username)
    g = find_group(kp, dest)
    if str(e.group.uuid) == str(g.uuid):
        raise WriteError(f"{path!r} is already in {dest!r}")
    if not cross_top_level and _top(_gpath(e.group)) != _top(_gpath(g)):
        raise WriteError(
            f"{path!r} is under {_top(_gpath(e.group)) or 'the root'!r} but {dest!r} is under "
            f"{_top(_gpath(g)) or 'the root'!r}; moves stay inside one top-level group (use --cross-top-level to override)"
        )
    if any(x.title == e.title for x in g.entries):
        raise WriteError(f"{dest!r} already has an entry titled {e.title!r}; rename one first")
    change = OrgChange(kind="move", target=path, dest=_gpath(g))
    if not apply:
        return change

    _guard(db)
    uid, dest_uid = str(e.uuid), str(g.uuid)
    expect_base, expect_custom = _base(e, with_group=False), _custom(e)
    before = _digests(kp, skip={uid})
    total = len(before) + 1
    kp.move_entry(e, g)
    if _fingerprint(db) != before_fp:
        raise WriteError("database file changed while working; nothing written")
    kp.save()

    again = pykeepass_open(db, kp.password, kp.keyfile)
    problems: list[str] = []
    _check_untouched(again, before, total, problems)
    moved = next((x for x in again.entries if str(x.uuid) == uid), None)
    if moved is None:
        problems.append("the moved entry is missing")
    else:
        if str(moved.group.uuid) != dest_uid:
            problems.append("the entry is not in the destination group")
        if _base(moved, with_group=False) != expect_base or _custom(moved) != expect_custom:
            problems.append("the moved entry's data changed")
    if problems:
        raise WriteError("verification failed: " + "; ".join(sorted(set(problems))) + ". Restore from your own backup.")
    return change.model_copy(update={"applied": True})
