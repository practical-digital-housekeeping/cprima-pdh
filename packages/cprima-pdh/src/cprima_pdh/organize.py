"""Group structure changes: create a group, move an entry. Dry run unless `apply`.

Entries keep their UUID when moved. Nothing but the group of the moved entry (or the
existence of the new group) may change; this is verified by reopening the saved file.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .fix import _base, _custom
from .models import OrgChange
from .source import _gpath

if TYPE_CHECKING:
    from pykeepass import PyKeePass
from .write import WriteError, find_entry


def find_group(kp: PyKeePass, path: str):
    """The single group whose path (as shown by `tree`/validate) equals path; '/' is the root."""
    wanted = "/" if path in ("", "/") else path.strip("/")
    hits = [g for g in kp.groups if _gpath(g) == wanted]
    if not hits:
        raise WriteError(f"no group {path!r}")
    if len(hits) > 1:
        raise WriteError(f"{len(hits)} groups match {path!r}; rename one first")
    return hits[0]


def new_group(open_db: Callable[[], PyKeePass], db: Path, parent: str, name: str, apply: bool) -> OrgChange:
    """Create a group below `parent`."""
    from .txn import Plan, execute

    def build(kp: PyKeePass) -> Plan:
        p = find_group(kp, parent)
        if not name or "/" in name:
            raise WriteError("group name must be non-empty and must not contain '/'")
        if any(g.name == name for g in p.subgroups):
            raise WriteError(f"{parent!r} already has a group {name!r}")
        parent_path = _gpath(p)
        target = name if parent_path == "/" else f"{parent_path}/{name}"
        parent_uid, n_groups = p.uuid, len(list(kp.groups))

        def mutate(k: PyKeePass) -> None:
            k.add_group(next(g for g in k.groups if g.uuid == parent_uid), name)

        def verify(again: PyKeePass) -> list[str]:
            problems = []
            if len(list(again.groups)) != n_groups + 1:
                problems.append("group count did not grow by one")
            try:
                find_group(again, target)
            except WriteError:
                problems.append("the new group is missing")
            return problems

        return Plan(change=OrgChange(kind="new-group", target=target, dest=parent_path), mutate=mutate, verify=verify)

    return execute(open_db, db, build, apply)


def new_entry(open_db: Callable[[], PyKeePass], db: Path, group: str, title: str, username: str, password: str,
              apply: bool, url: str | None = None, notes: str | None = None, tags: list[str] | None = None,
              expires: str | None = None, fields: dict[str, str] | None = None,
              secret_fields: dict[str, str] | None = None) -> OrgChange:
    """Create a complete entry in one call. Passwords and secret field values are written, never shown or returned."""
    from datetime import date, datetime, timezone

    from .backends.kdbx import OTP_PREFIXES, STANDARD_ATTR
    from .txn import Plan, execute

    fields, secret_fields, tags = dict(fields or {}), dict(secret_fields or {}), list(tags or [])
    day = None
    if expires is not None:
        try:
            day = date.fromisoformat(expires)
        except ValueError:
            raise WriteError(f"{expires!r} is not a date (YYYY-MM-DD)") from None
    for name in [*fields, *secret_fields]:
        if not name or name in STANDARD_ATTR or name.startswith(OTP_PREFIXES):
            raise WriteError(f"{name!r} is a standard or OTP field name; only custom fields can be given with --field")
    if set(fields) & set(secret_fields):
        raise WriteError("a field is given both as --field and --secret-field")
    for tag in tags:
        if not tag.strip() or ";" in tag or "," in tag:
            raise WriteError(f"tag {tag!r} must be non-empty and contain no ';' or ','")

    def build(kp: PyKeePass) -> Plan:
        g = find_group(kp, group)
        if not title or "/" in title:
            raise WriteError("title must be non-empty and must not contain '/'")
        if any(e.title == title for e in g.entries):
            raise WriteError(f"{group!r} already has an entry {title!r}")
        group_path, group_uid = _gpath(g), g.uuid
        change = OrgChange(kind="new-entry", target=f"{group_path}/{title}", dest=group_path)

        def mutate(k: PyKeePass) -> None:
            target = next(x for x in k.groups if x.uuid == group_uid)
            made = k.add_entry(target, title, username, password, url=url, notes=notes, tags=tags or None)
            for name, value in fields.items():
                made.set_custom_property(name, value)
            for name, value in secret_fields.items():
                made.set_custom_property(name, value, protect=True)
            if day is not None:
                made.expiry_time, made.expires = datetime(day.year, day.month, day.day, tzinfo=timezone.utc), True

        def verify(again: PyKeePass) -> list[str]:
            made = [e for e in again.entries if e.title == title and e.group.uuid == group_uid]
            if len(made) != 1:
                return ["the new entry is missing"]
            e = made[0]
            problems = []
            if (e.username, e.password, e.url or None, e.notes or None) != (username, password, url or None, notes or None):
                problems.append("the stored standard fields differ")
            if sorted(e.tags or []) != sorted(tags):
                problems.append("the stored tags differ")
            for name, value in {**fields, **secret_fields}.items():
                if e.get_custom_property(name) != value:
                    problems.append("a custom field differs")
                if e.is_custom_property_protected(name) != (name in secret_fields):
                    problems.append("a custom field has the wrong protection")
            if (day is not None) != bool(e.expires):
                problems.append("the expiry differs")
            return problems

        return Plan(change=change, mutate=mutate, count_delta=1, verify=verify)

    return execute(open_db, db, build, apply)


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
    """Move an entry to another group (its UUID is kept). A move changes the location, not the content: no history."""
    from .txn import Plan, execute

    def build(kp: PyKeePass) -> Plan:
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
        uid, dest_uid = str(e.uuid), g.uuid
        expect = (_base(e, with_group=False), _custom(e))

        def mutate(k: PyKeePass) -> None:
            k.move_entry(next(x for x in k.entries if str(x.uuid) == uid), next(x for x in k.groups if x.uuid == dest_uid))

        def verify(again: PyKeePass) -> list[str]:
            moved = next((x for x in again.entries if str(x.uuid) == uid), None)
            if moved is None:
                return ["the moved entry is missing"]
            problems = []
            if moved.group.uuid != dest_uid:
                problems.append("the entry is not in the destination group")
            if (_base(moved, with_group=False), _custom(moved)) != expect:
                problems.append("the moved entry's data changed")
            return problems

        return Plan(change=OrgChange(kind="move", target=path, dest=_gpath(g)), mutate=mutate, touched={uid}, verify=verify)

    return execute(open_db, db, build, apply)
