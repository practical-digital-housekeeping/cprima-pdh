"""Group structure changes: create a group, move an entry. Dry run unless `apply`.

Entries keep their UUID when moved. Nothing but the group of the moved entry (or the
existence of the new group) may change; this is verified by reopening the saved file.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Callable

from .models import OrgChange
from cprima_pdh_vault.vault import EntryData, Field, GroupData, Vault
from .write import WriteError, find_data


def find_group(vault: Vault, path: str) -> GroupData:
    """The single group whose path (as shown by `tree`/validate) equals path; '/' is the root."""
    wanted = "/" if path in ("", "/") else path.strip("/")
    hits = [g for g in vault.groups() if g.path == wanted]
    if not hits:
        raise WriteError(f"no group {path!r}")
    if len(hits) > 1:
        raise WriteError(f"{len(hits)} groups match {path!r}; rename one first")
    return hits[0]


def new_group(open_db: Callable[[], object], db: Path, parent: str, name: str, apply: bool) -> OrgChange:
    """Create a group below `parent`."""
    from .txn import Plan, execute_vault

    def build(vault: Vault) -> Plan:
        p = find_group(vault, parent)
        if not name or "/" in name:
            raise WriteError("group name must be non-empty and must not contain '/'")
        groups = vault.groups()
        if any(g.name == name and g.parent_id == p.id for g in groups):
            raise WriteError(f"{parent!r} already has a group {name!r}")
        target = name if p.path == "/" else f"{p.path}/{name}"
        n_groups = len(groups)

        def mutate(v: Vault) -> None:
            v.add_group(p.id, name)

        def verify(again: Vault) -> list[str]:
            problems = []
            if len(again.groups()) != n_groups + 1:
                problems.append("group count did not grow by one")
            try:
                find_group(again, target)
            except WriteError:
                problems.append("the new group is missing")
            return problems

        return Plan(change=OrgChange(kind="new-group", target=target, dest=p.path), mutate=mutate, verify=verify)

    return execute_vault(open_db, db, build, apply)


def new_entry(open_db: Callable[[], object], db: Path, group: str, title: str, username: str, password: str,
              apply: bool, url: str | None = None, notes: str | None = None, tags: list[str] | None = None,
              expires: str | None = None, fields: dict[str, str] | None = None, sset=None) -> OrgChange:
    """Create an entry in one call: structure, and the password it is handed (from a prompt, never from an argument). A custom
    field that holds a secret is refused (see `boundary`); it is added afterwards with `pdh edit set`. Nothing is shown."""
    from datetime import date, datetime, timezone

    from . import boundary
    from cprima_pdh_kdbxkit.kdbx_format import OTP_PREFIXES, STANDARD_ATTR
    from .txn import Plan, execute_vault

    fields, tags = dict(fields or {}), list(tags or [])
    day = None
    if expires is not None:
        try:
            day = date.fromisoformat(expires)
        except ValueError:
            raise WriteError(f"{expires!r} is not a date (YYYY-MM-DD)") from None
    for name in fields:
        if not name or name in STANDARD_ATTR or name.startswith(OTP_PREFIXES):
            raise WriteError(f"{name!r} is a standard or OTP field name; only custom fields can be given with --field")
        if boundary.secret_columns([name], sset):
            raise WriteError(f"--field {name}: a field that holds a secret is never given on the command line; create the "
                             f"entry, then `pdh edit set PATH {name} -` (hidden prompt)")
    for tag in tags:
        if not tag.strip() or ";" in tag or "," in tag:
            raise WriteError(f"tag {tag!r} must be non-empty and contain no ';' or ','")

    def build(vault: Vault) -> Plan:
        g = find_group(vault, group)
        if not title or "/" in title:
            raise WriteError("title must be non-empty and must not contain '/'")
        if any(e.title == title and e.group_id == g.id for e in vault.entries()):
            raise WriteError(f"{group!r} already has an entry {title!r}")
        change = OrgChange(kind="new-entry", target=f"{g.path}/{title}", dest=g.path)
        moment = datetime(day.year, day.month, day.day, tzinfo=timezone.utc) if day is not None else None
        data = EntryData(
            id="", group_path=g.path, group_id=g.id, title=title, username=username, password=password, url=url or "",
            notes=notes or "", tags=tuple(tags), expires=day is not None, expiry=moment,
            fields={n: Field(v, False) for n, v in fields.items()})

        def mutate(v: Vault) -> None:
            v.add_entry(g.id, data)

        def verify(again: Vault) -> list[str]:
            made = [e for e in again.entries() if e.title == title and e.group_id == g.id]
            if len(made) != 1:
                return ["the new entry is missing"]
            e = made[0]
            problems = []
            if (e.username, e.password, e.url or None, e.notes or None) != (username, password, url or None, notes or None):
                problems.append("the stored standard fields differ")
            if sorted(e.tags) != sorted(tags):
                problems.append("the stored tags differ")
            for name, value in fields.items():
                got = e.fields.get(name)
                if got is None or got.value != value:
                    problems.append("a custom field differs")
                elif got.protected:
                    problems.append("a custom field has the wrong protection")
            if (day is not None) != e.expires:
                problems.append("the expiry differs")
            return problems

        return Plan(change=change, mutate=mutate, count_delta=1, verify=verify)

    return execute_vault(open_db, db, build, apply)


def _top(group_path: str) -> str:
    """First path segment of a group path ('' for the root group)."""
    return "" if group_path == "/" else group_path.split("/", 1)[0]


def _same_data(e: EntryData) -> EntryData:
    """An entry minus where it is and when it was moved: what a move must leave alone."""
    return replace(e, group_path="", group_id="", in_bin=False, location_changed=None)


def move_entry(
    open_db: Callable[[], object],
    db: Path,
    path: str,
    dest: str,
    apply: bool,
    username: str | None = None,
    cross_top_level: bool = False,
) -> OrgChange:
    """Move an entry to another group (its UUID is kept). A move changes the location, not the content: no history."""
    from .txn import Plan, execute_vault

    def build(vault: Vault) -> Plan:
        e = find_data(vault, path, username)
        g = find_group(vault, dest)
        if e.group_id == g.id:
            raise WriteError(f"{path!r} is already in {dest!r}")
        if not cross_top_level and _top(e.group_path) != _top(g.path):
            raise WriteError(
                f"{path!r} is under {_top(e.group_path) or 'the root'!r} but {dest!r} is under "
                f"{_top(g.path) or 'the root'!r}; moves stay inside one top-level group (use --cross-top-level to override)"
            )
        if any(x.title == e.title and x.group_id == g.id for x in vault.entries()):
            raise WriteError(f"{dest!r} already has an entry titled {e.title!r}; rename one first")
        uid = e.id
        expect = _same_data(e)

        def mutate(v: Vault) -> None:
            v.move_entry(uid, g.id)

        def verify(again: Vault) -> list[str]:
            moved = next((x for x in again.entries() if x.id == uid), None)
            if moved is None:
                return ["the moved entry is missing"]
            problems = []
            if moved.group_id != g.id:
                problems.append("the entry is not in the destination group")
            if _same_data(moved) != expect:
                problems.append("the moved entry's data changed")
            return problems

        return Plan(change=OrgChange(kind="move", target=path, dest=g.path), mutate=mutate, touched={uid}, verify=verify,
                    stamp="location")

    return execute_vault(open_db, db, build, apply)
