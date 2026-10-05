"""Bringing data into a vault: CSV import, import from another vault, and merging two copies of one vault.

All of it runs through `txn.execute_vault`: dry run unless `apply`, one save, reopened and verified. Reports name entries
and counts, never values. Merging works the way git merges (see `merge.py`): by UUID, what loses nothing is done by itself, a
change that would be dropped is a conflict a person answers, and the state a change replaces is kept in the entry's history.
An entry is only removed by a deletion record of the other copy, never because that copy lacks it.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from . import boundary, secret_fields, spreadsheet
from .history import _state
from .merge import _deletions as _records_of
from .merge import merge_situation
from .models import ImportReport, MergeReport
from .schema import SchemaSet
from .txn import Plan, execute_vault
from cprima_pdh_vault.vault import EntryData, Field, GroupData, Vault, as_vault
from .write import WriteError

_COLUMNS = {  # lower-cased CSV header -> what it is
    "group": "group", "title": "title", "username": "username", "user name": "username", "user_name": "username",
    "url": "url", "notes": "notes", "tags": "tags", "expires": "expires", "expiry": "expires",
}
_EARLIEST = datetime.min.replace(tzinfo=timezone.utc)


def _root_id(vault: Vault) -> str:
    return next(g.id for g in vault.groups() if g.is_root)


def _find_group(vault: Vault, parts: list[str]) -> GroupData | None:
    groups = vault.groups()
    current = next(g for g in groups if g.is_root)
    for name in parts:
        current = next((g for g in groups if g.parent_id == current.id and g.name == name), None)
        if current is None:
            return None
    return current


def _ensure_path(vault: Vault, parts: list[str]) -> str:
    """The id of the group at `parts` below the root, created (with its parents) when missing."""
    current = _root_id(vault)
    for name in parts:
        child = next((g for g in vault.groups() if g.parent_id == current and g.name == name), None)
        current = child.id if child is not None else vault.add_group(current, name)
    return current


def _parts(path: str) -> list[str]:
    return [p for p in path.strip("/").split("/") if p]


def _new_paths(vault: Vault, wanted: set[tuple[str, ...]]) -> int:
    """How many groups would have to be created so that every wanted path exists."""
    missing = set()
    for path in wanted:
        for i in range(1, len(path) + 1):
            if _find_group(vault, list(path[:i])) is None:
                missing.add(path[:i])
    return len(missing)


def _entries_in(vault: Vault, group_id: str) -> list[EntryData]:
    return [e for e in vault.entries() if e.group_id == group_id]


# --- one entry from one vault into another ----------------------------------------------------------------------------

def copy_entry(src: Vault, src_entry: EntryData, dest: Vault, dest_group_id: str, keep_uuid: bool = False) -> str:
    """Copy an entry (fields with their protection, tags, icon, expiry, times, attachments, look) into a group."""
    content = {name: src.attachment(src_entry.id, name) for name, _ in src_entry.attachments}
    return dest.add_entry(dest_group_id, src_entry, content, keep_id=keep_uuid, keep_times=True)


# --- import from CSV ----------------------------------------------------------------------------------------------------

_EXCEL_EPOCH = date(1899, 12, 30)  # day 0 of the 1900 date system, which makes Excel's day numbers come out right after 1900-03-01


def _expiry_day(raw: str, from_workbook: bool) -> date:
    """A date as YYYY-MM-DD; from a workbook also the day number Excel stores for a date cell."""
    try:
        return date.fromisoformat(raw)
    except ValueError:
        if from_workbook and raw.replace(".", "", 1).isdigit() and 1 <= float(raw) < 2958466:
            return _EXCEL_EPOCH + timedelta(days=int(float(raw)))
        raise


def import_csv(open_db: Callable[[], object], db: Path, file: Path, group: str, apply: bool,
               sset: SchemaSet | None = None) -> ImportReport:
    """Import a CSV file (see `_import_table`). A workbook is refused with the command to use for it."""
    if Path(file).suffix.lower() == ".xlsx":
        raise WriteError(f"{Path(file).name} is a workbook: use `pdh io import-xlsx`")
    return _import_table(open_db, db, file, group, apply, sset, spreadsheet.read_csv)


def import_xlsx(open_db: Callable[[], object], db: Path, file: Path, group: str, apply: bool,
                sset: SchemaSet | None = None) -> ImportReport:
    """Import the first visible sheet of an .xlsx workbook (see `_import_table`). A CSV file is refused with the command to use."""
    if Path(file).suffix.lower() == ".csv":
        raise WriteError(f"{Path(file).name} is a CSV file: use `pdh io import-csv`")
    return _import_table(open_db, db, file, group, apply, sset, spreadsheet.read_xlsx)


def _import_table(open_db: Callable[[], object], db: Path, file: Path, group: str, apply: bool, sset: SchemaSet | None,
                  read: Callable[[Path], spreadsheet.Table]) -> ImportReport:
    """Import a file read by `read` as a table (see `import_table`)."""
    try:
        table = read(file)
    except spreadsheet.SpreadsheetError as exc:
        raise WriteError(str(exc)) from exc
    return import_table(open_db, db, table, str(file), group, apply, sset)


def import_table(open_db: Callable[[], object], db: Path, table: spreadsheet.Table, source: str, group: str, apply: bool,
                 sset: SchemaSet | None = None) -> ImportReport:
    """Add the rows of a table as entries below `group` (created if missing); unknown columns become custom fields. A column
    that names a secret refuses the whole table (see `boundary`): secrets are never read from a file or handed in as data. The
    report says how many secret fields of the new entries are still empty (see `secret_fields`). `source` names where the
    table came from, for the report and the messages."""
    name = Path(source).name
    header, raw_rows = table.header, table.rows
    if secret := boundary.secret_columns(header, sset):
        raise WriteError(boundary.refusal(secret, name))
    kinds = {h: _COLUMNS.get(h.strip().lower()) for h in header}
    if "title" not in kinds.values():
        raise WriteError(f"{name} needs a Title column")
    custom_columns = [h for h, kind in kinds.items() if kind is None and h]
    rows: list[dict] = []
    for number, raw in enumerate(raw_rows, start=2):  # row 1 is the header
        row = {"custom": {}}
        for h, kind in kinds.items():
            value = (raw.get(h) or "").strip() if kind != "notes" else (raw.get(h) or "")
            if kind:
                row[kind] = value
            elif h and value:
                row["custom"][h] = raw.get(h) or ""
        if not row.get("title"):
            raise WriteError(f"row {number}: the title is empty")
        if row.get("expires"):
            try:
                row["day"] = _expiry_day(row["expires"], table.kind == "xlsx")
            except ValueError:
                raise WriteError(f"row {number}: {row['expires']!r} is not a date (YYYY-MM-DD)") from None
        row["path"] = tuple(_parts(group) + _parts(row.get("group", "")))
        rows.append(row)
    seen = set()
    for row in rows:
        key = (row["path"], row["title"])
        if key in seen:
            raise WriteError(f"{name} has the title {row['title']!r} twice in {'/'.join(row['path']) or '/'}")
        seen.add(key)

    def build(vault: Vault) -> Plan:
        for row in rows:
            existing = _find_group(vault, list(row["path"]))
            if existing is not None and any(e.title == row["title"] for e in _entries_in(vault, existing.id)):
                raise WriteError(f"{'/'.join(row['path']) or '/'!r} already has an entry {row['title']!r}")
        report = ImportReport(kind=table.kind, source=source, entries=len(rows),
                              groups=_new_paths(vault, {r["path"] for r in rows}), columns=custom_columns,
                              secrets_to_fill=sum(_to_fill(r, sset) for r in rows))
        if not rows:
            return Plan(change=report)

        def mutate(v: Vault) -> None:
            for row in rows:
                day = row.get("day")
                data = EntryData(
                    id="", group_path="", title=row["title"], username=row.get("username", ""),
                    password=row.get("password", ""), url=row.get("url") or "", notes=row.get("notes") or "",
                    tags=tuple(t for t in row.get("tags", "").split(";") if t.strip()),
                    fields={n: Field(value, False) for n, value in row["custom"].items()},
                    expires=day is not None,
                    expiry=datetime(day.year, day.month, day.day, tzinfo=timezone.utc) if day is not None else None)
                v.add_entry(_ensure_path(v, list(row["path"])), data)

        def verify(again: Vault) -> list[str]:
            for row in rows:
                g = _find_group(again, list(row["path"]))
                if g is None or sum(1 for e in _entries_in(again, g.id) if e.title == row["title"]) != 1:
                    return ["an imported entry is missing"]
            return []

        return Plan(change=report, mutate=mutate, count_delta=len(rows), verify=verify)

    return execute_vault(open_db, db, build, apply)


def _to_fill(row: dict, sset: SchemaSet | None) -> int:
    """How many secret fields the entry this row makes will still lack: all of them, as no file brings a secret."""
    entry = EntryData(id="", group_path="", title=row["title"], fields={n: Field(v, False) for n, v in row["custom"].items()})
    if sset is None:
        return 1  # without a taxonomy: the password every login has
    return len(secret_fields.missing(entry, sset))


# --- import from another vault -----------------------------------------------------------------------------------------------

def import_vault(open_db: Callable[[], object], db: Path, other, source: str, group: str, apply: bool) -> ImportReport:
    """Copy the live entries of another vault, with their group structure, below `group` (new UUIDs)."""
    src = as_vault(other)
    groups = [g for g in src.groups() if not g.is_root and not g.is_bin and not g.in_bin]
    entries = [e for e in src.entries() if not e.in_bin]

    def build(vault: Vault) -> Plan:
        base = _parts(group)
        wanted = {tuple(base + _parts(e.group_path)) for e in entries}
        report = ImportReport(kind="vault", source=source, entries=len(entries), groups=_new_paths(vault, wanted),
                              columns=[])
        if not entries:
            return Plan(change=report)

        def mutate(v: Vault) -> None:
            for g in groups:
                _ensure_path(v, base + _parts(g.path))
            _ensure_path(v, base)
            for e in entries:
                copy_entry(src, e, v, _ensure_path(v, base + _parts(e.group_path)))

        def verify(again: Vault) -> list[str]:
            prefix = "/".join(base)
            count = sum(1 for x in again.entries() if x.group_path.strip("/").startswith(prefix))
            return [] if count >= len(entries) else ["fewer entries than planned were imported"]

        return Plan(change=report, mutate=mutate, count_delta=len(entries), verify=verify)

    return execute_vault(open_db, db, build, apply)


# --- merge two copies of one vault -----------------------------------------------------------------------------------------

def _group_like(vault: Vault, other_groups: dict[str, GroupData], gid: str) -> str:
    """The local group with the other copy's group id; created (same id, same place) when missing."""
    local = {g.id for g in vault.groups()}
    if gid in local:
        return gid
    src = other_groups[gid]
    parent = src.parent_id
    parent_id = _root_id(vault) if parent is None or other_groups[parent].is_root else _group_like(vault, other_groups, parent)
    return vault.add_group(parent_id, src.name, icon=src.icon, notes=src.notes, keep_id=gid)


# What `--prefer` answers for each kind of conflict: "mine" is this vault's side, "theirs" the other copy's.
_PREFER = {
    "mine": {"both-modified": "mine", "deleted-there-modified-here": "keep", "deleted-here-modified-there": "delete"},
    "theirs": {"both-modified": "theirs", "deleted-there-modified-here": "delete", "deleted-here-modified-there": "keep"},
}


def merge_vaults(open_db: Callable[[], object], db: Path, open_other: Callable[[], object], source: str, apply: bool,
                 resolutions: Mapping[str, str] | None = None, prefer: str | None = None) -> MergeReport:
    """Merge another copy of this vault into this one, the way git merges (`merge.merge_situation` works out what happens):
    what loses nothing is done by itself, a conflict is answered by `resolutions` (the conflict's id to its answer) or, for every
    one not answered, by `prefer` ("mine" or "theirs"), and while any conflict is open nothing is written. Deletions follow the
    deletion records of the other copy; this vault's own records and the other copy's are kept together. One verified write."""
    answers = dict(resolutions or {})

    def build(vault: Vault) -> Plan:
        other = as_vault(open_other())
        situation = merge_situation(vault, other, source)
        by_id = {c.id: c for c in situation.conflicts}
        for uid, choice in answers.items():
            if uid not in by_id:
                raise WriteError(f"{uid} is not a conflict of this merge")
            if choice not in by_id[uid].choices:
                raise WriteError(f"{choice!r} is not an answer for {by_id[uid].path}: it is {' or '.join(by_id[uid].choices)}")
        decided = dict(answers)
        if prefer:
            for c in situation.conflicts:
                decided.setdefault(c.id, _PREFER[prefer][c.kind])
        open_conflicts = [c for c in situation.conflicts if c.id not in decided]

        mine = {e.id: e for e in vault.entries()}
        theirs = {e.id: e for e in other.entries()}
        by_kind: dict[str, list[str]] = {k: [] for k in ("add", "update", "move", "trash", "delete", "delete-group")}
        for change in situation.clean:
            by_kind[change.kind].append(change.id)
        for c in situation.conflicts:  # the answers
            choice = decided.get(c.id)
            if choice == "theirs":
                by_kind["update"].append(c.id)
            elif c.kind == "deleted-there-modified-here" and choice == "delete":
                by_kind["delete"].append(c.id)
            elif c.kind == "deleted-here-modified-there" and choice == "keep":
                by_kind["add"].append(c.id)
        add, update, move, trash = by_kind["add"], by_kind["update"], by_kind["move"], by_kind["trash"]
        purge, purge_groups = by_kind["delete"], by_kind["delete-group"]
        groups_here = {g.id: g for g in vault.groups()}
        paths = {theirs[i].path for i in add} | {mine[i].path for i in [*update, *move, *trash, *purge]} \
            | {groups_here[g].path for g in purge_groups}
        report = MergeReport(
            source=source, added=len(add), updated=len(update), moved=len(move), trashed=len(trash), deleted=len(purge),
            groups_deleted=len(purge_groups), unchanged=situation.unchanged, skipped=situation.skipped, entries=sorted(paths),
            records_copied=situation.records_to_copy, changes=situation.clean, conflicts=situation.conflicts,
            unresolved=len(open_conflicts))
        if open_conflicts or not (paths or situation.records_to_copy):
            return Plan(change=report)  # a conflict is open (nothing is written), or there is nothing to do
        records = _records_of(other)
        other_groups = {g.id: g for g in other.groups()}

        def content(s: EntryData) -> dict[str, bytes]:
            return {name: other.attachment(s.id, name) for name, _ in s.attachments}

        def mutate(v: Vault) -> None:
            for uid in update:
                v.snapshot_history(uid)
            for uid in update:
                v.overwrite_entry(uid, theirs[uid], content(theirs[uid]), keep_mtime=True)
            for uid in move:
                v.move_entry(uid, _group_like(v, other_groups, theirs[uid].group_id))
            for uid in trash:
                v.trash_entry(uid)
            for uid in add:
                v.add_entry(_group_like(v, other_groups, theirs[uid].group_id), theirs[uid], content(theirs[uid]),
                            keep_id=True, keep_times=True)
            for uid in purge:
                v.purge_entry(uid)
            for gid in purge_groups:
                v.purge_group(gid)
            v.record_deleted(records)  # the other copy's records join this vault's, each with the earlier time

        def verify(again: Vault) -> list[str]:
            got = {e.id: e for e in again.entries()}
            problems = []
            for uid in add:
                if uid not in got or _state(got[uid]) != _state(theirs[uid]):
                    problems.append("an added entry is missing or differs")
            for uid in update:
                if uid not in got or _state(got[uid]) != _state(theirs[uid]):
                    problems.append("an updated entry does not match the other copy")
            for uid in move:
                if uid not in got or got[uid].group_id != theirs[uid].group_id:
                    problems.append("a moved entry is not where the other copy has it")
            if any(uid in got for uid in purge):
                problems.append("an entry that should be deleted is still there")
            if {g.id for g in again.groups()} & set(purge_groups):
                problems.append("a group that should be deleted is still there")
            if not set(records) <= again.deleted_ids():
                problems.append("a deletion record of the other copy is missing")
            return problems

        return Plan(change=report, mutate=mutate, touched=set(update) | set(move) | set(trash) | set(purge),
                    count_delta=len(add) - len(purge), verify=verify,
                    stamp="none")  # the entries keep the times of the copy they come from

    return execute_vault(open_db, db, build, apply)
