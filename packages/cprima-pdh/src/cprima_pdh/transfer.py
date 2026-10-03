"""Bringing data into a vault: CSV import, import from another vault, and merging two copies of one vault.

All of it runs through `txn.execute`: dry run unless `apply`, one save, reopened and verified. Reports name entries
and counts, never values. Merging is by UUID and modification time: the newer state wins and the replaced state is kept
in the entry's history; nothing is deleted because the other copy lacks it.
"""
from __future__ import annotations

import base64
import csv
import uuid as uuidlib
from datetime import date, datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .backends.kdbx import STANDARD_ATTR
from .entries import _root
from .history import _state
from .models import ImportReport, MergeReport
from .source import _aware, _gpath, _in_bin
from .txn import Plan, execute, snapshot
from .write import WriteError

if TYPE_CHECKING:
    from pykeepass import PyKeePass

_COLUMNS = {  # lower-cased CSV header -> what it is
    "group": "group", "title": "title", "username": "username", "user name": "username", "user_name": "username",
    "password": "password", "url": "url", "notes": "notes", "tags": "tags", "expires": "expires", "expiry": "expires",
}


def _find_group(kp: PyKeePass, parts: list[str]):
    group = kp.root_group
    for name in parts:
        group = next((g for g in group.subgroups if g.name == name), None)
        if group is None:
            return None
    return group


def _ensure_path(kp: PyKeePass, parts: list[str]):
    group = kp.root_group
    for name in parts:
        child = next((g for g in group.subgroups if g.name == name), None)
        group = child if child is not None else kp.add_group(group, name)
    return group


def _parts(path: str) -> list[str]:
    return [p for p in path.strip("/").split("/") if p]


def _new_paths(kp: PyKeePass, wanted: set[tuple[str, ...]]) -> int:
    """How many groups would have to be created so that every wanted path exists."""
    missing = set()
    for path in wanted:
        for i in range(1, len(path) + 1):
            if _find_group(kp, list(path[:i])) is None:
                missing.add(path[:i])
    return len(missing)


# --- one entry from one vault into another ----------------------------------------------------------------------------

def copy_entry(src, dest_kp: PyKeePass, dest_group, keep_uuid: bool = False):
    """Copy an entry (fields with their protection, tags, icon, expiry, times, attachments, look) into `dest_group`."""
    new = dest_kp.add_entry(dest_group, src.title or "", src.username or "", src.password or "", url=src.url or None,
                            notes=src.notes or None, tags=list(src.tags or []) or None, otp=src.otp or None,
                            icon=src.icon, force_creation=True)
    _copy_extras(src, new, dest_kp)
    if keep_uuid:
        new._element.find("UUID").text = src._element.findtext("UUID")
    for attr in ("ctime", "mtime", "atime"):
        value = getattr(src, attr)
        if value is not None:
            setattr(new, attr, value)
    return new


def _copy_extras(src, dest, dest_kp: PyKeePass) -> None:
    for key, value in (src.custom_properties or {}).items():
        dest.set_custom_property(key, value, protect=bool(src.is_custom_property_protected(key)))
    if src.expires:
        dest.expiry_time, dest.expires = src.expiry_time, True
    for a in src.attachments:
        dest.add_attachment(dest_kp.add_binary(a.data), a.filename)
    for tag in ("ForegroundColor", "BackgroundColor", "OverrideURL"):
        text = src._element.findtext(tag)
        el = dest._element.find(tag)
        if text and el is not None:
            el.text = text
    dest.autotype_enabled, dest.autotype_sequence = src.autotype_enabled, src.autotype_sequence


def _overwrite(target, src, kp: PyKeePass) -> None:
    """Make `target` look like `src` (same vault family, other copy): fields, tags, icon, expiry, attachments."""
    for attr in ("title", "username", "password", "url", "notes"):
        setattr(target, attr, getattr(src, attr) or "")
    if (src.otp or None) != (target.otp or None):
        target.otp = src.otp
    for key in list(target.custom_properties or {}):
        if key not in (src.custom_properties or {}):
            target.delete_custom_property(key)
    for key, value in (src.custom_properties or {}).items():
        target.set_custom_property(key, value, protect=bool(src.is_custom_property_protected(key)))
    target.tags = list(src.tags or [])
    target.icon = src.icon or "0"
    target.expires = bool(src.expires)
    if src.expires:
        target.expiry_time = src.expiry_time
    if {a.filename: a.data for a in target.attachments} != {a.filename: a.data for a in src.attachments}:
        for a in list(target.attachments):
            target.delete_attachment(a)
        for a in src.attachments:
            target.add_attachment(kp.add_binary(a.data), a.filename)
    target.autotype_enabled, target.autotype_sequence = src.autotype_enabled, src.autotype_sequence
    target.mtime = src.mtime


def _live(kp: PyKeePass):
    rb = kp.recyclebin_group
    return [e for e in kp.entries if rb is None or not _in_bin(e.group, rb.uuid)]


# --- import from CSV ----------------------------------------------------------------------------------------------------

def import_csv(open_db: Callable[[], PyKeePass], db: Path, file: Path, group: str, apply: bool) -> ImportReport:
    """Add the rows of a CSV file as entries below `group` (created if missing); unknown columns become custom fields."""
    try:
        with open(file, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            raw_rows = list(reader)
    except OSError as exc:
        raise WriteError(f"cannot read {file}: {exc.strerror or exc}") from exc
    kinds = {h: _COLUMNS.get(h.strip().lower()) for h in header}
    if "title" not in kinds.values():
        raise WriteError("the CSV needs a Title column")
    custom_columns = [h for h, kind in kinds.items() if kind is None and h]
    rows: list[dict] = []
    for number, raw in enumerate(raw_rows, start=2):  # row 1 is the header
        row = {"custom": {}}
        for h, kind in kinds.items():
            value = (raw.get(h) or "").strip() if kind != "password" and kind != "notes" else (raw.get(h) or "")
            if kind:
                row[kind] = value
            elif h and value:
                row["custom"][h] = raw.get(h) or ""
        if not row.get("title"):
            raise WriteError(f"row {number}: the title is empty")
        if row.get("expires"):
            try:
                row["day"] = date.fromisoformat(row["expires"])
            except ValueError:
                raise WriteError(f"row {number}: {row['expires']!r} is not a date (YYYY-MM-DD)") from None
        row["path"] = tuple(_parts(group) + _parts(row.get("group", "")))
        rows.append(row)
    seen = set()
    for row in rows:
        key = (row["path"], row["title"])
        if key in seen:
            raise WriteError(f"the CSV has the title {row['title']!r} twice in {'/'.join(row['path']) or '/'}")
        seen.add(key)

    def build(kp: PyKeePass) -> Plan:
        for row in rows:
            existing = _find_group(kp, list(row["path"]))
            if existing is not None and any(e.title == row["title"] for e in existing.entries):
                raise WriteError(f"{'/'.join(row['path']) or '/'!r} already has an entry {row['title']!r}")
        report = ImportReport(kind="csv", source=str(file), entries=len(rows),
                              groups=_new_paths(kp, {r["path"] for r in rows}), columns=custom_columns)
        if not rows:
            return Plan(change=report)

        def mutate(k: PyKeePass) -> None:
            for row in rows:
                g = _ensure_path(k, list(row["path"]))
                e = k.add_entry(g, row["title"], row.get("username", ""), row.get("password", ""),
                                url=row.get("url") or None, notes=row.get("notes") or None,
                                tags=[t for t in row.get("tags", "").split(";") if t.strip()] or None)
                for name, value in row["custom"].items():
                    e.set_custom_property(name, value)
                if "day" in row:
                    e.expiry_time, e.expires = datetime(row["day"].year, row["day"].month, row["day"].day,
                                                        tzinfo=timezone.utc), True

        def verify(again: PyKeePass) -> list[str]:
            for row in rows:
                g = _find_group(again, list(row["path"]))
                if g is None or sum(1 for e in g.entries if e.title == row["title"]) != 1:
                    return ["an imported entry is missing"]
            return []

        return Plan(change=report, mutate=mutate, count_delta=len(rows), verify=verify)

    return execute(open_db, db, build, apply)


# --- import from another vault -----------------------------------------------------------------------------------------------

def import_vault(open_db: Callable[[], PyKeePass], db: Path, other: PyKeePass, source: str, group: str,
                 apply: bool) -> ImportReport:
    """Copy the live entries of another vault, with their group structure, below `group` (new UUIDs)."""
    rb = other.recyclebin_group
    groups = [g for g in other.groups if not g.is_root_group and (rb is None or not _in_bin(g, rb.uuid))]
    entries = _live(other)

    def relative(g) -> list[str]:
        return list(g.path or [])

    def build(kp: PyKeePass) -> Plan:
        base = _parts(group)
        wanted = {tuple(base + relative(e.group)) for e in entries}
        report = ImportReport(kind="vault", source=source, entries=len(entries), groups=_new_paths(kp, wanted), columns=[])
        if not entries:
            return Plan(change=report)

        def mutate(k: PyKeePass) -> None:
            for g in groups:
                _ensure_path(k, base + relative(g))
            _ensure_path(k, base)
            for e in entries:
                copy_entry(e, k, _ensure_path(k, base + relative(e.group)))

        def verify(again: PyKeePass) -> list[str]:
            count = sum(1 for x in again.entries if "/".join(x.group.path or []).startswith("/".join(base)))
            return [] if count >= len(entries) else ["fewer entries than planned were imported"]

        return Plan(change=report, mutate=mutate, count_delta=len(entries), verify=verify)

    return execute(open_db, db, build, apply)


# --- merge two copies of one vault -----------------------------------------------------------------------------------------

def _location_changed(kp: PyKeePass, e) -> datetime | None:
    text = e._element.findtext("Times/LocationChanged")
    return _aware(kp._decode_time(text)) if text else None


def _deleted_uuids(kp: PyKeePass) -> set[str]:
    out = set()
    for el in _root(kp).findall("Root/DeletedObjects/DeletedObject/UUID"):
        try:
            out.add(str(uuidlib.UUID(bytes=base64.b64decode(el.text))))
        except (ValueError, TypeError):
            continue
    return out


def _group_like(kp: PyKeePass, src_group):
    """The local group with the other copy's group UUID; created (same UUID, same place) when missing."""
    local = next((g for g in kp.groups if g.uuid == src_group.uuid), None)
    if local is not None:
        return local
    parent = kp.root_group if src_group.parentgroup is None or src_group.parentgroup.is_root_group \
        else _group_like(kp, src_group.parentgroup)
    made = kp.add_group(parent, src_group.name, icon=src_group.icon, notes=src_group.notes)
    made._element.find("UUID").text = src_group._element.findtext("UUID")
    return made


def merge_vaults(open_db: Callable[[], PyKeePass], db: Path, open_other: Callable[[], PyKeePass], source: str,
                 apply: bool) -> MergeReport:
    """Merge another copy of this vault: add what is missing, take newer states, follow moves. Deletes nothing."""

    def build(kp: PyKeePass) -> Plan:
        other = open_other()
        local = {str(e.uuid): e for e in kp.entries}
        rb_local, rb_other = kp.recyclebin_group, other.recyclebin_group
        gone = _deleted_uuids(kp)
        add, update, move, trash = [], [], [], []
        unchanged = skipped = 0
        for src in other.entries:
            uid = str(src.uuid)
            in_other_bin = rb_other is not None and _in_bin(src.group, rb_other.uuid)
            mine = local.get(uid)
            if mine is None:
                if in_other_bin or uid in gone:
                    skipped += 1
                else:
                    add.append(src)
                continue
            mine_in_bin = rb_local is not None and _in_bin(mine.group, rb_local.uuid)
            theirs_newer_place = (_location_changed(other, src) or datetime.min.replace(tzinfo=timezone.utc)) > \
                                 (_location_changed(kp, mine) or datetime.min.replace(tzinfo=timezone.utc))
            if in_other_bin and not mine_in_bin and theirs_newer_place:
                trash.append(mine)
                continue
            if not in_other_bin and theirs_newer_place and mine.group.uuid != src.group.uuid:
                move.append((src, mine))
            if _state(src) != _state(mine) and (_aware(src.mtime) or datetime.min.replace(tzinfo=timezone.utc)) > \
                    (_aware(mine.mtime) or datetime.min.replace(tzinfo=timezone.utc)):
                update.append((src, mine))
            elif _state(src) == _state(mine) and not (move and move[-1][1] is mine):
                unchanged += 1
        report = MergeReport(source=source, added=len(add), updated=len(update), moved=len(move), trashed=len(trash),
                             unchanged=unchanged, skipped=skipped,
                             entries=sorted({f"{_gpath(e.group)}/{e.title}" for e in
                                             [*add, *(m for _, m in update), *(m for _, m in move), *trash]}))
        if not (add or update or move or trash):
            return Plan(change=report)
        touched = {str(m.uuid) for _, m in update} | {str(m.uuid) for _, m in move} | {str(m.uuid) for m in trash}
        add_ids = [str(s.uuid) for s in add]
        update_ids = [(str(s.uuid), str(m.uuid)) for s, m in update]
        move_ids = [(str(s.uuid), str(m.uuid)) for s, m in move]
        trash_ids = [str(m.uuid) for m in trash]

        def mutate(k: PyKeePass) -> None:
            by_uid = {str(e.uuid): e for e in k.entries}
            src_by = {str(e.uuid): e for e in other.entries}
            for _s, m in update_ids:
                snapshot(by_uid[m])
            for s, m in update_ids:
                _overwrite(by_uid[m], src_by[s], k)
            for s, m in move_ids:
                k.move_entry(by_uid[m], _group_like(k, src_by[s].group))
            for m in trash_ids:
                k.trash_entry(by_uid[m])
            for s in add_ids:
                copy_entry(src_by[s], k, _group_like(k, src_by[s].group), keep_uuid=True)

        def verify(again: PyKeePass) -> list[str]:
            got = {str(e.uuid): e for e in again.entries}
            src_by = {str(e.uuid): e for e in other.entries}
            problems = []
            for s in add_ids:
                if s not in got or _state(got[s]) != _state(src_by[s]):
                    problems.append("an added entry is missing or differs")
            for s, m in update_ids:
                if m not in got or _state(got[m]) != _state(src_by[s]):
                    problems.append("an updated entry does not match the other copy")
            for s, m in move_ids:
                if m not in got or got[m].group.uuid != src_by[s].group.uuid:
                    problems.append("a moved entry is not where the other copy has it")
            return problems

        return Plan(change=report, mutate=mutate, touched=touched, count_delta=len(add), verify=verify)

    return execute(open_db, db, build, apply)
