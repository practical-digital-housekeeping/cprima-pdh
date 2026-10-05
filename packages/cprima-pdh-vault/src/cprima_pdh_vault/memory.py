"""The in-memory backend: a Vault made of plain Python objects. Used by tests and as the reference implementation.

No files, no key derivation, no format. It reads like every other backend and it changes entries and groups like them, so
that a test of the engine can run on it and a contract test can hold it to the same results as a real file. What it cannot
do is what needs a file: the password and key file, the key derivation, the database settings, and saving or reopening.
Those answer `Unsupported`, as for any store that lacks them. (Like a KDBX 4.1 file it remembers where a trashed entry came
from.)
"""
from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from dataclasses import replace

from .vault import STANDARD, EntryData, Field, GroupData, VaultBase, VaultInfo, resolve_entry

_BIN_NAME = "Recycle Bin"


def _paths_of(group_path: str) -> list[str]:
    """Every group path an entry's group implies: `A/B` -> `A`, `A/B`."""
    if group_path in ("", "/"):
        return []
    parts = group_path.strip("/").split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MemoryVault(VaultBase):
    name = "memory"
    capabilities = frozenset({"fields", "groups", "protected", "tags", "expiry", "otp", "times", "uuid", "icons", "colours",
                              "autotype", "history", "attachments", "recycle_bin", "tombstones"})

    def __init__(self, entries: Iterable[EntryData] = (), groups: Iterable[GroupData] | None = None):
        self._entries = list(entries)
        self._groups = list(groups) if groups is not None else self._derive_groups()
        by_path = {g.path: g.id for g in self._groups}
        self._entries = [replace(e, group_id=by_path.get(e.group_path, "")) if not e.group_id else e for e in self._entries]
        self._content: dict[str, dict[str, bytes]] = {}  # attachment content by entry id
        self._history: dict[str, list[EntryData]] = {}  # earlier states by entry id, oldest first
        self._origin: dict[str, str] = {}  # where a trashed entry or group came from
        self._deleted: set[str] = set()  # ids of what was removed for good (tombstones)
        self._bin_on = True

    def _derive_groups(self) -> list[GroupData]:
        root = GroupData(id=str(uuid.uuid4()), path="/", name="", is_root=True)
        made = {"": root}
        for e in self._entries:
            for path in _paths_of(e.group_path):
                if path not in made:
                    parent = path.rsplit("/", 1)[0] if "/" in path else ""
                    made[path] = GroupData(id=str(uuid.uuid4()), path=path, name=path.rsplit("/", 1)[-1],
                                           parent_id=made[parent].id)
        return list(made.values())

    # --- reading -------------------------------------------------------------------------------------------------------------

    def entries(self) -> list[EntryData]:
        return list(self._entries)

    def groups(self) -> list[GroupData]:
        return list(self._groups)

    def info(self) -> VaultInfo:
        return VaultInfo(backend=self.name, format="memory")

    def find_entry(self, path: str, username: str | None = None) -> EntryData:
        return resolve_entry(self._entries, path, username)

    def history(self, eid: str) -> list[EntryData]:
        self._entry(eid)
        return list(self._history.get(eid, []))

    def attachment(self, eid: str, name: str) -> bytes:
        self._entry(eid)
        if name not in self._content.get(eid, {}):
            raise KeyError(f"no attachment named {name!r}")
        return self._content[eid][name]

    def deleted_ids(self) -> set[str]:
        return set(self._deleted)

    def bin_enabled(self) -> bool:
        return self._bin_on

    # --- locating ------------------------------------------------------------------------------------------------------------

    def _entry(self, eid: str) -> EntryData:
        for e in self._entries:
            if e.id == eid:
                return e
        raise KeyError(f"no entry with id {eid}")

    def _group(self, gid: str) -> GroupData:
        for g in self._groups:
            if g.id == gid:
                return g
        raise KeyError(f"no group with id {gid}")

    def _change(self, eid: str, **changes) -> None:
        self._entries = [replace(e, **changes) if e.id == eid else e for e in self._entries]

    def _change_group(self, gid: str, **changes) -> None:
        self._groups = [replace(g, **changes) if g.id == gid else g for g in self._groups]

    def _refresh(self) -> None:
        """Recompute every group's path and bin membership, and each entry's group path, from names and parents."""
        by_id = {g.id: g for g in self._groups}
        made: dict[str, tuple[str, bool]] = {}

        def place(g: GroupData) -> tuple[str, bool]:
            if g.id not in made:
                if g.is_root or g.parent_id is None:
                    made[g.id] = ("/", False)
                else:
                    path, in_bin = place(by_id[g.parent_id])
                    made[g.id] = (g.name if path == "/" else f"{path}/{g.name}", in_bin or by_id[g.parent_id].is_bin)
            return made[g.id]

        self._groups = [replace(g, path=place(g)[0], in_bin=place(g)[1] and not g.is_bin) for g in self._groups]
        paths = {g.id: (g.path, g.in_bin or g.is_bin) for g in self._groups}
        self._entries = [replace(e, group_path=paths[e.group_id][0], in_bin=paths[e.group_id][1]) if e.group_id in paths else e
                         for e in self._entries]

    # --- writing entries -----------------------------------------------------------------------------------------------------

    def snapshot_history(self, eid: str) -> None:
        e = self._entry(eid)
        old = replace(e, history_count=0, history_bytes=0)
        kept = self._history.setdefault(eid, [])
        kept.append(old)
        self._change(eid, history_count=len(kept), history_bytes=sum(len(repr(h)) for h in kept))

    def set_field(self, eid: str, name: str, value: str, protect: bool | None = None) -> None:
        e = self._entry(eid)
        if name in STANDARD:  # a standard field is the entry's attribute of the same name, lower case
            self._change(eid, **{name.lower(): value or ""})
            return
        keep = protect if protect is not None else (name in e.fields and e.fields[name].protected)
        self._change(eid, fields={**e.fields, name: Field(value, keep)})

    def delete_field(self, eid: str, name: str) -> None:
        e = self._entry(eid)
        if name in STANDARD:
            self._change(eid, **{name.lower(): ""})
        else:
            self._change(eid, fields={k: v for k, v in e.fields.items() if k != name})

    def set_tags(self, eid: str, tags: list[str]) -> None:
        self._change(eid, tags=tuple(tags))

    def set_icon(self, eid: str, icon: str) -> None:
        self._change(eid, icon=str(icon))

    def set_expiry(self, eid: str, when: datetime | None) -> None:
        self._change(eid, expires=when is not None, expiry=when)

    def set_colours(self, eid: str, fg: str, bg: str) -> None:
        self._change(eid, fg_color=fg, bg_color=bg)

    def set_override_url(self, eid: str, url: str) -> None:
        self._change(eid, override_url=url)

    def set_autotype(self, eid: str, enabled: bool, sequence: str) -> None:
        self._change(eid, autotype_enabled=enabled, autotype_sequence=sequence or "")

    def move_entry(self, eid: str, gid: str) -> None:
        self._entry(eid)
        self._group(gid)
        self._change(eid, group_id=gid)
        self._refresh()

    def _the_bin(self) -> GroupData:
        """The recycle bin group, made under the root when the vault has none yet."""
        for g in self._groups:
            if g.is_bin:
                return g
        root = next(g for g in self._groups if g.is_root)
        made = GroupData(id=str(uuid.uuid4()), path=_BIN_NAME, name=_BIN_NAME, parent_id=root.id, icon="43", is_bin=True)
        self._groups.append(made)
        return made

    def trash_entry(self, eid: str) -> None:
        e = self._entry(eid)
        self._origin[eid] = e.group_id
        self._change(eid, group_id=self._the_bin().id)
        self._refresh()

    def restore_entry(self, eid: str, gid: str | None = None) -> None:
        self._entry(eid)
        dest = gid or self.origin_group(eid)
        if dest is None:
            raise LookupError("the vault does not say where it came from")
        self.move_entry(eid, dest)

    def origin_group(self, eid: str) -> str | None:
        origin = self._origin.get(eid)
        return origin if origin is not None and any(g.id == origin for g in self._groups) else None

    def purge_entry(self, eid: str) -> None:
        self._entry(eid)
        self._entries = [e for e in self._entries if e.id != eid]
        for table in (self._content, self._history, self._origin):
            table.pop(eid, None)
        self._deleted.add(eid)

    def add_entry(self, gid: str, data: EntryData, content: dict[str, bytes] | None = None, keep_id: bool = False,
                  keep_times: bool = False) -> str:
        self._group(gid)
        eid = data.id if keep_id else str(uuid.uuid4())
        now = _now()
        times = {t: (getattr(data, t) if keep_times and getattr(data, t) is not None else now) for t in ("ctime", "mtime", "atime")}
        blobs = dict(content or {})
        self._entries.append(replace(
            data, id=eid, group_id=gid, in_bin=False, history_count=0, history_bytes=0,
            attachments=tuple((n, len(b)) for n, b in blobs.items()), **times))
        self._content[eid] = blobs
        self._refresh()
        return eid

    def overwrite_entry(self, eid: str, data: EntryData, content: dict[str, bytes] | None = None,
                        keep_mtime: bool = False) -> None:
        e = self._entry(eid)
        kept = {"id": e.id, "group_id": e.group_id, "group_path": e.group_path, "in_bin": e.in_bin, "ctime": e.ctime,
                "atime": e.atime, "history_count": e.history_count, "history_bytes": e.history_bytes,
                "location_changed": e.location_changed, "attachments": e.attachments,
                "mtime": data.mtime if keep_mtime and data.mtime is not None else e.mtime}
        self._entries = [replace(data, **kept) if x.id == eid else x for x in self._entries]
        if content is not None:
            self._content[eid] = dict(content)
            self._change(eid, attachments=tuple((n, len(b)) for n, b in content.items()))

    def prune_history(self, eid: str, keep: int) -> int:
        self._entry(eid)
        old = self._history.get(eid, [])
        doomed = max(len(old) - keep, 0)
        self._history[eid] = old[doomed:]
        self._change(eid, history_count=len(self._history[eid]), history_bytes=sum(len(repr(h)) for h in self._history[eid]))
        return doomed

    def attach(self, eid: str, name: str, content: bytes) -> None:
        e = self._entry(eid)
        self._content.setdefault(eid, {})[name] = content
        self._change(eid, attachments=tuple(a for a in e.attachments if a[0] != name) + ((name, len(content)),))

    def detach(self, eid: str, name: str) -> None:
        e = self._entry(eid)
        if name not in self._content.get(eid, {}):
            raise KeyError(f"no attachment named {name!r}")
        del self._content[eid][name]
        self._change(eid, attachments=tuple(a for a in e.attachments if a[0] != name))

    # --- writing groups ------------------------------------------------------------------------------------------------------

    def add_group(self, parent_id: str, name: str, icon: str | None = None, notes: str | None = None,
                  keep_id: str | None = None) -> str:
        self._group(parent_id)
        gid = keep_id or str(uuid.uuid4())
        self._groups.append(GroupData(id=gid, path=name, name=name, parent_id=parent_id, notes=notes or "", icon=icon or "0"))
        self._refresh()
        return gid

    def rename_group(self, gid: str, name: str) -> None:
        self._group(gid)
        self._change_group(gid, name=name)
        self._refresh()

    def set_group_notes(self, gid: str, text: str) -> None:
        self._group(gid)
        self._change_group(gid, notes=text)

    def set_group_icon(self, gid: str, icon: str) -> None:
        self._group(gid)
        self._change_group(gid, icon=str(icon))

    def move_group(self, gid: str, parent_id: str) -> None:
        self._group(gid)
        self._group(parent_id)
        self._change_group(gid, parent_id=parent_id)
        self._refresh()

    def trash_group(self, gid: str) -> None:
        g = self._group(gid)
        self._origin[gid] = g.parent_id or ""
        self._change_group(gid, parent_id=self._the_bin().id)
        self._refresh()

    def empty_bin(self) -> None:
        bin_ids = {g.id for g in self._groups if g.is_bin}
        if not bin_ids:
            return
        gone = {g.id for g in self._groups if g.in_bin}
        self._deleted |= {e.id for e in self._entries if e.in_bin} | gone
        self._entries = [e for e in self._entries if not e.in_bin]
        self._groups = [g for g in self._groups if g.id not in gone]

    # --- stamping ------------------------------------------------------------------------------------------------------------

    def stamp(self, entry_ids: set[str], group_ids: set[str], mode: str) -> None:
        if mode == "none":
            return
        now = _now()
        for eid in entry_ids:
            if mode == "modified":
                self._change(eid, mtime=now, atime=now)
            else:
                self._change(eid, location_changed=now)
