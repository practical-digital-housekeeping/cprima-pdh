"""KdbxVault: the KeePass implementation of the engine's Vault interface, read and write.

This is the one place that knows pykeepass' objects and the KDBX XML, and the one place every workaround for pykeepass'
gaps lives:
- the KDBX 3.x header hash that pykeepass never updates (`save` / `file_problems`, via `save_vault`);
- time stamps that pykeepass' setters do not set (`stamp`);
- History snapshots before an edit (`snapshot_history`);
- a one-time-password secret that cannot be set to nothing (`set_field` on `otp`);
- a custom field's protection that is lost when its value is set (`set_field` carries it over);
- `PreviousParentGroup` for KDBX 4.1 (`trash_entry`, `trash_group`, `restore_entry`);
- attachments whose binary must go with the last reference (`detach`);
- Argon2id, which pykeepass cannot name (`kdf`);
- formats nobody has verified writing (`check_writable`).
Everything is addressed by id (the entry's or group's UUID as text); callers hold snapshots (`EntryData`), never pykeepass objects.
"""
from __future__ import annotations

import base64
import hashlib
import os
import uuid as uuidlib
from datetime import datetime, timezone
from pathlib import Path

from cprima_pdh_vault.vault import STANDARD, EntryData, Field, GroupData, VaultBase, VaultInfo, register_adapter, resolve_entry
from .kdbx_format import STANDARD_ATTR, kdf_name

# KDBX versions whose writing has been verified against genuine KeePassXC files (3.1, 4.0 and 4.1 templates); anything else
# can be read but is not written.
VERIFIED_FORMATS = {(3, 1), (4, 0), (4, 1)}
SETTINGS = {  # name -> (Meta element, element holding its change time or None)
    "name": ("DatabaseName", "DatabaseNameChanged"),
    "description": ("DatabaseDescription", "DatabaseDescriptionChanged"),
    "history_max_items": ("HistoryMaxItems", None),
    "history_max_size": ("HistoryMaxSize", None),
    "recycle_bin": ("RecycleBinEnabled", "RecycleBinChanged"),
}


def _aware(moment):
    if moment is not None and moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _group_path(group) -> str:
    path = group.path
    if isinstance(path, (list, tuple)):
        path = "/".join(path)
    return path or "/"


def _below(group, ancestor_uuid) -> bool:
    while group is not None:
        if group.uuid == ancestor_uuid:
            return True
        group = group.parentgroup
    return False


def _root(kp):
    tree = kp.tree
    return tree.getroot() if hasattr(tree, "getroot") else tree


def _element_text(owner, tag: str) -> str:
    return owner._element.findtext(tag) or ""


def _set_element(owner, tag: str, value: str) -> None:
    element = owner._element.find(tag)
    if element is None:
        from lxml import etree

        element = etree.SubElement(owner._element, tag)
    element.text = value or None


def _encode_uuid(text: str) -> str:
    return base64.b64encode(uuidlib.UUID(text).bytes).decode()


def pykeepass_open(path: str | Path, password: str | None, keyfile: str | None) -> "PyKeePass":
    """The one place that constructs a PyKeePass; imported here so pykeepass stays optional."""
    from pykeepass import PyKeePass

    return PyKeePass(str(path), password=password, keyfile=keyfile)


# --- saving ---------------------------------------------------------------------------------------------------------
# A KDBX 3.x file stores a hash of its own file header inside the encrypted body (`Meta/HeaderHash`) and clients refuse a
# file whose header does not match it. pykeepass rotates the header's seeds on every save and never updates that hash, so
# every file it saves in KDBX 3.x is unreadable for KeePassXC. KDBX 4.x keeps the header hash outside the body (fine).

def header_end(data: bytes) -> int:
    """Where the KDBX 3.x file header ends: after the two signatures and the version, a list of (id, size, data) fields
    up to and including the end-of-header field (id 0)."""
    pos = 12
    while True:
        field_id, size = data[pos], int.from_bytes(data[pos + 1:pos + 3], "little")
        pos += 3 + size
        if field_id == 0:
            return pos


def _header_hash(path: Path) -> str:
    data = Path(path).read_bytes()
    return base64.b64encode(hashlib.sha256(data[:header_end(data)]).digest()).decode()


def _meta_header_hash(kp):
    tree = kp.tree
    return (tree.getroot() if hasattr(tree, "getroot") else tree).find("Meta/HeaderHash")


def stored_header_hash_ok(kp, path: Path) -> bool:
    """True when `path` (a file just written, `kp` reopened from it) has a header hash that matches its header; always
    true for KDBX 4.x, which has no such field in the body."""
    if tuple(kp.version)[0] != 3:
        return True
    element = _meta_header_hash(kp)
    return element is not None and element.text == _header_hash(path)


def save_vault(kp, filename: str | Path | None = None) -> None:
    """Save like `kp.save`, and keep the header hash of a KDBX 3.x file valid (see above)."""
    kp.save(filename)
    if tuple(kp.version)[0] != 3:
        return
    element = _meta_header_hash(kp)
    if element is None:
        return
    from pykeepass.kdbx_parsing import KDBX

    target = Path(filename) if filename else Path(kp.filename)
    element.text = _header_hash(target)  # the header just written; building again below keeps it byte for byte
    tmp = target.with_suffix(".tmp")
    try:
        KDBX.build_file(kp.kdbx, tmp, password=kp.password, keyfile=kp.keyfile, transformed_key=None, decrypt=True)
        os.replace(tmp, target)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise




class KdbxVault(VaultBase):
    name = "kdbx"
    capabilities = frozenset({
        "fields", "groups", "protected", "write", "tags", "expiry", "otp", "times", "uuid", "icons", "colours", "autotype",
        "history", "attachments", "recycle_bin", "credentials", "kdf", "settings", "create", "tombstones",
    })

    def __init__(self, kp, path=None):
        self.kp = kp
        self.path = Path(path) if path else None

    @classmethod
    def open(cls, path, password: str | None, keyfile: str | None = None) -> KdbxVault:
        return cls(pykeepass_open(path, password, keyfile), path)

    @classmethod
    def create(cls, path, password: str, keyfile: str | None = None) -> KdbxVault:
        """A new, empty KDBX 4.0 file (KeePass' default key derivation), saved at `path`."""
        from pykeepass import create_database

        kp = create_database(str(path), password=password, keyfile=str(keyfile) if keyfile else None)
        kp.save()
        return cls(kp, path)

    def can_open(self, password: str | None, keyfile: str | None = None, path=None) -> bool:
        """Whether the file at `path` (default: this vault's own) opens with these credentials."""
        try:
            pykeepass_open(path or self.path, password, keyfile)
        except Exception:  # noqa: BLE001 - any failure to open is the answer
            return False
        return True

    # --- reading -------------------------------------------------------------------------------------------------------------

    def _bin_uuid(self):
        rb = self.kp.recyclebin_group
        return rb.uuid if rb is not None else None

    def _data(self, e, group, bin_uuid, owner=None) -> EntryData:
        from lxml import etree

        history = [] if owner is not None else list(e.history or [])
        return EntryData(
            id=str((owner or e).uuid), group_path=_group_path(group), group_id=str(group.uuid), title=e.title or "",
            username=e.username or "", password=e.password or "", url=e.url or "", notes=e.notes or "", otp=e.otp or "",
            tags=tuple(e.tags or ()), icon=str(e.icon if e.icon is not None else "0"),
            expires=bool(e.expires), expiry=_aware(e.expiry_time) if e.expires else None,
            ctime=_aware(e.ctime), mtime=_aware(e.mtime), atime=_aware(e.atime),
            in_bin=bin_uuid is not None and _below(group, bin_uuid),
            fields={k: Field(v or "", bool(e.is_custom_property_protected(k))) for k, v in (e.custom_properties or {}).items()},
            attachments=tuple((a.filename, len(a.data)) for a in e.attachments),
            history_count=len(history), history_bytes=sum(len(etree.tostring(h._element)) for h in history),
            protected_standard=frozenset(
                n for n in STANDARD_ATTR if e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=n)),
            fg_color=_element_text(e, "ForegroundColor"), bg_color=_element_text(e, "BackgroundColor"),
            override_url=_element_text(e, "OverrideURL"), autotype_enabled=e.autotype_enabled,
            autotype_sequence=e.autotype_sequence or "", location_changed=self._location_changed(e))

    def _location_changed(self, e) -> datetime | None:
        text = e._element.findtext("Times/LocationChanged")
        return _aware(self.kp._decode_time(text)) if text else None

    def entries(self) -> list[EntryData]:
        bin_uuid = self._bin_uuid()
        return [self._data(e, e.group, bin_uuid) for e in self.kp.entries]

    def history(self, eid: str) -> list[EntryData]:
        """The earlier states of an entry, oldest first, as snapshots (their `id` is the entry's)."""
        owner = self._entry(eid)
        bin_uuid = self._bin_uuid()
        return [self._data(h, owner.group, bin_uuid, owner=owner) for h in (owner.history or [])]

    def groups(self) -> list[GroupData]:
        bin_uuid = self._bin_uuid()
        out = []
        for g in self.kp.groups:
            parent = g.parentgroup
            out.append(GroupData(
                id=str(g.uuid), path=_group_path(g), name=g.name or "", parent_id=str(parent.uuid) if parent else None,
                notes=g.notes or "", icon=str(g.icon if g.icon is not None else "0"), is_root=bool(g.is_root_group),
                is_bin=bin_uuid is not None and g.uuid == bin_uuid,
                in_bin=bin_uuid is not None and g.uuid != bin_uuid and _below(g, bin_uuid)))
        return out

    def info(self) -> VaultInfo:
        try:
            generator = self.kp.kdbx.body.payload.xml.findtext("Meta/Generator") or ""
        except AttributeError:
            generator = ""
        major, minor = self.kp.version
        return VaultInfo(backend=self.name, format=f"KDBX {major}.{minor}", cipher=str(self.kp.encryption_algorithm),
                         kdf=kdf_name(self.kp), generator=generator)

    def find_entry(self, path: str, username: str | None = None) -> EntryData:
        return resolve_entry(self.entries(), path, username)

    def attachment(self, eid: str, name: str) -> bytes:
        for a in self._entry(eid).attachments:
            if a.filename == name:
                return a.data
        raise KeyError(f"no attachment named {name!r}")

    def deleted_ids(self) -> set[str]:
        """Ids of entries and groups the file records as deleted (tombstones), for merging."""
        out = set()
        for element in _root(self.kp).findall("Root/DeletedObjects/DeletedObject/UUID"):
            try:
                out.add(str(uuidlib.UUID(bytes=base64.b64decode(element.text))))
            except (ValueError, TypeError):
                continue
        return out

    def bin_enabled(self) -> bool:
        return _root(self.kp).findtext("Meta/RecycleBinEnabled", default="True").strip().lower() != "false"

    # --- locating --------------------------------------------------------------------------------------------------------------

    def _entry(self, eid: str):
        for e in self.kp.entries:
            if str(e.uuid) == eid:
                return e
        raise KeyError(f"no entry with id {eid}")

    def _group(self, gid: str):
        for g in self.kp.groups:
            if str(g.uuid) == gid:
                return g
        raise KeyError(f"no group with id {gid}")

    # --- writing entries --------------------------------------------------------------------------------------------------------

    def snapshot_history(self, eid: str) -> None:
        """Keep the entry's current state in its History, as the KeePass GUI does before an edit."""
        self._entry(eid).save_history()

    def set_field(self, eid: str, name: str, value: str, protect: bool | None = None) -> None:
        """Set a standard or custom field. `protect` None keeps a custom field's protection (pykeepass would drop it)."""
        e = self._entry(eid)
        if name == "otp":
            self._set_otp(e, value)
        elif name in STANDARD_ATTR:
            setattr(e, STANDARD_ATTR[name], value or "")
        else:
            keep = protect if protect is not None else bool(
                name in (e.custom_properties or {}) and e.is_custom_property_protected(name))
            e.set_custom_property(name, value, protect=keep)

    def delete_field(self, eid: str, name: str) -> None:
        e = self._entry(eid)
        if name == "otp":
            self._set_otp(e, None)
        elif name in STANDARD_ATTR:
            setattr(e, STANDARD_ATTR[name], "")
        else:
            e.delete_custom_property(name)

    @staticmethod
    def _set_otp(entry, value: str | None) -> None:
        """Set the one-time-password secret, or remove it (pykeepass cannot set it to nothing)."""
        if value:
            entry.otp = value
            return
        for element in entry._element.xpath("String[Key='otp']"):
            entry._element.remove(element)

    def set_tags(self, eid: str, tags: list[str]) -> None:
        self._entry(eid).tags = list(tags)

    def set_icon(self, eid: str, icon: str) -> None:
        self._entry(eid).icon = str(icon)

    def set_expiry(self, eid: str, when: datetime | None) -> None:
        e = self._entry(eid)
        if when is None:
            e.expires = False
        else:
            e.expiry_time, e.expires = when, True

    def set_colours(self, eid: str, fg: str, bg: str) -> None:
        e = self._entry(eid)
        _set_element(e, "ForegroundColor", fg)
        _set_element(e, "BackgroundColor", bg)

    def set_override_url(self, eid: str, url: str) -> None:
        _set_element(self._entry(eid), "OverrideURL", url)

    def set_autotype(self, eid: str, enabled: bool, sequence: str) -> None:
        e = self._entry(eid)
        e.autotype_enabled = enabled
        e.autotype_sequence = sequence or None

    def move_entry(self, eid: str, gid: str) -> None:
        self.kp.move_entry(self._entry(eid), self._group(gid))

    def trash_entry(self, eid: str) -> None:
        """Move an entry to the recycle bin (created if missing) and, in KDBX 4.1, record where it came from."""
        e = self._entry(eid)
        origin = e.group
        self.kp.trash_entry(e)
        self._record_origin(e, origin)

    def restore_entry(self, eid: str, gid: str | None = None) -> None:
        """Move an entry out of the bin: into `gid`, else where the file says it came from (`LookupError` if it does not)."""
        e = self._entry(eid)
        dest = self._group(gid) if gid else self._previous_group(e)
        if dest is None:
            raise LookupError("the vault does not say where it came from")
        self.kp.move_entry(e, dest)

    def origin_group(self, eid: str) -> str | None:
        """The id of the group a client recorded as where the entry was deleted from (KDBX 4.1), if it still exists."""
        group = self._previous_group(self._entry(eid))
        return str(group.uuid) if group is not None else None

    def purge_entry(self, eid: str) -> None:
        self.kp.delete_entry(self._entry(eid))

    def _record_origin(self, owner, origin) -> None:
        """KDBX 4.1 and later have a place for it; older files get nothing (an unknown element could confuse their clients)."""
        if tuple(self.kp.version) < (4, 1):
            return
        _set_element(owner, "PreviousParentGroup", _encode_uuid(str(origin.uuid)))

    def _previous_group(self, owner):
        raw = owner._element.findtext("PreviousParentGroup")
        if not raw:
            return None
        try:
            wanted = uuidlib.UUID(bytes=base64.b64decode(raw))
        except ValueError:
            return None
        return next((g for g in self.kp.groups if g.uuid == wanted), None)

    def add_entry(self, gid: str, data: EntryData, content: dict[str, bytes] | None = None, keep_id: bool = False,
                  keep_times: bool = False) -> str:
        """Create an entry from a snapshot (fields with protection, tags, icon, expiry, look, attachments); returns its id."""
        new = self.kp.add_entry(self._group(gid), data.title, data.username, data.password, url=data.url or None,
                                notes=data.notes or None, tags=list(data.tags) or None, otp=data.otp or None,
                                icon=data.icon, force_creation=True)
        for key, field in data.fields.items():
            new.set_custom_property(key, field.value, protect=field.protected)
        self._apply_look(new, data)
        if data.expires:
            new.expiry_time, new.expires = data.expiry, True
        for name, blob in (content or {}).items():
            new.add_attachment(self.kp.add_binary(blob), name)
        if keep_id:
            new._element.find("UUID").text = _encode_uuid(data.id)
        if keep_times:
            for attr, value in (("ctime", data.ctime), ("mtime", data.mtime), ("atime", data.atime)):
                if value is not None:
                    setattr(new, attr, value)
        return str(new.uuid)

    @staticmethod
    def _apply_look(entry, data: EntryData) -> None:
        for tag, value in (("ForegroundColor", data.fg_color), ("BackgroundColor", data.bg_color),
                           ("OverrideURL", data.override_url)):
            if value:
                _set_element(entry, tag, value)
        if data.autotype_enabled is not None:
            entry.autotype_enabled = data.autotype_enabled
            entry.autotype_sequence = data.autotype_sequence or None

    def overwrite_entry(self, eid: str, data: EntryData, content: dict[str, bytes] | None = None,
                        keep_mtime: bool = False) -> None:
        """Make an entry look like a snapshot (a state restored from history, or the newer state of a merged copy)."""
        e = self._entry(eid)
        for attr, value in (("title", data.title), ("username", data.username), ("password", data.password),
                            ("url", data.url), ("notes", data.notes)):
            setattr(e, attr, value or "")
        if (data.otp or None) != (e.otp or None):
            self._set_otp(e, data.otp)
        for key in list(e.custom_properties or {}):
            if key not in data.fields:
                e.delete_custom_property(key)
        for key, field in data.fields.items():
            e.set_custom_property(key, field.value, protect=field.protected)
        e.tags = list(data.tags)
        e.icon = data.icon or "0"
        self.set_expiry(eid, data.expiry if data.expires else None)
        if content is not None and {a.filename: a.data for a in e.attachments} != content:
            for a in list(e.attachments):
                e.delete_attachment(a)
            for name, blob in content.items():
                e.add_attachment(self.kp.add_binary(blob), name)
        _set_element(e, "ForegroundColor", data.fg_color)
        _set_element(e, "BackgroundColor", data.bg_color)
        _set_element(e, "OverrideURL", data.override_url)
        if data.autotype_enabled is not None:
            e.autotype_enabled = data.autotype_enabled
            e.autotype_sequence = data.autotype_sequence or None
        if keep_mtime and data.mtime is not None:
            e.mtime = data.mtime

    def prune_history(self, eid: str, keep: int) -> int:
        """Drop all but the newest `keep` snapshots of an entry; returns how many were removed."""
        e = self._entry(eid)
        old = list(e.history or [])
        doomed = old[:max(len(old) - keep, 0)]
        for snapshot in doomed:
            e.delete_history(snapshot)
        return len(doomed)

    def attach(self, eid: str, name: str, content: bytes) -> None:
        self._entry(eid).add_attachment(self.kp.add_binary(content), name)

    def detach(self, eid: str, name: str) -> None:
        """Remove an attachment; its binary goes too when no other entry uses it."""
        e = self._entry(eid)
        att = next(a for a in e.attachments if a.filename == name)
        ident = att.id
        e.delete_attachment(att)
        if not any(a.id == ident for x in self.kp.entries for a in x.attachments):
            self.kp.delete_binary(ident)

    # --- writing groups ---------------------------------------------------------------------------------------------------------

    def add_group(self, parent_id: str, name: str, icon: str | None = None, notes: str | None = None,
                  keep_id: str | None = None) -> str:
        made = self.kp.add_group(self._group(parent_id), name, icon=icon, notes=notes)
        if keep_id:
            made._element.find("UUID").text = _encode_uuid(keep_id)
        return str(made.uuid)

    def rename_group(self, gid: str, name: str) -> None:
        self._group(gid).name = name

    def set_group_notes(self, gid: str, text: str) -> None:
        self._group(gid).notes = text

    def set_group_icon(self, gid: str, icon: str) -> None:
        self._group(gid).icon = str(icon)

    def move_group(self, gid: str, parent_id: str) -> None:
        self.kp.move_group(self._group(gid), self._group(parent_id))

    def trash_group(self, gid: str) -> None:
        g = self._group(gid)
        origin = g.parentgroup
        self.kp.trash_group(g)
        self._record_origin(g, origin)

    def empty_bin(self) -> None:
        rb = self.kp.recyclebin_group
        if rb is not None:
            self.kp.empty_group(rb)

    # --- the database itself --------------------------------------------------------------------------------------------------------

    def settings(self) -> dict[str, object]:
        meta = _root(self.kp).find("Meta")

        def text(tag: str, default: str = "") -> str:
            el = meta.find(tag)
            return (el.text or default) if el is not None else default

        return {"name": text("DatabaseName"), "description": text("DatabaseDescription"),
                "history_max_items": int(text("HistoryMaxItems", "-1")), "history_max_size": int(text("HistoryMaxSize", "-1")),
                "recycle_bin": text("RecycleBinEnabled", "True").strip().lower() != "false"}

    def set_settings(self, changes: dict[str, object]) -> None:
        meta = _root(self.kp).find("Meta")
        stamp = self.kp._encode_time(datetime.now(timezone.utc)) if hasattr(self.kp, "_encode_time") else None
        for key, value in changes.items():
            tag, changed_tag = SETTINGS[key]
            meta.find(tag).text = ("True" if value else "False") if key == "recycle_bin" else str(value)
            if changed_tag and stamp is not None and meta.find(changed_tag) is not None:
                meta.find(changed_tag).text = stamp

    def _kdf_params(self):
        return self.kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict

    def kdf(self) -> dict[str, object]:
        """The key derivation: its name, and for Argon2 the iterations, memory (KiB) and parallelism."""
        name = kdf_name(self.kp)
        if not name.startswith("argon2"):
            return {"algorithm": name, "iterations": None, "memory_kib": None, "parallelism": None}
        p = self._kdf_params()
        return {"algorithm": name, "iterations": int(p["I"].value), "memory_kib": int(p["M"].value) // 1024,
                "parallelism": int(p["P"].value)}

    def set_kdf(self, iterations: int, memory_kib: int, parallelism: int) -> None:
        p = self._kdf_params()
        p["I"].value, p["M"].value, p["P"].value = iterations, memory_kib * 1024, parallelism

    @property
    def password(self) -> str | None:
        return self.kp.password

    @property
    def keyfile(self):
        return self.kp.keyfile

    def set_password(self, new: str) -> None:
        self.kp.password = new

    def set_keyfile(self, path: str | None) -> None:
        self.kp.keyfile = str(path) if path else None

    # --- stamping and saving ---------------------------------------------------------------------------------------------------

    def stamp(self, entry_ids: set[str], group_ids: set[str], mode: str) -> None:
        """Stamp what was touched like a client would: `modified` (content changed) or `location` (moved or trashed)."""
        if mode == "none":
            return
        things = [e for e in self.kp.entries if str(e.uuid) in entry_ids] + [g for g in self.kp.groups if str(g.uuid) in group_ids]
        for thing in things:
            if mode == "modified":
                thing.touch(modify=True)
            else:
                element = thing._element.find("Times/LocationChanged")
                if element is not None:
                    element.text = self.kp._encode_time(datetime.now(timezone.utc))

    def check_writable(self) -> list[str]:
        """Why this file must not be written, if it must not: formats nobody has verified writing."""
        version = tuple(self.kp.version)
        if version not in VERIFIED_FORMATS:
            return [f"pdh has not been verified to write KDBX {version[0]}.{version[1]}; it reads it but does not change it"]
        return []

    def save(self, path: str | Path | None = None) -> None:
        """Save (to `path`, else the file it was opened from), keeping a KDBX 3.x header hash valid."""
        save_vault(self.kp, path if path else self.path)

    def reopen(self, path: str | Path | None = None) -> KdbxVault:
        """The file as it is on disk now, opened with the same credentials."""
        target = Path(path) if path else self.path
        return KdbxVault(pykeepass_open(target, self.kp.password, self.kp.keyfile), target)

    def file_problems(self, path: str | Path | None = None) -> list[str]:
        """Checks only the written file can show: a KDBX 3.x file must carry the hash of its own header."""
        target = Path(path) if path else self.path
        if not stored_header_hash_ok(self.kp, target):
            return ["the file header does not match its stored hash: clients would refuse the file"]
        return []


# Anything that is not a Vault and offers nothing else is taken to be an opened pykeepass database (what the engine was
# handed before there was a Vault); the registration makes `vault.as_vault` work without importing this module.
register_adapter(KdbxVault)
