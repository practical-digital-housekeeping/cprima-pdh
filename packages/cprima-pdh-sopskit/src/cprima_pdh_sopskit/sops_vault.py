"""The sops+age backend (read-only): a sops-encrypted JSON file read as a vault.

One file is one vault. A mapping of mappings is a group, a mapping of scalars is an entry, a leaf is a field. Titles, group
names and field names are the plaintext keys of the file (sops encrypts values only); every value that sops encrypted is a
*protected* field, a value under an `unencrypted_*` rule is not. The file's `lastmodified` is the only time it has. The file's
MAC is verified before anything is shown, so an altered or reordered file is refused. There is no recycle bin, history,
attachments or expiry: those capabilities are not offered, and commands that need them say so.

JSON is the first codec; YAML follows (it needs a YAML parser and care for comments), so the backend is one `sops` backend
with a codec, not one backend per syntax. Writing is not implemented yet.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cprima_pdh_vault.vault import STANDARD, EntryData, Field, GroupData, VaultBase, VaultInfo, resolve_entry

from . import age
from .sops_format import SopsDocument, SopsError, is_sops, open_document

_NAMESPACE = uuid.UUID("2f8a8a7e-5f4b-4f0e-9a39-7d1f6f2b6c11")  # ids are derived from paths: sops files have no UUIDs


def default_identities() -> list[bytes]:
    """The age identities sops itself would look for: SOPS_AGE_KEY, SOPS_AGE_KEY_FILE, then the default key file."""
    text = os.environ.get("SOPS_AGE_KEY", "").strip()
    if text:
        return age.identities_from_text(text)
    candidates = [os.environ.get("SOPS_AGE_KEY_FILE", "")]
    base = os.environ.get("APPDATA") if os.name == "nt" else os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    if base:
        candidates.append(str(Path(base) / "sops" / "age" / "keys.txt"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return age.load_identities(candidate)
    raise SopsError("no age identity: set SOPS_AGE_KEY_FILE (or SOPS_AGE_KEY), or pass --key FILE")


def _parse(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        raise SopsError("sops YAML files are not supported yet (JSON is)")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SopsError(f"{path.name} is not valid JSON: {exc.msg}") from None
    if not is_sops(doc):
        raise SopsError(f"{path.name} is not a sops file (it has no `sops` block)")
    return doc


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _is_scalar(value: Any) -> bool:
    return not isinstance(value, (dict, list))


def _is_entry(value: dict) -> bool:
    """A mapping whose values are scalars (or lists of scalars): everything else is a group."""
    if not value:
        return False
    return all(_is_scalar(v) or (isinstance(v, list) and all(_is_scalar(i) for i in v)) for v in value.values())


def _when(meta: dict) -> datetime | None:
    raw = str(meta.get("lastmodified", ""))
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


class SopsVault(VaultBase):
    name = "sops"
    capabilities = frozenset({"fields", "groups", "protected", "tags", "times", "uuid"})

    def __init__(self, document: SopsDocument, path: Path | None = None):
        self.document, self.path = document, path
        self._encrypted = {leaf.path: leaf.encrypted for leaf in document.leaves}
        self._entries: list[EntryData] = []
        self._groups: list[GroupData] = []
        self.unmapped = 0  # values that are not part of any entry (a scalar next to groups, a deeper structure)
        self._build()

    @classmethod
    def open(cls, path: str | Path, identities: list[bytes] | None = None) -> SopsVault:
        path = Path(path)
        return cls(open_document(_parse(path), identities if identities is not None else default_identities()), path)

    # --- mapping ---------------------------------------------------------------------------------------------------------

    def _gid(self, path: tuple[str, ...]) -> str:
        return str(uuid.uuid5(_NAMESPACE, "group:" + "/".join(path)))

    def _build(self) -> None:
        stamp = _when(self.document.meta)
        self._groups.append(GroupData(id=self._gid(()), path="/", name="", is_root=True))
        self._walk(self.document.tree, (), stamp)

    def _walk(self, node: dict, path: tuple[str, ...], stamp: datetime | None) -> None:
        for key, value in node.items():
            here = path + (key,)
            if isinstance(value, dict) and _is_entry(value):
                self._entries.append(self._entry(key, path, value, stamp))
            elif isinstance(value, dict):
                self._groups.append(GroupData(id=self._gid(here), path="/".join(here), name=key,
                                              parent_id=self._gid(path)))
                self._walk(value, here, stamp)
            else:
                self.unmapped += 1

    def _entry(self, title: str, group: tuple[str, ...], mapping: dict, stamp: datetime | None) -> EntryData:
        base = group + (title,)
        standard: dict[str, str] = {}
        protected_standard: set[str] = set()
        fields: dict[str, Field] = {}
        tags: tuple[str, ...] = ()
        for key, value in mapping.items():
            encrypted = self._encrypted.get(base + (key,), False)
            if key == "Tags" and isinstance(value, list):
                tags = tuple(_text(v) for v in value)
            elif key in STANDARD and key != "Title" and _is_scalar(value):
                standard[key] = _text(value)
                if encrypted:
                    protected_standard.add(key)
            elif key == "Title":
                self.unmapped += 1  # the entry's title is its key
            else:
                text = ", ".join(_text(v) for v in value) if isinstance(value, list) else _text(value)
                fields[key] = Field(text, encrypted)
        return EntryData(
            id=str(uuid.uuid5(_NAMESPACE, "entry:" + "/".join(base))), group_path="/".join(group) or "/",
            group_id=self._gid(group), title=title,
            username=standard.get("UserName", ""), password=standard.get("Password", ""), url=standard.get("URL", ""),
            notes=standard.get("Notes", ""), otp=standard.get("otp", ""), tags=tags, mtime=stamp, atime=stamp,
            fields=fields, protected_standard=frozenset(protected_standard))

    # --- the Vault interface -----------------------------------------------------------------------------------------------

    def entries(self) -> list[EntryData]:
        return list(self._entries)

    def groups(self) -> list[GroupData]:
        return list(self._groups)

    def info(self) -> VaultInfo:
        meta = self.document.meta
        return VaultInfo(
            backend=self.name, format=f"sops {meta.get('version', '?')} · json", cipher="AES256_GCM", kdf="age",
            generator=f"sops {meta.get('version', '?')}",
            extra={"recipients": str(len(meta.get("age") or [])), "mac": "verified",
                   "unmapped values": str(self.unmapped), "lastmodified": str(meta.get("lastmodified", ""))})

    def find_entry(self, path: str, username: str | None = None) -> EntryData:
        return resolve_entry(self._entries, path, username)
