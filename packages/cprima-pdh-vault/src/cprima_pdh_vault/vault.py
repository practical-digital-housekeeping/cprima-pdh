"""The Vault interface: what the engine may ask of any store of entries.

The engine (profile checks, tree, doctor, conform, online checks, command logic) talks to a `Vault` and to the immutable
snapshots it hands out (`EntryData`, `GroupData`), never to a store's own objects. A backend (`backends/kdbx.py` for
KeePass, `backends/memory.py` for tests, later `backends/sops.py`) implements the interface and keeps every quirk of its
format to itself. What a backend cannot do is declared in `capabilities`; a command that needs one fails with a clear
message (`require`) instead of faking it.

Phase 0 of the refactoring: the read side. Write operations follow.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable

# The standard fields every entry has, by the profile's names (see `[standard.*]`); how a store keeps them is its own business.
STANDARD = ("Title", "UserName", "Password", "URL", "Notes", "otp")

# What a backend may offer. `fields`, `groups` and `protected` are the read basics every backend has.
CAPABILITIES = frozenset({
    "fields", "groups", "protected", "write", "tags", "expiry", "otp", "times", "uuid", "icons", "colours", "autotype",
    "history", "attachments", "recycle_bin", "credentials", "kdf", "settings", "create",
})


class Unsupported(Exception):
    """The backend does not offer a capability the command needs."""


class WriteError(Exception):
    """A write was refused or failed verification; the vault is as it was."""


def find_data(vault, path: str, username: str | None = None):
    """The snapshot of the single entry at `group/path/title` (narrowed by user name) in a vault."""
    try:
        return vault.find_entry(path, username)
    except KeyError as exc:
        raise WriteError(exc.args[0]) from None
    except LookupError as exc:
        raise WriteError(str(exc).replace("a user name", "--username")) from None


@dataclass(frozen=True)
class Field:
    """A custom field's value and whether the store keeps it protected."""

    value: str
    protected: bool = False


@dataclass(frozen=True)
class EntryData:
    """One entry, as the engine sees it. `fields` holds the custom fields only; the standard ones are attributes."""

    id: str
    group_path: str  # slash-joined names below the root; "/" for an entry directly in the root group
    group_id: str = ""  # the id of that group (groups with equal paths stay apart)
    title: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    otp: str = ""
    tags: tuple[str, ...] = ()
    icon: str = "0"
    expires: bool = False
    expiry: datetime | None = None
    ctime: datetime | None = None
    mtime: datetime | None = None
    atime: datetime | None = None
    in_bin: bool = False
    fields: dict[str, Field] = field(default_factory=dict)
    attachments: tuple[tuple[str, int], ...] = ()  # (name, size in bytes); never the content
    history_count: int = 0
    history_bytes: int = 0
    # the standard fields the store keeps protected (KeePass: normally Password and otp, but the file decides)
    protected_standard: frozenset[str] = frozenset({"Password", "otp"})
    # how a client shows and treats the entry (KeePass only; empty elsewhere)
    fg_color: str = ""
    bg_color: str = ""
    override_url: str = ""
    autotype_enabled: bool | None = None
    autotype_sequence: str = ""
    location_changed: datetime | None = None  # when it was last moved (or trashed); merges decide by it

    @property
    def path(self) -> str:
        """`group/path/title`, as printed by every report and accepted by every command."""
        return f"{self.group_path}/{self.title}"

    def value(self, name: str) -> str:
        """The value of a standard field by the profile's name."""
        return {"Title": self.title, "UserName": self.username, "Password": self.password, "URL": self.url,
                "Notes": self.notes, "otp": self.otp}[name]

    def is_protected(self, name: str) -> bool:
        """Whether the store keeps this field protected (a custom field by its own flag, a standard one by the file)."""
        if name in self.fields:
            return self.fields[name].protected
        return name in self.protected_standard

    def names(self) -> list[str]:
        """The names of everything this entry has a value for: standard fields that are not empty, then custom fields."""
        return [n for n in STANDARD if self.value(n)] + list(self.fields)


@dataclass(frozen=True)
class GroupData:
    id: str
    path: str  # slash-joined; "/" for the root group
    name: str
    parent_id: str | None = None
    notes: str = ""
    icon: str = "0"
    in_bin: bool = False  # inside the recycle bin (the bin itself is not)
    is_root: bool = False
    is_bin: bool = False


@dataclass(frozen=True)
class VaultInfo:
    """Facts about the store, for `doctor` and reports. Nothing secret."""

    backend: str
    format: str = ""
    cipher: str = ""
    kdf: str = ""
    generator: str = ""
    extra: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class Vault(Protocol):
    name: str
    capabilities: frozenset[str]

    def entries(self) -> list[EntryData]: ...

    def groups(self) -> list[GroupData]: ...

    def info(self) -> VaultInfo: ...

    def find_entry(self, path: str, username: str | None = None) -> EntryData: ...


# Everything a backend may be asked to change. A backend implements what its store can do; the rest answers `Unsupported`.
WRITE_OPERATIONS = frozenset({
    "snapshot_history", "history", "prune_history", "set_field", "delete_field", "set_tags", "set_icon", "set_expiry",
    "set_colours", "set_override_url", "set_autotype", "move_entry", "trash_entry", "restore_entry", "origin_group",
    "purge_entry", "add_entry", "overwrite_entry", "attach", "attachment", "detach", "add_group", "rename_group",
    "set_group_notes", "set_group_icon", "move_group", "trash_group", "empty_bin", "bin_enabled", "deleted_ids",
    "deletions", "record_deleted", "purge_group",
    "settings", "set_settings", "kdf", "set_kdf", "password", "keyfile", "set_password", "set_keyfile", "can_open",
    "stamp", "save", "reopen", "file_problems",
})


class VaultBase:
    """What every backend inherits: reading is its own business, any write operation it does not implement says so."""

    name = "vault"

    def check_writable(self) -> list[str]:
        return [f"the {self.name} backend does not support writing"]

    def __getattr__(self, attr: str):
        if attr in WRITE_OPERATIONS:
            raise Unsupported(f"the {self.name} backend does not support {attr.replace('_', ' ')}")
        raise AttributeError(attr)


def require(vault: Vault, capability: str) -> None:
    """Raise `Unsupported` unless the backend offers the capability."""
    if capability not in vault.capabilities:
        raise Unsupported(f"the {vault.name} backend does not support {capability}")


def resolve_entry(entries: list[EntryData], path: str, username: str | None = None) -> EntryData:
    """The single entry whose `group/path/title` equals `path` (narrowed by user name); `KeyError` for none, `LookupError`
    for several. Shared by every backend."""
    hits = [e for e in entries if e.path == path]
    if username is not None:
        hits = [e for e in hits if e.username == username]
    if not hits:
        raise KeyError(f"no entry at {path!r}" + (f" with username {username!r}" if username else ""))
    if len(hits) > 1:
        raise LookupError(f"{len(hits)} entries at {path!r}; narrow it down with a user name or rename one")
    return hits[0]


_ADAPTERS: list = []


def register_adapter(adapt) -> None:
    """A backend that can wrap a store's own object (`adapt(obj)` returns a Vault, or None when `obj` is not its kind)
    registers here when its module is imported, so this module imports no backend."""
    if adapt not in _ADAPTERS:
        _ADAPTERS.append(adapt)


def as_vault(obj) -> Vault:
    """A Vault for `obj`: a Vault is returned as is, an object that knows its Vault view gives it, anything else is offered to
    the registered adapters. (A migration aid; goes when nothing hands a store's own object around any more.)"""
    if hasattr(obj, "capabilities") and callable(getattr(obj, "entries", None)):
        return obj
    if hasattr(obj, "__vault__"):  # a fake or adapter that knows its own Vault view
        return obj.__vault__()
    for adapt in _ADAPTERS:
        if (vault := adapt(obj)) is not None:
            return vault
    raise TypeError(f"{type(obj).__name__} is not a Vault and no backend adapts it")
