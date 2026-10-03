"""The in-memory backend: a Vault made of plain Python objects. Used by tests and as the reference implementation.

No files, no key derivation, no format. It offers the read basics plus whatever the entries it was built from carry.
"""
from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import replace

from ..vault import EntryData, GroupData, VaultBase, VaultInfo, resolve_entry


def _paths_of(group_path: str) -> list[str]:
    """Every group path an entry's group implies: `A/B` -> `A`, `A/B`."""
    if group_path in ("", "/"):
        return []
    parts = group_path.strip("/").split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]


class MemoryVault(VaultBase):
    name = "memory"
    capabilities = frozenset({"fields", "groups", "protected", "tags", "expiry", "otp", "times", "uuid", "icons"})

    def __init__(self, entries: Iterable[EntryData] = (), groups: Iterable[GroupData] | None = None):
        self._entries = list(entries)
        self._groups = list(groups) if groups is not None else self._derive_groups()
        by_path = {g.path: g.id for g in self._groups}
        self._entries = [replace(e, group_id=by_path.get(e.group_path, "")) if not e.group_id else e for e in self._entries]

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

    def entries(self) -> list[EntryData]:
        return list(self._entries)

    def groups(self) -> list[GroupData]:
        return list(self._groups)

    def info(self) -> VaultInfo:
        return VaultInfo(backend=self.name, format="memory")

    def find_entry(self, path: str, username: str | None = None) -> EntryData:
        return resolve_entry(self._entries, path, username)
