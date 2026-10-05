"""Build a MemoryVault from the same `Entry` specifications `synthetic_vault` writes to a real file."""
from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import timezone

from cprima_pdh_vault.memory import MemoryVault
from cprima_pdh_vault.vault import EntryData, Field

from .vault import Entry


def memory_vault(entries: Sequence[Entry]) -> MemoryVault:
    """A MemoryVault holding what `synthetic_vault(path, entries)` would write, with no file and no key derivation."""
    data = []
    for e in entries:
        expiry = e.expires.astimezone(timezone.utc) if e.expires is not None else None
        data.append(EntryData(
            id=str(uuid.uuid4()), group_path="/".join(p for p in e.group.split("/") if p) or "/", title=e.title,
            username=e.username, password=e.password, url=e.url, notes=e.notes, tags=tuple(e.tags),
            expires=expiry is not None, expiry=expiry,
            fields={k: Field(v, k in e.protected) for k, v in e.custom.items()}))
    return MemoryVault(data)
