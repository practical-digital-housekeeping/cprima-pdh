"""Synthetic vaults: written by pykeepass with the key derivation lowered. Unit and integration tests only."""
from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from pykeepass import PyKeePass, create_database

DEFAULT_PASSWORD = "pdh-test-password"

# Argon2 cost lowered from the client defaults (about a second per open) to milliseconds. This edits the
# KDF header directly, which is why such vaults are "synthetic" and never used for end-to-end tests.
_FAST_ARGON2 = {"I": 1, "M": 8 * 1024, "P": 1}


@dataclass(frozen=True)
class Entry:
    """One entry; `group` is a path below the root like "Shopping" or "Home/Network"."""

    title: str
    group: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    custom: dict[str, str] = field(default_factory=dict)
    protected: frozenset[str] = frozenset()  # custom fields stored as protected
    expires: datetime | None = None
    tags: tuple[str, ...] = ()


def _group(kp: PyKeePass, path: str):
    group = kp.root_group
    for name in [p for p in path.split("/") if p]:
        child = next((g for g in group.subgroups if g.name == name), None)
        group = child if child is not None else kp.add_group(group, name)
    return group


def _lower_kdf(kp: PyKeePass) -> None:
    params = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    for key, value in _FAST_ARGON2.items():
        if key in params:
            params[key].value = value


_PROTOTYPES: dict[str, bytes] = {}


def fresh_database(path: Path, password: str = DEFAULT_PASSWORD) -> PyKeePass:
    """An empty KDBX 4 vault at `path`, opened, with the cheap key derivation.

    `create_database` pays the client-default Argon2 cost (over a second) once at creation, so it is done once per process
    and password; every later vault is a copy of that file, which opens in milliseconds."""
    if password not in _PROTOTYPES:
        scratch = Path(tempfile.mkdtemp(prefix="pdh-prototype-")) / "p.kdbx"
        kp = create_database(str(scratch), password=password)
        _lower_kdf(kp)
        kp.save()
        _PROTOTYPES[password] = scratch.read_bytes()
        shutil.rmtree(scratch.parent, ignore_errors=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_PROTOTYPES[password])
    return PyKeePass(str(path), password=password)


def synthetic_vault(path: Path, entries: list[Entry] | tuple[Entry, ...] = (), password: str = DEFAULT_PASSWORD,
                    groups: list[str] | tuple[str, ...] = ()) -> Path:
    """Write a KDBX 4 vault with `entries` (and extra empty `groups`) to `path`; returns `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    kp = fresh_database(path, password)
    for g in groups:
        _group(kp, g)
    for e in entries:
        entry = kp.add_entry(_group(kp, e.group), e.title, e.username, e.password, url=e.url or None,
                             notes=e.notes or None, tags=list(e.tags) or None)
        for key, value in e.custom.items():
            entry.set_custom_property(key, value, protect=key in e.protected)
        if e.expires is not None:
            entry.expiry_time = e.expires
            entry.expires = True
    kp.save()
    return path
