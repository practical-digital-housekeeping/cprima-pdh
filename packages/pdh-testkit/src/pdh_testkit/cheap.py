"""A genuine KeePassXC template with a cheap key derivation, so behaviour tests do not pay for it on every open.

The templates differ in how slow their key derivation is: KDBX 3.1 (a million AES-KDF rounds, about four seconds per open),
KDBX 4.0 with AES-KDF (about 39 million rounds, 150 to 200 seconds per open) and the KDBX 4 Argon2 templates (one to four
seconds). What the behaviour tests check (header hash, delete and restore, settings, merge) does not depend on the cost of the
derivation, so they work on a copy whose cost is lowered. The copy is made once per machine and kept in the temporary
directory. The genuine files keep their real cost where that is the subject: the fixture checks and the contract test open every
template as it is.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from . import vaults
from .vault import _FAST_ARGON2

_FAST_ROUNDS = 1000
_prototypes: dict[str, bytes] = {}


def _lowered(name: str) -> bytes:
    """The template's bytes with the cost of its key derivation lowered."""
    from cprima_pdh.source import pykeepass_open, save_vault

    template = vaults.load(name)
    scratch = Path(tempfile.mkdtemp(prefix="pdh-cheap-")) / "p.kdbx"
    try:
        shutil.copyfile(template.path, scratch)
        kp = pykeepass_open(scratch, template.password, None)
        header = kp.kdbx.header.value.dynamic_header
        if template.format.startswith("KDBX 3"):
            header.transform_rounds.data = _FAST_ROUNDS
        else:
            params = header.kdf_parameters.data.dict
            if "R" in params:  # AES-KDF
                params["R"].value = _FAST_ROUNDS
            for key, value in _FAST_ARGON2.items():  # Argon2d / Argon2id
                if key in params:
                    params[key].value = value
        save_vault(kp, scratch)
        return scratch.read_bytes()
    finally:
        shutil.rmtree(scratch.parent, ignore_errors=True)


def _cached(name: str) -> bytes:
    """The cheap copy from the temporary directory, made first if it is not there or the template changed."""
    source = vaults.load(name).path
    stamp = f"{source.stat().st_size}-{source.stat().st_mtime_ns}"
    cache = Path(tempfile.gettempdir()) / f"pdh-cheap-{name}-{stamp}.kdbx"
    if not cache.exists():
        data = _lowered(name)
        part = cache.with_name(f"{cache.name}.{os.getpid()}.part")  # several test workers may build it at once
        part.write_bytes(data)
        os.replace(part, cache)
    return cache.read_bytes()


def cheap_copy(name: str, path: Path) -> Path:
    """Write a copy of the genuine template `name` to `path`, with the cost of its key derivation lowered."""
    if name not in _prototypes:
        _prototypes[name] = _cached(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_prototypes[name])
    return path
