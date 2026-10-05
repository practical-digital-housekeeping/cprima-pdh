"""KDBX (KeePass) backend, as pdh registers it: how a taxonomy profile is stored in a KeePass vault, and the plugin entry.

The profile says *what* exists (standard fields and their kinds, field kinds); this module says *how KeePass stores it*, and
holds the `Backend` class the `pdh.backends` entry point names. What the KDBX format itself says is in `kdbx_format.py`; the
Vault implementation, `KdbxVault`, is in `kdbx_vault.py`.
"""
from __future__ import annotations

from importlib.util import find_spec

# how each field kind of the profile is represented in a KDBX entry
KIND_STORAGE = {
    "text": "custom string field",
    "secret": "custom string field, protected",
    "key": "custom string field, protected",
    "identifier": "custom string field",
    "card": "custom string field, protected",
    "phone": "custom string field",
    "email": "custom string field",
    "address": "custom string field, multi-line",
    "url": "custom string field (the standard URL field for `URL`)",
    "date": "custom string field, ISO date",
    "otp": "the otp attribute, protected (or the KeePass 2 OTP plugin fields)",
    "link": "custom string field holding a KeePass reference {REF:T@I:<uuid>} (or the bare uuid)",
}


_KDBX_SIGNATURE = bytes.fromhex("03d9a29a67fb4bb5")  # the two signature words every KDBX file starts with


class Backend:
    name = "kdbx"
    requires = ("pykeepass",)
    detection = "the file starts with the KDBX signature"

    @staticmethod
    def capabilities() -> frozenset[str]:
        from cprima_pdh_kdbxkit.kdbx_vault import KdbxVault

        return KdbxVault.capabilities

    @staticmethod
    def detects(path) -> bool:
        """A KDBX file starts with the KDBX signature."""
        try:
            with open(path, "rb") as f:
                return f.read(8) == _KDBX_SIGNATURE
        except OSError:
            return False

    @classmethod
    def missing_dependencies(cls) -> list[str]:
        return [m for m in cls.requires if find_spec(m) is None]
