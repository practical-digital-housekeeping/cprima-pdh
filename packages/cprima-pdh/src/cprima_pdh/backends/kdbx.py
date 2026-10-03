"""KDBX (KeePass) backend: how a taxonomy profile is stored in a KeePass vault.

The profile says *what* exists (standard fields and their kinds, field kinds); this module says *how KeePass stores it*.
Another store (Bitwarden, 1Password) would carry its own copy of these mappings. Only the standard library is imported
here, so the mappings are available without the `[kdbx]` extra; pykeepass itself is loaded only by the code that
opens a vault. The Vault implementation, `KdbxVault`, lives in `kdbx_vault.py` and is reachable from here as well.
"""
from __future__ import annotations

from importlib.util import find_spec

# standard fields of the profile -> the pykeepass attribute that holds them (`otp` is the TOTP/HOTP secret)
STANDARD_ATTR = {
    "Title": "title", "UserName": "username", "Password": "password", "URL": "url", "Notes": "notes", "otp": "otp",
}
# standard fields KeePass always keeps in protected form
STANDARD_PROTECTED = frozenset({"Password", "otp"})

# the KeePass 2 OTP plugin keeps its settings in custom fields with these prefixes; they are not user fields
OTP_PREFIXES = ("TimeOtp-", "HmacOtp-")
OTP_STYLES = {"TimeOtp-": "TimeOtp", "HmacOtp-": "HmacOtp"}  # prefix -> the style reported for an entry


def plugin_otp(custom: dict[str, str]) -> dict | None:
    """The settings of a KeePass 2 OTP plugin entry (from its custom fields), normalised; None if it has none."""
    secret = custom.get("TimeOtp-Secret-Base32")
    if not secret:
        return None
    algorithm = {"HMAC-SHA-1": "SHA1", "HMAC-SHA-256": "SHA256", "HMAC-SHA-512": "SHA512"}.get(
        custom.get("TimeOtp-Algorithm", "HMAC-SHA-1"), "SHA1")
    return {"secret": secret, "digits": int(custom.get("TimeOtp-Length", "6") or 6),
            "period": int(custom.get("TimeOtp-Period", "30") or 30), "algorithm": algorithm}


# the key derivation functions a KDBX file can name (the UUID in its KDF parameters)
KDF_UUIDS = {"ef636ddf8c29444b91f7a9a403e30a0c": "argon2d", "9e298b1956db4773b23dfc3ec6f0a1e6": "argon2id",
             "c9d9f39a628a4460bf740d08c18a4fea": "aeskdf"}


def kdf_name(kp) -> str:
    """The key derivation of an opened vault, from its parameters (pykeepass reports nothing for Argon2id)."""
    try:
        uuid = bytes(kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict["$UUID"].value).hex()
    except (AttributeError, KeyError):  # KDBX 3.x has no KDF parameters: AES-KDF
        return kp.kdf_algorithm or "unknown"
    return KDF_UUIDS.get(uuid, kp.kdf_algorithm or "unknown")


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


class Backend:
    name = "kdbx"
    requires = ("pykeepass",)

    @classmethod
    def missing_dependencies(cls) -> list[str]:
        return [m for m in cls.requires if find_spec(m) is None]


def __getattr__(name: str):
    if name == "KdbxVault":  # lazily: kdbx_vault imports this module's constants
        from .kdbx_vault import KdbxVault

        return KdbxVault
    raise AttributeError(name)
