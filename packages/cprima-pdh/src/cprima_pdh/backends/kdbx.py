"""KDBX (KeePass) backend: how a taxonomy profile is stored in a KeePass vault.

The profile says *what* exists (standard fields and their kinds, field kinds); this module says *how KeePass stores it*.
Another store (Bitwarden, 1Password) would carry its own copy of these mappings. Only the standard library is imported
here, so the mappings are available without the `[kdbx]` extra; pykeepass itself is loaded only by the code that
opens a vault.
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
