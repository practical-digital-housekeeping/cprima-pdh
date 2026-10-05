"""What the KDBX (KeePass) format says, independent of any program that uses it: how the standard fields are stored, which attributes the
ecosystem treats as secrets, how the one-time-password plugin keeps its settings, which key derivation a file names.

Only the standard library is imported here, so this is available without the `[kdbx]` extra; pykeepass itself is loaded only
by the code that opens a vault (`kdbx_vault.py`). Another store (Bitwarden, 1Password) would carry its own copy of these.
"""
from __future__ import annotations

# the standard fields, by name -> the pykeepass attribute that holds them (`otp` is the TOTP/HOTP secret)
STANDARD_ATTR = {
    "Title": "title", "UserName": "username", "Password": "password", "URL": "url", "Notes": "notes", "otp": "otp",
}
# standard fields KeePass always keeps in protected form
STANDARD_PROTECTED = frozenset({"Password", "otp"})

# the KeePass 2 OTP plugin keeps its settings in custom fields with these prefixes; they are not user fields
OTP_PREFIXES = ("TimeOtp-", "HmacOtp-")
OTP_STYLES = {"TimeOtp-": "TimeOtp", "HmacOtp-": "HmacOtp"}  # prefix -> the style reported for an entry


# Attributes of the KDBX ecosystem that hold a secret whatever a file's own flags say: the one-time-password secrets (KeePassXC's
# `otp`, its legacy `TOTP Seed` and `TOTP Settings`, the KeePass 2 plugin's `TimeOtp-*` and `HmacOtp-*`) and a passkey's private key.
SECRET_ATTRIBUTES = frozenset(name.lower() for name in ("otp", "TOTP Seed", "TOTP Settings", "KPEX_PASSKEY_PRIVATE_KEY_PEM"))


def is_secret_attribute(name: str) -> bool:
    """Whether the KDBX ecosystem treats the attribute `name` as a secret (case does not matter)."""
    lowered = name.strip().lower()
    return lowered in SECRET_ATTRIBUTES or lowered.startswith(tuple(p.lower() for p in OTP_PREFIXES))


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
