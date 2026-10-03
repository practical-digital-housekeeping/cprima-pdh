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


# --- the Vault ---------------------------------------------------------------------------------------------------------
# KdbxVault is the KeePass implementation of the engine's Vault interface (`cprima_pdh.vault`). It wraps an opened pykeepass
# database and is the only place that is meant to know pykeepass' objects and the KDBX XML. Phase 0 of the refactoring: the
# read side; the write operations and the workarounds that now live elsewhere move here next.

def _aware(moment):
    from datetime import timezone

    if moment is not None and moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _group_path(group) -> str:
    path = group.path
    if isinstance(path, (list, tuple)):
        path = "/".join(path)
    return path or "/"


def _below(group, ancestor_uuid) -> bool:
    while group is not None:
        if group.uuid == ancestor_uuid:
            return True
        group = group.parentgroup
    return False


class KdbxVault:
    name = "kdbx"
    capabilities = frozenset({
        "fields", "groups", "protected", "write", "tags", "expiry", "otp", "times", "uuid", "icons", "colours", "autotype",
        "history", "attachments", "recycle_bin", "credentials", "kdf", "settings", "create",
    })

    def __init__(self, kp, path=None):
        self.kp = kp
        self.path = path

    def _bin_uuid(self):
        rb = self.kp.recyclebin_group
        return rb.uuid if rb is not None else None

    def entries(self):
        from lxml import etree

        from ..vault import EntryData, Field

        bin_uuid = self._bin_uuid()
        out = []
        for e in self.kp.entries:
            history = list(e.history or [])
            out.append(EntryData(
                id=str(e.uuid), group_path=_group_path(e.group), group_id=str(e.group.uuid), title=e.title or "", username=e.username or "",
                password=e.password or "", url=e.url or "", notes=e.notes or "", otp=e.otp or "",
                tags=tuple(e.tags or ()), icon=str(e.icon if e.icon is not None else "0"),
                expires=bool(e.expires), expiry=_aware(e.expiry_time) if e.expires else None,
                ctime=_aware(e.ctime), mtime=_aware(e.mtime), atime=_aware(e.atime),
                in_bin=bin_uuid is not None and _below(e.group, bin_uuid),
                fields={k: Field(v or "", bool(e.is_custom_property_protected(k)))
                        for k, v in (e.custom_properties or {}).items()},
                attachments=tuple((a.filename, len(a.data)) for a in e.attachments),
                history_count=len(history), history_bytes=sum(len(etree.tostring(h._element)) for h in history),
                protected_standard=frozenset(
                    n for n in STANDARD_ATTR
                    if e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=n)),
            ))
        return out

    def groups(self):
        from ..vault import GroupData

        bin_uuid = self._bin_uuid()
        out = []
        for g in self.kp.groups:
            parent = g.parentgroup
            out.append(GroupData(
                id=str(g.uuid), path=_group_path(g), name=g.name or "", parent_id=str(parent.uuid) if parent else None,
                notes=g.notes or "", icon=str(g.icon if g.icon is not None else "0"), is_root=bool(g.is_root_group),
                is_bin=bin_uuid is not None and g.uuid == bin_uuid,
                in_bin=bin_uuid is not None and g.uuid != bin_uuid and _below(g, bin_uuid)))
        return out

    def info(self):
        from ..vault import VaultInfo

        try:
            generator = self.kp.kdbx.body.payload.xml.findtext("Meta/Generator") or ""
        except AttributeError:
            generator = ""
        major, minor = self.kp.version
        return VaultInfo(backend=self.name, format=f"KDBX {major}.{minor}", cipher=str(self.kp.encryption_algorithm),
                         kdf=kdf_name(self.kp), generator=generator)

    def find_entry(self, path, username=None):
        from ..vault import resolve_entry

        return resolve_entry(self.entries(), path, username)
