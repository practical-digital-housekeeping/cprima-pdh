"""The sops file format, read side, independent of the file syntax: decrypt a parsed document and verify its MAC.

A sops file is a tree (a parsed JSON or YAML document) whose leaf values are `ENC[AES256_GCM,data:..,iv:..,tag:..,type:..]`
tokens, plus a top-level `sops` block with the recipients, the encrypted data key, `lastmodified` and a `mac`. This module takes
the parsed document (any codec produces the same dicts, lists and scalars) and an age identity, and gives back the plaintext
tree with the facts a vault needs. It never writes. Values are decrypted in memory only.
Format as observed from sops 3.13 output and verified against the real `sops` binary in the tests.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any

from . import age

# sops starts the MAC hash with these bytes (sha256 of b"sops") when `mac_only_encrypted` is set, so such a MAC always
# differs from one made without the setting (sops.go: MACOnlyEncryptedInitialization).
MAC_ONLY_ENCRYPTED_INIT = hashlib.sha256(b"sops").digest()

_ENC = re.compile(r"^ENC\[AES256_GCM,data:(?P<data>[^,]*),iv:(?P<iv>[^,]*),tag:(?P<tag>[^,]*),type:(?P<type>\w+)\]$")


class SopsError(ValueError):
    pass


@dataclass(frozen=True)
class Leaf:
    path: tuple[str, ...]  # the keys from the root to this value (list items share the key of their list)
    value: Any  # typed plaintext
    text: str  # the plaintext as sops hashes it
    encrypted: bool


@dataclass(frozen=True)
class SopsDocument:
    tree: dict  # the document without `sops`, values decrypted and typed
    leaves: list[Leaf]  # in document order
    meta: dict  # the `sops` block as parsed (recipients, lastmodified, version, ...)


def is_sops(doc: Any) -> bool:
    return isinstance(doc, dict) and isinstance(doc.get("sops"), dict) and ("mac" in doc["sops"] or "age" in doc["sops"])


def _b64(text: str) -> bytes:
    return base64.b64decode(text)


def _aead_decrypt(key: bytes, token: str, aad: bytes) -> tuple[str, bytes, str]:
    """(type name, plaintext bytes, ...) of one ENC[...] token."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    m = _ENC.match(token)
    if not m:
        raise SopsError("not a sops ENC[...] value")
    try:
        plain = AESGCM(key).decrypt(_b64(m["iv"]), _b64(m["data"]) + _b64(m["tag"]), aad)
    except InvalidTag:
        raise SopsError("a value could not be decrypted: wrong key, or the file was altered") from None
    return m["type"], plain, token


def _typed(kind: str, plain: bytes) -> tuple[Any, str]:
    text = plain.decode("utf-8", errors="replace")
    if kind == "str" or kind == "comment":
        return text, text
    if kind == "int":
        return int(text), text
    if kind == "float":
        return float(text), text
    if kind == "bool":
        return text == "True", text
    if kind == "bytes":
        return plain, text
    raise SopsError(f"unknown value type {kind!r}")


def _plain_text(value: Any) -> str:
    """How an unencrypted leaf enters the MAC (sops writes bool as True/False, ints and floats as plain decimals)."""
    if value is None:
        return ""  # a null contributes nothing to the MAC
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, float):
        from decimal import Decimal

        text = format(Decimal(repr(value)), "f")  # Go's FormatFloat(f, 'f', -1, 64): no exponent, no trailing ".0"
        return text[:-2] if text.endswith(".0") else text
    return str(value)


def data_key(meta: dict, identities: list[bytes]) -> bytes:
    """The 32-byte data key, unwrapped with the first identity that is a recipient."""
    recipients = meta.get("age") or []
    if not recipients:
        raise SopsError("the file has no age recipients (only age is supported)")
    failures = 0
    for item in recipients:
        for identity in identities:
            try:
                key = age.unwrap(item["enc"], identity)
            except age.AgeError:
                failures += 1
                continue
            if len(key) != 32:
                raise SopsError("the data key has an unexpected length")
            return key
    raise SopsError("none of the given age identities is a recipient of this file")


def _walk(node: Any, path: tuple[str, ...], key: bytes, out: list[Leaf]) -> Any:
    if isinstance(node, dict):
        return {k: _walk(v, path + (k,), key, out) for k, v in node.items()}
    if isinstance(node, list):
        return [_walk(v, path, key, out) for v in node]  # list items carry the key of their list
    aad = (":".join(path) + ":").encode("utf-8")
    if isinstance(node, str) and _ENC.match(node):
        kind, plain, _ = _aead_decrypt(key, node, aad)
        value, text = _typed(kind, plain)
        out.append(Leaf(path, value, text, True))
        return value
    out.append(Leaf(path, node, _plain_text(node), False))
    return node


def compute_mac(leaves: list[Leaf], only_encrypted: bool) -> str:
    """SHA-512 over the plaintext of every value in document order, upper-case hex (what sops encrypts as `mac`)."""
    digest = hashlib.sha512()
    if only_encrypted:
        digest.update(MAC_ONLY_ENCRYPTED_INIT)
    for leaf in leaves:
        if leaf.encrypted or not only_encrypted:
            digest.update(leaf.text.encode("utf-8"))
    return digest.hexdigest().upper()


def verify_mac(meta: dict, leaves: list[Leaf], key: bytes) -> None:
    if "mac" not in meta:
        raise SopsError("the file has no MAC")
    try:  # the MAC is encrypted with `lastmodified` as additional data: change either and it cannot be opened
        kind, plain, _ = _aead_decrypt(key, meta["mac"], str(meta.get("lastmodified", "")).encode("utf-8"))
    except SopsError:
        raise SopsError("the MAC does not match: the file was altered (its MAC or lastmodified changed)") from None
    expected = plain.decode("ascii", errors="replace")
    if compute_mac(leaves, bool(meta.get("mac_only_encrypted"))) != expected:
        raise SopsError("the MAC does not match: the file was altered or reordered")


def open_document(doc: dict, identities: list[bytes]) -> SopsDocument:
    """Decrypt a parsed sops document and verify its MAC; `SopsError` (or `age.AgeError`) says why it could not be read."""
    if not is_sops(doc):
        raise SopsError("not a sops file (no `sops` block)")
    meta = doc["sops"]
    key = data_key(meta, identities)
    leaves: list[Leaf] = []
    tree = _walk({k: v for k, v in doc.items() if k != "sops"}, (), key, leaves)
    verify_mac(meta, leaves, key)
    return SopsDocument(tree=tree, leaves=leaves, meta=meta)
