"""The part of the age file format sops needs: unwrap the 32-byte data key sops stores for an age recipient.

sops keeps its data key in `sops.age[].enc` as an armored age file (the key encrypted to one X25519 recipient). This reads
exactly that: bech32 keys, the armor, the X25519 stanza, the header MAC and a single-chunk payload. scrypt and ssh
recipients are out of scope and say so. The primitives come from `cryptography` (the optional extra `[sops]`).
Spec: https://age-encryption.org/v1
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class AgeError(ValueError):
    pass


def _polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generators[i] if (top >> i) & 1 else 0
    return chk


def bech32_decode(text: str) -> tuple[str, bytes]:
    """(human-readable part, data bytes) of a bech32 string; `AgeError` for a bad character or checksum."""
    text = text.strip()
    if text != text.lower() and text != text.upper():
        raise AgeError("mixed-case bech32")
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        raise AgeError("not a bech32 string")
    hrp, tail = text[:pos], text[pos + 1:]
    try:
        values = [_CHARSET.index(c) for c in tail]
    except ValueError:
        raise AgeError("invalid bech32 character") from None
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _polymod(expanded + values) != 1:
        raise AgeError("bech32 checksum mismatch")
    acc = bits = 0
    out = bytearray()
    for v in values[:-6]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc << (8 - bits)) & 0xFF:
        raise AgeError("bech32 padding is not zero")
    return hrp, bytes(out)


def identities_from_text(text: str) -> list[bytes]:
    """The X25519 secret keys (32 bytes each) in an age identity file or an `AGE-SECRET-KEY-1...` string."""
    keys = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        hrp, data = bech32_decode(line)
        if hrp != "age-secret-key-" or len(data) != 32:
            raise AgeError("not an age secret key (only X25519 identities are supported)")
        keys.append(data)
    if not keys:
        raise AgeError("no age identity found")
    return keys


def load_identities(path: str | Path) -> list[bytes]:
    return identities_from_text(Path(path).read_text(encoding="utf-8"))


def _unarmor(armored: str) -> bytes:
    lines = [ln.strip() for ln in armored.strip().splitlines()]
    if not lines or lines[0] != "-----BEGIN AGE ENCRYPTED FILE-----" or lines[-1] != "-----END AGE ENCRYPTED FILE-----":
        raise AgeError("not an armored age file")
    return base64.b64decode("".join(lines[1:-1]))


def _b64(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def _parse(binary: bytes) -> tuple[list[tuple[list[str], bytes]], bytes, bytes, bytes]:
    """(stanzas as (arguments, body), the header bytes the MAC covers, the MAC, the payload)."""
    if not binary.startswith(b"age-encryption.org/v1\n"):
        raise AgeError("not an age v1 file")
    pos = binary.index(b"\n") + 1
    stanzas: list[tuple[list[str], bytes]] = []
    while True:
        end = binary.index(b"\n", pos)
        line = binary[pos:end].decode("ascii")
        if line.startswith("---"):
            covered = binary[:pos + 3]  # through the three dashes, as the spec has it
            mac = _b64(line[3:].strip())
            return stanzas, covered, mac, binary[end + 1:]
        if not line.startswith("-> "):
            raise AgeError("malformed age header")
        args = line[3:].split(" ")
        pos, body = end + 1, b""
        while True:
            end = binary.index(b"\n", pos)
            chunk = binary[pos:end].decode("ascii")
            pos = end + 1
            body += _b64(chunk)
            if len(chunk) < 64:
                break
        stanzas.append((args, body))


def unwrap(armored: str, identity: bytes) -> bytes:
    """Decrypt an armored age file made for the X25519 recipient of `identity`; `AgeError` if it is not for this key."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    def hkdf(secret: bytes, salt: bytes, info: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(secret)

    stanzas, covered, mac, payload = _parse(_unarmor(armored))
    private = X25519PrivateKey.from_private_bytes(identity)
    own_public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    file_key = None
    for args, body in stanzas:
        if args[0] != "X25519" or len(args) != 2:
            continue  # scrypt, ssh-* and plugin recipients are not supported
        share = _b64(args[1])
        try:
            secret = private.exchange(X25519PublicKey.from_public_bytes(share))
            wrapping = hkdf(secret, share + own_public, b"age-encryption.org/v1/X25519")
            file_key = ChaCha20Poly1305(wrapping).decrypt(b"\x00" * 12, body, None)
            break
        except (InvalidTag, ValueError):
            continue
    if file_key is None:
        raise AgeError("this identity is not a recipient of the file")
    check = hmac.HMAC(hkdf(file_key, b"", b"header"), hashes.SHA256())
    check.update(covered)
    try:
        check.verify(mac)
    except Exception:  # noqa: BLE001
        raise AgeError("the age header MAC does not match: the file was altered") from None
    nonce, chunk = payload[:16], payload[16:]
    try:
        return ChaCha20Poly1305(hkdf(file_key, nonce, b"payload")).decrypt(b"\x00" * 11 + b"\x01", chunk, None)
    except InvalidTag:
        raise AgeError("the age payload could not be decrypted") from None


_RECIPIENT = re.compile(r"^age1[0-9a-z]{58}$")


def is_recipient(text: str) -> bool:
    return bool(_RECIPIENT.match(text))
