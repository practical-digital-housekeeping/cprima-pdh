"""One-time passwords (RFC 4226 HOTP, RFC 6238 TOTP, and Steam's variant), implemented with the standard library.

A code is computed from the secret in memory; the secret itself is never returned in a report.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

from .backends.kdbx import plugin_otp
from .models import OtpCode

_ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
_STEAM = "23456789BCDFGHJKMNPQRTVWXY"


@dataclass(frozen=True)
class Params:
    kind: str  # totp | hotp
    secret: bytes
    digits: int = 6
    period: int = 30
    counter: int = 0
    algorithm: str = "SHA1"
    steam: bool = False


def _secret(text: str) -> bytes:
    cleaned = unquote(text).replace(" ", "").replace("-", "").upper()
    if not cleaned:
        raise ValueError("the one-time-password value has no secret")
    try:
        return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except binascii.Error:
        raise ValueError("the secret is not valid Base32") from None


def _build(kind: str, query: dict[str, list[str]], secret_key: str, digits_key: str, period_key: str) -> Params:
    def one(key: str, default: str = "") -> str:
        return query.get(key, [default])[0]

    if secret_key not in query:
        raise ValueError("the one-time-password value has no secret")
    steam = one("encoder").lower() == "steam"
    digits = 5 if steam else int(one(digits_key, "6") or 6)
    algorithm = one("algorithm", "SHA1").upper()
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"unsupported algorithm {algorithm!r}")
    if not 5 <= digits <= 10:
        raise ValueError("digits must be between 5 and 10")
    period = int(one(period_key, "30") or 30)
    if period < 1:
        raise ValueError("the period must be positive")
    return Params(kind=kind, secret=_secret(one(secret_key)), digits=digits, period=period,
                  counter=int(one("counter", "0") or 0), algorithm=algorithm, steam=steam)


def parse(value: str) -> Params:
    """Read an `otpauth://` URL or KeePassXC's older `key=...&size=...&step=...` form."""
    value = (value or "").strip()
    try:
        if value.lower().startswith("otpauth://"):
            url = urlparse(value)
            kind = url.netloc.lower()
            if kind not in ("totp", "hotp"):
                raise ValueError(f"unsupported one-time-password type {kind!r}")
            return _build(kind, parse_qs(url.query), "secret", "digits", "period")
        if "key=" in value and "=" in value:
            return _build("totp", parse_qs(value), "key", "size", "step")
    except (ValueError, TypeError) as exc:
        raise ValueError(str(exc) or "not a usable one-time-password value") from None
    raise ValueError("not a one-time-password value (expected otpauth://... or key=...)")


def from_plugin_fields(custom: dict[str, str]) -> Params | None:
    """The KeePass 2 plugin's custom fields as parameters, or None when the entry does not have them."""
    found = plugin_otp(custom)
    if found is None:
        return None
    return Params(kind="totp", secret=_secret(found["secret"]), digits=found["digits"], period=found["period"],
                  algorithm=found["algorithm"])


def code(params: Params, at: float | None = None) -> OtpCode:
    """The code for `at` (seconds since the epoch; now by default). A counter-based code ignores the time."""
    now = time.time() if at is None else at
    counter = params.counter if params.kind == "hotp" else int(now // params.period)
    digest = hmac.new(params.secret, struct.pack(">Q", counter), _ALGORITHMS[params.algorithm]).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    if params.steam:
        chars = []
        for _ in range(params.digits):
            number, rest = divmod(number, len(_STEAM))
            chars.append(_STEAM[rest])
        text = "".join(chars)
    else:
        text = str(number % (10 ** params.digits)).zfill(params.digits)
    valid = 0 if params.kind == "hotp" else params.period - int(now % params.period)
    return OtpCode(code=text, period=params.period, valid_for=valid)
