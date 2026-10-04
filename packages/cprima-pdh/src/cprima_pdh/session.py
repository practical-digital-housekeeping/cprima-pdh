"""Session credential cache (Windows DPAPI, bound to the current user).

Blob lives in %LOCALAPPDATA%\\cprima-pdh\\session.bin with db path and expiry. The passphrase is never in the file as plain
text: it is encrypted with the current Windows user's key, so another user or a stolen disk cannot read it, but any process
running as the same user can. Expiry is enforced here, not cryptographically: an expired blob is deleted by the next pdh
call of any kind, and `pdh session lock` deletes it at once. Windows only; elsewhere use KDBX_PASSWORD or --password-stdin.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import time
from pathlib import Path

# PDH_SESSION_FILE lets tests use their own session file, so they never touch the real one.
SESSION_FILE = Path(
    os.environ.get("PDH_SESSION_FILE") or Path(os.environ.get("LOCALAPPDATA", Path.home())) / "cprima-pdh" / "session.bin"
)


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    inb = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = _Blob()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI call failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def supported() -> bool:
    """Whether the session cache can work here: it needs Windows DPAPI."""
    return os.name == "nt"


def _norm(path: str | Path) -> str:
    return os.path.normcase(str(Path(path).resolve()))


def _read() -> dict | None:
    try:
        return json.loads(_dpapi(SESSION_FILE.read_bytes(), protect=False))
    except (OSError, ValueError, AttributeError):  # (AttributeError: no ctypes.windll off Windows)
        return None


def load_session(db: str | Path) -> tuple[str | None, str | None] | None:
    """(password, keyfile) for db if a valid session exists, else None."""
    data = _read()
    if data is None:
        return None
    if data.get("expires", 0) < time.time():
        lock()
        return None
    if data.get("db") != _norm(db):
        return None
    return data.get("password"), data.get("keyfile")


def save_session(db: str | Path, password: str | None, keyfile: str | Path | None, minutes: int) -> None:
    payload = {
        "db": _norm(db),
        "password": password,
        "keyfile": str(Path(keyfile).resolve()) if keyfile else None,
        "expires": time.time() + minutes * 60,
    }
    SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_bytes(_dpapi(json.dumps(payload).encode(), protect=True))


def current_vault() -> Path | None:
    """The vault the valid session was unlocked for (paths are not secret), else None."""
    data = _read()
    if data is not None and data.get("expires", 0) < time.time():
        lock()  # every pdh call looks here first, so an expired blob does not stay on disk
        return None
    if data is None or not data.get("db"):
        return None
    return Path(data["db"])


def seconds_left() -> int:
    data = _read()
    if data is None:
        return 0
    left = int(data.get("expires", 0) - time.time())
    if left <= 0:
        lock()
        return 0
    return left


def lock() -> bool:
    try:
        SESSION_FILE.unlink()
        return True
    except OSError:
        return False
