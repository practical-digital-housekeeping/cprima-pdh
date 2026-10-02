"""Vault fixtures: `.kdbx` files with a sidecar `.toml` of the same name.

Sidecar keys: `password` (each fixture has its own), `client` (the program that wrote it), `format` ("KDBX 4.0",
"KDBX 3.1"), `description`, and optionally `filled_by` (the vault is a genuine client-made template that code then
filled; such a vault serves unit and integration tests only). A vault without `filled_by` is **genuine**: made by hand
in a real client, the only kind allowed in end-to-end tests.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .paths import REPO_ROOT

VAULT_DIR = REPO_ROOT / "packages" / "pdh-testkit" / "vaults"
_SIGNATURE = bytes.fromhex("03d9a29a67fb4bb5")  # KeePass 2.x file signature (both 32-bit words, little-endian)


@dataclass(frozen=True)
class Vault:
    name: str
    path: Path
    password: str
    client: str
    format: str
    description: str = ""
    filled_by: str = ""

    @property
    def genuine(self) -> bool:
        return not self.filled_by


def header_format(path: Path) -> str:
    """"KDBX <major>.<minor>" read from the file header; no password needed, nothing decrypted."""
    head = path.read_bytes()[:12]
    if head[:8] != _SIGNATURE:
        raise ValueError(f"{path.name} is not a KDBX file")
    minor, major = int.from_bytes(head[8:10], "little"), int.from_bytes(head[10:12], "little")
    return f"KDBX {major}.{minor}"


def load(name: str) -> Vault:
    """The fixture `name` (file stem), with the facts from its sidecar."""
    path = VAULT_DIR / f"{name}.kdbx"
    sidecar = path.with_suffix(".toml")
    if not path.is_file():
        raise FileNotFoundError(f"no vault fixture {path.name}")
    if not sidecar.is_file():
        raise FileNotFoundError(f"{path.name} has no sidecar {sidecar.name}")
    meta = tomllib.loads(sidecar.read_text(encoding="utf-8"))
    return Vault(name=name, path=path, password=meta["password"], client=meta["client"], format=meta["format"],
                 description=meta.get("description", ""), filled_by=meta.get("filled_by", ""))


def all_vaults() -> list[Vault]:
    return [load(p.stem) for p in sorted(VAULT_DIR.glob("*.kdbx"))]


def genuine_vaults() -> list[Vault]:
    """The vaults a real client made; the only ones end-to-end tests may use."""
    return [v for v in all_vaults() if v.genuine]
