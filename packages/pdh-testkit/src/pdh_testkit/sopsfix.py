"""sops fixtures: a sops-encrypted file made with the real `sops` binary, its throwaway age identity, its plaintext twin."""
from __future__ import annotations

import base64
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .vaults import VAULT_DIR

SOPS_DIR = VAULT_DIR / "sops"  # (a separate folder: the vault fixture tests expect every sidecar here to describe a .kdbx)


@dataclass(frozen=True)
class SopsFixture:
    name: str
    path: Path
    identity_text: str  # an age identity file's content (the throwaway test key)
    plain: dict  # what the file contains, decrypted
    description: str = ""

    def document(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))


def load_sops(name: str) -> SopsFixture:
    path = SOPS_DIR / f"{name}.json"
    meta = tomllib.loads(path.with_suffix(".toml").read_text(encoding="utf-8"))
    plain = json.loads((SOPS_DIR / meta["plain"]).read_text(encoding="utf-8"))
    return SopsFixture(name=name, path=path, identity_text=base64.b64decode(meta["identity_b64"]).decode("utf-8"),
                       plain=plain, description=meta.get("description", ""))
