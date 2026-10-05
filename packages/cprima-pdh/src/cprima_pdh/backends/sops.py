"""sops backend, as pdh registers it: the plugin entry for sops files. The vault itself is `cprima_pdh_sopskit`."""
from __future__ import annotations

from importlib.util import find_spec
from pathlib import Path


class Backend:
    name = "sops"
    requires = ("cryptography",)
    detection = "a JSON or YAML file with a `sops` block"

    @staticmethod
    def capabilities() -> frozenset[str]:
        from cprima_pdh_sopskit.sops_vault import SopsVault

        return SopsVault.capabilities

    @staticmethod
    def detects(path) -> bool:
        """A sops file (JSON or YAML) carries a `sops` block with its metadata."""
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return False
        json_like = text.lstrip().startswith("{") and '"sops"' in text
        yaml_like = any(line.startswith("sops:") for line in text.splitlines())
        return json_like or yaml_like

    @classmethod
    def missing_dependencies(cls) -> list[str]:
        return [m for m in cls.requires if find_spec(m) is None]
