"""KDBX (KeePass) backend. Placeholder: it reports whether its dependencies are installed, nothing else."""
from __future__ import annotations

from importlib.util import find_spec


class Backend:
    name = "kdbx"
    requires = ("pykeepass",)

    @classmethod
    def missing_dependencies(cls) -> list[str]:
        return [m for m in cls.requires if find_spec(m) is None]
