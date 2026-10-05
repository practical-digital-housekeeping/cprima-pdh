"""The borders of the KDBX backend: only `backends/kdbx*.py` knows pykeepass, lxml entry access and the KDBX XML.

Everything else talks to the Vault interface. Whatever a store's library cannot do is worked around inside its backend.
"""
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "cprima_pdh"
BACKEND = {"kdbx.py", "kdbx_format.py", "kdbx_vault.py"}
# (pattern, what it would mean)
FORBIDDEN = [
    (re.compile(r"^\s*(from|import)\s+pykeepass\b", re.M), "imports pykeepass"),
    (re.compile(r"^\s*(from|import)\s+lxml\b", re.M), "imports lxml"),
    (re.compile(r"\._element\b"), "reaches into a store's XML element"),
]
# `source.pykeepass_open` is the one constructor; the opener in cli/ and the backend call it, nothing else may
OPENER_USERS = {"kdbx_vault.py", "source.py", "io.py", "session.py", "export.py"}


def _modules():
    return [p for p in SRC.rglob("*.py") if p.name not in BACKEND]


def test_only_the_kdbx_backend_touches_the_store_library_and_its_xml():
    offenders = []
    for p in _modules():
        text = p.read_text(encoding="utf-8")
        for pattern, meaning in FORBIDDEN:
            if pattern.search(text):
                offenders.append(f"{p.relative_to(SRC)}: {meaning}")
    assert not offenders, "\n".join(offenders)


def test_nobody_but_the_opening_code_constructs_a_pykeepass_database():
    offenders = [p.name for p in _modules() if "pykeepass_open(" in p.read_text(encoding="utf-8")
                 and p.name not in OPENER_USERS]
    assert not offenders, f"{offenders} open a KDBX file themselves: use the vault opener"
