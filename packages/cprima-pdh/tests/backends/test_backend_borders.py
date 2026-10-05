"""The borders of the KDBX layer: only `cprima_pdh_kdbxkit` knows pykeepass, lxml entry access and the KDBX XML.

pdh itself talks to the Vault interface. Whatever a store's library cannot do is worked around inside its package.
"""
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "cprima_pdh"
KDBXKIT = Path(__file__).resolve().parents[3] / "cprima-pdh-kdbxkit" / "src" / "cprima_pdh_kdbxkit"
# (pattern, what it would mean)
FORBIDDEN = [
    (re.compile(r"^\s*(from|import)\s+pykeepass\b", re.M), "imports pykeepass"),
    (re.compile(r"^\s*(from|import)\s+lxml\b", re.M), "imports lxml"),
    (re.compile(r"\._element\b"), "reaches into a store's XML element"),
]
# `cprima_pdh_kdbxkit.kdbx_vault.pykeepass_open` is the one constructor; the opening code in pdh calls it, nothing else may
OPENER_USERS = {"source.py", "io.py", "session.py", "export.py"}


def _modules():
    return list(SRC.rglob("*.py"))


def test_pdh_itself_never_touches_the_store_library_and_its_xml():
    offenders = []
    for p in _modules():
        text = p.read_text(encoding="utf-8")
        for pattern, meaning in FORBIDDEN:
            if pattern.search(text):
                offenders.append(f"{p.relative_to(SRC)}: {meaning}")
    assert not offenders, "\n".join(offenders)


def test_the_kdbx_layer_is_where_pykeepass_is_used():
    text = (KDBXKIT / "kdbx_vault.py").read_text(encoding="utf-8")
    assert FORBIDDEN[0][0].search(text) and FORBIDDEN[1][0].search(text) and FORBIDDEN[2][0].search(text)  # the rules are not vacuous


def test_nobody_but_the_opening_code_constructs_a_pykeepass_database():
    offenders = [p.name for p in _modules() if "pykeepass_open(" in p.read_text(encoding="utf-8")
                 and p.name not in OPENER_USERS]
    assert not offenders, f"{offenders} open a KDBX file themselves: use the vault opener"
