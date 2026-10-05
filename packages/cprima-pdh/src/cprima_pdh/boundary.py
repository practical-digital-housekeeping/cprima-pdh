"""The data boundary: which input columns name a secret.

pdh never reads a secret from a plaintext file (see the README, "Data boundary"). A column counts as a secret if any of these
says so: it is a standard secret (`Password`, `otp`), the KDBX ecosystem treats it as one (`TOTP Seed`, `TimeOtp-*`, a passkey's
private key), or the taxonomy marks the field it names protected, by its name, an alias or its `match` rule. Nothing here ever
looks at a value.
"""
from __future__ import annotations

from cprima_pdh_kdbxkit.kdbx_format import STANDARD_PROTECTED, is_secret_attribute
from .schema import SchemaSet, lookup_term, vocabulary_index


def secret_columns(columns: list[str], sset: SchemaSet | None = None) -> list[str]:
    """The columns (as written in the file) that name a secret, in file order."""
    standard = {name.lower() for name in STANDARD_PROTECTED}
    exact, matchers = vocabulary_index(sset.fields) if sset is not None else ({}, [])
    found = []
    for column in columns:
        name = column.strip()
        if not name:
            continue
        term = lookup_term(name, exact, matchers)
        if name.lower() in standard or is_secret_attribute(name) or (term is not None and term[1].protected is True):
            found.append(column)
    return found


def refusal(columns: list[str], file_name: str) -> str:
    """The message for an input file with secret columns. It names columns, never values."""
    named = ", ".join(repr(c) for c in columns)
    which = "column" if len(columns) == 1 else "columns"
    return (f"{file_name}: {which} {named} {'is' if len(columns) == 1 else 'are'} for a secret; pdh does not read secrets from "
            f"files. Import the structure without {'it' if len(columns) == 1 else 'them'}, then add the secret with "
            f"`pdh edit set PATH FIELD -` (hidden prompt).")
