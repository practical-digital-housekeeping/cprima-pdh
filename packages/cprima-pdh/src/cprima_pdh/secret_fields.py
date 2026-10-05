"""The secret fields of an entry: which they are, which are empty, and filling them without a secret ever being an argument.

The taxonomy decides. An entry's secret fields are the fields its record types name (in the order the taxonomy lists them) that
are secrets under the data boundary (see `boundary`): the standard `Password` and `otp`, what the taxonomy marks protected, the
KDBX ecosystem's own. An entry with no record type has the one a login has, `Password`. All of them are alike, the password
as much as a Wi-Fi key or a PIN: one rule, one way of filling. A field may be generated when the taxonomy gives it the kind
`secret` (a password, a key made up for the account); a PIN or a card number is issued elsewhere and can only be typed.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import boundary
from .backends.kdbx_format import STANDARD_PROTECTED
from .generate import PasswordSettings, generate_password
from .models import OrgChange
from .schema import SchemaSet, _effective_protected, lookup_term, resolve, vocabulary_index
from .txn import Plan, execute_vault
from .validation import typing_of
from .vault import STANDARD, EntryData, Vault, as_vault
from .write import WriteError, find_data



@dataclass(frozen=True)
class SecretField:
    name: str
    generatable: bool  # the taxonomy gives it the kind `secret`


def _is_secret(name: str, schema_protected: list[str], sset: SchemaSet) -> bool:
    return (name in STANDARD_PROTECTED or name in schema_protected or bool(boundary.secret_columns([name], sset)))


def _generatable(name: str, types: dict[str, str], sset: SchemaSet, exact, matchers) -> bool:
    """Whether the taxonomy lets pdh generate this field: it opts a term in with `generate = true`. A PIN, a PUK, a licence key
    or an API key is issued by someone else and is never generated, whatever its kind."""
    if name in STANDARD:
        standard = sset.standard.get(name)
        return standard is not None and standard.generate
    if name in types and types[name] in sset.fields:
        return sset.fields[types[name]].generate
    found = lookup_term(name, exact, matchers)
    return found is not None and found[1].generate


def secret_fields(entry: EntryData, sset: SchemaSet) -> list[SecretField]:
    """The entry's secret fields, in the order of the taxonomy: the record types it has, each in the order the taxonomy lists its
    fields (required, recommended, optional, then any other protected one)."""
    exact, matchers = vocabulary_index(sset.fields)
    names = typing_of(entry, sset).names
    found: dict[str, SecretField] = {}
    if not names:
        found["Password"] = SecretField("Password", _generatable("Password", {}, sset, exact, matchers))
    for schema in names:
        d = resolve(sset.schemas[schema], sset.facets)
        protected = _effective_protected(d, sset.fields)
        for name in [*d.required, *d.recommended, *d.optional, *protected]:
            if name not in found and _is_secret(name, protected, sset):
                found[name] = SecretField(name, _generatable(name, d.types, sset, exact, matchers))
    return list(found.values())


def _value_of(entry: EntryData, name: str) -> str:
    return entry.value(name) if name in STANDARD else (entry.fields[name].value if name in entry.fields else "")


def _has_value(entry: EntryData, name: str) -> bool:
    return bool(_value_of(entry, name))


def missing(entry: EntryData, sset: SchemaSet) -> list[SecretField]:
    """The secret fields of the entry that are empty: what is still to be filled."""
    return [f for f in secret_fields(entry, sset) if not _has_value(entry, f.name)]


def generated(settings: PasswordSettings | None = None) -> str:
    """A new random password as `settings` say (the generator's defaults without), for a field that may be generated. It is
    stored by `fill`, never shown."""
    return generate_password(settings)


@dataclass(frozen=True)
class Target:
    entry: EntryData
    fields: list[SecretField]  # the ones still empty, in the taxonomy's order


def fill_targets(source, path: str, sset: SchemaSet, username: str | None = None) -> list[Target]:
    """The entries to fill for `path`: the entry at that path, or every live entry below that group, each with the secret
    fields it still lacks. An entry that lacks none is left out. Names only; no value is read."""
    vault = as_vault(source)
    entries = [e for e in vault.entries() if not e.in_bin]
    wanted = "/" if path in ("", "/") else path.strip("/")
    hits = [e for e in entries if e.path == wanted and (username is None or e.username == username)]
    group = next((g for g in vault.groups() if g.path == wanted and not g.is_bin and not g.in_bin), None)
    if hits and group is not None:
        raise WriteError(f"{path!r} is both an entry and a group; name the entry with its title or the group with a trailing /")
    if len(hits) > 1:
        raise WriteError(f"{len(hits)} entries at {path!r}; narrow it down with --username")
    if hits:
        chosen = hits
    elif group is not None:
        prefix = "" if group.is_root else group.path
        chosen = [e for e in entries if group.is_root or e.group_path == prefix or e.group_path.startswith(prefix + "/")]
    else:
        raise WriteError(f"no entry or group at {path!r}")
    out = []
    for e in sorted(chosen, key=lambda x: x.path):
        lacking = missing(e, sset)
        if lacking:
            out.append(Target(e, lacking))
    return out


def fill_entries(open_db: Callable[[], object], db: Path, values: Mapping[str, Mapping[str, str]], apply: bool,
                 sset: SchemaSet, any_secret: bool = False) -> OrgChange:
    """Set secret fields of several entries in one write, one history snapshot per entry. `values` maps an entry's id to its
    field values. Every name must be a secret field of that entry (with `any_secret`: or any field that is a secret under the
    data boundary, such as a one-time-password seed the entry's record type does not list) and no value may be empty. The
    report names fields only."""

    def build(vault: Vault) -> Plan:
        entries = {e.id: e for e in vault.entries()}
        for eid, fields in values.items():
            e = entries.get(eid)
            if e is None:
                raise WriteError("an entry to fill is no longer in the vault")
            allowed = {f.name for f in secret_fields(e, sset)}
            for name, value in fields.items():
                if name not in allowed and not (any_secret and _is_secret(name, [], sset)):
                    raise WriteError(f"{name} is not a secret field of {e.path!r}")
                if not value:
                    raise WriteError(f"{name}: an empty value is not a secret")
        count = sum(len(f) for f in values.values())
        names = ", ".join(n for f in values.values() for n in f)
        change = OrgChange(kind="secret-fields", target=f"{len(values)} entr{'y' if len(values) == 1 else 'ies'}",
                           dest=names if len(values) == 1 else f"{count} fields")

        def mutate(v: Vault) -> None:
            for eid, fields in values.items():
                v.snapshot_history(eid)
                for name, value in fields.items():
                    v.set_field(eid, name, value, protect=True)

        def verify(again: Vault) -> list[str]:
            found = {e.id: e for e in again.entries()}
            problems = []
            for eid, fields in values.items():
                x = found.get(eid)
                if x is None:
                    return ["an entry is missing"]
                if any(_value_of(x, n) != value for n, value in fields.items()):
                    problems.append("a secret field does not have the expected value")
                if any(n not in STANDARD and not x.is_protected(n) for n in fields):
                    problems.append("a secret field is not protected")
            return problems

        return Plan(change=change, mutate=mutate, touched=set(values), verify=verify)

    return execute_vault(open_db, db, build, apply)


def fill(open_db: Callable[[], object], db: Path, path: str, values: Mapping[str, str], apply: bool,
         sset: SchemaSet, username: str | None = None) -> OrgChange:
    """Set secret fields of one entry at `path` (see `fill_entries`). The report names the entry and the fields."""
    entry = find_data(as_vault(open_db()), path, username)
    change = fill_entries(open_db, db, {entry.id: values}, apply, sset)
    return change.model_copy(update={"target": path})
