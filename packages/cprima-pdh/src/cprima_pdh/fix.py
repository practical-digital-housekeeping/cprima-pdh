"""Field-name and protection fixes: vocabulary-driven `fix`, and the generic `rename-field`.

Only custom field *names* and the protect-in-memory flag change; values never do.
Dry run unless `apply`. One save for all changes, verified by reopening the database.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .backends.kdbx_format import OTP_PREFIXES, STANDARD_ATTR
from .models import FixAction, FixPlan
from .schema import SchemaSet, lookup_term, vocabulary_index
from .validation import live
from .vault import EntryData, Vault, as_vault
from .write import WriteError, find_data

if TYPE_CHECKING:
    from .txn import Plan

_RESERVED = tuple(STANDARD_ATTR)  # the standard fields: not custom fields, so never renamed or treated as one


@dataclass
class _Op:
    entry: EntryData
    ref: str
    key: str
    target: str  # new key name (== key when only the protection changes)
    protect: bool  # protection flag the field must end up with


def _plan(source, sset: SchemaSet, renames: bool, protection: bool) -> tuple[list[_Op], list[FixAction]]:
    exact, matchers = vocabulary_index(sset.fields)
    ops: list[_Op] = []
    actions: list[FixAction] = []
    for e in live(as_vault(source).entries()):
        ref = f"{e.group_path}/{e.title}"
        keys = [k for k in e.fields if not k.startswith(OTP_PREFIXES)]
        existing = set(keys)
        for key in keys:
            found = lookup_term(key, exact, matchers)
            if found is None:
                continue
            name, ft, _by_name = found
            target = key
            if renames and key != name and key in ft.aliases:
                if name in existing:
                    actions.append(FixAction(entry=ref, key=key, action=f"skipped: {name} already exists", new_key=name))
                else:
                    target = name
                    existing.discard(key)
                    existing.add(name)
            now = e.fields[key].protected
            want = now
            if protection and ft.protected is not None:
                want = ft.protected
            if target == key and want == now:
                continue
            ops.append(_Op(entry=e, ref=ref, key=key, target=target, protect=want))
            if target != key:
                actions.append(FixAction(entry=ref, key=key, action="rename", new_key=target))
            if want != now:
                actions.append(FixAction(entry=ref, key=target, action="protect" if want else "unprotect"))
    return ops, actions


def _digest(*parts: str | None) -> str:
    return hashlib.sha256("\x1f".join(p or "" for p in parts).encode()).hexdigest()


def _base(e: EntryData) -> str:
    """Everything about an entry except its custom fields."""
    return _digest(e.title, e.username, e.password, e.url, e.notes, e.otp, ",".join(sorted(e.tags)),
                   str(e.expires), e.group_id)  # not the expiry time: saved without sub-second precision


def _plan_result(actions: list[FixAction], touched: int, applied: bool) -> FixPlan:
    counts: dict[str, int] = {}
    for a in actions:
        label = a.action.split(":")[0]
        counts[label] = counts.get(label, 0) + 1
    return FixPlan(applied=applied, entries_touched=touched, counts=counts, actions=actions)


def _plan_from_ops(ops: list[_Op], actions: list[FixAction]) -> "Plan":
    """A `txn.Plan` for field renames and protection changes: history snapshot per touched entry, then the changes."""
    from .txn import Plan

    touched = {o.entry.id for o in ops}
    report = _plan_result(actions, len(touched), False)
    if not ops:
        return Plan(change=report)
    expect: dict[str, dict] = {}  # what every touched entry must look like after saving
    for o in ops:
        value = o.entry.fields[o.key].value  # kept in memory, never reported
        exp = expect.setdefault(o.entry.id, {"base": _base(o.entry), "fields": {}, "gone": set()})
        exp["fields"][o.target] = (_digest(value), o.protect)
        if o.target != o.key:
            exp["gone"].add(o.key)

    def mutate(v: Vault) -> None:
        for uid in touched:
            v.snapshot_history(uid)
        for o in ops:
            value = o.entry.fields[o.key].value
            if o.target != o.key:
                v.delete_field(o.entry.id, o.key)
            v.set_field(o.entry.id, o.target, value, protect=o.protect)

    def verify(again: Vault) -> list[str]:
        problems: list[str] = []
        entries = {e.id: e for e in again.entries()}
        for uid, exp in expect.items():
            e = entries.get(uid)
            if e is None or _base(e) != exp["base"]:
                problems.append("a touched entry changed outside its custom fields")
                continue
            for key, (vdigest, prot) in exp["fields"].items():
                got = e.fields.get(key)
                if got is None or _digest(got.value) != vdigest or got.protected != prot:
                    problems.append("a field does not have the expected name, value or protection")
                    break
            if exp["gone"] & set(e.fields):
                problems.append("a renamed field still exists under its old name")
        return problems

    return Plan(change=report, mutate=mutate, touched=touched, verify=verify)


def run_fix(
    open_db: Callable[[], object],
    db: Path,
    sset: SchemaSet,
    apply: bool,
    renames: bool = True,
    protection: bool = True,
) -> FixPlan:
    """Apply the vocabulary to every entry: canonical names and fixed protection (see `txn.execute_vault`)."""
    from .txn import execute_vault

    def build(vault: Vault):
        return _plan_from_ops(*_plan(vault, sset, renames, protection))

    return execute_vault(open_db, db, build, apply)


def _check_names(old: str, new: str) -> None:
    if not old or not new or old == new:
        raise WriteError("old and new must be different, non-empty field names")
    for name in (old, new):
        if name in _RESERVED or name.startswith(OTP_PREFIXES):
            raise WriteError(f"{name!r} is a standard or OTP field; only custom fields can be renamed")


def _plan_rename_all(source, old: str, new: str, under: str | None) -> tuple[list[_Op], list[FixAction]]:
    _check_names(old, new)
    prefix = (under or "").strip("/")
    ops: list[_Op] = []
    actions: list[FixAction] = []
    for e in live(as_vault(source).entries()):
        path = e.group_path
        if old not in e.fields:
            continue
        if prefix and path != prefix and not path.startswith(prefix + "/"):
            continue
        ref = f"{path}/{e.title}"
        if new in e.fields:
            actions.append(FixAction(entry=ref, key=old, action=f"skipped: {new} already exists", new_key=new))
            continue
        ops.append(_Op(entry=e, ref=ref, key=old, target=new, protect=e.fields[old].protected))
        actions.append(FixAction(entry=ref, key=old, action="rename", new_key=new))
    return ops, actions


def plan_rename_all(source, old: str, new: str, under: str | None = None) -> FixPlan:
    """What `rename_field_all` would do, without writing: every live entry that has `old` (below `under`, if given)."""
    ops, actions = _plan_rename_all(source, old, new, under)
    return _plan_result(actions, len(ops), False)


def rename_field_all(
    open_db: Callable[[], object],
    db: Path,
    old: str,
    new: str,
    apply: bool,
    under: str | None = None,
) -> FixPlan:
    """Rename one custom field on every live entry that has it, keeping value and protection. One save, verified."""
    from .txn import execute_vault

    return execute_vault(open_db, db, lambda v: _plan_from_ops(*_plan_rename_all(v, old, new, under)), apply)


def rename_field(
    open_db: Callable[[], object],
    db: Path,
    path: str,
    old: str,
    new: str,
    apply: bool,
    username: str | None = None,
) -> FixPlan:
    """Rename one custom field on one entry, keeping its value and protection."""
    from .txn import execute_vault

    def build(vault: Vault):
        e = find_data(vault, path, username)
        _check_names(old, new)
        if old not in e.fields:
            raise WriteError(f"{path!r} has no custom field {old!r}")
        if new in e.fields:
            raise WriteError(f"{new!r} already exists on {path!r}")
        return _plan_from_ops([_Op(entry=e, ref=path, key=old, target=new, protect=e.fields[old].protected)],
                              [FixAction(entry=path, key=old, action="rename", new_key=new)])

    return execute_vault(open_db, db, build, apply)
