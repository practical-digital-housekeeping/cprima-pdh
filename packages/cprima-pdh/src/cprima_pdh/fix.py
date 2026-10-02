"""Field-name and protection fixes: vocabulary-driven `fix`, and the generic `rename-field`.

Only custom field *names* and the protect-in-memory flag change; values never do.
Dry run unless `apply`. One save for all changes, verified by reopening the database.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .models import FixAction, FixPlan
from .backends.kdbx import OTP_PREFIXES, STANDARD_ATTR
from .schema import SchemaSet, _bind, lookup_term, vocabulary_index
from .source import _gpath, _in_bin, pykeepass_open
from .write import WriteError, _fingerprint, _lock_files, find_entry

if TYPE_CHECKING:
    from pykeepass import PyKeePass

_RESERVED = tuple(STANDARD_ATTR)  # the standard fields: not custom fields, so never renamed or treated as one


@dataclass
class _Op:
    entry: object
    ref: str
    key: str
    target: str  # new key name (== key when only the protection changes)
    protect: bool  # protection flag the field must end up with


def _protected(e, key: str) -> bool:
    return bool(e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=key))


def _plan(kp: PyKeePass, sset: SchemaSet, renames: bool, protection: bool) -> tuple[list[_Op], list[FixAction]]:
    exact, matchers = vocabulary_index(sset.fields)
    ops: list[_Op] = []
    actions: list[FixAction] = []
    for e, path, _names, _unknown in _bind(kp, sset):
        ref = f"{path}/{e.title}"
        keys = [k for k in (e.custom_properties or {}) if not k.startswith(OTP_PREFIXES)]
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
            now = _protected(e, key)
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


def _base(e, with_group: bool = True) -> str:
    """Everything about an entry except its custom fields (and, optionally, its group)."""
    return _digest(e.title, e.username, e.password, e.url, e.notes, e.otp, ",".join(sorted(e.tags or [])),
                   str(e.expires), str(e.group.uuid) if with_group else "")  # not expiry_time: saved without sub-second precision


def _custom(e) -> str:
    return _digest(repr(sorted((e.custom_properties or {}).items())))


def _plan_result(actions: list[FixAction], touched: int, applied: bool) -> FixPlan:
    counts: dict[str, int] = {}
    for a in actions:
        label = a.action.split(":")[0]
        counts[label] = counts.get(label, 0) + 1
    return FixPlan(applied=applied, entries_touched=touched, counts=counts, actions=actions)


def _commit(kp: PyKeePass, db: Path, before: tuple[int, int], ops: list[_Op], actions: list[FixAction]) -> FixPlan:
    """Apply ops, save once, reopen and verify. Raises WriteError if anything looks off."""
    if locks := _lock_files(db):
        raise WriteError(f"database seems open elsewhere (lock file {locks[0].name}); close it first")

    touched_uuids = {str(o.entry.uuid) for o in ops}  # by uuid: pykeepass makes new wrapper objects per access
    # what every entry must look like after saving
    untouched = {str(e.uuid): (_base(e), _custom(e)) for e in kp.entries if str(e.uuid) not in touched_uuids}
    expect: dict[str, dict] = {}
    for o in ops:
        value = o.entry.get_custom_property(o.key) or ""  # kept in memory, never reported
        exp = expect.setdefault(str(o.entry.uuid), {"base": _base(o.entry), "fields": {}, "gone": set()})
        exp["fields"][o.target] = (_digest(value), o.protect)
        if o.target != o.key:
            exp["gone"].add(o.key)
    total = len(list(kp.entries))

    for o in ops:
        value = o.entry.get_custom_property(o.key) or ""
        if o.target != o.key:
            o.entry.delete_custom_property(o.key)
        o.entry.set_custom_property(o.target, value, protect=o.protect)

    if _fingerprint(db) != before:
        raise WriteError("database file changed while working; nothing written")
    kp.save()

    again = pykeepass_open(db, kp.password, kp.keyfile)
    problems: list[str] = []
    entries = {str(e.uuid): e for e in again.entries}
    if len(entries) != total:
        problems.append(f"entry count changed ({total} -> {len(entries)})")
    for uid, (base, custom) in untouched.items():
        e = entries.get(uid)
        if e is None or (_base(e), _custom(e)) != (base, custom):
            problems.append("an entry that should be unchanged differs")
            break
    for uid, exp in expect.items():
        e = entries.get(uid)
        if e is None or _base(e) != exp["base"]:
            problems.append("a touched entry changed outside its custom fields")
            continue
        props = e.custom_properties or {}
        for key, (vdigest, prot) in exp["fields"].items():
            if key not in props or _digest(props[key]) != vdigest or _protected(e, key) != prot:
                problems.append("a field does not have the expected name, value or protection")
                break
        if exp["gone"] & set(props):
            problems.append("a renamed field still exists under its old name")
    if problems:
        raise WriteError("verification failed: " + "; ".join(sorted(set(problems))) + ". Restore from your own backup.")
    return _plan_result(actions, len(touched_uuids), True)


def run_fix(
    open_db: Callable[[], PyKeePass],
    db: Path,
    sset: SchemaSet,
    apply: bool,
    renames: bool = True,
    protection: bool = True,
) -> FixPlan:
    before = _fingerprint(db)
    kp = open_db()
    ops, actions = _plan(kp, sset, renames, protection)
    if not apply or not ops:
        return _plan_result(actions, len({str(o.entry.uuid) for o in ops}), False)
    return _commit(kp, db, before, ops, actions)


def _check_names(old: str, new: str) -> None:
    if not old or not new or old == new:
        raise WriteError("old and new must be different, non-empty field names")
    for name in (old, new):
        if name in _RESERVED or name.startswith(OTP_PREFIXES):
            raise WriteError(f"{name!r} is a standard or OTP field; only custom fields can be renamed")


def _plan_rename_all(kp: PyKeePass, old: str, new: str, under: str | None) -> tuple[list[_Op], list[FixAction]]:
    _check_names(old, new)
    prefix = (under or "").strip("/")
    rb = kp.recyclebin_group
    bin_uuid = rb.uuid if rb is not None else None
    ops: list[_Op] = []
    actions: list[FixAction] = []
    for e in kp.entries:
        props = e.custom_properties or {}
        path = _gpath(e.group)
        if old not in props or _in_bin(e.group, bin_uuid):
            continue
        if prefix and path != prefix and not path.startswith(prefix + "/"):
            continue
        ref = f"{path}/{e.title}"
        if new in props:
            actions.append(FixAction(entry=ref, key=old, action=f"skipped: {new} already exists", new_key=new))
            continue
        ops.append(_Op(entry=e, ref=ref, key=old, target=new, protect=_protected(e, old)))
        actions.append(FixAction(entry=ref, key=old, action="rename", new_key=new))
    return ops, actions


def plan_rename_all(kp: PyKeePass, old: str, new: str, under: str | None = None) -> FixPlan:
    """What `rename_field_all` would do, without writing: every live entry that has `old` (below `under`, if given)."""
    ops, actions = _plan_rename_all(kp, old, new, under)
    return _plan_result(actions, len(ops), False)


def rename_field_all(
    open_db: Callable[[], PyKeePass],
    db: Path,
    old: str,
    new: str,
    apply: bool,
    under: str | None = None,
) -> FixPlan:
    """Rename one custom field on every live entry that has it, keeping value and protection. One save, verified."""
    before = _fingerprint(db)
    kp = open_db()
    ops, actions = _plan_rename_all(kp, old, new, under)
    if not apply or not ops:
        return _plan_result(actions, len(ops), False)
    return _commit(kp, db, before, ops, actions)


def rename_field(
    open_db: Callable[[], PyKeePass],
    db: Path,
    path: str,
    old: str,
    new: str,
    apply: bool,
    username: str | None = None,
) -> FixPlan:
    """Rename one custom field on one entry, keeping its value and protection."""
    before = _fingerprint(db)
    kp = open_db()
    e = find_entry(kp, path, username)
    props = e.custom_properties or {}
    _check_names(old, new)
    if old not in props:
        raise WriteError(f"{path!r} has no custom field {old!r}")
    if new in props:
        raise WriteError(f"{new!r} already exists on {path!r}")
    ops = [_Op(entry=e, ref=path, key=old, target=new, protect=_protected(e, old))]
    actions = [FixAction(entry=path, key=old, action="rename", new_key=new)]
    if not apply:
        return _plan_result(actions, 1, False)
    return _commit(kp, db, before, ops, actions)
