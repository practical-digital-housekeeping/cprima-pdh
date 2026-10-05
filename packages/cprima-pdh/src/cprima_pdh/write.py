"""Write operations. Everything here is dry-run unless `apply` is set."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from cprima_pdh_kdbxkit.kdbx_format import STANDARD_ATTR, STANDARD_PROTECTED
from . import boundary
from .models import Change
from .schema import make_ref, uuid_key
from cprima_pdh_vault.vault import Vault, WriteError, as_vault, find_data  # noqa: F401  (re-exported: most of the engine imports them from here)

_HIDDEN = "(hidden)"


def protection_of(e, field: str, protect: bool, unprotect: bool = False) -> bool:
    """`effective_protection` for an entry snapshot: asked for, else asked against, else as it already is."""
    if field in STANDARD_ATTR:
        return field in STANDARD_PROTECTED
    if protect:
        return True
    if unprotect:
        return False
    return e.is_protected(field)


def _value(e, field: str) -> str:
    return e.value(field) if field in STANDARD_ATTR else (e.fields[field].value if field in e.fields else "")


def plan_set(
    source,
    path: str,
    field: str,
    value: str | Callable[[Vault], str],
    overwrite: bool,
    protect: bool,
    username: str | None = None,
    unprotect: bool = False,
    literal: bool = False,
    sset=None,
) -> Change:
    """What setting one field would do. `literal`: the value came from the command line, which is never allowed for a secret
    (the profile's protected fields, the standard ones, what the file protects, anything with --protect); `-` prompts instead."""
    if protect and unprotect:
        raise WriteError("--protect and --unprotect exclude each other")
    vault = as_vault(source)
    if callable(value):  # a value that needs the opened database, such as a link to another entry
        value = value(vault)
    e = find_data(vault, path, username)
    old = _value(e, field)
    hide = protection_of(e, field, protect, unprotect)
    if literal and (hide or protect or boundary.secret_columns([field], sset)):
        raise WriteError(f"{field} is a secret: pdh never takes a secret on the command line. Give `-` as the value "
                         f"for a hidden prompt.")
    shown = (lambda v: _HIDDEN if v and hide else v)
    if old == value:
        action = "unchanged"
    elif old and not overwrite:
        action = "skipped: field not empty (use --overwrite)"
    else:
        action = "set"
    return Change(entry=path, field=field, old=shown(old), new=shown(value), action=action)


def apply_set(
    open_db: Callable[[], object],
    db: Path,
    path: str,
    field: str,
    value: str,
    overwrite: bool,
    protect: bool,
    username: str | None = None,
    unprotect: bool = False,
    literal: bool = False,
    sset=None,
) -> Change:
    """Set one field on one entry: history snapshot, one save, reopened and verified (see `txn.execute_vault`)."""
    from .txn import Plan, execute_vault

    def build(vault: Vault) -> Plan:
        wanted = value(vault) if callable(value) else value
        change = plan_set(vault, path, field, wanted, overwrite, protect, username, unprotect, literal, sset)
        if change.action != "set":
            return Plan(change=change)
        e = find_data(vault, path, username)
        uid = e.id
        keep = protection_of(e, field, protect, unprotect)

        def mutate(v: Vault) -> None:
            v.snapshot_history(uid)
            v.set_field(uid, field, wanted, protect=keep)

        def verify(again: Vault) -> list[str]:
            target = next((x for x in again.entries() if x.id == uid), None)  # by id: Title changes the path
            if target is None or _value(target, field) != wanted:
                return [f"{field} not set as expected"]
            if field not in STANDARD_ATTR and target.is_protected(field) != keep:
                return [f"{field} does not have the expected protection"]
            return []

        return Plan(change=change, mutate=mutate, touched={uid}, verify=verify)

    return execute_vault(open_db, db, build, True)  # the caller decided to write


def _link_value(source, account: str, target: str, plain: bool, account_username: str | None,
                target_username: str | None) -> str:
    """The value to store in the link field: a KeePass reference to the target by UUID (or the bare UUID)."""
    vault = as_vault(source)
    t = find_data(vault, target, target_username)
    a = find_data(vault, account, account_username)
    if t.id == a.id:
        raise WriteError("an entry cannot link to itself")
    return uuid_key(t.id) if plain else make_ref(t.id)


def plan_link(
    kp,
    account: str,
    target: str,
    field: str = "device",
    plain: bool = False,
    overwrite: bool = False,
    account_username: str | None = None,
    target_username: str | None = None,
) -> Change:
    """Dry run: what would be written into `field` of `account` so that it links to `target`."""
    value = _link_value(kp, account, target, plain, account_username, target_username)
    return plan_set(kp, account, field, value, overwrite, False, account_username)


def apply_link(
    open_db: Callable[[], object],
    db: Path,
    account: str,
    target: str,
    field: str = "device",
    plain: bool = False,
    overwrite: bool = False,
    account_username: str | None = None,
    target_username: str | None = None,
) -> Change:
    """Write the link, with the same safeguards as `set` (lock file, change detection, verification)."""
    return apply_set(
        open_db, db, account, field,
        lambda vault: _link_value(vault, account, target, plain, account_username, target_username),
        overwrite, False, account_username,
    )


def set_field(open_db: Callable[[], object], db: Path, path: str, field: str, value: str, overwrite: bool, protect: bool,
              username: str | None = None, unprotect: bool = False, literal: bool = False, sset=None,
              apply: bool = False) -> Change:
    """Set one field on one entry, like every other write: a dry run unless `apply`."""
    if apply:
        return apply_set(open_db, db, path, field, value, overwrite, protect, username, unprotect, literal, sset)
    return plan_set(open_db(), path, field, value, overwrite, protect, username, unprotect, literal, sset)


def link_entries(open_db: Callable[[], object], db: Path, account: str, target: str, field: str = "device",
                 plain: bool = False, overwrite: bool = False, account_username: str | None = None,
                 target_username: str | None = None, apply: bool = False) -> Change:
    """Link one entry to another, like every other write: a dry run unless `apply`."""
    if apply:
        return apply_link(open_db, db, account, target, field, plain, overwrite, account_username, target_username)
    return plan_link(open_db(), account, target, field, plain, overwrite, account_username, target_username)
