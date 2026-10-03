"""The database itself: create it, change its credentials, its settings and key derivation, empty the recycle bin.

New passwords never come through argv or into a report. Everything but `create_vault` goes through `txn.execute_vault`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from .models import DbBin, DbKdf, DbSettings, OrgChange
from .txn import Plan, execute_vault
from .vault import Vault, require
from .write import WriteError

MIN_ITERATIONS, MIN_MEMORY_KIB, MIN_PARALLELISM = 1, 8 * 1024, 1  # below this a key derivation protects too little


def create_vault(path: Path, password: str, keyfile: Path | None, apply: bool) -> OrgChange:
    """Create a new, empty KDBX 4 vault; the file must not exist yet. KeePass' default key derivation applies."""
    from .backends.kdbx_vault import KdbxVault

    if path.exists():
        raise WriteError(f"{path} exists; pdh never overwrites a vault")
    if not path.parent.is_dir():
        raise WriteError(f"the folder {path.parent} does not exist")
    if keyfile is not None and not Path(keyfile).is_file():
        raise WriteError(f"the key file {keyfile} does not exist")
    if not password:
        raise WriteError("an empty master password is not accepted")
    change = OrgChange(kind="db-create", target=str(path), dest="KDBX 4.0")
    if not apply:
        return change
    KdbxVault.create(path, password, str(keyfile) if keyfile else None)
    again = KdbxVault.open(path, password, str(keyfile) if keyfile else None)
    if again.info().format != "KDBX 4.0" or again.entries():
        raise WriteError("verification failed: the new vault is not an empty KDBX 4.0 file")
    return change.model_copy(update={"applied": True})


def change_password(open_db: Callable[[], object], db: Path, new_password: str, apply: bool) -> OrgChange:
    """Change the master password. The old one must stop working."""
    if not new_password:
        raise WriteError("an empty master password is not accepted")

    def build(vault: Vault) -> Plan:
        require(vault, "credentials")
        old, keyfile = vault.password, vault.keyfile
        if old == new_password:
            return Plan(change=OrgChange(kind="db-password", target=str(db), dest="unchanged"))

        def verify(again: Vault) -> list[str]:
            return ["the old password still opens the vault"] if again.can_open(old, keyfile, again.path) else []

        return Plan(change=OrgChange(kind="db-password", target=str(db), dest="changed"),
                    mutate=lambda v: v.set_password(new_password), verify=verify)

    return execute_vault(open_db, db, build, apply)


def set_keyfile(open_db: Callable[[], object], db: Path, keyfile: Path | None, apply: bool) -> OrgChange:
    """Use a key file (in addition to the password) or stop using one."""
    if keyfile is not None and not Path(keyfile).is_file():
        raise WriteError(f"the key file {keyfile} does not exist")

    def build(vault: Vault) -> Plan:
        require(vault, "credentials")
        change = OrgChange(kind="db-keyfile", target=str(db), dest="set" if keyfile else "removed")
        if keyfile is None and not vault.keyfile:
            return Plan(change=change)
        return Plan(change=change, mutate=lambda v: v.set_keyfile(str(keyfile) if keyfile else None))

    return execute_vault(open_db, db, build, apply)


# --- settings ---------------------------------------------------------------------------------------------------------

def database_settings(open_db: Callable[[], object], db: Path, changes: dict[str, object], apply: bool) -> DbSettings:
    """Show the database settings, or change the ones given (`changes`: name, description, history_max_items, ...)."""
    for key in ("history_max_items", "history_max_size"):
        if changes.get(key) is not None and changes[key] < -1:
            raise WriteError(f"{key.replace('_', '-')} must be -1 (unlimited) or more")
    wanted = {k: v for k, v in changes.items() if v is not None}

    def build(vault: Vault) -> Plan:
        require(vault, "settings")
        have = vault.settings()
        differ = sorted(k for k, v in wanted.items() if have[k] != v)
        report = DbSettings(**{**have, **wanted}, changed=differ)
        if not differ:
            return Plan(change=report)

        def verify(again: Vault) -> list[str]:
            got = again.settings()
            return [] if all(got[k] == wanted[k] for k in differ) else ["the settings are not as planned"]

        return Plan(change=report, mutate=lambda v: v.set_settings({k: wanted[k] for k in differ}), verify=verify)

    return execute_vault(open_db, db, build, apply)


# --- key derivation -------------------------------------------------------------------------------------------------------

def key_derivation(open_db: Callable[[], object], db: Path, iterations: int | None, memory_kib: int | None,
                   parallelism: int | None, apply: bool) -> DbKdf:
    """Show the Argon2 parameters of a KDBX 4 vault, or change them (values below a safe minimum are refused)."""
    checks = (("iterations", iterations, MIN_ITERATIONS), ("memory", memory_kib, MIN_MEMORY_KIB),
              ("parallelism", parallelism, MIN_PARALLELISM))
    for name, value, minimum in checks:
        if value is not None and value < minimum:
            raise WriteError(f"{name} below {minimum} is not accepted: the vault would be too easy to attack")

    def build(vault: Vault) -> Plan:
        require(vault, "kdf")
        have = vault.kdf()
        if have["iterations"] is None:
            if any(v is not None for v in (iterations, memory_kib, parallelism)):
                raise WriteError(f"the key derivation {have['algorithm']!r} has no parameters pdh can change here")
            return Plan(change=DbKdf(**have))
        goal = {**have, **{k: v for k, v in (("iterations", iterations), ("memory_kib", memory_kib),
                                             ("parallelism", parallelism)) if v is not None}}
        report = DbKdf(**goal)
        if goal == have:
            return Plan(change=report)

        def verify(again: Vault) -> list[str]:
            return [] if again.kdf() == goal else ["the key derivation parameters are not as planned"]

        return Plan(change=report, verify=verify,
                    mutate=lambda v: v.set_kdf(goal["iterations"], goal["memory_kib"], goal["parallelism"]))

    return execute_vault(open_db, db, build, apply)


# --- recycle bin ------------------------------------------------------------------------------------------------------------

def empty_bin(open_db: Callable[[], object], db: Path, apply: bool) -> DbBin:
    """Delete everything in the recycle bin permanently."""

    def build(vault: Vault) -> Plan:
        require(vault, "recycle_bin")
        doomed = [e for e in vault.entries() if e.in_bin]
        groups = [g for g in vault.groups() if g.in_bin]
        report = DbBin(entries=len(doomed), groups=len(groups))
        if not doomed and not groups:
            return Plan(change=report)

        def verify(again: Vault) -> list[str]:
            leftover = [e for e in again.entries() if e.in_bin] or [g for g in again.groups() if g.in_bin]
            return ["the recycle bin is not empty"] if leftover else []

        return Plan(change=report, mutate=lambda v: v.empty_bin(), touched={e.id for e in doomed},
                    count_delta=-len(doomed), verify=verify)

    return execute_vault(open_db, db, build, apply)
