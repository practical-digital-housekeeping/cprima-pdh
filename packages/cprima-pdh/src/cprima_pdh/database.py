"""The database itself: create it, change its credentials, its settings and key derivation, empty the recycle bin.

New passwords never come through argv or into a report. Everything but `create_vault` goes through `txn.execute`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .entries import _root
from .models import DbBin, DbKdf, DbSettings, OrgChange
from .source import _in_bin, pykeepass_open
from .txn import Plan, execute
from .write import WriteError

if TYPE_CHECKING:
    from pykeepass import PyKeePass

MIN_ITERATIONS, MIN_MEMORY_KIB, MIN_PARALLELISM = 1, 8 * 1024, 1  # below this a key derivation protects too little


def create_vault(path: Path, password: str, keyfile: Path | None, apply: bool) -> OrgChange:
    """Create a new, empty KDBX 4 vault; the file must not exist yet. KeePass' default key derivation applies."""
    from pykeepass import create_database

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
    create_database(str(path), password=password, keyfile=str(keyfile) if keyfile else None).save()
    again = pykeepass_open(path, password, str(keyfile) if keyfile else None)
    if again.version != (4, 0) or list(again.entries):
        raise WriteError("verification failed: the new vault is not an empty KDBX 4.0 file")
    return change.model_copy(update={"applied": True})


def change_password(open_db: Callable[[], PyKeePass], db: Path, new_password: str, apply: bool) -> OrgChange:
    """Change the master password. The old one must stop working."""
    if not new_password:
        raise WriteError("an empty master password is not accepted")

    def build(kp: PyKeePass) -> Plan:
        old, keyfile = kp.password, kp.keyfile
        if old == new_password:
            return Plan(change=OrgChange(kind="db-password", target=str(db), dest="unchanged"))

        def mutate(k: PyKeePass) -> None:
            k.password = new_password

        def verify(_again: PyKeePass) -> list[str]:
            try:
                pykeepass_open(db, old, keyfile)
            except Exception:  # noqa: BLE001 - any failure to open with the old password is the point
                return []
            return ["the old password still opens the vault"]

        return Plan(change=OrgChange(kind="db-password", target=str(db), dest="changed"), mutate=mutate, verify=verify)

    return execute(open_db, db, build, apply)


def set_keyfile(open_db: Callable[[], PyKeePass], db: Path, keyfile: Path | None, apply: bool) -> OrgChange:
    """Use a key file (in addition to the password) or stop using one."""
    if keyfile is not None and not Path(keyfile).is_file():
        raise WriteError(f"the key file {keyfile} does not exist")

    def build(kp: PyKeePass) -> Plan:
        change = OrgChange(kind="db-keyfile", target=str(db), dest="set" if keyfile else "removed")
        if keyfile is None and not kp.keyfile:
            return Plan(change=change)

        def mutate(k: PyKeePass) -> None:
            k.keyfile = str(keyfile) if keyfile else None

        return Plan(change=change, mutate=mutate)

    return execute(open_db, db, build, apply)


# --- settings ---------------------------------------------------------------------------------------------------------

_SETTINGS = {  # name -> (Meta element, element holding its change time or None)
    "name": ("DatabaseName", "DatabaseNameChanged"),
    "description": ("DatabaseDescription", "DatabaseDescriptionChanged"),
    "history_max_items": ("HistoryMaxItems", None),
    "history_max_size": ("HistoryMaxSize", None),
    "recycle_bin": ("RecycleBinEnabled", "RecycleBinChanged"),
}


def _read_settings(kp: PyKeePass) -> dict[str, object]:
    meta = _root(kp).find("Meta")

    def text(tag: str, default: str = "") -> str:
        el = meta.find(tag)
        return (el.text or default) if el is not None else default

    return {"name": text("DatabaseName"), "description": text("DatabaseDescription"),
            "history_max_items": int(text("HistoryMaxItems", "-1")), "history_max_size": int(text("HistoryMaxSize", "-1")),
            "recycle_bin": text("RecycleBinEnabled", "True").strip().lower() != "false"}


def database_settings(open_db: Callable[[], PyKeePass], db: Path, changes: dict[str, object], apply: bool) -> DbSettings:
    """Show the database settings, or change the ones given (`changes`: name, description, history_max_items, ...)."""
    for key in ("history_max_items", "history_max_size"):
        if changes.get(key) is not None and changes[key] < -1:
            raise WriteError(f"{key.replace('_', '-')} must be -1 (unlimited) or more")
    wanted = {k: v for k, v in changes.items() if v is not None}

    def build(kp: PyKeePass) -> Plan:
        have = _read_settings(kp)
        differ = sorted(k for k, v in wanted.items() if have[k] != v)
        report = DbSettings(**{**have, **wanted}, changed=differ)
        if not differ:
            return Plan(change=report)

        def mutate(k: PyKeePass) -> None:
            meta = _root(k).find("Meta")
            stamp = k._encode_time(datetime.now(timezone.utc)) if hasattr(k, "_encode_time") else None
            for key in differ:
                tag, changed_tag = _SETTINGS[key]
                value = wanted[key]
                meta.find(tag).text = ("True" if value else "False") if key == "recycle_bin" else str(value)
                if changed_tag and stamp is not None and meta.find(changed_tag) is not None:
                    meta.find(changed_tag).text = stamp

        def verify(again: PyKeePass) -> list[str]:
            got = _read_settings(again)
            return [] if all(got[k] == wanted[k] for k in differ) else ["the settings are not as planned"]

        return Plan(change=report, mutate=mutate, verify=verify)

    return execute(open_db, db, build, apply)


# --- key derivation -------------------------------------------------------------------------------------------------------

def _kdf_params(kp: PyKeePass):
    return kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict


def _read_kdf(kp: PyKeePass) -> dict[str, object]:
    algo = kp.kdf_algorithm
    if not algo.startswith("argon2"):
        return {"algorithm": algo, "iterations": None, "memory_kib": None, "parallelism": None}
    p = _kdf_params(kp)
    return {"algorithm": algo, "iterations": int(p["I"].value), "memory_kib": int(p["M"].value) // 1024,
            "parallelism": int(p["P"].value)}


def key_derivation(open_db: Callable[[], PyKeePass], db: Path, iterations: int | None, memory_kib: int | None,
                   parallelism: int | None, apply: bool) -> DbKdf:
    """Show the Argon2 parameters of a KDBX 4 vault, or change them (values below a safe minimum are refused)."""
    checks = (("iterations", iterations, MIN_ITERATIONS), ("memory", memory_kib, MIN_MEMORY_KIB),
              ("parallelism", parallelism, MIN_PARALLELISM))
    for name, value, minimum in checks:
        if value is not None and value < minimum:
            raise WriteError(f"{name} below {minimum} is not accepted: the vault would be too easy to attack")

    def build(kp: PyKeePass) -> Plan:
        have = _read_kdf(kp)
        if have["iterations"] is None:
            if any(v is not None for v in (iterations, memory_kib, parallelism)):
                raise WriteError(f"the key derivation {have['algorithm']!r} has no parameters pdh can change here")
            return Plan(change=DbKdf(**have))
        goal = {**have, **{k: v for k, v in (("iterations", iterations), ("memory_kib", memory_kib),
                                             ("parallelism", parallelism)) if v is not None}}
        report = DbKdf(**goal)
        if goal == have:
            return Plan(change=report)

        def mutate(k: PyKeePass) -> None:
            p = _kdf_params(k)
            p["I"].value, p["M"].value, p["P"].value = goal["iterations"], goal["memory_kib"] * 1024, goal["parallelism"]

        def verify(again: PyKeePass) -> list[str]:
            return [] if _read_kdf(again) == goal else ["the key derivation parameters are not as planned"]

        return Plan(change=report, mutate=mutate, verify=verify)

    return execute(open_db, db, build, apply)


# --- recycle bin ------------------------------------------------------------------------------------------------------------

def empty_bin(open_db: Callable[[], PyKeePass], db: Path, apply: bool) -> DbBin:
    """Delete everything in the recycle bin permanently."""

    def build(kp: PyKeePass) -> Plan:
        rb = kp.recyclebin_group
        if rb is None:
            return Plan(change=DbBin(entries=0, groups=0))
        doomed = [e for e in kp.entries if _in_bin(e.group, rb.uuid)]
        groups = [g for g in kp.groups if g.uuid != rb.uuid and _in_bin(g, rb.uuid)]
        report = DbBin(entries=len(doomed), groups=len(groups))
        if not doomed and not groups:
            return Plan(change=report)
        rb_uid = rb.uuid

        def mutate(k: PyKeePass) -> None:
            k.empty_group(next(g for g in k.groups if g.uuid == rb_uid))

        def verify(again: PyKeePass) -> list[str]:
            rb2 = again.recyclebin_group
            bad = rb2 is None or list(rb2.entries) or list(rb2.subgroups)
            return ["the recycle bin is not empty"] if bad else []

        return Plan(change=report, mutate=mutate, touched={str(e.uuid) for e in doomed}, count_delta=-len(doomed),
                    verify=verify)

    return execute(open_db, db, build, apply)
