"""The one write path: plan, apply, save once to a temporary file, reopen, verify, replace.

A command describes what it wants as a `Plan`: the change it reports (always, also as a dry run), the mutation (a function
of the opened Vault), which entries it may touch, and what must be true after reopening the saved file. `execute`
does the rest: refuses when the file is open elsewhere or changed meanwhile, refuses formats nobody has verified writing,
makes sure every other entry is unchanged and the entry count is what the plan says, and raises `WriteError` otherwise.
The new file is written beside the vault and replaces it only after it has been checked, so a failed check never damages
the vault. Nothing is written without `apply`, and pdh never makes a backup copy: that is the owner's job.

Nothing here knows what a "change" is: the report a command wants to hand back travels through as an opaque object.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable

from .vault import Unsupported, Vault, WriteError, as_vault


@dataclass
class Plan:
    """What a command wants to do. `change` is the report handed back; the caller marks it applied after a verified write."""

    change: object
    mutate: Callable[[Vault], None] | None = None  # None: nothing to do (a no-op, or the plan is only a report)
    touched: set[str] = field(default_factory=set)  # ids of entries the mutation may change
    count_delta: int = 0  # expected change of the number of entries (all groups, bin included)
    verify: Callable[[Vault], list[str]] | None = None  # problems found in the reopened file
    touched_groups: set[str] = field(default_factory=set)  # ids of groups the mutation changes or moves
    # What to stamp on the touched entries and groups after the mutation. A store's setters may leave the times alone,
    # a client stamps them, and clients, merges and the breach check rely on them:
    #   "modified": modification and access time (a content change, the default)
    #   "location": when it was moved (or deleted into the bin; its content is as it was)
    #   "none":     leave the times as the mutation set them (a merge keeps the other copy's times; a history prune
    #               is not an edit of the entry)
    stamp: str = "modified"


def _fingerprint(db: Path) -> tuple[int, int]:
    st = os.stat(db)
    return st.st_mtime_ns, st.st_size


def _lock_files(db: Path) -> list[Path]:
    return [p for p in (db.with_name(db.name + ".lock"), db.with_name("." + db.name + ".lock")) if p.exists()]


def guard(db: Path) -> None:
    if locks := _lock_files(db):
        raise WriteError(f"database seems open elsewhere (lock file {locks[0].name}); close it first")


def _content(e) -> object:
    """An entry as it must stay when untouched: everything but where it sits (a moved group changes paths)."""
    return replace(e, group_path="", group_id="", in_bin=False)


def execute(open_vault, db: Path, build, apply: bool) -> tuple[object, bool]:
    """Run `build(vault)` (it returns a `Plan`) on the opened vault; without `apply` hand back its change untouched, else
    write and verify. Returns the plan's change and whether the file was written."""
    before_fp = _fingerprint(db)
    vault = as_vault(open_vault())
    try:
        plan = build(vault)
    except Unsupported as exc:
        raise WriteError(str(exc)) from None
    if not apply or plan.mutate is None:
        return plan.change, False

    guard(db)
    if problems := vault.check_writable():
        raise WriteError("; ".join(problems))
    before = {e.id: _content(e) for e in vault.entries() if e.id not in plan.touched}
    total = len(vault.entries())
    plan.mutate(vault)
    vault.stamp(plan.touched, set(plan.touched_groups), plan.stamp)
    if _fingerprint(db) != before_fp:
        raise WriteError("database file changed while working; nothing written")
    temp = db.with_name(db.stem + ".pdh-new" + db.suffix)
    try:
        vault.save(temp)
        again = vault.reopen(temp)
        found = {e.id: e for e in again.entries()}
        problems = []
        if len(found) != total + plan.count_delta:
            problems.append(f"entry count changed ({total} -> {len(found)}, expected {total + plan.count_delta})")
        for uid, content in before.items():
            e = found.get(uid)
            if e is None or _content(e) != content:
                problems.append("an entry that should be unchanged differs")
                break
        problems += again.file_problems(temp)
        if plan.verify is not None:
            problems += plan.verify(again)
        if problems:
            raise WriteError("verification failed: " + "; ".join(sorted(set(problems)))
                             + ". The vault was not changed.")
        os.replace(temp, db)
    finally:
        temp.unlink(missing_ok=True)
    return plan.change, True
