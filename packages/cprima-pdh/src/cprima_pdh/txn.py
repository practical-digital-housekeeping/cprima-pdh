"""The one write path: plan, apply, save once, reopen and verify.

A command describes what it wants as a `Plan`: the change it reports (always, also as a dry run), the in-memory
mutation, which entries it may touch, and what must be true after reopening the saved file. `execute` does the rest:
refuses when the file is open elsewhere or changed meanwhile, makes sure every other entry is byte-for-byte unchanged
and the entry count is what the plan says, and raises `WriteError` otherwise. Nothing is written without `apply`, and
pdh never makes a backup copy: that is the owner's job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, TypeVar

from pydantic import BaseModel

from .fix import _base, _custom
from .source import pykeepass_open
from .write import WriteError, _fingerprint, _lock_files

if TYPE_CHECKING:
    from pykeepass import PyKeePass

C = TypeVar("C", bound=BaseModel)


@dataclass
class Plan:
    """What a command wants to do. `change` needs an `applied` field; it is set to True after a verified write."""

    change: BaseModel
    mutate: Callable[[PyKeePass], None] | None = None  # None: nothing to do (a no-op, or the plan is only a report)
    touched: set[str] = field(default_factory=set)  # UUIDs of entries the mutation may change
    count_delta: int = 0  # expected change of the number of entries (all groups, bin included)
    verify: Callable[[PyKeePass], list[str]] | None = None  # problems found in the reopened file
    touched_groups: set = field(default_factory=set)  # UUIDs of groups the mutation changes or moves
    # What to stamp on the touched entries and groups after the mutation. pykeepass' setters leave the times alone,
    # a client stamps them, and clients, merges and the breach check rely on them:
    #   "modified": LastModificationTime and LastAccessTime (a content change, the default)
    #   "location": LocationChanged (the thing was moved or deleted into the bin; its content is as it was)
    #   "none":     leave the times as the mutation set them (a merge keeps the other copy's times; a history prune
    #               is not an edit of the entry)
    stamp: str = "modified"


def guard(db: Path) -> None:
    if locks := _lock_files(db):
        raise WriteError(f"database seems open elsewhere (lock file {locks[0].name}); close it first")


def snapshot(entry) -> None:
    """Save the entry's current state into its History, as the KeePass GUI does before an edit."""
    entry.save_history()


def _stamp(kp: PyKeePass, plan: Plan) -> None:
    if plan.stamp == "none":
        return
    for thing in [*(e for e in kp.entries if str(e.uuid) in plan.touched),
                  *(g for g in kp.groups if g.uuid in plan.touched_groups)]:
        if plan.stamp == "modified":
            thing.touch(modify=True)
        else:
            element = thing._element.find("Times/LocationChanged")
            if element is not None:
                element.text = kp._encode_time(datetime.now(timezone.utc))


def _digests(kp: PyKeePass, skip: set[str]) -> dict[str, tuple[str, str]]:
    return {str(e.uuid): (_base(e), _custom(e)) for e in kp.entries if str(e.uuid) not in skip}


def execute(open_db: Callable[[], PyKeePass], db: Path, build: Callable[[PyKeePass], Plan], apply: bool) -> BaseModel:
    """Run `build` on the opened vault; without `apply` return its change untouched, else write and verify."""
    before_fp = _fingerprint(db)
    kp = open_db()
    plan = build(kp)
    if not apply or plan.mutate is None:
        return plan.change

    guard(db)
    untouched = _digests(kp, plan.touched)
    total = len(list(kp.entries))
    plan.mutate(kp)
    _stamp(kp, plan)
    if _fingerprint(db) != before_fp:
        raise WriteError("database file changed while working; nothing written")
    kp.save()

    again = pykeepass_open(db, kp.password, kp.keyfile)
    problems: list[str] = []
    entries = {str(e.uuid): e for e in again.entries}
    if len(entries) != total + plan.count_delta:
        problems.append(f"entry count changed ({total} -> {len(entries)}, expected {total + plan.count_delta})")
    for uid, digest in untouched.items():
        e = entries.get(uid)
        if e is None or (_base(e), _custom(e)) != digest:
            problems.append("an entry that should be unchanged differs")
            break
    if plan.verify is not None:
        problems += plan.verify(again)
    if problems:
        raise WriteError("verification failed: " + "; ".join(sorted(set(problems))) + ". Restore from your own backup.")
    return plan.change.model_copy(update={"applied": True})
