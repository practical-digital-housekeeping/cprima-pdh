"""The write path as the commands use it: `transaction.execute` plus pdh's report models.

The generic part (plan, write once to a temporary file, reopen, verify, replace) is `transaction.py` and knows nothing of pdh.
Here the report a command returns is a pydantic model with an `applied` field, which is set after a verified write.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from .transaction import Plan, guard  # noqa: F401  (re-exported: commands import them from here)
from .transaction import execute


def execute_vault(open_vault, db: Path, build, apply: bool) -> BaseModel:
    """Run `build(vault)` (it returns a `Plan` whose change is a model with an `applied` field) on the opened vault; without
    `apply` return its change untouched, else write, verify, and return it marked applied."""
    change, written = execute(open_vault, db, build, apply)
    return change.model_copy(update={"applied": True}) if written else change
