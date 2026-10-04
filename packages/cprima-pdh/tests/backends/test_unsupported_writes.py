"""A backend answers `Unsupported` for any operation its store cannot do, and a write command turns that into a refusal."""
import pytest
from pdh_testkit.memory import memory_vault
from pydantic import BaseModel

from cprima_pdh.txn import Plan, execute_vault
from cprima_pdh.vault import WRITE_OPERATIONS, Unsupported
from cprima_pdh.write import WriteError


class Change(BaseModel):
    applied: bool = False


def test_every_write_operation_is_refused_by_a_backend_without_it():
    vault = memory_vault([])
    for operation in sorted(WRITE_OPERATIONS):
        with pytest.raises(Unsupported, match="does not support"):
            getattr(vault, operation)


def test_check_writable_names_the_backend():
    assert memory_vault([]).check_writable() == ["the memory backend does not support writing"]


def test_a_write_command_on_such_a_backend_is_a_clean_refusal(tmp_path):
    db = tmp_path / "x.kdbx"
    db.write_bytes(b"")
    vault = memory_vault([])
    with pytest.raises(WriteError, match="memory backend does not support writing"):
        execute_vault(lambda: vault, db, lambda v: Plan(change=Change(), mutate=lambda _v: None), apply=True)


def test_a_command_that_needs_an_unsupported_capability_is_a_clean_refusal(tmp_path):
    db = tmp_path / "x.kdbx"
    db.write_bytes(b"")
    vault = memory_vault([])

    def build(v):
        v.snapshot_history("id")
        return Plan(change=Change())

    with pytest.raises(WriteError, match="does not support snapshot history"):
        execute_vault(lambda: vault, db, build, apply=False)
