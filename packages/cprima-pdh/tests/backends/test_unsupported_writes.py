"""A backend answers `Unsupported` for any operation its store cannot do, and a write command turns that into a refusal.

The read-only backend here is sops: it reads a file and has no way to write one. (The memory backend writes entries and
groups; what it lacks is covered at the end.)
"""
import pytest
from pdh_testkit.memory import memory_vault
from pdh_testkit.sopsfix import load_sops
from pydantic import BaseModel

from cprima_pdh.backends import age
from cprima_pdh.backends.sops import SopsVault
from cprima_pdh.txn import Plan, execute_vault
from cprima_pdh.vault import WRITE_OPERATIONS, Unsupported
from cprima_pdh.write import WriteError

FIX = load_sops("sops-json-basic")
IDS = age.identities_from_text(FIX.identity_text)


class Change(BaseModel):
    applied: bool = False


@pytest.fixture
def readonly():
    return SopsVault.open(FIX.path, IDS)


def test_every_write_operation_is_refused_by_a_backend_without_it(readonly):
    for operation in sorted(WRITE_OPERATIONS):
        with pytest.raises(Unsupported, match="does not support"):
            getattr(readonly, operation)


def test_check_writable_names_the_backend(readonly):
    assert readonly.check_writable() == ["the sops backend does not support writing"]


def test_a_write_command_on_such_a_backend_is_a_clean_refusal(tmp_path, readonly):
    db = tmp_path / "x.kdbx"
    db.write_bytes(b"")
    with pytest.raises(WriteError, match="sops backend does not support writing"):
        execute_vault(lambda: readonly, db, lambda v: Plan(change=Change(), mutate=lambda _v: None), apply=True)


def test_a_command_that_needs_an_unsupported_capability_is_a_clean_refusal(tmp_path, readonly):
    db = tmp_path / "x.kdbx"
    db.write_bytes(b"")

    def build(v):
        v.snapshot_history("id")
        return Plan(change=Change())

    with pytest.raises(WriteError, match="does not support snapshot history"):
        execute_vault(lambda: readonly, db, build, apply=False)


# --- the memory backend: no file, so nothing that needs one -----------------------------------------------------------------

FILE_OPERATIONS = ("settings", "set_settings", "kdf", "set_kdf", "password", "keyfile", "set_password", "set_keyfile",
                   "can_open", "save", "reopen", "file_problems")


def test_memory_refuses_what_needs_a_file():
    vault = memory_vault([])
    for operation in FILE_OPERATIONS:
        with pytest.raises(Unsupported, match="does not support"):
            getattr(vault, operation)
    assert vault.check_writable() == ["the memory backend does not support writing"]


def test_memory_implements_every_other_write_operation():
    vault = memory_vault([])
    for operation in sorted(WRITE_OPERATIONS - set(FILE_OPERATIONS)):
        assert callable(getattr(vault, operation)), operation
