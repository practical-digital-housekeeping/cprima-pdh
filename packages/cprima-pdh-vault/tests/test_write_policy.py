"""The write path's choices are a `WritePolicy` the caller passes, with defaults, and the adapter registry lets a host go first.

A fake vault stands in for a file format: it writes a few bytes on `save`, so the path of the temporary file and the lock rule
can be seen without any backend.
"""
from pathlib import Path

import pytest

from cprima_pdh_vault import vault as vault_module
from cprima_pdh_vault.transaction import DEFAULT_WRITE_POLICY, Plan, WritePolicy, default_lock_files, execute, guard
from cprima_pdh_vault.vault import VaultBase, VaultInfo, WriteError, as_vault, register_adapter


class Fake(VaultBase):
    name = "fake"
    capabilities = frozenset({"fields", "groups", "protected"})

    def entries(self):
        return []

    def groups(self):
        return []

    def info(self):
        return VaultInfo(backend="fake", format="fake")

    def find_entry(self, path, username=None):
        raise KeyError(path)

    def check_writable(self):
        return []

    def stamp(self, entry_ids, group_ids, mode):
        pass

    def save(self, path=None):
        Path(path).write_bytes(b"new")

    def reopen(self, path=None):
        return Fake()

    def file_problems(self, path=None):
        return []


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "v.kdbx"
    path.write_bytes(b"old")
    return path


def write(db, policy=None):
    """One write through `execute`; returns the names of the files beside the vault seen while the new one was being checked."""
    seen = []

    def build(vault):
        return Plan(change="report", mutate=lambda v: None,
                    verify=lambda again: seen.append(sorted(p.name for p in db.parent.iterdir())) or [])

    kwargs = {} if policy is None else {"policy": policy}
    _change, written = execute(lambda: Fake(), db, build, True, **kwargs)
    assert written and db.read_bytes() == b"new"
    return seen[0]


def test_the_defaults_are_neutral_and_the_temporary_file_is_gone_afterwards(db):
    assert DEFAULT_WRITE_POLICY == WritePolicy() and WritePolicy().temp_suffix == ".writing"
    assert write(db) == ["v.kdbx", "v.writing.kdbx"]
    assert [p.name for p in db.parent.iterdir()] == ["v.kdbx"]


def test_a_host_chooses_the_name_of_the_temporary_file(db):
    assert write(db, WritePolicy(temp_suffix=".mine")) == ["v.kdbx", "v.mine.kdbx"]
    assert [p.name for p in db.parent.iterdir()] == ["v.kdbx"]


# --- the lock rule --------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("lock", ["v.kdbx.lock", ".v.kdbx.lock"])
def test_by_default_a_lock_file_beside_the_vault_stops_a_write(db, lock):
    (db.parent / lock).write_text("")
    assert default_lock_files(db) == [db.parent / lock]
    with pytest.raises(WriteError, match="lock file"):
        write(db)
    assert db.read_bytes() == b"old"


def test_a_dry_run_ignores_the_lock_rule(db):
    (db.parent / "v.kdbx.lock").write_text("")
    change, written = execute(lambda: Fake(), db, lambda v: Plan(change="report", mutate=lambda x: None), False)
    assert (change, written) == ("report", False)


def test_a_host_can_allow_writing_whatever_lock_files_are_there(db):
    (db.parent / "v.kdbx.lock").write_text("")
    write(db, WritePolicy(lock_files=lambda path: []))


def test_a_host_can_name_its_own_lock_files(db):
    (db.parent / "v.kdbx.lock").write_text("")  # the default's file no longer matters
    (db.parent / "v.kdbx.busy").write_text("")
    policy = WritePolicy(lock_files=lambda path: [p for p in [path.with_name(path.name + ".busy")] if p.exists()])
    with pytest.raises(WriteError, match=r"v\.kdbx\.busy"):
        write(db, policy)
    with pytest.raises(WriteError, match=r"v\.kdbx\.lock"):
        guard(db)  # the default policy still sees its own file


# --- a host's adapter goes first ----------------------------------------------------------------------------------------------

class Thing:
    """A store's own object, as a backend would adapt it."""


def test_the_first_adapter_that_answers_wins_and_a_host_can_register_ahead_of_the_default(monkeypatch):
    monkeypatch.setattr(vault_module, "_ADAPTERS", [])
    default, host = Fake(), Fake()
    register_adapter(lambda obj: default if isinstance(obj, Thing) else None)
    assert as_vault(Thing()) is default
    register_adapter(lambda obj: host if isinstance(obj, Thing) else None, first=True)
    assert as_vault(Thing()) is host


def test_an_object_no_adapter_knows_is_refused(monkeypatch):
    monkeypatch.setattr(vault_module, "_ADAPTERS", [])
    with pytest.raises(TypeError, match="no backend adapts it"):
        as_vault(Thing())


def test_registering_the_same_adapter_again_does_not_duplicate_it(monkeypatch):
    monkeypatch.setattr(vault_module, "_ADAPTERS", [])

    def adapt(obj):
        return None

    register_adapter(adapt)
    register_adapter(adapt, first=True)
    assert vault_module._ADAPTERS == [adapt]
