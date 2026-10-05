"""The KDBX layer's choices are a `KdbxPolicy` the caller passes, with defaults; another program that uses the layer has full
reign over them. Each one is tested with a value that is not the default."""
import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault, vaults
from pdh_testkit.cheap import cheap_copy

from cprima_pdh_kdbxkit.kdbx_vault import DEFAULT_KDBX_POLICY, GENERATOR, VERIFIED_FORMATS, KdbxPolicy, KdbxVault, pykeepass_open
from cprima_pdh_vault import vault as vault_module
from cprima_pdh_vault.transaction import Plan, execute
from cprima_pdh_vault.vault import as_vault, register_adapter


@pytest.fixture
def db(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [Entry("a", group="G")])  # (a vault pykeepass made from a KeePassXC template)


def generator(path):
    return KdbxVault.open(path, DEFAULT_PASSWORD).info().generator


def touch(vault_or_db, policy=None):
    """One verified write through `execute`; the entry's notes change."""
    def opened():
        return KdbxVault.open(vault_or_db, DEFAULT_PASSWORD, policy=policy) if policy else KdbxVault.open(vault_or_db, DEFAULT_PASSWORD)

    def build(vault):
        eid = next(e.id for e in vault.entries() if e.title == "a")
        return Plan(change="report", mutate=lambda v: v.set_field(eid, "Notes", "changed"), touched={eid})

    return execute(opened, vault_or_db, build, True)


# --- the defaults ---------------------------------------------------------------------------------------------------------------

def test_the_defaults_name_the_layer_and_write_the_verified_formats():
    assert DEFAULT_KDBX_POLICY == KdbxPolicy() and KdbxPolicy().generator == GENERATOR
    assert KdbxPolicy().writable_formats == VERIFIED_FORMATS == {(3, 1), (4, 0), (4, 1)}


def test_a_vault_opened_without_a_policy_has_the_defaults(db):
    assert KdbxVault.open(db, DEFAULT_PASSWORD).policy is DEFAULT_KDBX_POLICY


# --- the generator --------------------------------------------------------------------------------------------------------------

def test_a_made_up_generator_is_written_on_every_save(db):
    assert generator(db) != "my-app"
    touch(db, KdbxPolicy(generator="my-app"))
    assert generator(db) == "my-app"


def test_a_made_up_generator_is_written_when_a_vault_is_created(tmp_path):
    made = KdbxVault.create(tmp_path / "new.kdbx", "pw", policy=KdbxPolicy(generator="my-app"))
    assert made.info().generator == "my-app" and KdbxVault.open(tmp_path / "new.kdbx", "pw").info().generator == "my-app"


def test_no_generator_leaves_what_the_file_says(db):
    before = generator(db)
    touch(db, KdbxPolicy(generator=None))
    assert generator(db) == before != GENERATOR  # a client that does not stamp, like KeePassXC with a file it did not make


# --- the formats it writes ------------------------------------------------------------------------------------------------------

def test_a_format_outside_the_policys_list_is_read_but_not_written(tmp_path):
    t = vaults.load("template-kdbx3")
    path = cheap_copy("template-kdbx3", tmp_path / "w.kdbx")
    refusing = KdbxVault.open(path, t.password, policy=KdbxPolicy(writable_formats=frozenset({(4, 0)})))
    assert refusing.check_writable() == ["writing KDBX 3.1 has not been verified; it can be read but is not changed"]
    assert refusing.entries() == [] and refusing.info().format == "KDBX 3.1"  # reading is fine
    assert KdbxVault.open(path, t.password, policy=KdbxPolicy(writable_formats=frozenset({(3, 1)}))).check_writable() == []
    assert KdbxVault.open(path, t.password).check_writable() == []  # the default list has it


def test_no_list_writes_any_format(tmp_path):
    t = vaults.load("template-kdbx3")
    path = cheap_copy("template-kdbx3", tmp_path / "w.kdbx")
    assert KdbxVault.open(path, t.password, policy=KdbxPolicy(writable_formats=frozenset())).check_writable() != []
    assert KdbxVault.open(path, t.password, policy=KdbxPolicy(writable_formats=None)).check_writable() == []


def test_an_empty_list_makes_a_vault_read_only_through_the_write_path(db):
    from cprima_pdh_vault.vault import WriteError

    with pytest.raises(WriteError, match="has not been verified"):
        touch(db, KdbxPolicy(writable_formats=frozenset()))


# --- the policy travels with the vault ------------------------------------------------------------------------------------------

def test_a_reopened_vault_has_the_same_policy(db):
    policy = KdbxPolicy(generator="my-app")
    vault = KdbxVault.open(db, DEFAULT_PASSWORD, policy=policy)
    assert vault.reopen().policy is policy


def test_the_verified_reopened_vault_of_a_write_has_the_same_policy(db):
    policy = KdbxPolicy(generator="my-app")
    seen = []

    def build(vault):
        eid = next(e.id for e in vault.entries() if e.title == "a")
        return Plan(change="report", mutate=lambda v: v.set_field(eid, "Notes", "x"), touched={eid},
                    verify=lambda again: seen.append(again.policy) or [])

    execute(lambda: KdbxVault.open(db, DEFAULT_PASSWORD, policy=policy), db, build, True)
    assert seen == [policy] and generator(db) == "my-app"


# --- a host's adapter -----------------------------------------------------------------------------------------------------------

def test_an_adapter_made_for_a_policy_wraps_a_raw_database_with_it(db):
    policy = KdbxPolicy(generator="my-app")
    assert KdbxVault.adapter(policy)(pykeepass_open(db, DEFAULT_PASSWORD, None)).policy is policy


def test_a_host_registered_first_decides_the_policy_of_raw_databases(db, monkeypatch):
    monkeypatch.setattr(vault_module, "_ADAPTERS", list(vault_module._ADAPTERS))
    raw = pykeepass_open(db, DEFAULT_PASSWORD, None)
    assert as_vault(raw).policy == DEFAULT_KDBX_POLICY  # the backend's own adapter (or a host's that kept the defaults)
    policy = KdbxPolicy(generator="my-app")
    register_adapter(KdbxVault.adapter(policy), first=True)
    assert as_vault(raw).policy is policy
