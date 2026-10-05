"""pdh states its choices for the backends once (`cprima_pdh.policy`) and uses them everywhere it opens or writes a vault."""
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault

from cprima_pdh import policy
from cprima_pdh.database import create_vault
from cprima_pdh.models import OrgChange
from cprima_pdh.txn import Plan, execute_vault
from cprima_pdh_kdbxkit.kdbx_vault import DEFAULT_KDBX_POLICY, KdbxVault, pykeepass_open
from cprima_pdh_vault.transaction import DEFAULT_WRITE_POLICY
from cprima_pdh_vault.vault import as_vault


def test_pdh_keeps_the_kdbx_backends_defaults_and_names_its_own_temporary_file():
    assert policy.KDBX_POLICY == DEFAULT_KDBX_POLICY
    assert policy.WRITE_POLICY.temp_suffix == ".pdh-new" != DEFAULT_WRITE_POLICY.temp_suffix
    assert policy.WRITE_POLICY.lock_files is DEFAULT_WRITE_POLICY.lock_files


def test_every_pdh_write_goes_through_pdhs_write_policy(tmp_path):
    db = synthetic_vault(tmp_path / "v.kdbx", [Entry("a", group="G")])
    seen = []

    def build(vault):
        eid = next(e.id for e in vault.entries() if e.title == "a")
        return Plan(change=OrgChange(kind="x", target="a", dest="a"), mutate=lambda v: v.set_field(eid, "Notes", "x"), touched={eid},
                    verify=lambda again: seen.append(sorted(p.name for p in db.parent.iterdir())) or [])

    execute_vault(lambda: KdbxVault.open(db, DEFAULT_PASSWORD), db, build, True)
    assert "v.pdh-new.kdbx" in seen[0]  # the temporary file had pdh's name while it was checked
    assert not list(db.parent.glob("*.pdh-new*"))  # and it is gone again


def test_a_raw_pykeepass_database_is_wrapped_with_pdhs_policy(tmp_path):
    db = synthetic_vault(tmp_path / "v.kdbx", [Entry("a")])
    assert as_vault(pykeepass_open(db, DEFAULT_PASSWORD, None)).policy is policy.KDBX_POLICY


def test_a_vault_pdh_creates_names_itself_as_the_policy_says(tmp_path):
    path = tmp_path / "new.kdbx"
    create_vault(path, "pw", None, True)
    assert KdbxVault.open(path, "pw").info().generator == policy.KDBX_POLICY.generator
