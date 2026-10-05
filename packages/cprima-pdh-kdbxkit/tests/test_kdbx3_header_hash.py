"""KDBX 3.x keeps a hash of its own file header inside the encrypted body (`Meta/HeaderHash`) and clients refuse a file
whose header does not match ("Header stimmt nicht mit Hash überein"). pykeepass rotates the header on every save and never
updates that hash, so `save_vault` does: found with the genuine KDBX 3.1 template and KeePassXC's engine.

The same rule through the pdh commands is tested in pdh (`test_kdbx3_header_hash_cli.py`).
"""
import base64
import hashlib
from pathlib import Path

import pytest
from pdh_testkit import vaults
from pdh_testkit.cheap import cheap_copy

from cprima_pdh_kdbxkit.kdbx_vault import KdbxVault, header_end, pykeepass_open, save_vault, stored_header_hash_ok
from cprima_pdh_vault.transaction import Plan, execute
from cprima_pdh_vault.vault import WriteError

T3 = vaults.load("template-kdbx3")


def actual_header_hash(path: Path) -> str:
    data = Path(path).read_bytes()
    return base64.b64encode(hashlib.sha256(data[:header_end(data)]).digest()).decode()


def stored_hash(path: Path, password: str) -> str:
    kp = pykeepass_open(path, password, None)
    root = kp.tree.getroot() if hasattr(kp.tree, "getroot") else kp.tree
    return root.find("Meta/HeaderHash").text


@pytest.fixture
def work(tmp_path):
    return cheap_copy("template-kdbx3", tmp_path / "w.kdbx")  # the genuine template with a cheap key derivation (see pdh_testkit.cheap)


def test_the_untouched_genuine_template_has_a_matching_header_hash():
    assert stored_hash(T3.path, T3.password) == actual_header_hash(T3.path)


def test_plain_pykeepass_leaves_a_stale_hash_which_is_the_bug(work):
    """Documents the library behaviour pdh works around; if pykeepass fixes it, this test says so and can go."""
    kp = pykeepass_open(work, T3.password, None)
    kp.add_group(kp.root_group, "Money")
    kp.save()
    assert stored_hash(work, T3.password) != actual_header_hash(work)
    assert not stored_header_hash_ok(pykeepass_open(work, T3.password, None), work)


def test_save_vault_keeps_the_header_hash_of_a_kdbx3_file_valid(work):
    kp = pykeepass_open(work, T3.password, None)
    kp.add_group(kp.root_group, "Money")
    save_vault(kp)
    assert stored_hash(work, T3.password) == actual_header_hash(work)
    assert [g.name for g in pykeepass_open(work, T3.password, None).groups][-1] == "Money"


def test_a_write_through_the_vault_leaves_a_valid_kdbx3_file(work):
    def build(vault):
        root = next(g.id for g in vault.groups() if g.is_root)
        return Plan(change="the report", mutate=lambda v: v.add_group(root, "Money"))

    _change, written = execute(lambda: KdbxVault.open(work, T3.password), work, build, apply=True)
    assert written and stored_hash(work, T3.password) == actual_header_hash(work)


def test_a_new_master_password_keeps_the_hash_valid(work):
    vault = KdbxVault.open(work, T3.password)
    vault.set_password("second-pw")
    vault.save()
    assert stored_hash(work, "second-pw") == actual_header_hash(work)


def test_the_write_path_would_refuse_a_file_whose_hash_is_stale(work, monkeypatch):
    """The verification step catches it even if the fix is ever bypassed (a reopen alone cannot see it)."""
    import cprima_pdh_kdbxkit.kdbx_vault as backend

    monkeypatch.setattr(backend, "save_vault", lambda kp, path=None: kp.save(path))  # the unfixed save

    def build(vault):
        root = next(g.id for g in vault.groups() if g.is_root)
        return Plan(change="the report", mutate=lambda v: v.add_group(root, "Money"))

    with pytest.raises(WriteError, match="header"):
        execute(lambda: KdbxVault.open(work, T3.password), work, build, apply=True)
