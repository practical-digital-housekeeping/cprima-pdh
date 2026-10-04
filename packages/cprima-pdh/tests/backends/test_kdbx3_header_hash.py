"""KDBX 3.x keeps a hash of its own file header inside the encrypted body (`Meta/HeaderHash`) and clients refuse a file
whose header does not match ("Header stimmt nicht mit Hash überein"). pykeepass rotates the header on every save and never
updates that hash, so pdh does: found with the genuine KDBX 3.1 template and KeePassXC's engine.
"""
import base64
import hashlib
from pathlib import Path

import pytest
from pdh_testkit import vaults
from pdh_testkit.cheap import cheap_copy
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app
from cprima_pdh.source import header_end, pykeepass_open, save_vault, stored_header_hash_ok

T3 = vaults.load("template-kdbx3")


def actual_header_hash(path: Path) -> str:
    data = Path(path).read_bytes()
    return base64.b64encode(hashlib.sha256(data[:header_end(data)]).digest()).decode()


def stored_hash(path: Path, password: str) -> str:
    kp = pykeepass_open(path, password, None)
    root = kp.tree.getroot() if hasattr(kp.tree, "getroot") else kp.tree
    return root.find("Meta/HeaderHash").text


@pytest.fixture
def work(tmp_path, monkeypatch):
    db = cheap_copy("template-kdbx3", tmp_path / "w.kdbx")  # the genuine template with a cheap key derivation (see pdh_testkit.cheap)
    monkeypatch.setattr(_common, "open_db", lambda path, _key: pykeepass_open(path, T3.password, None))
    return db


def invoke(db, *args, env=None):
    result = CliRunner().invoke(app, ["--db", str(db), *args], env=env)
    assert result.exit_code == 0, result.output + (result.stderr or "")


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


def test_every_pdh_write_command_leaves_a_valid_kdbx3_file(work):
    invoke(work, "edit", "new-group", "/", "Money", "--apply")
    assert stored_hash(work, T3.password) == actual_header_hash(work)
    invoke(work, "edit", "new-entry", "Money", "a", "alex", "--tag", "x", "--apply")
    invoke(work, "edit", "delete", "Money/a", "--apply")
    invoke(work, "db", "settings", "--name", "Work", "--apply")
    assert stored_hash(work, T3.password) == actual_header_hash(work)


def test_a_copy_exported_from_a_kdbx3_vault_is_valid_too(work, tmp_path):
    copy = tmp_path / "copy.kdbx"
    invoke(work, "io", "export-kdbx", "--out", str(copy), env={"PDH_NEW_PASSWORD": "copy-pw"})
    assert stored_hash(copy, "copy-pw") == actual_header_hash(copy)


def test_a_new_master_password_keeps_the_hash_valid(work):
    invoke(work, "db", "password", "--apply", env={"PDH_NEW_PASSWORD": "second-pw"})
    assert stored_hash(work, "second-pw") == actual_header_hash(work)


def test_the_write_path_would_refuse_a_file_whose_hash_is_stale(work, monkeypatch):
    """The verification step catches it even if the fix is ever bypassed (pdh's reopen alone cannot see it)."""
    import cprima_pdh.backends.kdbx_vault as backend
    from cprima_pdh.write import WriteError

    monkeypatch.setattr(backend, "save_vault", lambda kp, path=None: kp.save(path))  # the unfixed save
    result = CliRunner().invoke(app, ["--db", str(work), "edit", "new-group", "/", "Money", "--apply"])
    assert result.exit_code == 2 and "header" in (result.stderr or "").lower()
    assert WriteError  # (imported for the message type only)
