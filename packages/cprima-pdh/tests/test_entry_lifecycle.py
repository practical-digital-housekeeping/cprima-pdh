"""`edit delete` / `restore` / `purge`: an entry goes to the recycle bin, comes back, or is deleted for good (only from the bin)."""
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app
from cprima_pdh.entries import delete_entry, purge_entry, restore_entry
from cprima_pdh.source import pykeepass_open
from cprima_pdh.write import WriteError


def opener(db):
    return lambda: pykeepass_open(db, DEFAULT_PASSWORD, None)


def load(db):
    return pykeepass_open(db, DEFAULT_PASSWORD, None)


def where(db, title):
    kp = load(db)
    e = next(e for e in kp.entries if e.title == title)
    in_bin = kp.recyclebin_group is not None and e.group.uuid == kp.recyclebin_group.uuid
    return e.group.name, in_bin


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [
        Entry("a", group="Money", username="u", password="pw-a", custom={"k": "v"}, protected=frozenset({"k"})),
        Entry("b", group="Money", username="u", password="pw-b"),
        Entry("c", group="Other"),
    ])


# --- delete: to the recycle bin, nothing else changes ---------------------------------------------------------

def test_a_dry_run_changes_nothing(vault):
    before = vault.read_bytes()
    change = delete_entry(opener(vault), vault, "Money/a", apply=False)
    assert (change.kind, change.target, change.applied) == ("delete", "Money/a", False)
    assert vault.read_bytes() == before


def test_apply_moves_the_entry_to_the_recycle_bin_with_everything_it_has(vault):
    uid = str(next(e for e in load(vault).entries if e.title == "a").uuid)
    change = delete_entry(opener(vault), vault, "Money/a", apply=True)
    assert change.applied and change.dest == "Recycle Bin"
    kp = load(vault)
    a = next(e for e in kp.entries if e.title == "a")
    assert str(a.uuid) == uid and a.group.uuid == kp.recyclebin_group.uuid  # same entry, now in the bin
    assert (a.username, a.password, a.get_custom_property("k")) == ("u", "pw-a", "v")
    assert where(vault, "b") == ("Money", False) and where(vault, "c") == ("Other", False)


def test_an_entry_already_in_the_bin_is_refused_and_purge_is_suggested(vault):
    delete_entry(opener(vault), vault, "Money/a", apply=True)
    with pytest.raises(WriteError, match="purge"):
        delete_entry(opener(vault), vault, "Recycle Bin/a", apply=True)


def test_a_vault_with_the_bin_switched_off_is_refused(vault):
    kp = load(vault)
    kp.tree.getroot().find("Meta/RecycleBinEnabled").text = "False"
    kp.save()
    with pytest.raises(WriteError, match="recycle bin is switched off"):
        delete_entry(opener(vault), vault, "Money/a", apply=True)


def test_an_unknown_entry_is_refused(vault):
    with pytest.raises(WriteError, match="no entry"):
        delete_entry(opener(vault), vault, "Money/zzz", apply=False)


# --- restore --------------------------------------------------------------------------------------------------

def test_restore_needs_a_destination_when_the_vault_does_not_remember_one(vault):
    delete_entry(opener(vault), vault, "Money/a", apply=True)
    with pytest.raises(WriteError, match="--to"):
        restore_entry(opener(vault), vault, "Recycle Bin/a", apply=True)


def test_restore_to_a_group_brings_the_entry_back(vault):
    delete_entry(opener(vault), vault, "Money/a", apply=True)
    change = restore_entry(opener(vault), vault, "Recycle Bin/a", apply=True, to="Money")
    assert (change.kind, change.dest, change.applied) == ("restore", "Money", True)
    assert where(vault, "a") == ("Money", False)


def test_restore_uses_the_previous_parent_group_a_client_recorded(vault):
    kp = load(vault)
    a = next(e for e in kp.entries if e.title == "a")
    money = a.group
    kp.trash_entry(a)
    import base64

    from lxml import etree
    etree.SubElement(a._element, "PreviousParentGroup").text = base64.b64encode(money.uuid.bytes).decode()  # as KeePassXC
    kp.save()
    restore_entry(opener(vault), vault, "Recycle Bin/a", apply=True)
    assert where(vault, "a") == ("Money", False)


def test_only_an_entry_in_the_bin_can_be_restored(vault):
    with pytest.raises(WriteError, match="not in the recycle bin"):
        restore_entry(opener(vault), vault, "Money/a", apply=False, to="Other")


# --- purge: permanent, only from the bin ----------------------------------------------------------------------

def test_purge_refuses_an_entry_outside_the_bin(vault):
    with pytest.raises(WriteError, match="recycle bin"):
        purge_entry(opener(vault), vault, "Money/a", apply=True)
    assert where(vault, "a") == ("Money", False)


def test_purge_deletes_an_entry_from_the_bin_for_good(vault):
    delete_entry(opener(vault), vault, "Money/a", apply=True)
    before = vault.read_bytes()
    assert purge_entry(opener(vault), vault, "Recycle Bin/a", apply=False).applied is False
    assert vault.read_bytes() == before
    change = purge_entry(opener(vault), vault, "Recycle Bin/a", apply=True)
    assert (change.kind, change.applied) == ("purge", True)
    assert [e.title for e in load(vault).entries] == ["b", "c"]


# --- the command line -----------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def opens_with_the_test_password(monkeypatch):
    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, None))


def invoke(vault, *args):
    return CliRunner().invoke(app, ["--db", str(vault), *args])


def test_the_cli_round_trip(vault):
    assert invoke(vault, "edit", "delete", "Money/a").exit_code == 0 and where(vault, "a") == ("Money", False)
    result = invoke(vault, "edit", "delete", "Money/a", "--apply", "-f", "json")
    assert result.exit_code == 0 and json.loads(result.stdout)["applied"] is True and where(vault, "a")[1]
    assert invoke(vault, "edit", "restore", "Recycle Bin/a", "--to", "Other", "--apply").exit_code == 0
    assert where(vault, "a") == ("Other", False)
    invoke(vault, "edit", "delete", "Other/a", "--apply")
    assert invoke(vault, "edit", "purge", "Recycle Bin/a", "--apply").exit_code == 0
    assert all(e.title != "a" for e in load(vault).entries)


def test_a_refused_write_exits_2_with_a_message(vault):
    result = invoke(vault, "edit", "purge", "Money/a", "--apply")
    assert result.exit_code == 2 and "refused" in result.stderr


# --- the origin is recorded where the format has a place for it (KDBX 4.1) ---------------------------------------------

def _as_kdbx41(monkeypatch):
    from pykeepass import PyKeePass

    monkeypatch.setattr(PyKeePass, "version", property(lambda self: (4, 1)))


def test_a_delete_in_a_41_vault_records_the_origin_so_restore_needs_no_group(vault, monkeypatch):
    _as_kdbx41(monkeypatch)
    delete_entry(opener(vault), vault, "Money/a", apply=True)
    assert load(vault).find_entries(title="a", first=True)._element.findtext("PreviousParentGroup")
    restore_entry(opener(vault), vault, "Recycle Bin/a", apply=True)  # no --to
    assert where(vault, "a") == ("Money", False)


def test_a_delete_in_an_older_vault_adds_no_element_it_may_not_know(vault):
    delete_entry(opener(vault), vault, "Money/a", apply=True)
    assert load(vault).find_entries(title="a", first=True)._element.findtext("PreviousParentGroup") is None


def test_deleting_a_group_in_a_41_vault_records_where_it_was(vault, monkeypatch):
    from cprima_pdh.groups import delete_group

    _as_kdbx41(monkeypatch)
    delete_group(opener(vault), vault, "Money", apply=True)
    g = next(x for x in load(vault).groups if x.name == "Money")
    assert g._element.findtext("PreviousParentGroup")
