"""`pdh db ...`: create a vault, change its password or key file, its settings and key derivation, empty the bin."""
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from pdh_testkit.mess import messy_vault
from pykeepass import PyKeePass
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app
from cprima_pdh.source import pykeepass_open


@pytest.fixture
def vault(tmp_path):
    return messy_vault(tmp_path / "m.kdbx").path


@pytest.fixture(autouse=True)
def opens_with_the_test_password(monkeypatch):
    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, None))


def invoke(vault, *args, env=None):
    return CliRunner().invoke(app, ["--db", str(vault), *args], env=env)


def data(vault, *args, env=None):
    result = invoke(vault, *args, "-f", "json", env=env)
    assert result.exit_code == 0, result.output + (result.stderr or "")
    return json.loads(result.stdout)


# --- create --------------------------------------------------------------------------------------------------------

def test_create_makes_an_empty_kdbx4_vault_that_opens_with_the_password(tmp_path):
    target = tmp_path / "new.kdbx"
    result = CliRunner().invoke(app, ["db", "create", str(target), "--apply", "-f", "json"],
                                env={"PDH_NEW_PASSWORD": "brand-new-pw"})
    assert result.exit_code == 0, result.output + (result.stderr or "")
    kp = PyKeePass(str(target), password="brand-new-pw")
    assert kp.version == (4, 0) and list(kp.entries) == [] and "brand-new-pw" not in result.stdout


def test_create_is_a_dry_run_by_default_and_refuses_an_existing_file(tmp_path, vault):
    target = tmp_path / "new.kdbx"
    assert CliRunner().invoke(app, ["db", "create", str(target)], env={"PDH_NEW_PASSWORD": "x"}).exit_code == 0
    assert not target.exists()
    assert CliRunner().invoke(app, ["db", "create", str(vault), "--apply"], env={"PDH_NEW_PASSWORD": "x"}).exit_code == 2


def test_create_needs_a_password_source(tmp_path):
    assert CliRunner().invoke(app, ["db", "create", str(tmp_path / "n.kdbx"), "--apply"], env={}).exit_code == 2


# --- password and key file ---------------------------------------------------------------------------------------

def test_password_change_makes_the_old_password_stop_working(vault):
    before = vault.read_bytes()
    assert invoke(vault, "db", "password", env={"PDH_NEW_PASSWORD": "second-pw"}).exit_code == 0
    assert vault.read_bytes() == before
    result = invoke(vault, "db", "password", "--apply", env={"PDH_NEW_PASSWORD": "second-pw"})
    assert result.exit_code == 0 and "second-pw" not in result.stdout
    assert PyKeePass(str(vault), password="second-pw").entries
    with pytest.raises(Exception):
        PyKeePass(str(vault), password=DEFAULT_PASSWORD)


def test_a_key_file_can_be_added_and_removed(vault, tmp_path, monkeypatch):
    key = tmp_path / "k.key"
    key.write_bytes(b"0123456789abcdef" * 4)
    assert invoke(vault, "db", "keyfile", "--set", str(key), "--apply").exit_code == 0
    assert PyKeePass(str(vault), password=DEFAULT_PASSWORD, keyfile=str(key)).entries
    with pytest.raises(Exception):
        PyKeePass(str(vault), password=DEFAULT_PASSWORD)
    # now removing it: the opener must supply the key file the vault currently needs
    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, str(key)))
    assert invoke(vault, "db", "keyfile", "--remove", "--apply").exit_code == 0
    assert PyKeePass(str(vault), password=DEFAULT_PASSWORD).entries


def test_keyfile_needs_exactly_one_of_set_and_remove_and_an_existing_file(vault, tmp_path):
    assert invoke(vault, "db", "keyfile", "--apply").exit_code == 2
    assert invoke(vault, "db", "keyfile", "--set", str(tmp_path / "nope.key"), "--apply").exit_code == 2


# --- settings ----------------------------------------------------------------------------------------------------

def test_settings_without_options_only_show(vault):
    before = vault.read_bytes()
    shown = data(vault, "db", "settings")
    assert shown["applied"] is False and shown["recycle_bin"] is True and vault.read_bytes() == before
    assert shown["history_max_items"] > 0


def test_settings_are_changed_and_read_back(vault):
    result = data(vault, "db", "settings", "--name", "My vault", "--description", "Housekeeping",
                  "--history-max-items", "5", "--history-max-size", "1048576", "--apply")
    assert result["applied"] is True and sorted(result["changed"]) == [
        "description", "history_max_items", "history_max_size", "name"]
    kp = pykeepass_open(vault, DEFAULT_PASSWORD, None)
    assert (kp.database_name, kp.database_description) == ("My vault", "Housekeeping")
    again = data(vault, "db", "settings")
    assert (again["name"], again["history_max_items"], again["history_max_size"]) == ("My vault", 5, 1048576)


def test_the_recycle_bin_can_be_switched_off_and_on(vault):
    assert data(vault, "db", "settings", "--no-recycle-bin", "--apply")["recycle_bin"] is False
    assert data(vault, "db", "settings")["recycle_bin"] is False
    assert data(vault, "db", "settings", "--recycle-bin", "--apply")["recycle_bin"] is True


def test_unchanged_settings_are_a_noop(vault):
    data(vault, "db", "settings", "--name", "Same", "--apply")
    before = vault.read_bytes()
    assert data(vault, "db", "settings", "--name", "Same", "--apply")["applied"] is False and vault.read_bytes() == before


def test_settings_refuse_negative_limits(vault):
    assert invoke(vault, "db", "settings", "--history-max-items", "-5", "--apply").exit_code == 2


# --- key derivation ------------------------------------------------------------------------------------------------

def test_kdf_shows_the_parameters_without_writing(vault):
    shown = data(vault, "db", "kdf")
    assert shown["algorithm"].startswith("argon2") and shown["iterations"] >= 1 and shown["applied"] is False


def test_kdf_parameters_are_changed_and_the_vault_still_opens(vault):
    result = data(vault, "db", "kdf", "--iterations", "2", "--memory", "8192", "--parallelism", "1", "--apply")
    assert result["applied"] is True and (result["iterations"], result["memory_kib"], result["parallelism"]) == (2, 8192, 1)
    kp = pykeepass_open(vault, DEFAULT_PASSWORD, None)
    assert kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict["I"].value == 2


def test_kdf_refuses_values_below_the_safe_minimum(vault):
    for args in (["--iterations", "0"], ["--memory", "1024"], ["--parallelism", "0"]):
        assert invoke(vault, "db", "kdf", *args, "--apply").exit_code == 2


# --- empty the recycle bin -----------------------------------------------------------------------------------------

def test_empty_bin_deletes_what_is_in_it_for_good_and_nothing_else(vault):
    kp = pykeepass_open(vault, DEFAULT_PASSWORD, None)
    live = sorted(e.title for e in kp.entries if e.group.uuid != kp.recyclebin_group.uuid)
    plan = data(vault, "db", "empty-bin")
    assert plan["applied"] is False and plan["entries"] == 1
    assert data(vault, "db", "empty-bin", "--apply")["applied"] is True
    after = pykeepass_open(vault, DEFAULT_PASSWORD, None)
    assert sorted(e.title for e in after.entries) == live and all(e.title != "In the bin" for e in after.entries)


def test_empty_bin_on_an_empty_or_missing_bin_is_a_noop(tmp_path):
    plain = synthetic_vault(tmp_path / "p.kdbx", [Entry("a", group="G")])
    before = plain.read_bytes()
    assert data(plain, "db", "empty-bin", "--apply")["entries"] == 0 and plain.read_bytes() == before
