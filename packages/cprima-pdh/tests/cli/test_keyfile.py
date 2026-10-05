"""Opening a vault that needs a key file, through every way pdh takes one: `--key`, `KDBX_KEY`, the library, `db create --keyfile`,
the other vault of an import. A key file is key material: it is read to open a vault and never written by pdh."""
import json
import os
import shutil

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault, vaults
from typer.testing import CliRunner

from cprima_pdh import session
from cprima_pdh.api import OpenError, open_vault
from cprima_pdh.cli import app
from cprima_pdh_kdbxkit.kdbx_vault import pykeepass_open

KEY_BYTES = b"0123456789abcdef" * 4


@pytest.fixture
def key(tmp_path):
    path = tmp_path / "master.key"
    path.write_bytes(KEY_BYTES)
    return path


@pytest.fixture
def locked(tmp_path, key):
    """A vault that needs the password and the key file."""
    db = synthetic_vault(tmp_path / "v.kdbx", [Entry("a", group="G")])
    kp = pykeepass_open(db, DEFAULT_PASSWORD, None)
    kp.keyfile = str(key)
    kp.save()
    return db


def entries(db, *options, env=None, input=None):
    result = CliRunner().invoke(app, [*options, "--db", str(db), "inspect", "entries", "-f", "json"], env=env, input=input)
    return result


def titles(result):
    return sorted(e["title"] for e in json.loads(result.stdout)["entries"])


# --- the command line ---------------------------------------------------------------------------------------------------

def test_the_key_option_and_the_password_open_it(locked, key):
    result = entries(locked, "--key", str(key), "--password-stdin", input=DEFAULT_PASSWORD + "\n")
    assert result.exit_code == 0 and titles(result) == ["a"]


def test_the_key_environment_variable_and_the_password_open_it(locked, key):
    result = entries(locked, env={"KDBX_KEY": str(key), "KDBX_PASSWORD": DEFAULT_PASSWORD})
    assert result.exit_code == 0 and titles(result) == ["a"]


def test_without_the_key_file_it_is_a_clear_error_that_does_not_ask_again(locked):
    result = entries(locked, env={"KDBX_PASSWORD": DEFAULT_PASSWORD})
    shown = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 1 and "open failed" in shown and DEFAULT_PASSWORD not in shown


def test_a_wrong_key_file_is_the_same_clear_error(locked, tmp_path):
    wrong = tmp_path / "wrong.key"
    wrong.write_bytes(b"not the key at all" * 4)
    result = entries(locked, "--key", str(wrong), env={"KDBX_PASSWORD": DEFAULT_PASSWORD})
    assert result.exit_code == 1 and "open failed" in (result.stderr or "")


def test_a_key_file_that_does_not_exist_is_refused_by_the_option(locked, tmp_path):
    result = entries(locked, "--key", str(tmp_path / "missing.key"), env={"KDBX_PASSWORD": DEFAULT_PASSWORD})
    assert result.exit_code != 0


def test_write_commands_open_with_the_key_file_too_and_keep_requiring_it(locked, key):
    env = {"KDBX_PASSWORD": DEFAULT_PASSWORD, "KDBX_KEY": str(key)}
    result = CliRunner().invoke(app, ["--db", str(locked), "edit", "new-group", "/", "Money", "--apply"], env=env)
    assert result.exit_code == 0, result.stderr
    kp = pykeepass_open(locked, DEFAULT_PASSWORD, str(key))
    assert "Money" in [g.name for g in kp.groups]
    with pytest.raises(Exception):
        pykeepass_open(locked, DEFAULT_PASSWORD, None)  # still needs the key file after the write


def test_the_master_passphrase_can_be_changed_without_losing_the_key_file(locked, key):
    env = {"KDBX_PASSWORD": DEFAULT_PASSWORD, "KDBX_KEY": str(key), "PDH_NEW_PASSWORD": "second-passphrase"}
    assert CliRunner().invoke(app, ["--db", str(locked), "db", "password", "--apply"], env=env).exit_code == 0
    assert pykeepass_open(locked, "second-passphrase", str(key)).entries
    with pytest.raises(Exception):
        pykeepass_open(locked, "second-passphrase", None)


# --- a vault that is protected by a key file alone ------------------------------------------------------------------------

@pytest.fixture
def key_only(tmp_path, key):
    db = synthetic_vault(tmp_path / "k.kdbx", [Entry("a", group="G")])
    kp = pykeepass_open(db, DEFAULT_PASSWORD, None)
    kp.password = None
    kp.keyfile = str(key)
    kp.save()
    return db


def test_the_library_opens_a_vault_protected_by_a_key_file_alone(key_only, key):
    with open_vault(key_only, keyfile=key) as v:
        assert [a.title for a in v.accounts()] == ["a"]


@pytest.mark.xfail(strict=True, reason="a vault with only a key file cannot be opened by the command line without a terminal: "
                                       "no channel says 'no passphrase', so it falls through to the prompt")
def test_the_command_line_opens_a_vault_protected_by_a_key_file_alone_without_a_terminal(key_only, key):
    result = entries(key_only, "--key", str(key))
    assert result.exit_code == 0


# --- the library ------------------------------------------------------------------------------------------------------

def test_the_library_opens_with_a_key_file_given_or_from_the_environment(locked, key, monkeypatch):
    with open_vault(locked, password=DEFAULT_PASSWORD, keyfile=key) as v:
        assert [a.title for a in v.accounts()] == ["a"]
    monkeypatch.setenv("KDBX_PASSWORD", DEFAULT_PASSWORD)
    monkeypatch.setenv("KDBX_KEY", str(key))
    with open_vault(locked) as v:
        assert len(v.accounts()) == 1


def test_the_library_without_the_key_file_is_one_error_that_carries_neither_secret(locked):
    with pytest.raises(OpenError) as raised:
        open_vault(locked, password=DEFAULT_PASSWORD)
    assert DEFAULT_PASSWORD not in str(raised.value)


# --- creating, and the other vault of an import ---------------------------------------------------------------------------

def test_a_vault_created_with_a_key_file_needs_both(tmp_path, key):
    target = tmp_path / "new.kdbx"
    env = {"PDH_NEW_PASSWORD": "created-passphrase"}
    result = CliRunner().invoke(app, ["db", "create", str(target), "--keyfile", str(key), "--apply"], env=env)
    assert result.exit_code == 0, result.stderr
    assert pykeepass_open(target, "created-passphrase", str(key)) is not None
    with pytest.raises(Exception):
        pykeepass_open(target, "created-passphrase", None)


def test_the_other_vault_of_an_import_is_opened_with_its_own_key_file(locked, key, tmp_path):
    target = synthetic_vault(tmp_path / "target.kdbx")
    env = {"KDBX_PASSWORD": DEFAULT_PASSWORD, "PDH_IMPORT_PASSWORD": DEFAULT_PASSWORD}
    result = CliRunner().invoke(
        app, ["--db", str(target), "io", "import-kdbx", str(locked), "--keyfile", str(key), "--group", "Imported", "--apply"],
        env=env)
    assert result.exit_code == 0, result.stderr
    assert [e.title for e in pykeepass_open(target, DEFAULT_PASSWORD, None).entries] == ["a"]
    refused = CliRunner().invoke(app, ["--db", str(target), "io", "import-kdbx", str(locked), "--group", "Again", "--apply"],
                                 env=env)
    assert refused.exit_code == 2  # without its key file the other vault cannot be read


# --- the session cache ----------------------------------------------------------------------------------------------------

@pytest.mark.skipif(os.name != "nt", reason="the session cache is encrypted with Windows DPAPI")
def test_the_session_remembers_where_the_key_file_is_not_what_is_in_it(locked, key):
    session.save_session(locked, DEFAULT_PASSWORD, key, 5)
    password, keyfile = session.load_session(locked)
    assert password == DEFAULT_PASSWORD and keyfile == str(key.resolve())
    assert KEY_BYTES not in session.SESSION_FILE.read_bytes()


# --- the genuine fixture: a KDBX 4.0 vault and its KeePassXC key file, both written by KeePassXC -------------------------------

@pytest.fixture
def genuine(tmp_path):
    """Copies of the committed fixture (never the originals) and the environment that opens them."""
    fixture = vaults.load("keyfile-kdbx4")
    db, key = tmp_path / "g.kdbx", tmp_path / "g.keyx"
    shutil.copyfile(fixture.path, db)
    shutil.copyfile(fixture.keyfile, key)
    return db, key, {"KDBX_PASSWORD": fixture.password, "KDBX_KEY": str(key)}


def test_pdh_opens_the_genuine_vault_with_its_key_file(genuine):
    db, key, env = genuine
    assert entries(db, env=env).exit_code == 0
    assert entries(db, "--key", str(key), env={"KDBX_PASSWORD": env["KDBX_PASSWORD"]}).exit_code == 0
    assert entries(db, env={"KDBX_PASSWORD": env["KDBX_PASSWORD"]}).exit_code == 1  # without the key file: refused


def test_doctor_names_the_genuine_vaults_format(genuine):
    db, _, env = genuine
    result = CliRunner().invoke(app, ["--db", str(db), "doctor"], env=env)
    assert result.exit_code == 0 and "KDBX 4.0" in result.stdout


def test_the_library_opens_the_genuine_vault(genuine):
    db, key, env = genuine
    with open_vault(db, password=env["KDBX_PASSWORD"], keyfile=key) as v:
        assert v.accounts() == []
    with pytest.raises(OpenError):
        open_vault(db, password=env["KDBX_PASSWORD"])


def test_a_write_to_the_genuine_vault_keeps_the_key_file_requirement(genuine):
    db, key, env = genuine
    for command in (["edit", "new-group", "/", "Shops"], ["edit", "new-entry", "Shops", "site", "alex"],
                    ["edit", "fill", "Shops/site", "--generate"]):
        result = CliRunner().invoke(app, ["--db", str(db), *command, "--apply"], env=env)
        assert result.exit_code == 0, f"{command}: {result.stderr}"
    with open_vault(db, password=env["KDBX_PASSWORD"], keyfile=key) as v:
        assert [a.title for a in v.accounts()] == ["site"] and v.secret("Shops/site").get_secret_value()
    with pytest.raises(Exception):
        pykeepass_open(db, env["KDBX_PASSWORD"], None)
