"""`edit set` (one field, keeps protection, snapshots history) and `edit new-entry` (a complete entry in one call)."""
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app
from cprima_pdh.source import pykeepass_open


def load(db):
    return pykeepass_open(db, DEFAULT_PASSWORD, None)


def entry(db, title="a"):
    return next(e for e in load(db).entries if e.title == title)


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [
        Entry("a", group="G", username="u", password="pw", url="https://old.example.org",
              custom={"secret_k": "s1", "plain_k": "p1"}, protected=frozenset({"secret_k"})),
        Entry("b", group="G"),
    ])


@pytest.fixture(autouse=True)
def opens_with_the_test_password(monkeypatch):
    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, None))


def invoke(vault, *args, env=None):
    return CliRunner().invoke(app, ["--db", str(vault), *args], env=env)


def prot(e, key):
    return e.is_custom_property_protected(key)


# --- set: protection is kept unless asked otherwise ---------------------------------------------------------------

def test_setting_a_protected_custom_field_keeps_it_protected(vault):
    assert invoke(vault, "edit", "set", "G/a", "secret_k", "new", "--overwrite", "--apply").exit_code == 0
    a = entry(vault)
    assert a.get_custom_property("secret_k") == "new" and prot(a, "secret_k")  # not silently unprotected


def test_unprotect_removes_the_protection_and_protect_adds_it(vault):
    invoke(vault, "edit", "set", "G/a", "secret_k", "new", "--overwrite", "--unprotect", "--apply")
    assert not prot(entry(vault), "secret_k")
    invoke(vault, "edit", "set", "G/a", "plain_k", "new", "--overwrite", "--protect", "--apply")
    assert prot(entry(vault), "plain_k")


def test_protect_and_unprotect_together_are_refused(vault):
    assert invoke(vault, "edit", "set", "G/a", "plain_k", "x", "--protect", "--unprotect").exit_code == 2


def test_a_dry_run_shows_the_change_without_values_of_protected_fields(vault):
    before = vault.read_bytes()
    result = invoke(vault, "edit", "set", "G/a", "secret_k", "brand-new", "--overwrite", "-f", "json")
    data = json.loads(result.stdout)
    assert vault.read_bytes() == before and data["applied"] is False
    assert "brand-new" not in result.stdout and "s1" not in result.stdout  # hidden, old and new


def test_an_edit_keeps_the_previous_value_in_the_history(vault):
    invoke(vault, "edit", "set", "G/a", "URL", "https://new.example.org", "--overwrite", "--apply")
    a = entry(vault)
    assert a.url == "https://new.example.org" and [h.url for h in a.history] == ["https://old.example.org"]


def test_a_non_empty_field_is_not_replaced_without_overwrite(vault):
    result = invoke(vault, "edit", "set", "G/a", "URL", "https://new.example.org", "--apply")
    assert result.exit_code == 1 and entry(vault).url == "https://old.example.org"


def test_title_and_notes_can_be_set_and_nothing_else_changes(vault):
    invoke(vault, "edit", "set", "G/a", "Title", "renamed", "--overwrite", "--apply")
    invoke(vault, "edit", "set", "G/renamed", "Notes", "hello", "--apply")
    a = entry(vault, "renamed")
    assert (a.notes, a.username, a.password, a.get_custom_property("plain_k")) == ("hello", "u", "pw", "p1")
    assert entry(vault, "b").title == "b"


# --- new-entry ----------------------------------------------------------------------------------------------

def test_new_entry_with_the_standard_fields_only(vault):
    result = invoke(vault, "edit", "new-entry", "G", "c", "cu", "--apply", env={"PDH_NEW_PASSWORD": "pw-c"})
    assert result.exit_code == 0
    c = entry(vault, "c")
    assert (c.username, c.password) == ("cu", "pw-c")


def test_new_entry_takes_everything_in_one_call(vault):
    result = invoke(vault, "edit", "new-entry", "G", "d", "du", "--url", "https://d.example.org", "--notes", "n",
                    "--tag", "t1", "--tag", "t2", "--expires", "2032-05-06", "--field", "plain=visible",
                    "--secret-field", "token=MY_TOKEN", "--apply",
                    env={"PDH_NEW_PASSWORD": "pw-d", "MY_TOKEN": "tok-123"})
    assert result.exit_code == 0, result.output
    d = entry(vault, "d")
    assert (d.url, d.notes, sorted(d.tags)) == ("https://d.example.org", "n", ["t1", "t2"])
    assert d.expires and d.expiry_time.date().isoformat() == "2032-05-06"
    assert d.get_custom_property("plain") == "visible" and not prot(d, "plain")
    assert d.get_custom_property("token") == "tok-123" and prot(d, "token")
    assert "tok-123" not in result.stdout and "pw-d" not in result.stdout


def test_new_entry_refuses_bad_input(vault):
    env = {"PDH_NEW_PASSWORD": "x"}
    assert invoke(vault, "edit", "new-entry", "G", "a", "u", "--apply", env=env).exit_code == 2  # title exists
    assert invoke(vault, "edit", "new-entry", "G", "e", "u", "--expires", "nope", env=env).exit_code == 2
    assert invoke(vault, "edit", "new-entry", "G", "e", "u", "--field", "no-equals", env=env).exit_code == 2
    assert invoke(vault, "edit", "new-entry", "G", "e", "u", "--field", "Title=x", env=env).exit_code == 2  # standard
    assert invoke(vault, "edit", "new-entry", "G", "e", "u", "--secret-field", "t=UNSET_VAR", env=env).exit_code == 2
    assert invoke(vault, "edit", "new-entry", "G", "e", "u", env={}).exit_code == 2  # no password variable


def test_new_entry_dry_run_writes_nothing(vault):
    before = vault.read_bytes()
    assert invoke(vault, "edit", "new-entry", "G", "z", "u", env={"PDH_NEW_PASSWORD": "x"}).exit_code == 0
    assert vault.read_bytes() == before
