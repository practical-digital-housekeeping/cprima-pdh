"""`edit tags` / `expiry` / `clone`: attributes of an entry that are not fields. Each keeps history and verifies the file."""
import json
from datetime import datetime, timezone

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app
from cprima_pdh.entries import change_tags, clone_entry, set_expiry
from cprima_pdh.source import pykeepass_open
from cprima_pdh.write import WriteError


def opener(db):
    return lambda: pykeepass_open(db, DEFAULT_PASSWORD, None)


def load(db):
    return pykeepass_open(db, DEFAULT_PASSWORD, None)


def entry(db, title):
    return next(e for e in load(db).entries if e.title == title)


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [
        Entry("a", group="Money", username="u", password="pw", tags=("x", "y"), custom={"k": "v"},
              protected=frozenset({"k"}), url="https://a.example.org"),
        Entry("b", group="Money", username="u2"),
    ])


# --- tags ---------------------------------------------------------------------------------------------------

def test_tags_are_added_and_removed_and_nothing_else_changes(vault):
    before = vault.read_bytes()
    change = change_tags(opener(vault), vault, "Money/a", add=["z"], remove=["x"], apply=False)
    assert (change.kind, change.applied) == ("tags", False) and vault.read_bytes() == before
    change_tags(opener(vault), vault, "Money/a", add=["z"], remove=["x"], apply=True)
    a = entry(vault, "a")
    assert sorted(a.tags) == ["y", "z"] and (a.username, a.password, a.get_custom_property("k")) == ("u", "pw", "v")
    assert entry(vault, "b").tags in ([], None)


def test_an_edit_leaves_the_previous_state_in_the_history(vault):
    change_tags(opener(vault), vault, "Money/a", add=["z"], remove=[], apply=True)
    a = entry(vault, "a")
    assert len(a.history) == 1 and sorted(a.history[0].tags) == ["x", "y"]


def test_adding_an_existing_tag_and_removing_a_missing_one_is_a_noop(vault):
    before = vault.read_bytes()
    change = change_tags(opener(vault), vault, "Money/a", add=["x"], remove=["nope"], apply=True)
    assert change.applied is False and vault.read_bytes() == before  # nothing to write: no save, no history


def test_tags_with_separators_are_refused(vault):
    for bad in ("a;b", "a,b", ""):
        with pytest.raises(WriteError, match="tag"):
            change_tags(opener(vault), vault, "Money/a", add=[bad], remove=[], apply=False)


# --- expiry -------------------------------------------------------------------------------------------------

def test_expiry_is_set_and_cleared(vault):
    set_expiry(opener(vault), vault, "Money/a", date="2031-02-03", clear=False, apply=True)
    a = entry(vault, "a")
    assert a.expires is True and a.expiry_time.astimezone(timezone.utc).date().isoformat() == "2031-02-03"
    change = set_expiry(opener(vault), vault, "Money/a", date=None, clear=True, apply=True)
    assert change.applied and entry(vault, "a").expires is False


def test_expiry_needs_a_valid_date_or_clear(vault):
    for date, clear in (("not-a-date", False), (None, False), ("2031-02-03", True)):
        with pytest.raises(WriteError):
            set_expiry(opener(vault), vault, "Money/a", date=date, clear=clear, apply=False)


def test_the_same_expiry_again_is_a_noop(vault):
    set_expiry(opener(vault), vault, "Money/a", date="2031-02-03", clear=False, apply=True)
    before = vault.read_bytes()
    assert set_expiry(opener(vault), vault, "Money/a", date="2031-02-03", clear=False, apply=True).applied is False
    assert vault.read_bytes() == before


# --- clone --------------------------------------------------------------------------------------------------

def test_clone_makes_a_new_entry_with_the_same_content(vault):
    original = entry(vault, "a")
    change = clone_entry(opener(vault), vault, "Money/a", title="a copy", apply=True)
    assert (change.kind, change.dest) == ("clone", "Money/a copy") and change.applied
    kp = load(vault)
    copy = next(e for e in kp.entries if e.title == "a copy")
    assert copy.uuid != original.uuid and copy.group.uuid == original.group.uuid
    assert (copy.username, copy.password, copy.url, sorted(copy.tags)) == ("u", "pw", "https://a.example.org", ["x", "y"])
    assert copy.get_custom_property("k") == "v" and copy.is_custom_property_protected("k")
    assert len(list(kp.entries)) == 3


def test_clone_default_title_and_refusal_of_a_duplicate_title(vault):
    clone_entry(opener(vault), vault, "Money/a", title=None, apply=True)
    assert {e.title for e in load(vault).entries} == {"a", "b", "a - copy"}
    with pytest.raises(WriteError, match="already has"):
        clone_entry(opener(vault), vault, "Money/a", title="b", apply=False)


# --- the command line ---------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def opens_with_the_test_password(monkeypatch):
    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, None))


def invoke(vault, *args):
    return CliRunner().invoke(app, ["--db", str(vault), *args])


def test_the_cli_commands(vault):
    assert invoke(vault, "edit", "tags", "Money/a", "--add", "z", "--remove", "x", "--apply").exit_code == 0
    assert sorted(entry(vault, "a").tags) == ["y", "z"]
    assert invoke(vault, "edit", "expiry", "Money/a", "2031-02-03", "--apply").exit_code == 0
    assert invoke(vault, "edit", "expiry", "Money/a", "--clear", "--apply").exit_code == 0
    result = invoke(vault, "edit", "clone", "Money/a", "--title", "c2", "--apply", "-f", "json")
    assert result.exit_code == 0 and json.loads(result.stdout)["dest"] == "Money/c2"


def test_the_cli_refuses_with_exit_2(vault):
    assert invoke(vault, "edit", "expiry", "Money/a", "garbage").exit_code == 2
    assert invoke(vault, "edit", "tags", "Money/a").exit_code == 2  # nothing to add or remove
