"""`edit set` (one field, keeps protection, snapshots history) and `edit new-entry` (a complete entry in one call)."""
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault

from cprima_pdh.source import pykeepass_open
from pdh_testkit.cli import invoke

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")


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


def prot(e, key):
    return e.is_custom_property_protected(key)


# --- set: protection is kept unless asked otherwise ---------------------------------------------------------------

def test_setting_a_protected_custom_field_keeps_it_protected(vault):
    assert invoke(vault, "edit", "set", "G/a", "secret_k", "-", "--overwrite", "--apply", input="new\n").exit_code == 0
    a = entry(vault)
    assert a.get_custom_property("secret_k") == "new" and prot(a, "secret_k")  # not silently unprotected


def test_unprotect_removes_the_protection_and_protect_adds_it(vault):
    invoke(vault, "edit", "set", "G/a", "secret_k", "-", "--overwrite", "--unprotect", "--apply", input="new\n")
    assert not prot(entry(vault), "secret_k")
    invoke(vault, "edit", "set", "G/a", "plain_k", "-", "--overwrite", "--protect", "--apply", input="new\n")
    assert prot(entry(vault), "plain_k")


def test_protect_and_unprotect_together_are_refused(vault):
    assert invoke(vault, "edit", "set", "G/a", "plain_k", "x", "--protect", "--unprotect").exit_code == 2


def test_a_dry_run_shows_the_change_without_values_of_protected_fields(vault):
    before = vault.read_bytes()
    result = invoke(vault, "edit", "set", "G/a", "secret_k", "-", "--overwrite", "-f", "json", input="brand-new\n")
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


# --- set: a secret is never an argument -----------------------------------------------------------------------

SECRETS_BY_RULE = [
    ("Password", []),                 # a standard secret
    ("otp", []),                      # a standard secret
    ("secret_k", []),                 # protected in the file (and by name in the profile)
    ("api_token", []),                # protected by the profile, by name
    ("TOTP Seed", []),                # the KDBX ecosystem's
    ("plain_k", ["--protect"]),       # asked to be protected
]


@pytest.mark.parametrize("field,flags", SECRETS_BY_RULE, ids=[f for f, _ in SECRETS_BY_RULE])
@pytest.mark.parametrize("apply", [[], ["--apply"]], ids=["dry-run", "applied"])
def test_a_secret_on_the_command_line_is_refused_and_never_echoed(vault, field, flags, apply):
    before = vault.read_bytes()
    result = invoke(vault, "edit", "set", "G/a", field, "literal-secret-value", "--overwrite", *flags, *apply)
    shown = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 2 and "pdh never takes a secret on the command line" in shown and "`-`" in shown
    assert "literal-secret-value" not in shown and vault.read_bytes() == before


def test_a_secret_is_given_by_the_hidden_prompt(vault):
    result = invoke(vault, "edit", "set", "G/a", "Password", "-", "--overwrite", "--apply", input="from-the-prompt\n")
    assert result.exit_code == 0 and entry(vault).password == "from-the-prompt"
    assert "from-the-prompt" not in result.stdout


def test_a_value_that_is_not_a_secret_may_still_be_an_argument(vault):
    assert invoke(vault, "edit", "set", "G/a", "plain_k", "visible", "--overwrite", "--apply").exit_code == 0
    assert entry(vault).get_custom_property("plain_k") == "visible"


# --- new-entry ----------------------------------------------------------------------------------------------

def test_new_entry_without_a_terminal_has_no_password(vault):
    result = invoke(vault, "edit", "new-entry", "G", "c", "cu", "--apply")
    assert result.exit_code == 0
    c = entry(vault, "c")
    assert c.username == "cu" and not c.password


def test_the_environment_is_not_a_channel_for_an_entrys_password(vault):
    result = invoke(vault, "edit", "new-entry", "G", "c", "cu", "--apply", env={"PDH_NEW_PASSWORD": "must-be-ignored"})
    assert result.exit_code == 0 and not entry(vault, "c").password


def test_new_entry_asks_for_its_password_with_a_hidden_prompt_on_a_terminal(vault, monkeypatch):
    from cprima_pdh.cli import _common

    monkeypatch.setattr(_common, "_has_console", lambda: True)
    result = invoke(vault, "edit", "new-entry", "G", "c", "cu", "--apply", input="pw-c\npw-c\n")
    assert result.exit_code == 0 and entry(vault, "c").password == "pw-c" and "pw-c" not in result.stdout


def test_new_entry_takes_structure_in_one_call(vault):
    result = invoke(vault, "edit", "new-entry", "G", "d", "du", "--url", "https://d.example.org", "--notes", "n",
                    "--tag", "t1", "--tag", "t2", "--expires", "2032-05-06", "--field", "plain=visible", "--apply")
    assert result.exit_code == 0, result.output
    d = entry(vault, "d")
    assert (d.url, d.notes, sorted(d.tags)) == ("https://d.example.org", "n", ["t1", "t2"])
    assert d.expires and d.expiry_time.date().isoformat() == "2032-05-06"
    assert d.get_custom_property("plain") == "visible" and not prot(d, "plain")


@pytest.mark.parametrize("option", ["--secret-field", "--password-env"])
def test_the_options_that_took_secrets_from_the_environment_are_gone(vault, option):
    result = invoke(vault, "edit", "new-entry", "G", "e", "u", option, "X=Y")
    assert result.exit_code == 2 and "No such option" in (result.stderr or result.output)


@pytest.mark.parametrize("name", ["Password", "api_token", "TimeOtp-Secret-Base32", "secret_k"])
def test_a_field_that_holds_a_secret_is_refused_on_new_entry(vault, name):
    result = invoke(vault, "edit", "new-entry", "G", "e", "u", "--field", f"{name}=literal-secret-value", "--apply")
    shown = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 2 and "literal-secret-value" not in shown
    assert not any(e.title == "e" for e in load(vault).entries)


def test_new_entry_refuses_bad_input(vault):
    assert invoke(vault, "edit", "new-entry", "G", "a", "u", "--apply").exit_code == 2  # title exists
    assert invoke(vault, "edit", "new-entry", "G", "e", "u", "--expires", "nope").exit_code == 2
    assert invoke(vault, "edit", "new-entry", "G", "e", "u", "--field", "no-equals").exit_code == 2
    assert invoke(vault, "edit", "new-entry", "G", "e", "u", "--field", "Title=x").exit_code == 2  # standard


def test_new_entry_dry_run_writes_nothing(vault):
    before = vault.read_bytes()
    assert invoke(vault, "edit", "new-entry", "G", "z", "u").exit_code == 0
    assert vault.read_bytes() == before
