"""`pdh edit fill`: the secret fields an entry (or every entry below a group) still lacks, by the taxonomy. Typed with a hidden
prompt or generated and stored without being shown; never an argument, never in any output; one write, one snapshot per entry."""
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from pdh_testkit.cli import invoke

from cprima_pdh import profiles
from cprima_pdh.cli import _common
from cprima_pdh.source import pykeepass_open

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")

BINDING = profiles.load(profiles.DEFAULT).binding.field


@pytest.fixture
def vault(tmp_path):
    db = synthetic_vault(tmp_path / "v.kdbx", [
        Entry("ap", group="Home", custom={BINDING: "wifi-access-point"}),         # wifi_key and Password to fill
        Entry("site", group="Home"),                                               # untyped: Password to fill
        Entry("done", group="Home", password="already-set"),                       # nothing to fill
        Entry("card", group="Cards", custom={BINDING: "credit-card"}),             # card_number, PIN, CVV to fill: all typed
        Entry("router", group="Net", custom={BINDING: "openwrt-device"}),          # Password (generated) and ssh_key (typed)
        Entry("trashed", group="Home"),                                            # in the bin: left alone
    ])
    kp = pykeepass_open(db, DEFAULT_PASSWORD, None)
    kp.trash_entry(next(e for e in kp.entries if e.title == "trashed"))
    kp.save()
    return db


@pytest.fixture
def terminal(monkeypatch):
    monkeypatch.setattr(_common, "_has_console", lambda: True)


def entry(db, title):
    return next(e for e in pykeepass_open(db, DEFAULT_PASSWORD, None).entries if e.title == title)


def fill(db, *args, input=None):
    return invoke(db, "edit", "fill", *args, "-f", "json", input=input)


def report(result):
    assert result.exit_code == 0, (result.stdout or "") + (result.stderr or "")
    return json.loads(result.stdout)


# --- the dry run -------------------------------------------------------------------------------------------------------

def test_a_dry_run_lists_what_is_missing_and_asks_nothing(vault):
    before = vault.read_bytes()
    r = report(fill(vault, "Home"))
    assert r["applied"] is False and r["entries"] == 2 and r["fields"] == 3
    assert {(i["entry"], i["field"], i["how"]) for i in r["items"]} == {
        ("Home/ap", "wifi_key", "to type"), ("Home/ap", "Password", "to type"), ("Home/site", "Password", "to type")}
    assert vault.read_bytes() == before


def test_a_dry_run_says_which_fields_would_be_generated(vault):
    how = {i["field"]: i["how"] for i in report(fill(vault, "Net", "--generate"))["items"]}
    assert how == {"Password": "to generate", "ssh_key": "to type"}  # a key is typed, a password is made up


def test_a_card_is_never_generated_because_everything_on_it_comes_from_the_bank(vault):
    how = {i["field"]: i["how"] for i in report(fill(vault, "Cards", "--generate"))["items"]}
    assert how == {"card_number": "to type", "PIN": "to type", "CVV": "to type"}


def test_the_text_layout_says_it_was_a_dry_run(vault):
    out = invoke(vault, "edit", "fill", "Home/site").stdout
    assert "Home/site: Password (to type)" in out and "a dry run: nothing was asked or written" in out


# --- generating ---------------------------------------------------------------------------------------------------------

def test_a_generated_password_is_stored_and_never_shown(vault):
    result = fill(vault, "Home/site", "--generate", "--apply")
    r = report(result)
    stored = entry(vault, "site").password
    assert r["applied"] is True and r["generated"] == 1 and len(stored) == 20  # the generator's default length
    assert stored not in (result.stdout or "") + (result.stderr or "")
    assert len(entry(vault, "site").history) == 1  # the previous state is kept, once


def test_nothing_is_left_to_fill_the_second_time(vault):
    fill(vault, "Home/site", "--generate", "--apply")
    again = report(fill(vault, "Home/site", "--generate", "--apply"))
    assert again["fields"] == 0 and again["applied"] is False and len(entry(vault, "site").history) == 1


def test_two_runs_generate_different_passwords(vault):
    fill(vault, "Home/site", "--generate", "--apply")
    fill(vault, "Home/ap", "--generate", "--apply")
    assert entry(vault, "site").password != entry(vault, "ap").password


def test_a_group_is_filled_below_it_and_what_is_set_or_in_the_bin_is_left_alone(vault):
    r = report(fill(vault, "Home", "--generate", "--apply"))
    assert r["entries"] == 2 and r["generated"] == 3 and r["skipped"] == 0
    assert entry(vault, "ap").password and entry(vault, "ap").get_custom_property("wifi_key")
    assert entry(vault, "ap").is_custom_property_protected("wifi_key")
    assert entry(vault, "done").password == "already-set" and not entry(vault, "done").history
    assert not entry(vault, "trashed").password


def test_without_a_terminal_only_what_may_be_generated_is_filled_and_the_rest_is_reported_skipped(vault):
    r = report(fill(vault, "Net", "--generate", "--apply"))
    assert r["generated"] == 1 and r["skipped"] == 1 and r["typed"] == 0
    router = entry(vault, "router")
    assert router.password and not router.get_custom_property("ssh_key")


def test_nothing_that_comes_from_outside_is_generated_so_without_a_terminal_nothing_is_written(vault):
    before = vault.read_bytes()
    result = fill(vault, "Cards", "--generate", "--apply")  # PIN, card number and CVV can only be typed
    assert result.exit_code == 2 and "no terminal to ask on" in result.stderr and vault.read_bytes() == before


# --- typing -------------------------------------------------------------------------------------------------------------

def test_a_secret_is_typed_at_a_hidden_prompt_in_the_taxonomys_order_and_enter_skips(vault, terminal):
    result = fill(vault, "Home/ap", "--apply", input="\npw-typed-123\n")  # wifi_key skipped, then Password
    r = report(result)
    assert (r["typed"], r["skipped"]) == (1, 1) and entry(vault, "ap").password == "pw-typed-123"
    assert not entry(vault, "ap").get_custom_property("wifi_key")
    assert "pw-typed-123" not in (result.stdout or "") + (result.stderr or "")


def test_typed_and_generated_fields_mix(vault, terminal):
    r = report(fill(vault, "Net", "--generate", "--apply", input="ssh-key-material-unique\n"))  # the key typed, the password made
    assert (r["typed"], r["generated"]) == (1, 1)
    router = entry(vault, "router")
    assert router.get_custom_property("ssh_key") == "ssh-key-material-unique" and router.is_custom_property_protected("ssh_key")
    assert router.password not in ("", "ssh-key-material-unique") and len(router.history) == 1


def test_a_card_is_typed_field_by_field_at_the_prompt(vault, terminal):
    r = report(fill(vault, "Cards", "--generate", "--apply", input="4111-1111\n1234\n987\n"))
    assert (r["typed"], r["generated"]) == (3, 0)
    card = entry(vault, "card")
    assert [card.get_custom_property(f) for f in ("card_number", "PIN", "CVV")] == ["4111-1111", "1234", "987"]


def test_a_typed_value_is_never_in_any_output(vault, terminal):
    result = fill(vault, "Home/site", "--apply", input="hunter2-unique-token\n")
    assert "hunter2-unique-token" not in (result.stdout or "") + (result.stderr or "")


# --- refusals -----------------------------------------------------------------------------------------------------------

def test_without_a_terminal_and_without_generate_nothing_is_written(vault):
    before = vault.read_bytes()
    result = fill(vault, "Home/site", "--apply")
    assert result.exit_code == 2 and "no terminal to ask on" in result.stderr and "--generate" in result.stderr
    assert vault.read_bytes() == before


def test_an_unknown_path_is_refused(vault):
    result = fill(vault, "Nowhere/at/all", "--generate", "--apply")
    assert result.exit_code == 2 and "no entry or group at" in result.stderr


def test_a_path_that_is_both_an_entry_and_a_group_is_refused(tmp_path):
    db = synthetic_vault(tmp_path / "v.kdbx", [Entry("ap", group="Home")], groups=["Home/ap"])
    result = fill(db, "Home/ap", "--generate", "--apply")
    assert result.exit_code == 2 and "both an entry and a group" in result.stderr


def test_the_secret_is_not_an_argument_so_there_is_no_option_for_it(vault):
    result = invoke(vault, "edit", "fill", "Home/site", "--password", "x")
    assert result.exit_code == 2 and "No such option" in (result.stderr or result.output)


# --- the generator's knobs, as `pdh generate` has them ----------------------------------------------------------------

def test_the_generated_password_follows_the_knobs_and_is_still_never_shown(vault):
    result = fill(vault, "Home/site", "--generate", "--apply", "--length", "16", "--special", "--no-numeric", "--exclude", "abc")
    stored = entry(vault, "site").password
    assert report(result)["generated"] == 1 and len(stored) == 16
    assert not any(ch.isdigit() for ch in stored) and not set(stored) & set("abc")
    assert any(not ch.isalnum() for ch in stored)  # --special, with a character from every group
    assert stored not in (result.stdout or "") + (result.stderr or "")


def test_a_setting_that_cannot_make_a_password_is_refused_before_anything_is_opened_or_written(vault):
    before = vault.read_bytes()
    result = fill(vault, "Home/site", "--generate", "--apply", "--no-lower", "--no-upper", "--no-numeric")
    assert result.exit_code == 2 and "no character group is selected" in result.stderr and vault.read_bytes() == before


def test_a_mass_fill_runs_unattended_and_every_password_follows_the_same_settings(tmp_path):
    entries = [Entry(f"user{n:03d}", group="Test accounts") for n in range(60)]
    db = synthetic_vault(tmp_path / "v.kdbx", entries)
    r = report(fill(db, "Test accounts", "--generate", "--apply", "--length", "14", "--no-special"))
    kp = pykeepass_open(db, DEFAULT_PASSWORD, None)
    passwords = [e.password for e in kp.entries]
    assert r["entries"] == 60 and r["generated"] == 60 and len(set(passwords)) == 60
    assert all(len(p) == 14 and p.isalnum() for p in passwords)
