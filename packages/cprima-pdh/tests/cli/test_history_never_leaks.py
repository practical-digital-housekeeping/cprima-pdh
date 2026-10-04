"""An entry's history keeps its old values, among them old passwords. No report, view or export may show one.

Reports name fields and counts (`inspect history` lists *which fields* a snapshot differs in, never what they held). The
one-line rule behind it: history is read only by the history commands that restore or prune it, never printed.
"""
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from pdh_testkit.cli import invoke

from cprima_pdh.source import pykeepass_open

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")

OLD = {"password": "hist-old-password-1", "password2": "hist-old-password-2", "token": "hist-old-token-1",
       "serial": "SERIAL-OLD-7788", "username": "olduser-9911"}
NOW = {"password": "now-current-password", "token": "now-current-token", "serial": "SERIAL-NOW-1234"}


@pytest.fixture
def vault(tmp_path):
    db = synthetic_vault(tmp_path / "v.kdbx", [Entry("subject", group="G", username=OLD["username"], password=OLD["password"],
                                                     custom={"api_token": OLD["token"], "serial": OLD["serial"]},
                                                     protected=frozenset({"api_token"}))])
    kp = pykeepass_open(db, DEFAULT_PASSWORD, None)
    e = next(x for x in kp.entries if x.title == "subject")
    e.save_history()  # first snapshot: everything as the fixture made it
    e.password = OLD["password2"]
    e.save_history()  # second snapshot: a later password
    e.password, e.username = NOW["password"], "currentuser-4242"
    e.set_custom_property("api_token", NOW["token"], protect=True)
    e.set_custom_property("serial", NOW["serial"])
    kp.save()
    return db


COMMANDS = [
    ("inspect", "entries"), ("inspect", "show", "G/subject"), ("inspect", "history", "G/subject"),
    ("inspect", "attachments", "G/subject"), ("inspect", "inventory"), ("inspect", "tree", "--entries"),
    ("inspect", "unclassified", "--entries"), ("inspect", "find", "subject"), ("check", "validate"),
    ("check", "conform", "--status", "all"),
]


def seen_by(vault, *command, fmt="text"):
    result = invoke(vault, *command, "-f", fmt)
    assert result.exit_code in (0, 1), f"{command}: {result.output} {result.stderr or ''}"
    return (result.stdout or "") + (result.stderr or "")


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("command", COMMANDS, ids=[" ".join(c) for c in COMMANDS])
def test_no_command_shows_an_old_value_or_a_secret(vault, command, fmt):
    output = seen_by(vault, *command, fmt=fmt)
    for token in (OLD["password"], OLD["password2"], OLD["token"], OLD["serial"], OLD["username"],
                  NOW["password"], NOW["token"]):
        assert token not in output, f"{token!r} appears in `pdh {' '.join(command)} -f {fmt}`"


def test_the_history_report_names_the_fields_that_changed_and_nothing_else(vault):
    snapshots = json.loads(seen_by(vault, "inspect", "history", "G/subject", fmt="json"))["snapshots"]
    assert len(snapshots) == 2 and all(set(s) == {"index", "modified", "changed"} for s in snapshots)
    assert "Password" in snapshots[1]["changed"]  # the report says *that* it changed, never *to what*


def test_searching_in_fields_does_not_look_into_history(vault):
    for old in (OLD["password"], OLD["password2"], OLD["token"], OLD["serial"]):
        found = json.loads(seen_by(vault, "inspect", "find", old, "--in-fields", fmt="json"))["entries"]
        assert found == [], f"a search for {old!r} found an entry through its history"


@pytest.mark.parametrize("secrets", [False, True])
def test_an_export_never_contains_history(vault, tmp_path, secrets):
    out = tmp_path / ("with.csv" if secrets else "without.csv")
    args = ["io", "export-csv", "--out", str(out), *(["--with-secrets"] if secrets else [])]
    assert invoke(vault, *args).exit_code == 0
    text = out.read_text(encoding="utf-8")
    for token in (OLD["password"], OLD["password2"], OLD["token"], OLD["serial"], OLD["username"]):
        assert token not in text
    if not secrets:
        assert NOW["password"] not in text and NOW["token"] not in text


def test_the_fixture_really_keeps_the_old_values_in_its_history(vault):
    """Without this the tests above could pass on an empty history."""
    kp = pykeepass_open(vault, DEFAULT_PASSWORD, None)
    e = next(x for x in kp.entries if x.title == "subject")
    old = [(h.password, h.username, h.get_custom_property("api_token"), h.get_custom_property("serial")) for h in e.history]
    assert old == [(OLD["password"], OLD["username"], OLD["token"], OLD["serial"]),
                   (OLD["password2"], OLD["username"], OLD["token"], OLD["serial"])]
    assert (e.password, e.get_custom_property("api_token")) == (NOW["password"], NOW["token"])


@pytest.mark.parametrize("apply", [[], ["--apply"]], ids=["dry-run", "applied"])
def test_the_write_commands_do_not_print_old_values_either(vault, apply):
    for command in (("edit", "history-restore", "G/subject", "0", *apply), ("edit", "history-prune", "--keep", "1", *apply)):
        result = invoke(vault, *command)
        shown = (result.stdout or "") + (result.stderr or "")
        for token in (*OLD.values(), NOW["password"], NOW["token"]):
            assert token not in shown, f"{token!r} appears in `pdh {' '.join(command)}`"
