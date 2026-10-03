"""History (`inspect history`, `edit history-restore`, `edit history-prune`) and attachments (`inspect attachments`,
`edit attach`, `edit detach`). Names, sizes and counts only: never a value, never attachment bytes."""
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD
from pdh_testkit.mess import messy_vault
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app
from cprima_pdh.source import pykeepass_open


@pytest.fixture
def vault(tmp_path):
    return messy_vault(tmp_path / "m.kdbx").path


@pytest.fixture(autouse=True)
def opens_with_the_test_password(monkeypatch):
    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, None))


def invoke(vault, *args):
    return CliRunner().invoke(app, ["--db", str(vault), *args])


def entry(vault, title):
    return next(e for e in pykeepass_open(vault, DEFAULT_PASSWORD, None).entries if e.title == title)


def data(vault, *args):
    result = invoke(vault, *args, "-f", "json")
    assert result.exit_code == 0, result.output + (result.stderr or "")
    return json.loads(result.stdout)


# --- inspect history --------------------------------------------------------------------------------------------

def test_history_lists_snapshots_with_the_names_of_what_changed_and_no_values(vault):
    report = data(vault, "inspect", "history", "Money/With history")
    assert [s["index"] for s in report["snapshots"]] == [0, 1, 2]
    assert all(s["changed"] == ["Password"] for s in report["snapshots"])  # only the password changed, each time
    assert "pw-" not in json.dumps(report)


def test_an_entry_without_history_has_an_empty_report(vault):
    assert data(vault, "inspect", "history", "Money/Tagged")["snapshots"] == []


# --- edit history-restore ---------------------------------------------------------------------------------------

def test_restore_brings_back_an_earlier_state_and_keeps_the_current_one_in_the_history(vault):
    before = vault.read_bytes()
    assert invoke(vault, "edit", "history-restore", "Money/With history", "0").exit_code == 0
    assert vault.read_bytes() == before  # a dry run
    assert invoke(vault, "edit", "history-restore", "Money/With history", "0", "--apply").exit_code == 0
    e = entry(vault, "With history")
    assert e.password == "pw-0" and len(e.history) == 4  # three old states plus the one just replaced
    assert e.history[-1].password == "pw-3"


def test_restore_refuses_an_index_that_does_not_exist(vault):
    assert invoke(vault, "edit", "history-restore", "Money/With history", "9", "--apply").exit_code == 2
    assert invoke(vault, "edit", "history-restore", "Money/Tagged", "0", "--apply").exit_code == 2


# --- edit history-prune -----------------------------------------------------------------------------------------

def test_prune_keeps_the_newest_snapshots_of_one_entry(vault):
    plan = data(vault, "edit", "history-prune", "Money/With history", "--keep", "1")
    assert plan["applied"] is False and plan["removed"] == 2 and len(entry(vault, "With history").history) == 3
    assert invoke(vault, "edit", "history-prune", "Money/With history", "--keep", "1", "--apply").exit_code == 0
    e = entry(vault, "With history")
    assert len(e.history) == 1 and e.history[0].password == "pw-2"  # the newest of the three kept
    assert e.password == "pw-3"


def test_prune_without_a_path_covers_every_entry(vault):
    plan = data(vault, "edit", "history-prune", "--keep", "0", "--apply")
    assert plan["applied"] is True and plan["removed"] == 3 and plan["entries"] == 1
    assert all(len(e.history) == 0 for e in pykeepass_open(vault, DEFAULT_PASSWORD, None).entries)


def test_prune_with_nothing_to_remove_is_a_noop(vault):
    before = vault.read_bytes()
    plan = data(vault, "edit", "history-prune", "--keep", "5", "--apply")
    assert plan["removed"] == 0 and plan["applied"] is False and vault.read_bytes() == before


# --- attachments ----------------------------------------------------------------------------------------------------

def test_attachments_are_listed_by_name_and_size(vault):
    report = data(vault, "inspect", "attachments", "Money/With attachments")
    assert [(a["name"], a["size"]) for a in report["attachments"]] == [("note.txt", 5), ("data.bin", 16)]
    assert "hello" not in json.dumps(report)


def test_attach_adds_a_file_and_keeps_the_others(vault, tmp_path):
    f = tmp_path / "new.txt"
    f.write_bytes(b"fresh bytes")
    assert invoke(vault, "edit", "attach", "Money/Tagged", str(f)).exit_code == 0 and not entry(vault, "Tagged").attachments
    assert invoke(vault, "edit", "attach", "Money/Tagged", str(f), "--name", "renamed.txt", "--apply").exit_code == 0
    t = entry(vault, "Tagged")
    assert [(a.filename, a.data) for a in t.attachments] == [("renamed.txt", b"fresh bytes")]
    both = {a.filename: a.data for a in entry(vault, "With attachments").attachments}
    assert both == {"note.txt": b"hello", "data.bin": bytes(range(16))}


def test_attach_refuses_a_duplicate_name_and_a_missing_file(vault, tmp_path):
    f = tmp_path / "note.txt"
    f.write_bytes(b"x")
    assert invoke(vault, "edit", "attach", "Money/With attachments", str(f), "--apply").exit_code == 2
    assert invoke(vault, "edit", "attach", "Money/Tagged", str(tmp_path / "nope.txt"), "--apply").exit_code == 2


def test_detach_removes_one_attachment_and_keeps_the_other_intact(vault):
    assert invoke(vault, "edit", "detach", "Money/With attachments", "note.txt", "--apply").exit_code == 0
    left = entry(vault, "With attachments").attachments
    assert [(a.filename, a.data) for a in left] == [("data.bin", bytes(range(16)))]


def test_detach_refuses_an_unknown_name(vault):
    assert invoke(vault, "edit", "detach", "Money/With attachments", "zzz", "--apply").exit_code == 2
