"""History (`inspect history`, `edit history-restore`, `edit history-prune`) and attachments (`inspect attachments`,
`edit attach`, `edit detach`). Names, sizes and counts only: never a value, never attachment bytes."""
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD
from pdh_testkit.mess import messy_vault
from typer.testing import CliRunner

from cprima_pdh.cli import app
from cprima_pdh_kdbxkit.kdbx_vault import pykeepass_open
from pdh_testkit.cli import invoke

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")


@pytest.fixture
def vault(tmp_path):
    return messy_vault(tmp_path / "m.kdbx").path


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


# --- a one-time password that did not exist in the snapshot (found by the end-to-end run) --------------------------------

def _entry_that_got_an_otp_later(vault):
    from pykeepass import PyKeePass

    kp = PyKeePass(str(vault), password=DEFAULT_PASSWORD)
    e = next(x for x in kp.entries if x.title == "Tagged")
    e.save_history()
    e.otp = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
    kp.save()


def test_restoring_a_state_from_before_the_otp_removes_the_otp(vault):
    _entry_that_got_an_otp_later(vault)
    assert entry(vault, "Tagged").otp
    assert invoke(vault, "edit", "history-restore", "Money/Tagged", "0", "--apply").exit_code == 0
    assert not entry(vault, "Tagged").otp


def test_restoring_a_state_that_had_an_otp_brings_it_back(vault):
    _entry_that_got_an_otp_later(vault)
    from pykeepass import PyKeePass

    kp = PyKeePass(str(vault), password=DEFAULT_PASSWORD)
    e = next(x for x in kp.entries if x.title == "Tagged")
    e.save_history()
    e.otp = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ"  # a second secret
    kp.save()
    assert invoke(vault, "edit", "history-restore", "Money/Tagged", "1", "--apply").exit_code == 0
    assert "JBSWY3DPEHPK3PXP" in entry(vault, "Tagged").otp


def test_a_merge_takes_over_the_removal_of_an_otp(tmp_path):
    from datetime import datetime, timedelta, timezone
    import shutil

    from pykeepass import PyKeePass

    local = messy_vault(tmp_path / "l.kdbx").path
    kp = PyKeePass(str(local), password=DEFAULT_PASSWORD)
    next(x for x in kp.entries if x.title == "Tagged").otp = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
    kp.save()
    other = tmp_path / "o.kdbx"
    shutil.copyfile(local, other)
    ko = PyKeePass(str(other), password=DEFAULT_PASSWORD)
    t = next(x for x in ko.entries if x.title == "Tagged")
    t.save_history()  # a client keeps the state an edit replaces; the merge reads the order of two copies from it
    t._element.remove(t._element.xpath("String[Key='otp']")[0])  # the other copy dropped its otp, later
    t.mtime = datetime.now(timezone.utc) + timedelta(hours=1)
    ko.save()
    result = CliRunner().invoke(app, ["--db", str(local), "io", "merge", str(other), "--apply"],
                                env={"PDH_IMPORT_PASSWORD": DEFAULT_PASSWORD})
    assert result.exit_code == 0, result.output + (result.stderr or "")
    assert not entry(local, "Tagged").otp
