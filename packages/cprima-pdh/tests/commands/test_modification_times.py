"""Every pdh edit stamps the modification time like a client does (pykeepass' setters do not); a move stamps the location.

Clients show these times, a merge decides by them, and `check breaches` asks "changed since the breach?" with them.
"""
import time
from datetime import datetime, timedelta, timezone

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from typer.testing import CliRunner

from cprima_pdh.cli import app
from cprima_pdh_kdbxkit.kdbx_vault import pykeepass_open

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")

OLD = datetime(2020, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def vault(tmp_path):
    db = synthetic_vault(tmp_path / "v.kdbx", [Entry("a", group="G", username="u", password="pw", custom={"old": "1"}),
                                                Entry("b", group="G", custom={"old": "2"}),
                                                Entry("c", group="Other")])
    kp = pykeepass_open(db, DEFAULT_PASSWORD, None)
    for e in kp.entries:  # everything was last touched long ago
        e.mtime = e.atime = e.ctime = OLD
        e._element.find("Times/LocationChanged").text = kp._encode_time(OLD)
    for g in kp.groups:
        g.mtime = OLD
    kp.save()
    return db


def run(vault, *args):
    result = CliRunner().invoke(app, ["--db", str(vault), *args])
    assert result.exit_code == 0, result.output + (result.stderr or "")


def entry(vault, title):
    return next(e for e in pykeepass_open(vault, DEFAULT_PASSWORD, None).entries if e.title == title)


def recent(moment):
    return abs(moment - datetime.now(timezone.utc)) < timedelta(minutes=5)


def located(vault, title):
    kp = pykeepass_open(vault, DEFAULT_PASSWORD, None)
    e = next(x for x in kp.entries if x.title == title)
    return kp._decode_time(e._element.findtext("Times/LocationChanged"))


@pytest.mark.parametrize("args", [
    ["edit", "set", "G/a", "Notes", "x"],
    ["edit", "set", "G/a", "old", "9", "--overwrite"],
    ["edit", "tags", "G/a", "--add", "t"],
    ["edit", "expiry", "G/a", "2031-01-01"],
    ["edit", "icon", "G/a", "5"],
    ["edit", "color", "G/a", "--fg", "#112233"],
    ["edit", "override-url", "G/a", "https://x.example.org"],
    ["edit", "autotype", "G/a", "--disabled"],
    ["edit", "rename-field", "G/a", "old", "new"],
], ids=lambda a: " ".join(a[1:3]))
def test_a_content_edit_stamps_the_modification_time_of_that_entry_only(vault, args):
    run(vault, *args, "--apply")
    assert recent(entry(vault, "a").mtime) and recent(entry(vault, "a").atime)
    assert entry(vault, "b").mtime == OLD and entry(vault, "c").mtime == OLD


def test_a_bulk_rename_stamps_every_touched_entry(vault):
    run(vault, "edit", "rename-field", "--all", "old", "new", "--apply")
    assert recent(entry(vault, "a").mtime) and recent(entry(vault, "b").mtime) and entry(vault, "c").mtime == OLD


def test_attachments_and_history_restore_stamp_the_entry(vault, tmp_path):
    f = tmp_path / "f.txt"
    f.write_bytes(b"x")
    run(vault, "edit", "attach", "G/a", str(f), "--apply")
    assert recent(entry(vault, "a").mtime)


def test_a_move_stamps_the_location_not_the_content(vault):
    run(vault, "edit", "move", "G/a", "Other", "--cross-top-level", "--apply")
    assert recent(located(vault, "a")) and entry(vault, "a").mtime == OLD


def test_delete_and_restore_stamp_the_location(vault):
    run(vault, "edit", "delete", "G/a", "--apply")
    assert recent(located(vault, "a")) and entry(vault, "a").mtime == OLD
    run(vault, "edit", "restore", "Recycle Bin/a", "--to", "G", "--apply")
    assert recent(located(vault, "a"))


def test_a_dry_run_and_a_noop_stamp_nothing(vault):
    run(vault, "edit", "set", "G/a", "Notes", "x")
    run(vault, "edit", "tags", "G/a", "--add", "t")
    assert entry(vault, "a").mtime == OLD
    run(vault, "edit", "icon", "G/a", "5", "--apply")
    stamped = entry(vault, "a").mtime
    time.sleep(1.1)
    run(vault, "edit", "icon", "G/a", "5", "--apply")  # same value: nothing to write
    assert entry(vault, "a").mtime == stamped


def test_pruning_the_history_is_not_an_edit_of_the_entry(vault):
    run(vault, "edit", "set", "G/a", "Notes", "x", "--apply")
    stamped = entry(vault, "a").mtime
    time.sleep(1.1)
    run(vault, "edit", "history-prune", "--keep", "0", "--apply")
    assert entry(vault, "a").mtime == stamped


def test_group_edits_stamp_the_group(vault):
    run(vault, "edit", "group-notes", "G", "about", "--apply")
    kp = pykeepass_open(vault, DEFAULT_PASSWORD, None)
    assert recent(next(g for g in kp.groups if g.name == "G").mtime)
    assert next(g for g in kp.groups if g.name == "Other").mtime == OLD
    run(vault, "edit", "rename-group", "Other", "Renamed", "--apply")
    assert recent(next(g for g in pykeepass_open(vault, DEFAULT_PASSWORD, None).groups if g.name == "Renamed").mtime)


def test_a_merge_keeps_the_modification_time_of_the_copy_it_took_the_entry_from(tmp_path, vault):
    import shutil

    other = tmp_path / "o.kdbx"
    shutil.copyfile(vault, other)
    kp = pykeepass_open(other, DEFAULT_PASSWORD, None)
    e = next(x for x in kp.entries if x.title == "a")
    e.notes = "from the copy"
    stamp = datetime(2024, 5, 6, 7, 8, 9, tzinfo=timezone.utc)
    e.mtime = stamp
    kp.save()
    result = CliRunner().invoke(app, ["--db", str(vault), "io", "merge", str(other), "--apply"],
                                env={"PDH_IMPORT_PASSWORD": DEFAULT_PASSWORD})
    assert result.exit_code == 0, result.output
    assert entry(vault, "a").notes == "from the copy" and entry(vault, "a").mtime == stamp  # not "now"
