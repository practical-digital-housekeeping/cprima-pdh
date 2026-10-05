"""`pdh io merge`, the way git merges: what loses nothing is done by itself, a conflict is a person's decision, and nothing is
written while one is open. Deletions follow the deletion records (a delete needs a record, otherwise a merge cannot tell a
deleted entry from one that never arrived). `target` is the vault the command runs on; the other copy is only read."""
import json
import shutil
from datetime import datetime, timedelta, timezone

import pytest
from pdh_testkit import DEFAULT_PASSWORD
from pdh_testkit.cli import invoke
from pdh_testkit.mess import messy_vault

from cprima_pdh_kdbxkit.kdbx_vault import KdbxVault, pykeepass_open

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")
ENV = {"PDH_IMPORT_PASSWORD": DEFAULT_PASSWORD}


@pytest.fixture
def pair(tmp_path):
    """The same vault twice, as after a sync conflict."""
    local = messy_vault(tmp_path / "local.kdbx").path
    other = tmp_path / "other.kdbx"
    shutil.copyfile(local, other)
    return local, other


def edit(db, title, **changes):
    """Change an entry the way a client does: keep the state it replaces in the history, then change it."""
    kp = pykeepass_open(db, DEFAULT_PASSWORD, None)
    e = next(x for x in kp.entries if x.title == title)
    e.save_history()
    for k, v in changes.items():
        setattr(e, k, v)
    e.mtime = datetime.now(timezone.utc) + timedelta(hours=1)
    kp.save()


def entry_id(db, title):
    return next(e.id for e in KdbxVault.open(db, DEFAULT_PASSWORD).entries() if e.title == title)


def purge(db, path, title):
    """Delete an entry for good the way pdh does: into the bin, then out of it."""
    for args in (("edit", "delete", path, "--apply"), ("edit", "purge", f"Recycle Bin/{title}", "--apply")):
        result = invoke(db, *args)
        assert result.exit_code == 0, result.output + (result.stderr or "")


def merge(target, other, *options, fmt="json", env=ENV):
    return invoke(target, "io", "merge", str(other), *options, "-f", fmt, env=env)


def report(result):
    return json.loads(result.stdout)  # all of stdout is the report, nothing else


def password(db, title):
    return next(e.password for e in pykeepass_open(db, DEFAULT_PASSWORD, None).entries if e.title == title)


def titles(db):
    return {e.title for e in KdbxVault.open(db, DEFAULT_PASSWORD).entries() if not e.in_bin}


def deleted(db):
    return KdbxVault.open(db, DEFAULT_PASSWORD).deleted_ids()


# --- a delete is remembered ---------------------------------------------------------------------------------------------------

def test_an_entry_this_vault_purged_is_not_brought_back_by_a_stale_copy(pair):
    local, other = pair
    gone = entry_id(local, "Tagged")
    purge(local, "Money/Tagged", "Tagged")
    assert gone in deleted(local)  # pdh wrote the record
    result = merge(local, other, "--apply")
    assert result.exit_code == 0 and report(result)["added"] == 0 and report(result)["skipped"] == 1
    assert "Tagged" not in titles(local)


def test_a_deletion_the_other_copy_recorded_removes_the_entry_here_but_only_with_apply(pair):
    local, other = pair
    gone = entry_id(other, "Soon")
    purge(other, "Other/Soon", "Soon")
    before = local.read_bytes()
    dry = report(merge(local, other))
    assert dry["deleted"] == 1 and dry["applied"] is False and local.read_bytes() == before and "Soon" in titles(local)
    done = report(merge(local, other, "--apply"))
    assert done["deleted"] == 1 and done["applied"] is True
    assert "Soon" not in titles(local) and gone in deleted(local)  # gone for good, and the record travels with it


# --- a conflict stops the merge ------------------------------------------------------------------------------------------------

def test_a_change_in_both_copies_is_a_conflict_nothing_is_written_and_the_exit_code_says_so(pair):
    local, other = pair
    edit(local, "Tagged", password="mine-secret")
    edit(other, "Tagged", password="theirs-secret")
    before = local.read_bytes()
    result = merge(local, other, "--apply")
    assert result.exit_code == 1 and local.read_bytes() == before
    r = report(result)
    assert r["applied"] is False and r["unresolved"] == 1
    conflict = r["conflicts"][0]
    assert (conflict["kind"], conflict["fields"], conflict["choices"]) == ("both-modified", ["Password"], ["mine", "theirs"])
    assert conflict["id"] == entry_id(local, "Tagged")


def test_the_report_names_the_conflict_and_never_shows_a_value(pair):
    local, other = pair
    edit(local, "Tagged", password="mine-secret")
    edit(other, "Tagged", password="theirs-secret")
    for fmt in ("json", "text"):
        result = merge(local, other, "--apply", fmt=fmt)
        out = (result.stdout or "") + (result.stderr or "")
        assert "mine-secret" not in out and "theirs-secret" not in out, fmt
    text = merge(local, other, fmt="text").stdout
    assert f"--resolve {entry_id(local, 'Tagged')}=<mine|theirs>" in text and "Money/Tagged" in text
    assert "differing fields: Password" in text and "nothing was written" in text


@pytest.mark.parametrize("answer,expected", [("theirs", "theirs-secret"), ("mine", "mine-secret")])
def test_a_conflict_answered_with_resolve_is_merged_that_way(pair, answer, expected):
    local, other = pair
    edit(local, "Tagged", password="mine-secret")
    edit(other, "Tagged", password="theirs-secret")
    result = merge(local, other, "--resolve", f"{entry_id(local, 'Tagged')}={answer}", "--apply")
    assert result.exit_code == 0 and report(result)["unresolved"] == 0
    assert password(local, "Tagged") == expected


@pytest.mark.parametrize("side,expected", [("theirs", "theirs-secret"), ("mine", "mine-secret")])
def test_prefer_answers_every_open_conflict_and_is_never_the_default(pair, side, expected):
    local, other = pair
    edit(local, "Tagged", password="mine-secret")
    edit(other, "Tagged", password="theirs-secret")
    assert merge(local, other, "--apply").exit_code == 1  # without --prefer a conflict stays open
    assert merge(local, other, "--prefer", side, "--apply").exit_code == 0
    assert password(local, "Tagged") == expected


def test_the_state_an_answer_replaces_is_kept_in_the_history(pair):
    local, other = pair
    edit(local, "Tagged", password="mine-secret")
    edit(other, "Tagged", password="theirs-secret")
    merge(local, other, "--prefer", "theirs", "--apply")
    kp = pykeepass_open(local, DEFAULT_PASSWORD, None)
    assert "mine-secret" in {h.password for h in next(e for e in kp.entries if e.title == "Tagged").history}


@pytest.mark.parametrize("args", [
    ("--resolve", "{id}=keep"),        # not an answer for a change in both copies
    ("--resolve", "no-such-id=mine"),  # not a conflict of this merge
    ("--resolve", "{id}"),             # not ID=ANSWER
    ("--prefer", "both"),              # not mine or theirs
])
def test_a_wrong_answer_is_refused_and_nothing_is_written(pair, args):
    local, other = pair
    edit(local, "Tagged", password="mine-secret")
    edit(other, "Tagged", password="theirs-secret")
    before = local.read_bytes()
    args = [a.format(id=entry_id(local, "Tagged")) for a in args]
    assert merge(local, other, *args, "--apply").exit_code == 2 and local.read_bytes() == before


# --- deleted in one copy, changed in the other -----------------------------------------------------------------------------------

def test_deleted_there_but_changed_here_afterwards_is_a_conflict_and_keep_or_delete_decides(pair):
    local, other = pair
    purge(other, "Other/Soon", "Soon")
    edit(local, "Soon", notes="changed after the deletion")
    uid = entry_id(local, "Soon")
    r = report(merge(local, other))
    assert [c["kind"] for c in r["conflicts"]] == ["deleted-there-modified-here"] and r["conflicts"][0]["choices"] == ["keep", "delete"]
    assert merge(local, other, "--apply").exit_code == 1 and "Soon" in titles(local)
    assert merge(local, other, "--resolve", f"{uid}=keep", "--apply").exit_code == 0 and "Soon" in titles(local)


def test_deleted_there_changed_here_and_answered_delete_removes_it(pair):
    local, other = pair
    purge(other, "Other/Soon", "Soon")
    edit(local, "Soon", notes="changed after the deletion")
    uid = entry_id(local, "Soon")
    assert merge(local, other, "--resolve", f"{uid}=delete", "--apply").exit_code == 0
    assert "Soon" not in titles(local)


def test_deleted_here_but_changed_there_afterwards_is_a_conflict_and_keep_brings_it_back(pair):
    local, other = pair
    purge(local, "Other/Soon", "Soon")
    edit(other, "Soon", notes="changed after the deletion")
    uid = entry_id(other, "Soon")
    r = report(merge(local, other))
    assert [c["kind"] for c in r["conflicts"]] == ["deleted-here-modified-there"]
    assert merge(local, other, "--resolve", f"{uid}=delete", "--apply").exit_code == 0 and "Soon" not in titles(local)
    assert merge(local, other, "--resolve", f"{uid}=keep", "--apply").exit_code == 0 and "Soon" in titles(local)


def test_after_a_kept_entry_is_merged_back_the_conflict_is_gone(pair):
    local, other = pair
    purge(other, "Other/Soon", "Soon")
    edit(local, "Soon", notes="changed after the deletion")
    uid = entry_id(local, "Soon")
    merge(local, other, "--resolve", f"{uid}=keep", "--apply")
    r = merge(other, local)  # the result merged back into the other copy: it has the record, this copy has the newer entry
    assert [c["kind"] for c in report(r)["conflicts"]] == ["deleted-here-modified-there"]
    assert merge(other, local, "--resolve", f"{uid}=keep", "--apply").exit_code == 0
    assert merge(local, other).exit_code == 0 and merge(other, local).exit_code == 0  # both ways: nothing left to decide


# --- both directions converge -----------------------------------------------------------------------------------------------------

def test_merging_both_ways_leaves_the_same_entries_and_the_same_records(pair):
    local, other = pair
    purge(local, "Money/Tagged", "Tagged")
    edit(other, "Soon", notes="edited in the other copy")
    assert merge(local, other, "--apply").exit_code == 0
    assert merge(other, local, "--apply").exit_code == 0
    assert titles(local) == titles(other) and "Tagged" not in titles(local)
    assert deleted(local) == deleted(other) and entry_id(other, "Soon")  # the record travelled to the other copy
    notes = lambda db: next(e.notes for e in KdbxVault.open(db, DEFAULT_PASSWORD).entries() if e.title == "Soon")  # noqa: E731
    assert notes(local) == notes(other) == "edited in the other copy"
    assert merge(local, other).exit_code == 0 and merge(other, local).exit_code == 0  # and nothing is left to do


def test_the_direction_matters_only_the_target_changes(pair):
    local, other = pair
    purge(other, "Money/Tagged", "Tagged")
    other_before = other.read_bytes()
    assert merge(local, other, "--apply").exit_code == 0
    assert other.read_bytes() == other_before and "Tagged" not in titles(local)  # the other copy is only read
