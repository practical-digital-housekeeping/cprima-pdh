"""What a merge would do, as data: what loses nothing is done by itself, what would drop a change is a conflict (git's way).

Pure: two memory vaults in, a `MergeSituation` out; nothing is written, printed or asked. `target` changes, `source` is only read.
"""
from dataclasses import replace
from datetime import datetime, timezone

from cprima_pdh_vault.memory import MemoryVault
from cprima_pdh_vault.vault import EntryData

from cprima_pdh.merge import merge_situation

T0, T1, T2, T3 = (datetime(year, 1, 1, tzinfo=timezone.utc) for year in (2020, 2021, 2022, 2023))
A, B, C = ("00000000-0000-4000-8000-00000000000%d" % n for n in (1, 2, 3))


def entry(eid, title="t", group="G", mtime=T0, **kw):
    return EntryData(id=eid, group_path=group, title=title, password="secret-pw", mtime=mtime, ctime=T0, **kw)


def twins(*entries):
    """Two independent copies of one vault (the same entries and groups, then each goes its own way)."""
    base = MemoryVault(list(entries))
    return MemoryVault(base.entries(), base.groups()), MemoryVault(base.entries(), base.groups())


def gid(vault, path="G"):
    return next(g.id for g in vault.groups() if g.path == path)


def edit(vault, eid, notes, snapshot=True):
    if snapshot:
        vault.snapshot_history(eid)  # what a client does before it changes an entry
    vault.set_field(eid, "Notes", notes)


def clean(situation):
    return sorted((c.kind, c.path) for c in situation.clean)


# --- the same entry in both copies -------------------------------------------------------------------------------------------

def test_identical_copies_have_nothing_to_do():
    mine, theirs = twins(entry(A))
    s = merge_situation(mine, theirs)
    assert (s.clean, s.conflicts, s.unchanged) == ([], [], 1)


def test_the_other_copy_has_gone_on_from_this_one_so_its_state_is_taken_without_a_question():
    mine, theirs = twins(entry(A))
    edit(theirs, A, "newer")  # its history now holds the state this copy is still at
    s = merge_situation(mine, theirs)
    assert clean(s) == [("update", "G/t")] and s.conflicts == []


def test_this_copy_has_gone_on_from_the_other_one_so_nothing_is_taken():
    mine, theirs = twins(entry(A))
    edit(mine, A, "newer")
    s = merge_situation(mine, theirs)
    assert (s.clean, s.conflicts, s.unchanged) == ([], [], 1)


def test_both_copies_changed_it_differently_is_a_conflict_that_names_the_fields_and_never_a_value():
    mine, theirs = twins(entry(A))
    edit(mine, A, "my notes")
    edit(theirs, A, "their notes")
    theirs.set_field(A, "Password", "another-secret")
    s = merge_situation(mine, theirs)
    assert s.clean == [] and len(s.conflicts) == 1
    conflict = s.conflicts[0]
    assert conflict.kind == "both-modified" and conflict.id == A and conflict.choices == ["mine", "theirs"]
    assert conflict.fields == ["Notes", "Password"]
    dumped = s.model_dump_json()
    for value in ("secret-pw", "another-secret", "my notes", "their notes"):
        assert value not in dumped


def test_without_history_nothing_can_be_shown_so_it_is_a_conflict_and_the_clocks_do_not_decide():
    mine, theirs = twins(entry(A, mtime=T3))
    edit(theirs, A, "changed", snapshot=False)
    theirs.overwrite_entry(A, replace(theirs.find_entry("G/t"), mtime=T0), keep_mtime=True)  # theirs is much older
    edit(mine, A, "also changed", snapshot=False)
    s = merge_situation(mine, theirs)
    assert [c.kind for c in s.conflicts] == ["both-modified"] and s.clean == []


# --- only one copy has it ------------------------------------------------------------------------------------------------------

def test_an_entry_only_the_other_copy_has_is_added():
    mine, theirs = twins(entry(A))
    theirs.add_entry(gid(theirs), entry(B, "new"), keep_id=True, keep_times=True)
    assert clean(merge_situation(mine, theirs)) == [("add", "G/new")]


def test_an_entry_in_the_others_bin_is_not_brought_back():
    mine, theirs = twins(entry(A))
    theirs.add_entry(gid(theirs), entry(B, "binned"), keep_id=True)
    theirs.trash_entry(B)
    s = merge_situation(mine, theirs)
    assert s.clean == [] and s.skipped == 1


def test_the_direction_matters_only_the_target_changes():
    mine, theirs = twins(entry(A))
    theirs.add_entry(gid(theirs), entry(B, "new"), keep_id=True)
    assert clean(merge_situation(mine, theirs)) == [("add", "G/new")]
    assert clean(merge_situation(theirs, mine)) == []  # the other way round there is nothing to add


# --- deletions need their record -----------------------------------------------------------------------------------------------

def test_an_entry_the_other_copy_deleted_and_nobody_changed_since_goes():
    mine, theirs = twins(entry(A, mtime=T0), entry(B))
    theirs.purge_entry(A)
    theirs.record_deleted({A: T2})
    s = merge_situation(mine, theirs)
    assert clean(s) == [("delete", "G/t")] and s.conflicts == [] and s.records_to_copy == 1


def test_an_entry_missing_in_the_other_copy_without_a_record_is_kept():
    mine, theirs = twins(entry(A), entry(B))
    theirs._entries = [e for e in theirs._entries if e.id != A]  # it just lacks it: no record, so nothing says it was deleted
    s = merge_situation(mine, theirs)
    assert s.clean == [] and s.conflicts == []


def test_deleted_there_but_changed_here_afterwards_is_a_conflict():
    mine, theirs = twins(entry(A, mtime=T3), entry(B))
    theirs.purge_entry(A)
    theirs.record_deleted({A: T2})
    c = merge_situation(mine, theirs).conflicts
    assert [(x.kind, x.choices, x.deleted_at) for x in c] == [("deleted-there-modified-here", ["keep", "delete"], T2)]


def test_deleted_here_and_not_changed_there_stays_deleted():
    mine, theirs = twins(entry(A, mtime=T0), entry(B))
    mine.purge_entry(A)
    mine.record_deleted({A: T2})
    s = merge_situation(mine, theirs)
    assert s.clean == [] and s.conflicts == [] and s.skipped == 1


def test_deleted_here_but_changed_there_afterwards_is_a_conflict():
    mine, theirs = twins(entry(A, mtime=T3), entry(B))
    mine.purge_entry(A)
    mine.record_deleted({A: T2})
    c = merge_situation(mine, theirs).conflicts
    assert [(x.kind, x.choices) for x in c] == [("deleted-here-modified-there", ["keep", "delete"])]


def test_a_record_beside_an_entry_that_is_alive_in_both_copies_is_moot():
    mine, theirs = twins(entry(A), entry(B))
    theirs.record_deleted({A: T2})  # (legal: a client may keep a record beside a live entry)
    s = merge_situation(mine, theirs)
    assert s.clean == [] and s.conflicts == [] and s.unchanged == 2


def test_both_copies_deleted_it_leaves_nothing_to_do_but_the_records():
    mine, theirs = twins(entry(A), entry(B))
    mine.purge_entry(A)
    theirs.purge_entry(A)
    mine.record_deleted({A: T1})
    theirs.record_deleted({A: T2})
    s = merge_situation(mine, theirs)
    assert s.clean == [] and s.conflicts == [] and s.records_to_copy == 0  # this copy already has the earlier time


def test_a_record_for_an_entry_that_is_in_neither_copy_is_still_passed_on():
    mine, theirs = twins(entry(A))
    theirs.record_deleted({C: T2})
    s = merge_situation(mine, theirs)
    assert s.clean == [] and s.records_to_copy == 1


def test_a_record_with_an_earlier_time_than_the_one_held_is_passed_on():
    mine, theirs = twins(entry(A))
    mine.record_deleted({C: T2})
    theirs.record_deleted({C: T1})
    assert merge_situation(mine, theirs).records_to_copy == 1


# --- groups ------------------------------------------------------------------------------------------------------------------

def test_a_group_the_other_copy_deleted_goes_when_it_is_empty_after_its_entries_went():
    mine, theirs = twins(entry(A, "a1"), entry(B, "a2"), entry(C, "keep", group="Other"))
    theirs.purge_group(gid(theirs, "G"))
    s = merge_situation(mine, theirs)
    assert clean(s) == [("delete", "G/a1"), ("delete", "G/a2"), ("delete-group", "G")] and s.groups_kept == 0


def test_a_deleted_group_that_still_holds_something_stays():
    mine, theirs = twins(entry(A, "a1"), entry(B, "mine-only"))
    theirs._entries = [e for e in theirs._entries if e.id != B]  # theirs never had it
    theirs.purge_entry(A)
    theirs.record_deleted({gid(theirs): T2})
    s = merge_situation(mine, theirs)
    assert ("delete-group", "G") not in clean(s) and s.groups_kept == 1


# --- moves and the bin lose nothing, so they are not asked about --------------------------------------------------------------

def test_a_move_in_the_other_copy_is_followed():
    mine, theirs = twins(entry(A), entry(C, "x", group="Other"))
    theirs.move_entry(A, gid(theirs, "Other"))
    theirs.stamp({A}, set(), "location")
    assert clean(merge_situation(mine, theirs)) == [("move", "G/t")]


def test_an_entry_the_other_copy_put_in_its_bin_goes_to_the_bin_here_too():
    mine, theirs = twins(entry(A))
    theirs.trash_entry(A)
    theirs.stamp({A}, set(), "location")
    assert clean(merge_situation(mine, theirs)) == [("trash", "G/t")]
