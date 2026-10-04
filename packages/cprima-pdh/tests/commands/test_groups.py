"""Group commands: rename, move, delete (to the recycle bin), notes, icon. Entries below a group keep their UUIDs and data."""
import pytest
from pdh_testkit import DEFAULT_PASSWORD
from pdh_testkit.mess import messy_vault

from cprima_pdh.source import pykeepass_open
from pdh_testkit.cli import invoke

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")


@pytest.fixture
def vault(tmp_path):
    return messy_vault(tmp_path / "m.kdbx").path


def kp_of(vault):
    return pykeepass_open(vault, DEFAULT_PASSWORD, None)


def group(vault, name):
    return next(g for g in kp_of(vault).groups if g.name == name)


def snapshot(vault):
    """uuid -> (title, password) of every entry: groups may change, entries must not."""
    return {str(e.uuid): (e.title, e.password) for e in kp_of(vault).entries}


# --- rename ---------------------------------------------------------------------------------------------------------

def test_rename_changes_the_name_and_nothing_inside(vault):
    before_bytes, entries, uid = vault.read_bytes(), snapshot(vault), str(group(vault, "Money").uuid)
    assert invoke(vault, "edit", "rename-group", "Money", "Cash").exit_code == 0 and vault.read_bytes() == before_bytes
    assert invoke(vault, "edit", "rename-group", "Money", "Cash", "--apply").exit_code == 0
    g = group(vault, "Cash")
    assert str(g.uuid) == uid and not any(x.name == "Money" for x in kp_of(vault).groups)
    assert snapshot(vault) == entries
    assert {e.title for e in g.entries} >= {"With history", "Tagged"}


@pytest.mark.parametrize("new", ["", "a/b", "Other"])  # empty, a slash, a sibling's name
def test_rename_refuses_bad_names(vault, new):
    assert invoke(vault, "edit", "rename-group", "Money", new, "--apply").exit_code == 2


def test_the_root_and_the_recycle_bin_cannot_be_renamed(vault):
    assert invoke(vault, "edit", "rename-group", "/", "x", "--apply").exit_code == 2
    assert invoke(vault, "edit", "rename-group", "Recycle Bin", "x", "--apply").exit_code == 2


# --- move -----------------------------------------------------------------------------------------------------------

def test_move_puts_a_group_below_another_and_keeps_its_content(vault):
    entries, uid = snapshot(vault), str(group(vault, "Deep").uuid)
    assert invoke(vault, "edit", "move-group", "Deep", "Other", "--cross-top-level", "--apply").exit_code == 0
    g = group(vault, "Deep")
    assert str(g.uuid) == uid and "/".join(g.parentgroup.path) == "Other"
    assert snapshot(vault) == entries


def test_move_refuses_a_group_into_itself_or_below_itself(vault):
    assert invoke(vault, "edit", "move-group", "Deep", "Deep", "--cross-top-level", "--apply").exit_code == 2
    assert invoke(vault, "edit", "move-group", "Deep", "Deep/Deeper", "--cross-top-level", "--apply").exit_code == 2


def test_move_stays_inside_one_top_level_group_unless_told_otherwise(vault):
    assert invoke(vault, "edit", "move-group", "Other", "Money", "--apply").exit_code == 2  # both under the root: same top
    # Deep/Deeper to Money crosses from one top-level group to another
    assert invoke(vault, "edit", "move-group", "Deep/Deeper", "Money", "--apply").exit_code == 2
    assert invoke(vault, "edit", "move-group", "Deep/Deeper", "Money", "--cross-top-level", "--apply").exit_code == 0


def test_move_refuses_a_name_the_destination_already_has(vault):
    assert invoke(vault, "edit", "move-group", "Deep/Deeper", "Deep", "--cross-top-level", "--apply").exit_code == 2


# --- delete ---------------------------------------------------------------------------------------------------------

def test_delete_group_moves_it_with_everything_in_it_to_the_recycle_bin(vault):
    entries, uid = snapshot(vault), str(group(vault, "Deep").uuid)
    assert invoke(vault, "edit", "delete-group", "Deep").exit_code == 0 and any(g.name == "Deep" for g in kp_of(vault).groups)
    assert invoke(vault, "edit", "delete-group", "Deep", "--apply").exit_code == 0
    kp = kp_of(vault)
    g = next(x for x in kp.groups if str(x.uuid) == uid)
    assert g.parentgroup.uuid == kp.recyclebin_group.uuid
    assert snapshot(vault) == entries  # nothing deleted, only moved with the group


def test_delete_group_refuses_the_root_the_bin_and_groups_already_in_it(vault):
    assert invoke(vault, "edit", "delete-group", "/", "--apply").exit_code == 2
    assert invoke(vault, "edit", "delete-group", "Recycle Bin", "--apply").exit_code == 2
    invoke(vault, "edit", "delete-group", "Deep", "--apply")
    assert invoke(vault, "edit", "delete-group", "Recycle Bin/Deep", "--apply").exit_code == 2


# --- notes and icon -------------------------------------------------------------------------------------------------

def test_notes_and_icon_are_set(vault):
    assert invoke(vault, "edit", "group-notes", "Money", "money notes", "--apply").exit_code == 0
    assert invoke(vault, "edit", "group-icon", "Money", "9", "--apply").exit_code == 0
    g = group(vault, "Money")
    assert g.notes == "money notes" and str(g.icon) == "9"


def test_an_icon_outside_the_standard_set_is_refused_and_the_same_value_is_a_noop(vault):
    assert invoke(vault, "edit", "group-icon", "Money", "99", "--apply").exit_code == 2
    before = vault.read_bytes()
    assert invoke(vault, "edit", "group-notes", "Notes group", "about this group", "--apply").exit_code == 0
    assert vault.read_bytes() == before
