"""`pdh edit rename-field --all OLD NEW`: rename one custom field on every entry that has it. Dry run unless --apply."""
import json

import pytest
from pdh_testkit.stubs import E, StubGroup, StubKP
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from pykeepass import PyKeePass
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app
from cprima_pdh.fix import plan_rename_all
from cprima_pdh.write import WriteError
from pdh_testkit.cli import invoke


def rows(plan):
    return [(a.entry, a.key, a.action, a.new_key) for a in plan.actions]


# --- planning: only entries that have the old field, nothing else ----------------------------------------

def test_every_entry_with_the_field_is_planned():
    kp = StubKP([E(title="a", custom={"Kundennummer": "1"}), E(title="b", custom={"Kundennummer": "2"}),
                 E(title="c", custom={"other": "3"})])
    plan = plan_rename_all(kp, "Kundennummer", "customer_no")
    assert rows(plan) == [("Area/a", "Kundennummer", "rename", "customer_no"),
                          ("Area/b", "Kundennummer", "rename", "customer_no")]
    assert plan.applied is False and plan.entries_touched == 2


def test_an_entry_that_already_has_the_new_name_is_skipped_not_overwritten():
    kp = StubKP([E(title="a", custom={"Kundennummer": "1", "customer_no": "9"})])
    assert rows(plan_rename_all(kp, "Kundennummer", "customer_no")) == \
        [("Area/a", "Kundennummer", "skipped: customer_no already exists", "customer_no")]


def test_the_recycle_bin_is_left_alone():
    bin_ = StubGroup(["Recycle Bin"])
    kp = StubKP([E(title="live", custom={"old": "1"}), E(title="gone", group=bin_, custom={"old": "1"})], bin_)
    assert [a.entry for a in plan_rename_all(kp, "old", "new").actions] == ["Area/live"]


def test_under_limits_the_rename_to_one_group_tree():
    kp = StubKP([E(title="a", group="alex/IT", custom={"old": "1"}), E(title="b", group="alex", custom={"old": "1"}),
                 E(title="c", group="sam/IT", custom={"old": "1"}), E(title="d", group="alex2", custom={"old": "1"})])
    plan = plan_rename_all(kp, "old", "new", under="alex")
    assert sorted(a.entry for a in plan.actions) == ["alex/IT/a", "alex/b"]  # `alex2` is another group


@pytest.mark.parametrize("old,new", [("Title", "x"), ("otp", "x"), ("TimeOtp-Secret", "x"), ("x", "Password"),
                                     ("x", "HmacOtp-Counter"), ("same", "same"), ("", "x"), ("x", "")])
def test_standard_otp_empty_and_identical_names_are_refused(old, new):
    with pytest.raises(WriteError):
        plan_rename_all(StubKP([E(custom={"x": "1", "same": "1"})]), old, new)


def test_no_value_ever_appears_in_the_plan():
    plan = plan_rename_all(StubKP([E(custom={"old": "S3CR3T-VALUE"})]), "old", "new")
    assert "S3CR3T-VALUE" not in plan.model_dump_json()


# --- writing, on a real (synthetic) file ------------------------------------------------------------------

@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [
        Entry("a", group="alex/IT", custom={"old": "1", "keep": "k"}, protected=frozenset({"old"})),
        Entry("b", group="alex", custom={"old": "2"}),
        Entry("c", group="sam", custom={"old": "3"}),
        Entry("d", group="alex", custom={"keep": "4"}),
    ])


@pytest.fixture(autouse=True)
def opens_with_the_test_password(monkeypatch):
    from cprima_pdh_kdbxkit.kdbx_vault import pykeepass_open

    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, None))


def custom(vault):
    kp = PyKeePass(str(vault), password=DEFAULT_PASSWORD)
    return {e.title: (dict(e.custom_properties), [k for k in e.custom_properties
                                                  if e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=k)])
            for e in kp.entries}


def test_a_dry_run_writes_nothing(vault):
    before = vault.read_bytes()
    result = invoke(vault, "edit", "rename-field", "--all", "old", "new", "-f", "json")
    assert result.exit_code == 0 and json.loads(result.stdout)["applied"] is False
    assert vault.read_bytes() == before


def test_apply_renames_everywhere_keeping_value_and_protection(vault):
    result = invoke(vault, "edit", "rename-field", "--all", "old", "new", "--apply", "-f", "json")
    assert result.exit_code == 0, result.output
    state = custom(vault)
    assert state["a"] == ({"new": "1", "keep": "k"}, ["new"])  # value kept, protection kept
    assert state["b"][0] == {"new": "2"} and state["c"][0] == {"new": "3"} and state["d"][0] == {"keep": "4"}


def test_apply_with_under_touches_only_that_tree(vault):
    assert invoke(vault, "edit", "rename-field", "--all", "old", "new", "--under", "alex", "--apply").exit_code == 0
    state = custom(vault)
    assert "new" in state["a"][0] and "new" in state["b"][0] and "old" in state["c"][0]  # `sam` untouched


def test_nothing_to_rename_is_not_an_error_and_writes_nothing(vault):
    before = vault.read_bytes()
    result = invoke(vault, "edit", "rename-field", "--all", "missing", "new", "--apply", "-f", "json")
    assert result.exit_code == 0 and json.loads(result.stdout)["entries_touched"] == 0
    assert vault.read_bytes() == before


# --- the command line ---------------------------------------------------------------------------------------

def test_all_takes_two_arguments_and_without_it_three(vault):
    assert invoke(vault, "edit", "rename-field", "--all", "only-one").exit_code == 2
    assert invoke(vault, "edit", "rename-field", "alex/b", "old").exit_code == 2  # path + old, new missing
    assert invoke(vault, "edit", "rename-field", "alex/b", "old", "new").exit_code == 0  # the single form still works


def test_under_needs_all(vault):
    assert invoke(vault, "edit", "rename-field", "alex/b", "old", "new", "--under", "alex").exit_code == 2


def test_refused_names_exit_with_a_message(vault):
    result = invoke(vault, "edit", "rename-field", "--all", "Password", "x")
    assert result.exit_code != 0 and "refused" in result.output


def test_a_bulk_rename_leaves_one_history_snapshot_per_touched_entry_and_none_on_the_others(vault):
    assert invoke(vault, "edit", "rename-field", "--all", "old", "new", "--apply").exit_code == 0
    kp = PyKeePass(str(vault), password=DEFAULT_PASSWORD)
    by = {e.title: e for e in kp.entries}
    assert [len(by[t].history) for t in ("a", "b", "c")] == [1, 1, 1] and len(by["d"].history) == 0
    assert by["a"].history[0].get_custom_property("old") == "1"  # undo is possible: the old name is in the snapshot


def test_vocabulary_snapshots_the_entries_it_changes(tmp_path):
    vocab = synthetic_vault(tmp_path / "x.kdbx", [Entry("a", group="G", custom={"serialnumber": "1"}),
                                                   Entry("b", group="G", custom={"fine": "2"})])
    result = CliRunner().invoke(app, ["--db", str(vocab), "--schemas", str(_aliases(tmp_path)), "edit", "vocabulary", "--apply"])
    assert result.exit_code == 0, result.output
    kp = PyKeePass(str(vocab), password=DEFAULT_PASSWORD)
    by = {e.title: e for e in kp.entries}
    assert by["a"].get_custom_property("serial_number") == "1" and len(by["a"].history) == 1 and len(by["b"].history) == 0


def _aliases(tmp_path):
    f = tmp_path / "t.toml"
    f.write_text(
        "\n".join(["[field.serial_number]", 'aliases = ["serialnumber"]', "[schema.s]", 'required = ["Title"]', ""]),
        encoding="utf-8")
    return f
