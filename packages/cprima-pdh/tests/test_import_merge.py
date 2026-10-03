"""`pdh io import-csv`, `import-kdbx` and `merge`: bring data in, by UUID and modification time where it is a merge."""
import json
import shutil
from datetime import datetime, timedelta, timezone

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from pdh_testkit.mess import messy_vault
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app
from cprima_pdh.source import pykeepass_open


def load(db, password=DEFAULT_PASSWORD):
    return pykeepass_open(db, password, None)


@pytest.fixture(autouse=True)
def opens_with_the_test_password(monkeypatch):
    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, None))


def invoke(vault, *args, env=None):
    return CliRunner().invoke(app, ["--db", str(vault), *args], env=env)


def data(vault, *args, env=None):
    result = invoke(vault, *args, "-f", "json", env=env)
    assert result.exit_code == 0, result.output + (result.stderr or "")
    return json.loads(result.stdout)


@pytest.fixture
def empty(tmp_path):
    return synthetic_vault(tmp_path / "target.kdbx", [Entry("existing", group="Keep")])


# --- import-csv -------------------------------------------------------------------------------------------------------

CSV = (
    "Group,Title,UserName,Password,URL,Notes,Tags,Expires,account_no\n"
    "Money/Cards,Visa,alex,pw-visa,https://visa.example.org,n1,a;b,2031-01-02,4711\n"
    "Money,Bank,sam,pw-bank,,,,,\n"
    ",Loose,x,pw-loose,,,,,\n"
)


def test_a_csv_is_imported_with_groups_tags_expiry_and_extra_columns(empty, tmp_path):
    f = tmp_path / "in.csv"
    f.write_text(CSV, encoding="utf-8")
    before = empty.read_bytes()
    plan = data(empty, "io", "import-csv", str(f), "--group", "Imported")
    assert plan["applied"] is False and plan["entries"] == 3 and plan["columns"] == ["account_no"] and empty.read_bytes() == before
    assert "pw-visa" not in json.dumps(plan)
    assert data(empty, "io", "import-csv", str(f), "--group", "Imported", "--apply")["applied"] is True
    kp = load(empty)
    visa = next(e for e in kp.entries if e.title == "Visa")
    assert "/".join(visa.group.path) == "Imported/Money/Cards" and visa.password == "pw-visa"
    assert visa.tags == ["a", "b"] and visa.expiry_time.date().isoformat() == "2031-01-02"
    assert visa.get_custom_property("account_no") == "4711" and visa.url == "https://visa.example.org"
    assert "/".join(next(e for e in kp.entries if e.title == "Loose").group.path) == "Imported"
    assert any(e.title == "existing" for e in kp.entries)  # what was there stays


def test_a_csv_without_a_title_column_or_with_an_empty_title_is_refused_whole(empty, tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("UserName\nx\n", encoding="utf-8")
    assert invoke(empty, "io", "import-csv", str(bad), "--apply").exit_code == 2
    bad.write_text("Title,UserName\nok,x\n,y\n", encoding="utf-8")
    result = invoke(empty, "io", "import-csv", str(bad), "--apply")
    assert result.exit_code == 2 and "row 3" in result.stderr
    assert len(list(load(empty).entries)) == 1  # nothing imported


def test_a_title_that_exists_in_the_target_group_refuses_the_import(empty, tmp_path):
    f = tmp_path / "in.csv"
    f.write_text("Group,Title\nKeep,existing\n", encoding="utf-8")
    assert invoke(empty, "io", "import-csv", str(f), "--group", "/", "--apply").exit_code == 2


def test_export_then_import_round_trips(tmp_path, empty):
    src = messy_vault(tmp_path / "m.kdbx").path
    out = tmp_path / "e.csv"
    assert invoke(src, "io", "export-csv", "--out", str(out), "--with-secrets").exit_code == 0
    assert invoke(empty, "io", "import-csv", str(out), "--group", "Back", "--apply").exit_code == 0
    kp = load(empty)
    got = next(e for e in kp.entries if e.title == "With history")
    assert got.password == "pw-3" and got.url == "https://h.example.org"


# --- import-kdbx --------------------------------------------------------------------------------------------------------

def test_another_vault_is_imported_with_its_structure_and_content(empty, tmp_path):
    src = messy_vault(tmp_path / "m.kdbx").path
    env = {"PDH_IMPORT_PASSWORD": DEFAULT_PASSWORD}
    before = empty.read_bytes()
    plan = data(empty, "io", "import-kdbx", str(src), "--group", "Imported", env=env)
    assert plan["applied"] is False and empty.read_bytes() == before and plan["entries"] > 10
    data(empty, "io", "import-kdbx", str(src), "--group", "Imported", "--apply", env=env)
    kp, original = load(empty), load(src)
    got = {e.title: e for e in kp.entries if "/".join(e.group.path).startswith("Imported")}
    assert "In the bin" not in got and "With attachments" in got
    assert [(a.filename, a.data) for a in got["With attachments"].attachments] == [("note.txt", b"hello"), ("data.bin", bytes(range(16)))]
    assert got["Flags"].is_custom_property_protected("secret_k") and not got["Flags"].is_custom_property_protected("plain_k")
    assert sorted(got["Tagged"].tags) == ["one", "three", "two"] and got["Soon"].expires
    imported_ids = {str(e.uuid) for e in got.values()}
    assert not imported_ids & {str(e.uuid) for e in original.entries}  # new UUIDs: it is an import, not a merge


def test_a_wrong_password_for_the_other_vault_is_refused(empty, tmp_path):
    src = messy_vault(tmp_path / "m.kdbx").path
    assert invoke(empty, "io", "import-kdbx", str(src), "--apply", env={"PDH_IMPORT_PASSWORD": "wrong"}).exit_code == 2


# --- merge ----------------------------------------------------------------------------------------------------------------

def _touch(entry, when):
    entry.mtime = when


@pytest.fixture
def pair(tmp_path):
    """The same vault twice, as after a sync conflict."""
    local = messy_vault(tmp_path / "local.kdbx").path
    other = tmp_path / "other.kdbx"
    shutil.copyfile(local, other)
    return local, other


def edit(db, title, **changes):
    kp = load(db)
    e = next(x for x in kp.entries if x.title == title)
    when = changes.pop("when", datetime.now(timezone.utc) + timedelta(hours=1))
    for k, v in changes.items():
        setattr(e, k, v)
    e.mtime = when
    kp.save()


ENV = {"PDH_IMPORT_PASSWORD": DEFAULT_PASSWORD}


def test_merge_takes_newer_entries_from_the_other_copy_and_keeps_the_old_state_in_the_history(pair):
    local, other = pair
    edit(other, "Tagged", password="from-other")
    edit(local, "Coloured", password="from-local")
    report = data(local, "io", "merge", str(other), "--apply", env=ENV)
    assert report["applied"] is True and report["updated"] == 1 and report["added"] == 0
    kp = load(local)
    tagged = next(e for e in kp.entries if e.title == "Tagged")
    assert tagged.password == "from-other" and tagged.history[-1].password == "pw"
    assert next(e for e in kp.entries if e.title == "Coloured").password == "from-local"  # the newer local one stays


def test_merge_adds_entries_that_only_the_other_copy_has_with_their_uuid(pair):
    local, other = pair
    kp = load(other)
    made = kp.add_entry(next(g for g in kp.groups if g.name == "Money"), "Only there", "u", "pw-new", tags=["t"])
    uid = str(made.uuid)
    kp.save()
    report = data(local, "io", "merge", str(other), "--apply", env=ENV)
    assert report["added"] == 1
    got = next(e for e in load(local).entries if e.title == "Only there")
    assert str(got.uuid) == uid and got.password == "pw-new" and got.tags == ["t"]


def test_merge_is_a_dry_run_by_default_and_a_second_merge_changes_nothing(pair):
    local, other = pair
    edit(other, "Tagged", password="from-other")
    before = local.read_bytes()
    assert data(local, "io", "merge", str(other), env=ENV)["updated"] == 1 and local.read_bytes() == before
    invoke(local, "io", "merge", str(other), "--apply", env=ENV)
    again = data(local, "io", "merge", str(other), "--apply", env=ENV)
    assert (again["updated"], again["added"], again["moved"], again["applied"]) == (0, 0, 0, False)


def test_merge_does_not_resurrect_what_the_other_copy_keeps_in_its_bin(pair):
    local, other = pair
    kp = load(other)
    kp.trash_entry(next(e for e in kp.entries if e.title == "Soon"))
    kp.save()
    report = data(local, "io", "merge", str(other), "--apply", env=ENV)
    assert report["added"] == 0
    assert all(e.group.name != "Recycle Bin" for e in load(local).entries if e.title == "Soon")  # still live here


def test_merge_follows_a_move_made_in_the_other_copy(pair):
    local, other = pair
    kp = load(other)
    target = next(g for g in kp.groups if g.name == "Other")
    moved = next(e for e in kp.entries if e.title == "Tagged")
    kp.move_entry(moved, target)
    moved._element.find("Times/LocationChanged").text = kp._encode_time(datetime.now(timezone.utc) + timedelta(hours=1))
    kp.save()  # (a client stamps the move; pykeepass does not)
    report = data(local, "io", "merge", str(other), "--apply", env=ENV)
    assert report["moved"] == 1
    assert next(e for e in load(local).entries if e.title == "Tagged").group.name == "Other"


def test_merge_with_a_wrong_password_or_a_missing_file_is_refused(pair, tmp_path):
    local, other = pair
    assert invoke(local, "io", "merge", str(other), "--apply", env={"PDH_IMPORT_PASSWORD": "wrong"}).exit_code == 2
    assert invoke(local, "io", "merge", str(tmp_path / "nope.kdbx"), "--apply", env=ENV).exit_code == 2
