"""The write commands on copies of the genuine, hand-made templates (KDBX 3.1 and 4.0 written by KeePassXC).

Synthetic vaults are pykeepass-made KDBX 4.0 only; these files come from a real client. The originals are never written:
each test works on a copy. A template added to `packages/pdh-testkit/vaults/` (for example a KDBX 4.1 one made by hand)
is picked up automatically.
"""
import csv
import json
import shutil

import pytest
from pdh_testkit import vaults
from pdh_testkit.mess import messy_vault
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app
from cprima_pdh.source import pykeepass_open

pytestmark = pytest.mark.slow  # real Argon2 on every open: minutes, so `just test-genuine`, not the default run

TEMPLATES = [v.name for v in vaults.all_vaults() if v.name.startswith("template-")]


@pytest.fixture(params=TEMPLATES)
def ctx(request, tmp_path, monkeypatch):
    template = vaults.load(request.param)
    db = tmp_path / "work.kdbx"
    shutil.copyfile(template.path, db)
    state = {"password": template.password}
    monkeypatch.setattr(_common, "open_db", lambda path, _key: pykeepass_open(path, state["password"], None))

    class Ctx:
        path, format, template_name = db, template.format, request.param
        password = property(lambda self: state["password"])

        def set_password(self, value):
            state["password"] = value

        def run(self, *args, env=None, expect=0):
            result = CliRunner().invoke(app, ["--db", str(db), *args], env=env)
            assert result.exit_code == expect, f"pdh {' '.join(args)} -> {result.exit_code}\n{result.output}{result.stderr or ''}"
            return result

        def js(self, *args, **kw):
            return json.loads(self.run(*args, "-f", "json", **kw).stdout)

        def kp(self):
            return pykeepass_open(db, state["password"], None)

        def entry(self, title):
            return next(e for e in self.kp().entries if e.title == title)

    return Ctx()


def same_format(ctx):
    kp = ctx.kp()
    return f"KDBX {kp.version[0]}.{kp.version[1]}" == ctx.format


# --- creating ------------------------------------------------------------------------------------------------------

def test_groups_and_a_complete_entry(ctx):
    ctx.run("edit", "new-group", "/", "Money", "--apply")
    ctx.run("edit", "new-entry", "Money", "a", "alex", "--url", "https://a.example.org", "--notes", "n", "--tag", "t1",
            "--tag", "t2", "--expires", "2031-02-03", "--field", "plain=v", "--secret-field", "tok=TOK", "--apply",
            env={"PDH_NEW_PASSWORD": "pw-a", "TOK": "secret-tok"})
    a = ctx.entry("a")
    assert (a.username, a.password, a.url, a.notes, sorted(a.tags)) == ("alex", "pw-a", "https://a.example.org", "n", ["t1", "t2"])
    assert a.expires and a.expiry_time.date().isoformat() == "2031-02-03"
    assert a.get_custom_property("plain") == "v" and not a.is_custom_property_protected("plain")
    assert a.get_custom_property("tok") == "secret-tok" and a.is_custom_property_protected("tok")
    assert same_format(ctx)


# --- changing ------------------------------------------------------------------------------------------------------

def test_attributes_fields_and_clone(ctx):
    ctx.run("edit", "new-group", "/", "Money", "--apply")
    ctx.run("edit", "new-entry", "Money", "a", "u", "--tag", "x", "--apply", env={"PDH_NEW_PASSWORD": "pw"})
    ctx.run("edit", "set", "Money/a", "Notes", "hello", "--apply")
    ctx.run("edit", "set", "Money/a", "k", "v1", "--protect", "--apply")
    ctx.run("edit", "set", "Money/a", "k", "v2", "--overwrite", "--apply")  # protection must survive
    ctx.run("edit", "tags", "Money/a", "--add", "y", "--remove", "x", "--apply")
    ctx.run("edit", "expiry", "Money/a", "2032-01-01", "--apply")
    ctx.run("edit", "icon", "Money/a", "12", "--apply")
    ctx.run("edit", "color", "Money/a", "--fg", "#112233", "--bg", "#AABBCC", "--apply")
    ctx.run("edit", "override-url", "Money/a", "https://o.example.org", "--apply")
    ctx.run("edit", "autotype", "Money/a", "--disabled", "--sequence", "{PASSWORD}", "--apply")
    ctx.run("edit", "set", "Money/a", "k", "v3", "--overwrite", "--unprotect", "--apply")
    a = ctx.entry("a")
    assert (a.notes, a.tags, str(a.icon), a.autotype_enabled) == ("hello", ["y"], "12", False)
    assert a.get_custom_property("k") == "v3" and not a.is_custom_property_protected("k")
    assert a._element.findtext("OverrideURL") == "https://o.example.org" and a.expires
    assert len(a.history) >= 8  # every content change left the previous state behind
    ctx.run("edit", "clone", "Money/a", "--title", "a2", "--apply")
    b = ctx.entry("a2")
    assert (b.password, b.get_custom_property("k"), b.tags) == ("pw", "v3", ["y"]) and b.uuid != a.uuid
    assert same_format(ctx)


def test_history_and_attachments(ctx, tmp_path):
    ctx.run("edit", "new-group", "/", "G", "--apply")
    ctx.run("edit", "new-entry", "G", "a", "u", "--apply", env={"PDH_NEW_PASSWORD": "pw-0"})
    for n in (1, 2):
        ctx.run("edit", "set", "G/a", "Password", f"pw-{n}", "--overwrite", "--apply")
    assert [s["changed"] for s in ctx.js("inspect", "history", "G/a")["snapshots"]] == [["Password"], ["Password"]]
    ctx.run("edit", "history-restore", "G/a", "0", "--apply")
    assert ctx.entry("a").password == "pw-0"
    f = tmp_path / "f.txt"
    f.write_bytes(b"attached bytes")
    ctx.run("edit", "attach", "G/a", str(f), "--apply")
    ctx.run("edit", "attach", "G/a", str(f), "--name", "second.txt", "--apply")
    assert [(a["name"], a["size"]) for a in ctx.js("inspect", "attachments", "G/a")["attachments"]] == [("f.txt", 14), ("second.txt", 14)]
    out = tmp_path / "out.txt"
    ctx.run("io", "export-attachment", "G/a", "second.txt", "--out", str(out))
    assert out.read_bytes() == b"attached bytes"
    ctx.run("edit", "detach", "G/a", "f.txt", "--apply")
    assert [a.filename for a in ctx.entry("a").attachments] == ["second.txt"]
    assert ctx.js("edit", "history-prune", "--keep", "0", "--apply")["applied"] is True
    assert len(ctx.entry("a").history) == 0 and same_format(ctx)


def test_delete_restore_purge_and_groups(ctx):
    ctx.run("edit", "new-group", "/", "Money", "--apply")
    ctx.run("edit", "new-group", "/", "Other", "--apply")
    ctx.run("edit", "new-entry", "Money", "a", "u", "--apply", env={"PDH_NEW_PASSWORD": "pw"})
    ctx.run("edit", "delete", "Money/a", "--apply")
    kp = ctx.kp()
    assert kp.recyclebin_group is not None and ctx.entry("a").group.uuid == kp.recyclebin_group.uuid
    if ctx.format == "KDBX 4.1":  # the format records where it came from: no --to needed
        ctx.run("edit", "restore", "Recycle Bin/a", "--apply")
    else:
        ctx.run("edit", "restore", "Recycle Bin/a", "--to", "Money", "--apply")
        ctx.run("edit", "restore", "Recycle Bin/a", "--apply", expect=2)  # (already restored: refused, not a crash)
    assert ctx.entry("a").group.name == "Money"
    ctx.run("edit", "delete", "Money/a", "--apply")
    ctx.run("edit", "purge", "Recycle Bin/a", "--apply")
    assert not list(ctx.kp().entries)
    ctx.run("edit", "rename-group", "Other", "Renamed", "--apply")
    ctx.run("edit", "group-notes", "Renamed", "about", "--apply")
    ctx.run("edit", "group-icon", "Renamed", "9", "--apply")
    ctx.run("edit", "move-group", "Renamed", "Money", "--cross-top-level", "--apply")
    g = next(x for x in ctx.kp().groups if x.name == "Renamed")
    assert (g.notes, str(g.icon), g.parentgroup.name) == ("about", "9", "Money")
    ctx.run("edit", "delete-group", "Money", "--apply")
    ctx.run("db", "empty-bin", "--apply")
    assert not any(x.name in ("Money", "Renamed") for x in ctx.kp().groups) and same_format(ctx)


def test_rename_field_everywhere_and_the_vocabulary(ctx):
    ctx.run("edit", "new-group", "/", "G", "--apply")
    for title in ("a", "b"):
        ctx.run("edit", "new-entry", "G", title, "u", "--field", "Kundennummer=K1", "--apply", env={"PDH_NEW_PASSWORD": "pw"})
    ctx.run("edit", "rename-field", "--all", "Kundennummer", "customer_no", "--apply")
    assert all(ctx.entry(t).get_custom_property("customer_no") == "K1" for t in ("a", "b"))
    ctx.run("edit", "vocabulary", "--apply")
    ctx.run("edit", "move", "G/a", "G", expect=2)  # already there: refused, not a crash
    assert same_format(ctx)


# --- the database ----------------------------------------------------------------------------------------------------

def test_settings_key_derivation_and_password(ctx):
    assert ctx.js("db", "settings", "--name", "Work", "--history-max-items", "7", "--apply")["applied"] is True
    shown = ctx.js("db", "settings")
    assert (shown["name"], shown["history_max_items"]) == ("Work", 7)
    if ctx.format.startswith("KDBX 3"):
        ctx.run("db", "kdf", "--iterations", "2", "--apply", expect=2)  # AES-KDF has no Argon2 parameters: refused cleanly
        assert ctx.js("db", "kdf")["iterations"] is None
    else:
        assert ctx.js("db", "kdf", "--iterations", "3", "--memory", "8192", "--apply")["iterations"] == 3
    ctx.run("db", "password", "--apply", env={"PDH_NEW_PASSWORD": "changed-pw"})
    ctx.set_password("changed-pw")
    assert ctx.kp().database_name == "Work" and same_format(ctx)


# --- moving data -----------------------------------------------------------------------------------------------------

def test_export_import_and_merge(ctx, tmp_path):
    ctx.run("edit", "new-group", "/", "G", "--apply")
    ctx.run("edit", "new-entry", "G", "a", "u", "--apply", env={"PDH_NEW_PASSWORD": "pw"})
    out = tmp_path / "e.csv"
    ctx.run("io", "export-csv", "--out", str(out), "--with-secrets")
    assert {r["Title"]: r["Password"] for r in csv.DictReader(open(out, encoding="utf-8"))} == {"a": "pw"}
    copy = tmp_path / "copy.kdbx"
    ctx.run("io", "export-kdbx", "--out", str(copy), env={"PDH_NEW_PASSWORD": "copy-pw"})
    assert [e.title for e in pykeepass_open(copy, "copy-pw", None).entries] == ["a"]
    assert ctx.js("io", "merge", str(copy), env={"PDH_IMPORT_PASSWORD": "copy-pw"})["updated"] == 0  # same content: nothing to do
    src = messy_vault(tmp_path / "m.kdbx")
    result = ctx.js("io", "import-kdbx", str(src.path), "--group", "Imported", "--apply", env={"PDH_IMPORT_PASSWORD": src.password})
    assert result["applied"] is True and any(e.title == "With attachments" for e in ctx.kp().entries)
    assert same_format(ctx)
