"""The KDBX layer on copies of the genuine, hand-made templates (KDBX 3.1, 4.0 and 4.1 written by KeePassXC; AES, ChaCha20 and
Twofish; Argon2d, Argon2id and AES-KDF).

Synthetic vaults are pykeepass-made KDBX 4.0 only; these files come from a real client. The originals are never written:
each test works on a copy with a lowered key derivation (see `pdh_testkit.cheap`). A template added to
`packages/pdh-testkit/vaults/` is picked up automatically. The same behaviour through the pdh commands is in pdh's
`tests/compatibility/`.
"""
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from pdh_testkit import vaults
from pdh_testkit.cheap import cheap_copy

from cprima_pdh_kdbxkit.kdbx_vault import KdbxVault
from cprima_pdh_vault.transaction import Plan, execute
from cprima_pdh_vault.vault import EntryData, Field

pytestmark = pytest.mark.compatibility  # the same behaviour on every template: `just test-compatibility`, not the default run

TEMPLATES = [v.name for v in vaults.all_vaults() if v.name.startswith("template-")]


@pytest.fixture(params=TEMPLATES)
def template(request, tmp_path):
    t = vaults.load(request.param)
    return t, cheap_copy(request.param, tmp_path / "work.kdbx")  # the genuine template with a cheap key derivation


def opened(t, db):
    return KdbxVault.open(db, t.password)


def by_title(vault, title):
    return next(e for e in vault.entries() if e.title == title)


def test_one_verified_write_of_everything_a_vault_can_hold_survives_on_every_template(template):
    t, db = template
    when = datetime(2031, 2, 3, tzinfo=timezone.utc)

    def build(vault):
        root = next(g.id for g in vault.groups() if g.is_root)
        seed = EntryData(id="", group_path="", title="login", username="alex", password="pw-1", url="https://example.org",
                         notes="n", tags=("a", "b"), icon="12", expires=True, expiry=when,
                         fields={"customer_no": Field("C-1", False), "token": Field("t", True)})

        def mutate(v):
            group = v.add_group(root, "Money", icon="5", notes="about")
            eid = v.add_entry(group, seed, content={"note.txt": b"hello"})
            v.snapshot_history(eid)
            v.set_field(eid, "Password", "pw-2")
            v.rename_group(group, "Cash")

        return Plan(change="the report", mutate=mutate, count_delta=1)

    _change, written = execute(lambda: opened(t, db), db, build, apply=True)
    assert written
    vault = opened(t, db)
    entry = by_title(vault, "login")
    assert entry.group_path == "Cash" and entry.password == "pw-2" and entry.history_count == 1
    assert entry.fields == {"customer_no": Field("C-1", False), "token": Field("t", True)}
    assert list(entry.tags) == ["a", "b"] and entry.icon == "12" and entry.expires
    assert entry.attachments == (("note.txt", 5),) and vault.attachment(entry.id, "note.txt") == b"hello"
    assert vault.file_problems(db) == [] and vault.info().format == t.format
    assert vault.info().generator == "cprima-pdh-kdbxkit"  # the genuine template said KeePassXC until this layer wrote it


def test_trash_restore_and_purge_work_on_every_template(template):
    t, db = template

    def build(vault):
        root = next(g.id for g in vault.groups() if g.is_root)

        def mutate(v):
            group = v.add_group(root, "Money")
            keep = v.add_entry(group, EntryData(id="", group_path="", title="keep", password="x"))
            gone = v.add_entry(group, EntryData(id="", group_path="", title="gone", password="y"))
            v.trash_entry(keep)
            v.restore_entry(keep, group)
            v.purge_entry(gone)

        return Plan(change="the report", mutate=mutate, count_delta=1, stamp="location")

    execute(lambda: opened(t, db), db, build, apply=True)
    vault = opened(t, db)
    titles = {e.title: e for e in vault.entries()}
    assert "keep" in titles and not titles["keep"].in_bin and "gone" not in titles


def test_a_changed_master_password_and_key_derivation_settings_survive_on_every_template(template):
    t, db = template
    vault = opened(t, db)
    info = vault.kdf()
    if info["iterations"]:
        vault.set_kdf(info["iterations"], info["memory_kib"], info["parallelism"])
    vault.set_password("second-pw")
    vault.save()
    again = KdbxVault.open(db, "second-pw")
    assert again.info().format == t.format and again.file_problems(db) == []
    assert not again.can_open("wrong", None, db) and again.can_open("second-pw", None, db)
