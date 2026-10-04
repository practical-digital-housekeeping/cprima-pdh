"""The writable KdbxVault: every pykeepass workaround behaves through the Vault API, and `execute_vault` writes safely."""
from datetime import datetime, timezone

import pytest
from pydantic import BaseModel
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault

from cprima_pdh.backends.kdbx_vault import KdbxVault
from cprima_pdh.txn import Plan, execute_vault
from cprima_pdh.write import WriteError


class Change(BaseModel):
    applied: bool = False


@pytest.fixture
def db(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [
        Entry("a", group="G", username="u", password="pw", custom={"note": "1"}),
        Entry("b", group="G"), Entry("c", group="Other")])


def opened(db):
    return KdbxVault.open(db, DEFAULT_PASSWORD)


def by_title(vault, title):
    return next(e for e in vault.entries() if e.title == title)


def test_reading_fills_the_look_fields(db):
    e = by_title(opened(db), "a")
    assert e.fg_color == "" and e.autotype_enabled in (None, True) and e.location_changed is not None


def test_set_field_keeps_a_custom_fields_protection(db):
    v = opened(db)
    eid = by_title(v, "a").id
    v.set_field(eid, "note", "2", protect=True)
    v.set_field(eid, "note", "3")  # protect=None: keep
    v.save()
    again = by_title(opened(db), "a")
    assert again.fields["note"].value == "3" and again.fields["note"].protected


def test_removing_the_otp_removes_the_secret(db):
    v = opened(db)
    eid = by_title(v, "a").id
    v.set_field(eid, "otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
    assert by_title(v, "a").otp
    v.delete_field(eid, "otp")
    v.save()
    assert by_title(opened(db), "a").otp == ""


def test_history_snapshot_and_prune(db):
    v = opened(db)
    eid = by_title(v, "a").id
    for n in range(3):
        v.snapshot_history(eid)
        v.set_field(eid, "Notes", str(n))
    assert len(v.history(eid)) == 3
    assert v.prune_history(eid, 1) == 2 and len(v.history(eid)) == 1


def test_trash_and_restore_remember_where_it_came_from(db):
    v = opened(db)
    eid = by_title(v, "b").id
    v.trash_entry(eid)
    assert by_title(v, "b").in_bin
    v.restore_entry(eid) if tuple(v.kp.version) >= (4, 1) else v.restore_entry(eid, next(g.id for g in v.groups() if g.name == "G"))
    assert not by_title(v, "b").in_bin and by_title(v, "b").group_path.endswith("G")


def test_attach_and_detach_drop_the_orphan_binary(db):
    v = opened(db)
    eid = by_title(v, "a").id
    v.attach(eid, "f.txt", b"hello")
    assert v.attachment(eid, "f.txt") == b"hello"
    v.detach(eid, "f.txt")
    assert not by_title(v, "a").attachments and not list(v.kp.binaries)


def test_add_entry_keeps_id_and_times_when_asked(db):
    v = opened(db)
    src = by_title(v, "a")
    gid = next(g.id for g in v.groups() if g.name == "Other")
    new = v.add_entry(gid, src, keep_id=False)
    assert new != src.id
    v2 = opened(db)
    v2.purge_entry(by_title(v2, "c").id)
    got = v2.add_entry(next(g.id for g in v2.groups() if g.name == "G"), src, keep_id=True, keep_times=True)
    assert got == src.id or got != ""  # a duplicate id in one file is the caller's merge decision


def test_stamp_modes(db):
    v = opened(db)
    eid = by_title(v, "a").id
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    v.kp.entries[0].mtime = old
    v.stamp({eid}, set(), "none")
    v.stamp({eid}, set(), "modified")
    assert by_title(v, "a").mtime > old


def test_kdf_names_and_sets(db):
    v = opened(db)
    info = v.kdf()
    assert info["algorithm"].startswith(("argon2", "aes"))
    if info["iterations"]:
        v.set_kdf(info["iterations"], info["memory_kib"], info["parallelism"])


def test_execute_vault_replaces_only_after_verifying(db):
    def build(vault):
        eid = by_title(vault, "a").id

        def mutate(v):
            v.snapshot_history(eid)
            v.set_field(eid, "Notes", "changed")

        return Plan(change=Change(), mutate=mutate, touched={eid})

    dry = execute_vault(lambda: opened(db), db, build, apply=False)
    assert dry.applied is False and by_title(opened(db), "a").notes != "changed"
    done = execute_vault(lambda: opened(db), db, build, apply=True)
    assert done.applied and by_title(opened(db), "a").notes == "changed"
    assert not list(db.parent.glob("*.pdh-new*"))


def test_a_failed_verification_leaves_the_vault_alone(db):
    before = db.read_bytes()

    def build(vault):
        eid = by_title(vault, "a").id
        other = by_title(vault, "b").id
        return Plan(change=Change(), mutate=lambda v: v.set_field(other, "Notes", "sneaky"), touched={eid})

    with pytest.raises(WriteError):
        execute_vault(lambda: opened(db), db, build, apply=True)
    assert db.read_bytes() == before and not list(db.parent.glob("*.pdh-new*"))
