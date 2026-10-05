"""The Vault contract: what the engine may rely on from any backend (read side).

The same specification is built as a MemoryVault and as a real KDBX file; both must give the same snapshot. Backend-specific
facts (history, attachments, the recycle bin, format info) are checked on the KDBX side only, against the messy vault and the
genuine templates. A sops backend joins this file when it exists.
"""
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from pdh_testkit.memory import memory_vault
from pdh_testkit.mess import messy_vault

from cprima_pdh_kdbxkit.kdbx_vault import KdbxVault
from cprima_pdh_kdbxkit.kdbx_vault import pykeepass_open
from cprima_pdh_vault.vault import STANDARD, EntryData, Field, GroupData, VaultInfo, as_vault, require, Unsupported

SPEC = [
    Entry("login", group="Money/Cards", username="alex", password="pw-1", url="https://example.org", notes="n",
          tags=("a", "b"), custom={"customer_no": "C-1", "token": "t"}, protected=frozenset({"token"}),
          expires=datetime(2031, 2, 3, tzinfo=timezone.utc)),
    Entry("plain", group="Money", username="", password="", custom={}),
    Entry("at root", group="", username="u", password="p"),
    Entry("twin", group="Money", username="u1", password="x"),
    Entry("twin", group="Money", username="u3", password="w"),
    Entry("twin", group="Other", username="u2", password="y"),
]


@pytest.fixture(params=["memory", "kdbx"])
def vault(request, tmp_path):
    if request.param == "memory":
        return memory_vault(SPEC)
    path = synthetic_vault(tmp_path / "c.kdbx", SPEC)
    return KdbxVault(pykeepass_open(path, DEFAULT_PASSWORD, None), path)


def by_path(vault):
    return {f"{e.group_path}/{e.title}/{e.username}": e for e in vault.entries()}


def test_entries_are_snapshots_with_the_standard_fields(vault):
    e = by_path(vault)["Money/Cards/login/alex"]
    assert isinstance(e, EntryData)
    assert (e.title, e.username, e.password, e.url, e.notes) == ("login", "alex", "pw-1", "https://example.org", "n")
    assert list(e.tags) == ["a", "b"] and e.expires and e.expiry.date().isoformat() == "2031-02-03"
    assert [e.value(n) for n in ("Title", "UserName", "Password", "URL", "Notes")] == ["login", "alex", "pw-1", "https://example.org", "n"]


def test_custom_fields_carry_their_protection(vault):
    e = by_path(vault)["Money/Cards/login/alex"]
    assert e.fields == {"customer_no": Field("C-1", False), "token": Field("t", True)}
    assert set(e.names()) >= {"Title", "customer_no", "token"}  # the names of everything the entry has a value for


def test_an_empty_standard_field_is_not_a_name_the_entry_has(vault):
    plain = by_path(vault)["Money/plain/"]
    assert "UserName" not in plain.names() and "Password" not in plain.names() and "Title" in plain.names()


def test_group_paths_are_slash_joined_and_the_root_is_a_slash(vault):
    paths = {e.group_path for e in vault.entries()}
    assert paths == {"Money/Cards", "Money", "/", "Other"}


def test_the_path_of_an_entry_is_its_group_and_title(vault):
    e = by_path(vault)["Money/Cards/login/alex"]
    assert e.path == "Money/Cards/login" and by_path(vault)["//at root/u"].path == "//at root"


def test_equal_titles_in_different_groups_are_different_entries(vault):
    twins = [e for e in vault.entries() if e.title == "twin"]
    assert len(twins) == 3 and len({t.id for t in twins}) == 3


def test_ids_are_unique(vault):
    ids = [e.id for e in vault.entries()]
    assert len(ids) == len(set(ids)) == len(SPEC)


def test_nothing_is_in_the_bin_in_a_vault_without_one(vault):
    assert not any(e.in_bin for e in vault.entries())
    assert not any(g.in_bin for g in vault.groups())


def test_groups_are_listed_with_their_paths(vault):
    groups = {g.path for g in vault.groups() if not g.is_root}
    assert groups == {"Money", "Money/Cards", "Other"}
    assert all(isinstance(g, GroupData) for g in vault.groups())
    assert sum(1 for g in vault.groups() if g.is_root) == 1


def test_find_entry_resolves_by_path_and_username(vault):
    assert vault.find_entry("Money/twin", "u1").username == "u1"
    assert vault.find_entry("Money/Cards/login").username == "alex"
    assert vault.find_entry("Other/twin").username == "u2"
    with pytest.raises(KeyError):
        vault.find_entry("Money/nope")
    with pytest.raises(LookupError, match="narrow"):  # two entries share Money/twin
        vault.find_entry("Money/twin")


def test_info_names_the_backend(vault):
    info = vault.info()
    assert isinstance(info, VaultInfo) and info.backend in ("memory", "kdbx")


def test_capabilities_include_the_read_basics_and_are_checked_by_require(vault):
    assert {"fields", "groups", "protected"} <= vault.capabilities
    require(vault, "fields")
    with pytest.raises(Unsupported, match="does not support"):
        require(vault, "teleportation")


def test_as_vault_accepts_a_vault_and_wraps_a_pykeepass_object(tmp_path):
    path = synthetic_vault(tmp_path / "w.kdbx", SPEC)
    kp = pykeepass_open(path, DEFAULT_PASSWORD, None)
    wrapped = as_vault(kp)
    assert wrapped.info().backend == "kdbx" and as_vault(wrapped) is wrapped
    assert len(wrapped.entries()) == len(SPEC)


def test_the_standard_names_are_the_profiles():
    from cprima_pdh_kdbxkit.kdbx_format import STANDARD_ATTR

    assert set(STANDARD) == set(STANDARD_ATTR)


# --- what holds for every backend, whatever it contains: memory, a KDBX file and a sops file ---------------------------------

@pytest.fixture(params=["memory", "kdbx", "sops"])
def any_vault(request, tmp_path):
    if request.param == "memory":
        return memory_vault(SPEC)
    if request.param == "kdbx":
        path = synthetic_vault(tmp_path / "a.kdbx", SPEC)
        return KdbxVault(pykeepass_open(path, DEFAULT_PASSWORD, None), path)
    from pdh_testkit.sopsfix import load_sops

    from cprima_pdh_sopskit import age
    from cprima_pdh_sopskit.sops_vault import SopsVault

    fix = load_sops("sops-json-basic")
    return SopsVault.open(fix.path, age.identities_from_text(fix.identity_text))


def test_every_backend_hands_out_snapshots_whose_paths_agree_with_its_groups(any_vault):
    entries, groups = any_vault.entries(), any_vault.groups()
    assert entries and all(isinstance(e, EntryData) for e in entries) and all(isinstance(g, GroupData) for g in groups)
    assert sum(1 for g in groups if g.is_root) == 1
    paths = {g.path for g in groups}
    assert all(e.group_path in paths for e in entries)
    assert all(e.path == f"{e.group_path}/{e.title}" for e in entries)
    assert len({e.id for e in entries}) == len(entries) and len({g.id for g in groups}) == len(groups)
    assert {g.id for g in groups} >= {e.group_id for e in entries if e.group_id}


def test_every_backend_finds_each_entry_by_its_path_or_says_it_is_ambiguous(any_vault):
    for e in any_vault.entries():
        try:
            assert any_vault.find_entry(e.path, e.username).id == e.id or any_vault.find_entry(e.path).path == e.path
        except LookupError:
            assert sum(1 for x in any_vault.entries() if x.path == e.path) > 1
    with pytest.raises(KeyError):
        any_vault.find_entry("No/such/entry")


def test_every_backend_names_itself_and_declares_the_read_basics(any_vault):
    assert any_vault.info().backend == any_vault.name and any_vault.name in ("memory", "kdbx", "sops")
    assert {"fields", "groups", "protected"} <= any_vault.capabilities
    require(any_vault, "fields")


def test_every_backends_groups_form_one_tree_whose_paths_follow_the_names(any_vault):
    groups = {g.id: g for g in any_vault.groups()}
    for g in groups.values():
        if g.is_root:
            assert g.parent_id is None and g.path == "/"
            continue
        parent = groups[g.parent_id]  # a parent that is not a group of the vault is a defect
        assert g.path == (g.name if parent.is_root else f"{parent.path}/{g.name}")


def test_every_backends_snapshots_are_stable_complete_and_cannot_be_changed(any_vault):
    first, second = any_vault.entries(), any_vault.entries()
    assert [(e.id, e.path, e.fields) for e in first] == [(e.id, e.path, e.fields) for e in second]
    for e in first:
        assert "Title" in e.names() and e.protected_standard <= set(STANDARD)
        assert all(isinstance(f, Field) and isinstance(f.protected, bool) for f in e.fields.values())
        with pytest.raises(Exception):  # a frozen snapshot: the vault is changed through its operations, never through this
            e.title = "changed"


def test_every_backend_counts_what_it_holds_the_same_way(any_vault):
    entries, groups = any_vault.entries(), any_vault.groups()
    live = [e for e in entries if not e.in_bin]
    assert len(live) + sum(1 for e in entries if e.in_bin) == len(entries)
    held = {e.group_id for e in entries}
    assert held <= {g.id for g in groups}


def test_every_backend_says_whether_it_can_be_written(any_vault):
    problems = any_vault.check_writable()
    assert isinstance(problems, list)
    if "write" in any_vault.capabilities:
        assert problems == []
    else:
        assert problems and all(isinstance(p, str) for p in problems)


# --- the write side: the same operations, the same results, in memory and in a real file ------------------------------------

def one(vault, path, username=None):
    return vault.find_entry(path, username)


def group_id(vault, path):
    return next(g.id for g in vault.groups() if g.path == path)


def test_a_standard_field_is_set_and_a_custom_field_keeps_its_protection(vault):
    eid = one(vault, "Money/Cards/login").id
    vault.set_field(eid, "Password", "new-pw")
    vault.set_field(eid, "token", "t2")  # protection not given: stays as it was (protected)
    vault.set_field(eid, "extra", "x", protect=True)
    vault.set_field(eid, "customer_no", "C-2")  # not protected before, not now
    e = one(vault, "Money/Cards/login")
    assert e.password == "new-pw"
    assert e.fields == {"customer_no": Field("C-2", False), "token": Field("t2", True), "extra": Field("x", True)}


def test_a_field_is_deleted_standard_ones_become_empty(vault):
    eid = one(vault, "Money/Cards/login").id
    vault.delete_field(eid, "token")
    vault.delete_field(eid, "URL")
    e = one(vault, "Money/Cards/login")
    assert "token" not in e.fields and e.url == "" and "URL" not in e.names()


def test_tags_icon_expiry_look_and_autotype(vault):
    eid = one(vault, "Money/plain").id
    when = datetime(2032, 5, 6, tzinfo=timezone.utc)
    vault.set_tags(eid, ["x", "y"])
    vault.set_icon(eid, "12")
    vault.set_expiry(eid, when)
    vault.set_colours(eid, "#112233", "#445566")
    vault.set_override_url(eid, "https://override.example")
    vault.set_autotype(eid, False, "{USERNAME}{ENTER}")
    e = one(vault, "Money/plain")
    assert list(e.tags) == ["x", "y"] and e.icon == "12" and e.expires and e.expiry.date().isoformat() == "2032-05-06"
    assert (e.fg_color, e.bg_color, e.override_url) == ("#112233", "#445566", "https://override.example")
    assert e.autotype_enabled is False and e.autotype_sequence == "{USERNAME}{ENTER}"
    vault.set_expiry(eid, None)
    assert not one(vault, "Money/plain").expires


def test_an_entry_is_added_from_a_snapshot_and_given_an_id(vault):
    source = one(vault, "Money/Cards/login")
    new_id = vault.add_entry(group_id(vault, "Other"), replace(source, title="copy"), content={"a.txt": b"hello"})
    made = next(e for e in vault.entries() if e.id == new_id)
    assert made.id != source.id and made.path == "Other/copy" and made.group_path == "Other"
    assert (made.username, made.password, made.tags, made.fields) == (source.username, source.password, source.tags, source.fields)
    assert made.attachments == (("a.txt", 5),) and vault.attachment(new_id, "a.txt") == b"hello"
    assert len(vault.entries()) == len(SPEC) + 1


def test_an_entry_added_with_keep_id_keeps_the_id(vault):
    source = one(vault, "Money/plain")
    new_id = vault.add_entry(group_id(vault, "Other"), replace(source, id="11111111-1111-4111-8111-111111111111", title="kept"),
                             keep_id=True)
    assert new_id == "11111111-1111-4111-8111-111111111111"


def test_an_entry_moves_to_another_group(vault):
    eid = one(vault, "Money/plain").id
    vault.move_entry(eid, group_id(vault, "Other"))
    assert one(vault, "Other/plain").id == eid


def test_a_trashed_entry_is_in_the_bin_and_can_be_restored_to_a_group(vault):
    eid = one(vault, "Money/plain").id
    vault.trash_entry(eid)
    trashed = next(e for e in vault.entries() if e.id == eid)
    assert trashed.in_bin and any(g.is_bin for g in vault.groups())
    vault.restore_entry(eid, group_id(vault, "Money"))
    assert not next(e for e in vault.entries() if e.id == eid).in_bin


def test_a_trashed_entry_goes_back_where_it_came_from_or_the_vault_says_it_cannot(vault):
    eid = one(vault, "Money/plain").id
    vault.trash_entry(eid)
    if vault.origin_group(eid) is None:  # a store that does not record it (KDBX before 4.1)
        with pytest.raises(LookupError):
            vault.restore_entry(eid)
    else:
        vault.restore_entry(eid)
        assert next(e for e in vault.entries() if e.id == eid).group_path == "Money"


def test_a_purged_entry_is_gone(vault):
    eid = one(vault, "Money/plain").id
    vault.purge_entry(eid)
    assert all(e.id != eid for e in vault.entries())


def test_a_purged_entry_is_recorded_as_deleted(vault):
    """A delete needs a record, otherwise a merge cannot tell a deleted entry from one that never arrived. (pykeepass writes
    none; the KDBX layer does, as a client does.)"""
    before = datetime.now(timezone.utc).replace(microsecond=0)
    eid = one(vault, "Money/plain").id
    vault.purge_entry(eid)
    assert eid in vault.deleted_ids() and eid in vault.deletions()
    assert before <= vault.deletions()[eid] <= datetime.now(timezone.utc)


def test_a_purge_records_only_what_was_purged(vault):
    vault.purge_entry(one(vault, "Money/plain").id)
    assert len(vault.deletions()) == 1


def test_emptying_the_bin_records_every_entry_and_group_below_it_but_not_the_bin(vault):
    money = group_id(vault, "Money")
    inner = vault.add_group(money, "Inner")
    deep = vault.add_entry(inner, replace(one(vault, "Money/plain"), id="", title="deep"))
    top = one(vault, "Money/plain").id
    vault.trash_entry(top)
    vault.trash_group(inner)
    bin_id = next(g.id for g in vault.groups() if g.is_bin)
    vault.empty_bin()
    assert vault.deleted_ids() == {top, deep, inner} and bin_id not in vault.deleted_ids()


def test_a_recorded_deletion_keeps_the_earlier_time(vault):
    eid = one(vault, "Money/plain").id
    early, late = datetime(2020, 1, 1, tzinfo=timezone.utc), datetime(2021, 1, 1, tzinfo=timezone.utc)
    vault.record_deleted({"11111111-1111-4111-8111-111111111111": late})
    vault.record_deleted({"11111111-1111-4111-8111-111111111111": early})
    vault.record_deleted({"11111111-1111-4111-8111-111111111111": late})
    assert vault.deletions()["11111111-1111-4111-8111-111111111111"] == early
    assert eid not in vault.deleted_ids()  # recording a deletion does not remove anything


def test_a_purged_group_takes_its_subtree_and_records_it(vault):
    ids = {e.id for e in vault.entries() if e.group_path in ("Money", "Money/Cards")}
    groups = {group_id(vault, "Money"), group_id(vault, "Money/Cards")}
    vault.purge_group(group_id(vault, "Money"))
    assert vault.deleted_ids() == ids | groups
    assert all(e.group_path not in ("Money", "Money/Cards") for e in vault.entries())


def test_the_top_group_cannot_be_purged(vault):
    with pytest.raises(ValueError):
        vault.purge_group(next(g.id for g in vault.groups() if g.is_root))


def test_groups_are_added_renamed_moved_and_their_entries_follow(vault):
    root = next(g.id for g in vault.groups() if g.is_root)
    new = vault.add_group(root, "Fresh", icon="5", notes="about")
    assert any(g.id == new and g.path == "Fresh" and g.notes == "about" and g.icon == "5" for g in vault.groups())
    vault.rename_group(group_id(vault, "Money"), "Cash")
    assert {e.group_path for e in vault.entries() if e.title in ("login", "plain")} == {"Cash/Cards", "Cash"}
    vault.move_group(group_id(vault, "Cash/Cards"), new)
    assert one(vault, "Fresh/Cards/login").username == "alex"
    vault.set_group_notes(new, "changed")
    vault.set_group_icon(new, "7")
    assert any(g.id == new and g.notes == "changed" and g.icon == "7" for g in vault.groups())


def test_a_trashed_group_is_in_the_bin_with_its_entries_and_emptying_the_bin_removes_them(vault):
    gid = group_id(vault, "Money/Cards")
    vault.trash_group(gid)
    assert any(g.id == gid and g.in_bin for g in vault.groups())
    assert next(e for e in vault.entries() if e.title == "login").in_bin
    vault.empty_bin()
    assert all(e.title != "login" for e in vault.entries()) and all(g.id != gid for g in vault.groups())


def test_history_is_kept_listed_and_pruned(vault):
    eid = one(vault, "Money/Cards/login").id
    vault.snapshot_history(eid)
    vault.set_field(eid, "Password", "second")
    vault.snapshot_history(eid)
    vault.set_field(eid, "Password", "third")
    assert one(vault, "Money/Cards/login").history_count == 2
    assert [h.password for h in vault.history(eid)] == ["pw-1", "second"] and all(h.id == eid for h in vault.history(eid))
    assert vault.prune_history(eid, 1) == 1
    assert [h.password for h in vault.history(eid)] == ["second"] and one(vault, "Money/Cards/login").history_count == 1


def test_attachments_are_attached_read_and_detached(vault):
    eid = one(vault, "Money/plain").id
    vault.attach(eid, "note.txt", b"abc")
    vault.attach(eid, "data.bin", b"0123456789")
    assert one(vault, "Money/plain").attachments == (("note.txt", 3), ("data.bin", 10))
    assert vault.attachment(eid, "data.bin") == b"0123456789"
    vault.detach(eid, "note.txt")
    assert one(vault, "Money/plain").attachments == (("data.bin", 10),)
    with pytest.raises(KeyError):
        vault.attachment(eid, "note.txt")


def test_an_entry_is_overwritten_with_a_snapshot_but_keeps_its_place_and_id(vault):
    target = one(vault, "Money/plain")
    source = one(vault, "Money/Cards/login")
    vault.overwrite_entry(target.id, replace(source, title="plain"))
    e = one(vault, "Money/plain")
    assert e.id == target.id and e.group_path == "Money"
    assert (e.username, e.password, e.fields, list(e.tags)) == (source.username, source.password, source.fields, list(source.tags))


def test_stamping_changes_the_modification_time_of_what_was_touched_only(vault):
    a = one(vault, "Money/plain")
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    vault.overwrite_entry(a.id, replace(a, mtime=old), keep_mtime=True)  # (a file stores whole seconds: start from the past)
    b = one(vault, "Money/Cards/login")
    vault.stamp({a.id}, set(), "modified")
    assert one(vault, "Money/plain").mtime > old
    assert one(vault, "Money/Cards/login").mtime == b.mtime


# --- KDBX only: what the format adds ----------------------------------------------------------------------------------

@pytest.fixture
def messy(tmp_path):
    path = messy_vault(tmp_path / "m.kdbx").path
    return KdbxVault(pykeepass_open(path, DEFAULT_PASSWORD, None), path)


def test_kdbx_reports_history_attachments_and_the_bin(messy):
    by = {e.title: e for e in messy.entries()}
    assert by["With history"].history_count == 3 and by["With history"].history_bytes > 0
    assert [(n, s) for n, s in by["With attachments"].attachments] == [("note.txt", 5), ("data.bin", 16)]
    assert by["In the bin"].in_bin and not by["Tagged"].in_bin
    assert any(g.in_bin for g in messy.groups() if g.name == "Recycle Bin") is False  # the bin itself is not "in" the bin
    assert {"history", "attachments", "recycle_bin"} <= messy.capabilities


def test_kdbx_reports_look_and_behaviour_attributes(messy):
    by = {e.title: e for e in messy.entries()}
    assert by["Tagged"].icon == "12" and sorted(by["Tagged"].tags) == ["one", "three", "two"]
    assert by["Expired"].expires and by["Far"].expires and not by["Tagged"].expires


def test_kdbx_snapshots_are_stable_across_reopening(tmp_path):
    path = synthetic_vault(tmp_path / "s.kdbx", SPEC)
    first = KdbxVault(pykeepass_open(path, DEFAULT_PASSWORD, None), path).entries()
    second = KdbxVault(pykeepass_open(path, DEFAULT_PASSWORD, None), path).entries()
    assert [(e.id, e.path, e.fields) for e in first] == [(e.id, e.path, e.fields) for e in second]


def test_kdbx_info_has_the_format_cipher_and_key_derivation(messy):
    info = messy.info()
    assert info.format == "KDBX 4.0" and info.cipher == "aes256" and info.kdf == "argon2d"


@pytest.mark.compatibility
@pytest.mark.parametrize("name", ["template-kdbx3", "template-kdbx4", "template-kdbx41", "template-kdbx4-argon2id",
                                  "template-kdbx4-aeskdf", "template-kdbx4-chacha20", "template-kdbx4-twofish"])
def test_every_genuine_template_is_an_empty_vault_with_a_root(name):
    from pdh_testkit import vaults

    t = vaults.load(name)
    v = KdbxVault(pykeepass_open(t.path, t.password, None), t.path)
    assert v.entries() == [] or name == "template-kdbx41"  # (the 4.1 template keeps one moved entry)
    assert sum(1 for g in v.groups() if g.is_root) == 1
    assert v.info().format == t.format
