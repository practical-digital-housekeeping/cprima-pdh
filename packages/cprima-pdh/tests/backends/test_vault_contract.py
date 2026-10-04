"""The Vault contract: what the engine may rely on from any backend (read side).

The same specification is built as a MemoryVault and as a real KDBX file; both must give the same snapshot. Backend-specific
facts (history, attachments, the recycle bin, format info) are checked on the KDBX side only, against the messy vault and the
genuine templates. A sops backend joins this file when it exists.
"""
from datetime import datetime, timezone

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from pdh_testkit.memory import memory_vault
from pdh_testkit.mess import messy_vault

from cprima_pdh.backends.kdbx import KdbxVault
from cprima_pdh.source import pykeepass_open
from cprima_pdh.vault import STANDARD, EntryData, Field, GroupData, VaultInfo, as_vault, require, Unsupported

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
    from cprima_pdh.backends.kdbx import STANDARD_ATTR

    assert set(STANDARD) == set(STANDARD_ATTR)


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
