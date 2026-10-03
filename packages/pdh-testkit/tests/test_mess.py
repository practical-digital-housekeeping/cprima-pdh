"""The messy-vault generator: every KDBX feature a real vault can have, with invented data only."""
from pdh_testkit import DEFAULT_PASSWORD
from pdh_testkit.mess import messy_vault
from pykeepass import PyKeePass


def test_the_generator_builds_a_vault_with_every_feature(tmp_path):
    made = messy_vault(tmp_path / "m.kdbx")
    kp = PyKeePass(str(made.path), password=DEFAULT_PASSWORD)
    by = {e.title: e for e in kp.entries}

    assert len(by["With history"].history) == 3  # three earlier states
    assert [a.filename for a in by["With attachments"].attachments] == ["note.txt", "data.bin"]
    assert sorted(by["Tagged"].tags) == ["one", "three", "two"]
    assert str(by["Tagged"].icon) == "12"
    assert by["Coloured"]._element.findtext("ForegroundColor") == "#112233"
    assert by["Coloured"]._element.findtext("OverrideURL") == "https://override.example.org"
    assert by["Coloured"].autotype_enabled is False and by["Coloured"].autotype_sequence == "{PASSWORD}{ENTER}"
    assert by["Expired"].expires and by["Soon"].expires and by["Far"].expires
    assert by["Flags"].is_custom_property_protected("secret_k") and not by["Flags"].is_custom_property_protected("plain_k")
    assert by["Flags"]._element.xpath("String[Key='explicit_false']/Value/@Protected") == ["False"]
    assert by["Linker"].get_custom_property("device").startswith("{REF:")
    assert by["Origin"]._element.findtext("PreviousParentGroup")  # as KeePassXC 2.7 writes it

    assert kp.recyclebin_group is not None and by["In the bin"].group.uuid == kp.recyclebin_group.uuid
    assert [e.title for e in kp.entries if e.title == "Twin"].__len__() == 2  # same title in two groups
    assert {g.name for g in kp.groups} >= {"Notes group", "Deep"}
    notes_group = next(g for g in kp.groups if g.name == "Notes group")
    assert notes_group.notes == "about this group" and str(notes_group.icon) == "5"
    assert max(len(g.path or []) for g in kp.groups) >= 5  # a deep tree


def test_a_second_vault_can_be_built_without_a_recycle_bin(tmp_path):
    made = messy_vault(tmp_path / "n.kdbx", recycle_bin=False)
    kp = PyKeePass(str(made.path), password=DEFAULT_PASSWORD)
    assert kp.recyclebin_group is None and all(e.title != "In the bin" for e in kp.entries)


def test_the_description_names_what_was_built(tmp_path):
    made = messy_vault(tmp_path / "m.kdbx")
    assert "history" in made.features and "attachments" in made.features and "recycle-bin" in made.features
    assert made.password == DEFAULT_PASSWORD
