"""`pdh inspect tree`: the vault's groups seen through the method (owner, area, record type). Read-only.

Counts are totals (every entry below a group); the recycle bin is shown last and not counted.
"""
import json

import pytest
from pdh_testkit import Entry, synthetic_vault
from pykeepass import PyKeePass
from typer.testing import CliRunner

from cprima_pdh import tree as tree_mod
from cprima_pdh.cli import app
from cprima_pdh.render import TextRenderer, get_renderer, Format
from cprima_pdh.schema import parse_schemas

SSET = parse_schemas("""
[profile]
taxonomy = "t"
name = "p"
version = "1"

[area."Money"]
description = "x"
[area."Shopping"]
description = "x"

[schema.website]
required = ["Title"]
[schema.bank-card]
required = ["Title"]
""")

ENTRIES = [
    Entry("Loose", group="", custom={"_schema": "website"}),                       # directly at the root
    Entry("Bank", group="alex/Money", custom={"_schema": "bank-card"}),
    Entry("Card", group="alex/Money", custom={"_schema": "bank-card, website"}),
    Entry("Shop", group="alex/Shopping"),                                         # untyped
    Entry("Recipe", group="alex/Cooking"),                                        # not an area of the profile
    Entry("Deep", group="alex/Money/Archive", custom={"_schema": "nope"}),        # an unknown schema name: not typed
    Entry("At owner", group="sam", custom={"_schema": "website"}),                # directly at an owner
    Entry("Sams card", group="sam/Money", custom={"_schema": "bank-card"}),
]


@pytest.fixture(scope="module")
def kp(tmp_path_factory):
    path = synthetic_vault(tmp_path_factory.mktemp("tree") / "v.kdbx", ENTRIES)
    return PyKeePass(str(path), password="pdh-test-password")


def node(root, *path):
    for name in path:
        root = next(c for c in root.children if c.name == name)
    return root


def test_totals_add_up_level_by_level(kp):
    root = tree_mod.build(kp, SSET)
    assert root.total == len(ENTRIES) and root.entry_count == 1
    alex = node(root, "alex")
    assert alex.total == 5 and alex.entry_count == 0
    assert node(alex, "Money").total == 3 and node(alex, "Money").entry_count == 2
    assert alex.total == sum(c.total for c in alex.children) + alex.entry_count


def test_typed_counts_only_valid_schema_names(kp):
    root = tree_mod.build(kp, SSET)
    assert root.typed == 5  # Loose, Bank, Card, At owner, Sams card; not "nope", not untyped
    assert node(root, "alex", "Money").typed == 2 and node(root, "alex", "Money", "Archive").typed == 0


def test_levels_are_named_by_the_method(kp):
    root = tree_mod.build(kp, SSET)
    assert root.kind == "root" and node(root, "alex").kind == "owner"
    assert node(root, "alex", "Money").kind == "area" and node(root, "alex", "Cooking").kind == "group"
    assert node(root, "alex", "Money", "Archive").kind == "group"  # deeper folders are for browsing, no rule


def test_notes_flag_what_the_method_would_not_expect(kp):
    root = tree_mod.build(kp, SSET)
    assert "1 entry directly at the root" in root.note
    assert "not an area of t-p" in node(root, "alex", "Cooking").note
    assert "1 entry directly at the owner" in node(root, "sam").note
    assert node(root, "alex", "Money").note == "" and node(root, "alex", "Money", "Archive").note == ""


def test_the_taxonomy_is_named_when_there_is_no_profile(kp):
    root = tree_mod.build(kp, parse_schemas('[area."Money"]\ndescription = "x"\n'))
    assert "not an area of the taxonomy" in node(root, "alex", "Cooking").note


def test_entries_show_their_record_types(kp):
    root = tree_mod.build(kp, SSET, with_entries=True)
    money = node(root, "alex", "Money")
    assert {(e.title, tuple(e.schemas)) for e in money.entries} == {("Bank", ("bank-card",)),
                                                                   ("Card", ("bank-card", "website"))}
    assert node(root, "alex", "Shopping").entries[0].schemas == []
    assert tree_mod.build(kp, SSET).children[0].entries == []  # without --entries nothing is listed


@pytest.mark.parametrize("depth,levels", [(1, ["alex", "sam"]), (2, ["Cooking", "Money", "Shopping"])])
def test_depth_limits_the_levels_shown(kp, depth, levels):
    root = tree_mod.build(kp, SSET, with_entries=True, depth=depth)
    shown = root.children if depth == 1 else node(root, "alex").children
    assert [c.name for c in shown] == levels
    if depth == 1:
        assert all(c.collapsed and not c.children for c in shown) and root.total == len(ENTRIES)  # totals stay true
    else:
        assert node(root, "alex", "Money").collapsed and not node(root, "alex", "Money").children


# --- types written and types that follow from the fields ------------------------------------------------

RULED = parse_schemas(SSET_TOML := """
[area."Money"]
description = "x"
[schema.website]
required = ["Title"]
[schema.membership]
required = ["Title", "member_no"]
[schema.bank-account]
required = ["Title", "IBAN"]
[[match]]
schema = "membership"
has = ["member_no"]
[[match]]
schema = "bank-account"
has = ["IBAN"]
""")


@pytest.fixture
def ruled(tmp_path):
    path = synthetic_vault(tmp_path / "r.kdbx", [
        Entry("Written", group="alex/Money", custom={"_schema": "website"}),
        Entry("Derived", group="alex/Money", custom={"IBAN": "x"}),                      # only by its fields
        Entry("Both", group="alex/Money", custom={"_schema": "website", "member_no": "1"}),  # written + derived
        Entry("Plain", group="alex/Money"),
    ])
    return PyKeePass(str(path), password="pdh-test-password")


def test_entries_say_which_types_were_written_and_which_follow_from_fields(ruled):
    root = tree_mod.build(ruled, RULED, with_entries=True)
    money = node(root, "alex", "Money")
    seen = {e.title: (e.schemas, e.by_fields) for e in money.entries}
    assert seen == {"Written": (["website"], []), "Derived": ([], ["bank-account"]),
                    "Both": (["website"], ["membership"]), "Plain": ([], [])}


def test_the_typed_count_includes_the_types_that_follow_from_fields(ruled):
    assert tree_mod.build(ruled, RULED).typed == 3  # Written, Derived, Both; not Plain


def test_text_shows_the_provenance(ruled):
    text = render(tree_mod.build(ruled, RULED, with_entries=True))
    assert "Written  [website]" in text and "Derived  [by fields: bank-account]" in text
    assert "Both  [website; by fields: membership]" in text and "Plain  [?]" in text


# --- the recycle bin -----------------------------------------------------------------------------

@pytest.fixture
def kp_with_bin(tmp_path):
    kp = PyKeePass(str(synthetic_vault(tmp_path / "b.kdbx", [Entry("Keep", group="alex/Money"),
                                                             Entry("Gone", group="alex/Money")])),
                   password="pdh-test-password")
    kp.trash_entry(kp.find_entries(title="Gone", first=True))  # into the recycle bin (`delete_entry` removes for good)
    return kp


def test_the_recycle_bin_is_last_and_not_counted(kp_with_bin):
    root = tree_mod.build(kp_with_bin, SSET, with_entries=True)
    assert root.children[-1].kind == "recycle-bin" and root.children[-1].total == 1
    assert root.total == 1 and node(root, "alex", "Money").total == 1  # the deleted entry counts nowhere else
    assert not root.children[-1].children and not root.children[-1].entries


# --- rendering: always through the Renderer --------------------------------------------------------

def render(node, fmt=Format.text, ascii_only=True):
    import io

    out = io.StringIO()
    get_renderer(fmt, ascii_only).render(node, out)
    return out.getvalue()


def test_text_rendering(kp):
    text = render(tree_mod.build(kp, SSET, with_entries=True))
    lines = text.splitlines()
    assert lines[0] == "Root/  (8, 5 typed)  <- 1 entry directly at the root, outside an owner"
    assert "|-- alex/  (5, 2 typed)" in text and "|-- sam/  (2, 2 typed)  <- 1 entry directly at the owner" in text
    assert lines[-1] == "`-- Loose  [website]"  # a group's own entries come after its sub-groups
    assert "Cooking/  (1)  <- not an area of t-p" in text            # nothing typed: no 'typed' phrase
    assert "Bank  [bank-card]" in text and "Shop  [?]" in text and "Card  [bank-card, website]" in text


def test_collapsed_groups_say_so_and_the_bin_says_not_counted(kp, kp_with_bin):
    assert "Money/  (3, 2 typed) ..." in render(tree_mod.build(kp, SSET, depth=2))
    assert "Recycle Bin/  (1, not counted)" in render(tree_mod.build(kp_with_bin, SSET))


def test_the_unicode_tree_is_the_default(kp):
    text = render(tree_mod.build(kp, SSET), ascii_only=False)
    assert "└── " in text and "├── " in text and "│   " in text and "|--" not in text


def test_markdown_wraps_the_tree_in_a_code_block(kp):
    md = render(tree_mod.build(kp, SSET), Format.markdown)
    assert md.startswith("```\n") and md.rstrip().endswith("```")


# --- the CLI ---------------------------------------------------------------------------------------

def test_cli_json_has_totals_kinds_and_notes(tmp_path, monkeypatch):
    path = synthetic_vault(tmp_path / "v.kdbx", ENTRIES)
    (tmp_path / "v.toml").write_text('password = "pdh-test-password"\n', encoding="utf-8")
    schemas = tmp_path / "s.toml"
    schemas.write_text(
        '[profile]\ntaxonomy = "t"\nname = "p"\nversion = "1"\n[area."Money"]\ndescription = "x"\n[schema.website]\nrequired = ["Title"]\n',
        encoding="utf-8")
    out = CliRunner().invoke(app, ["--db", str(path), "--schemas", str(schemas), "inspect", "tree", "--depth", "2",
                                   "-f", "json"])
    data = json.loads(out.stdout)
    assert out.exit_code == 0 and data["total"] == len(ENTRIES) and data["kind"] == "root"
    assert {c["name"] for c in data["children"]} == {"alex", "sam"}


def test_cli_rejects_a_zero_depth(tmp_path):
    path = synthetic_vault(tmp_path / "v.kdbx", ENTRIES)
    (tmp_path / "v.toml").write_text('password = "pdh-test-password"\n', encoding="utf-8")
    assert CliRunner().invoke(app, ["--db", str(path), "inspect", "tree", "--depth", "0"]).exit_code != 0
