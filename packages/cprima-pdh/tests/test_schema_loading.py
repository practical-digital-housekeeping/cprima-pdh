"""Loading and checking schema files, and parsing the `_schema` value."""
import pytest
from pdh_testkit.paths import TAXONOMY

from cprima_pdh.schema import SchemaError, load_schemas, parse_schema_names, parse_schemas

VALID = [
    ("empty-file", ""),
    ("schema-only", "[schema.a]\nrequired = ['Title']\n"),
    ("facet-and-schema", "[facet.f]\nrequired = ['URL']\n[schema.a]\nfacets = ['f']\n"),
    ("field-with-aliases", "[field.serial_number]\naliases = ['serialnumber']\nprotected = false\n"),
]

INVALID = [
    ("unknown-top-level-section", "[surprise.x]\na = 1\n"),
    ("bad-value-pattern", "[field.f]\npattern = '('\n"),
    ("bad-name-regex", "[field.f]\nmatch = '['\n"),
    ("alias-claimed-by-two-terms", "[field.a]\naliases = ['x']\n[field.b]\naliases = ['x']\n"),
    ("unknown-facet", "[schema.a]\nfacets = ['nope']\n"),
    ("facet-cycle", "[facet.a]\nfacets = ['b']\n[facet.b]\nfacets = ['a']\n[schema.s]\nfacets = ['a']\n"),
    ("unknown-field-type", "[schema.a]\n[schema.a.types]\nX = 'nope'\n"),
    ("old-groups-key-is-rejected", "[schema.a]\ngroups = ['**/X']\n"),
    ("typo-in-a-key", "[schema.a]\nrequired_fields = ['Title']\n"),
    ("not-toml", "this is = = not toml"),
]


@pytest.mark.parametrize("text", [c[1] for c in VALID], ids=[c[0] for c in VALID])
def test_valid_files_load(text):
    parse_schemas(text)


@pytest.mark.parametrize("text", [c[1] for c in INVALID], ids=[c[0] for c in INVALID])
def test_invalid_files_are_rejected(text):
    with pytest.raises(SchemaError):
        parse_schemas(text)


def test_the_public_taxonomy_loads():
    sset = load_schemas(TAXONOMY)
    assert {"website", "onlineshop", "credit-card", "bank-card", "sim-card", "keypair"} <= set(sset.schemas)
    assert "payment-card" not in sset.schemas and "card-core" in sset.facets
    assert "key_material" in sset.fields


def test_missing_file_is_a_schema_error(tmp_path):
    with pytest.raises(SchemaError):
        load_schemas(tmp_path / "nope.toml")


# (value, known schemas, expected (known names, unknown names))
NAMES = [
    ("website", {"website"}, (["website"], [])),
    ("website, shop", {"website", "shop"}, (["website", "shop"], [])),
    ("  website ,, website , ", {"website"}, (["website"], [])),
    ("shop,website", {"website", "shop"}, (["shop", "website"], [])),
    ("website, nope", {"website"}, (["website"], ["nope"])),
    ("nope", {"website"}, ([], ["nope"])),
    ("Website", {"website"}, ([], ["Website"])),
    ("", {"website"}, ([], [])),
    (None, {"website"}, ([], [])),
    (" , ,", {"website"}, ([], [])),
]


@pytest.mark.parametrize("raw,known,expected", NAMES, ids=[repr(n[0]) for n in NAMES])
def test_parse_schema_names(raw, known, expected):
    assert parse_schema_names(raw, known) == expected
