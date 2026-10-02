"""The public taxonomy: completeness, consistency, and that proposals never change validation."""
import re

import pytest
from pdh_testkit.paths import PACKAGED_TAXONOMY, TAXONOMY, TAXONOMY_MD
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.schema import KINDS, load_schemas, parse_schemas, validate
from cprima_pdh.taxonomy import build

SSET = load_schemas(TAXONOMY)
ALL_TERMS = {**SSET.fields, **SSET.proposed_fields}
ALL_SCHEMAS = {**SSET.schemas, **SSET.proposed_schemas}


# --- completeness: nothing half-filled ---------------------------------------------------------

@pytest.mark.parametrize("name", sorted(ALL_TERMS))
def test_every_term_has_a_description_and_a_kind(name):
    term = ALL_TERMS[name]
    assert term.description.strip(), f"field.{name} needs a description"
    assert term.kind in KINDS, f"field.{name} needs a kind"


@pytest.mark.parametrize("name", sorted(ALL_SCHEMAS))
def test_every_schema_has_a_description_and_a_family(name):
    schema = ALL_SCHEMAS[name]
    assert schema.description.strip(), f"schema.{name} needs a description"
    assert schema.family in SSET.families, f"schema.{name} needs a known family"


@pytest.mark.parametrize("kind", KINDS)
def test_every_kind_is_documented(kind):
    assert kind in SSET.kinds and SSET.kinds[kind].description.strip()


@pytest.mark.parametrize("name", sorted(SSET.areas))
def test_every_area_has_a_description(name):
    assert SSET.areas[name].description.strip()


@pytest.mark.parametrize("name", sorted(SSET.families))
def test_every_family_has_a_description_and_members(name):
    assert SSET.families[name].description.strip()
    used = [s for s in ALL_SCHEMAS.values() if s.family == name] + [t for t in ALL_TERMS.values() if name in t.family]
    assert used, f"family {name!r} is empty"


# --- consistency ------------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(ALL_TERMS))
def test_secrets_keys_and_cards_are_protected(name):
    term = ALL_TERMS[name]
    if term.kind in ("secret", "key", "card", "otp"):
        assert term.protected is True, f"field.{name} is a {term.kind}: protected must be true"


@pytest.mark.parametrize("name", sorted(ALL_TERMS))
def test_identifiers_are_not_protected(name):
    term = ALL_TERMS[name]
    if term.kind == "identifier":
        assert term.protected is not True, f"field.{name} is an identifier, not a secret"


@pytest.mark.parametrize("name", sorted(ALL_TERMS))
def test_canonical_term_names_have_no_spaces(name):
    assert not re.search(r"\s", name), f"field.{name}: no spaces in labels"


ABBREVIATIONS = {"pin", "puk", "cvv", "iban", "bic", "iccid", "imei", "mac", "ssid"}


@pytest.mark.parametrize("name", sorted(ALL_TERMS))
def test_abbreviations_are_uppercase(name):
    """Decided: abbreviations such as PIN are capitals; snake_case is not applied mechanically."""
    if name.lower() in ABBREVIATIONS:
        assert name == name.upper(), f"field.{name}: abbreviations are written in capitals"


def test_decisions_are_dated_and_the_open_ones_are_listed():
    assert SSET.decisions
    assert all(re.fullmatch(r"\d{4}-\d{2}-\d{2}", d.date) for d in SSET.decisions)
    assert {"decided", "open"} == {d.status for d in SSET.decisions}


def test_sources_have_urls():
    assert SSET.sources and all(s.url.startswith("https://") for s in SSET.sources)


# --- proposals are documentation only ----------------------------------------------------------

def test_proposed_items_are_not_active():
    assert "IBAN" in SSET.proposed_fields and "IBAN" not in SSET.fields
    assert "bank-account" in SSET.proposed_schemas and "bank-account" not in SSET.schemas


def test_a_proposed_term_changes_no_validation_result():
    sset = parse_schemas("""
[field.serial_number]
aliases = ["serialnumber"]
protected = false

[field.api_key]
status = "proposed"
kind = "secret"
aliases = ["apikey"]
protected = true

[schema.shop]
status = "proposed"
""")
    entry = E(custom={"apikey": "k", "serialnumber": "1", "_x": "y"}, schema="shop")
    report = validate(StubKP([entry]), sset)
    rules = {(f.schema_name, f.rule) for f in report.findings}
    # `apikey` and `_x` are not active terms: unsupported (the proposed `api_key` and its alias change nothing)
    assert rules == {("vocabulary", "alias:serial_number"), ("schema-field", "schema:unknown"),
                     ("vocabulary", "unknown-field")}


def test_a_proposed_alias_may_not_clash_with_an_active_term():
    from cprima_pdh.schema import SchemaError

    with pytest.raises(SchemaError):
        parse_schemas("""
[field.a]
aliases = ["x"]
[field.b]
status = "proposed"
aliases = ["x"]
""")


# --- the generated document --------------------------------------------------------------------

def test_the_document_names_every_area_schema_and_term():
    md = build(SSET).markdown
    for name in [*SSET.areas, *ALL_SCHEMAS, *ALL_TERMS, *SSET.families, *KINDS]:
        assert name in md, f"{name} is missing from the generated document"


def test_the_document_has_its_sections_and_no_leftovers():
    md = build(SSET).markdown
    for heading in ("## Principles", "## Axes", "## Naming rules", "## Binding rules", "## Areas",
                    "## Record types (schemas)", "## Field kinds", "## Field vocabulary", "## Sources",
                    "## Decision log"):
        assert heading in md
    allowed_braces = ("{4,8}", "{3,4}", "{13,23}", "{5,}", "{8}", "{REF:T@I:...}")  # patterns and the link syntax
    stripped = md
    for token in allowed_braces:
        stripped = stripped.replace(token, "")
    assert "None" not in md and "{" not in stripped


def test_the_document_is_deterministic_and_marks_status():
    assert build(SSET).markdown == build(SSET).markdown
    md = build(SSET).markdown
    assert "| proposed |" in md and "| implemented |" in md


def test_taxonomy_md_is_current():
    """TAXONOMY.md is generated from schemas.toml; this fails when someone changed one but not the other."""
    on_disk = TAXONOMY_MD.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    assert on_disk == build(SSET).markdown, "TAXONOMY.md is stale: regenerate it with `just taxonomy`"


def test_the_packaged_taxonomy_is_the_source():
    """The wheel ships a copy of method/taxonomy/schemas.toml; `just taxonomy` refreshes it."""
    assert PACKAGED_TAXONOMY.read_bytes() == TAXONOMY.read_bytes(), "packaged copy is stale: run `just taxonomy`"

def test_the_decision_log_is_newest_first():
    log = build(SSET).markdown.split("## Decision log")[1]
    dates = re.findall(r"- (\d{4}-\d{2}-\d{2}) ", log)
    assert dates == sorted(dates, reverse=True)
