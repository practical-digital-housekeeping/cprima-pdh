"""The public taxonomy: completeness, consistency, and that proposals never change validation."""
import re

import pytest
from pdh_testkit.paths import TAXONOMY
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.schema import load_schemas, parse_schemas, resolve, validate
from cprima_pdh.taxonomy import build

SSET = load_schemas(TAXONOMY)
ALL_TERMS = {**SSET.fields, **SSET.proposed_fields}
ALL_SCHEMAS = {**SSET.schemas, **SSET.proposed_schemas}


# --- completeness: nothing half-filled ---------------------------------------------------------

@pytest.mark.parametrize("name", sorted(ALL_TERMS))
def test_every_term_has_a_description_and_a_kind(name):
    term = ALL_TERMS[name]
    assert term.description.strip(), f"field.{name} needs a description"
    assert term.kind in SSET.kinds, f"field.{name} needs a kind"


@pytest.mark.parametrize("name", sorted(ALL_SCHEMAS))
def test_every_schema_has_a_description_and_a_family(name):
    schema = ALL_SCHEMAS[name]
    assert schema.description.strip(), f"schema.{name} needs a description"
    assert schema.family in SSET.families, f"schema.{name} needs a known family"


@pytest.mark.parametrize("kind", sorted(SSET.kinds))
def test_every_kind_is_documented(kind):
    assert SSET.kinds[kind].description.strip()


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


# --- the default profile: opinionated, complete, enforced -----------------------------------------

STANDARD = set(SSET.standard)  # declared by the profile itself


def _named_fields(defn):
    return {*defn.required, *defn.recommended, *defn.optional, *defn.protected, *defn.links}


def test_the_default_profile_has_nothing_merely_proposed():
    assert not SSET.proposed_fields and not SSET.proposed_schemas


@pytest.mark.parametrize("name", sorted({**SSET.schemas, **SSET.facets}))
def test_a_field_a_record_type_names_is_a_vocabulary_term(name):
    defn = {**SSET.facets, **SSET.schemas}[name]
    unknown = _named_fields(defn) - set(SSET.fields) - STANDARD
    assert not unknown, f"{name} names fields that are not vocabulary terms: {sorted(unknown)}"


def test_the_default_profile_uses_no_schema_local_aliases_or_types():
    for name, defn in {**SSET.facets, **SSET.schemas}.items():
        assert not defn.aliases and not defn.types, f"{name}: use vocabulary terms, not local aliases/types"


@pytest.mark.parametrize("name", sorted(ALL_TERMS))
def test_terms_follow_the_label_style(name):
    """snake_case; a term that is itself an abbreviation is all capitals; no compound mixes cases."""
    if name.isupper():
        return  # PIN, MAC, SSID, ...
    assert re.fullmatch(r"[a-z][a-z0-9]*(_[a-z0-9]+)*", name), f"field.{name}: snake_case expected"


@pytest.mark.parametrize("name", sorted(SSET.schemas))
def test_schema_names_are_kebab_case(name):
    assert re.fullmatch(r"[a-z][a-z0-9]*(-[a-z0-9]+)*", name)


# --- proposals are documentation only ----------------------------------------------------------

def test_a_proposed_item_is_documentation_not_a_rule():
    sset = parse_schemas('[field.IBAN]\nstatus = "proposed"\n[schema.bank-account]\nstatus = "proposed"\n')
    assert "IBAN" in sset.proposed_fields and "IBAN" not in sset.fields
    assert "bank-account" in sset.proposed_schemas and "bank-account" not in sset.schemas


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
    for name in [*SSET.areas, *ALL_SCHEMAS, *ALL_TERMS, *SSET.families, *SSET.kinds]:
        assert name in md, f"{name} is missing from the generated document"


def test_the_document_has_its_sections_and_no_leftovers():
    md = build(SSET).markdown
    for heading in ("## Principles", "## Axes", "## Naming rules", "## Binding rules", "## Areas",
                    "## Record types (schemas)", "## Field-based matching", "## Finding levels", "## Advice", "## Standard fields",
                    "## Field kinds", "## Field vocabulary", "## Sources", "## Decision log"):
        assert heading in md
    allowed_braces = ("{4,8}", "{3,4}", "{13,23}", "{5,}", "{8}", "{REF:T@I:...}",
                      "{entry}", "{term}", "{field}", "{binding}")  # patterns, the link syntax and the advice templates
    stripped = md
    for token in allowed_braces:
        stripped = stripped.replace(token, "")
    assert "None" not in md and "{" not in stripped


def test_the_document_is_deterministic_and_names_its_profile():
    assert build(SSET).markdown == build(SSET).markdown
    md = build(SSET).markdown
    assert "| implemented |" in md and "| proposed |" not in md  # the default profile enforces everything
    assert "profile `pdh-default` (version 0.1)" in md


def test_the_matching_section_appears_only_with_match_rules():
    plain = build(parse_schemas("[schema.a]\nrequired = ['Title']\n")).markdown
    ruled = build(parse_schemas("[schema.a]\nrequired = ['Title']\n[[match]]\nschema='a'\nhas=['X']\n"
                                "[[match]]\nschema='a'\nhas=['Y','Z']\n")).markdown
    assert "Field-based matching" not in plain
    assert "| `a` | `X` or `Y` and `Z` |" in ruled


# --- the match rules of the default profile ----------------------------------------------------------

def test_match_rules_name_vocabulary_terms_and_active_types():
    for m in SSET.matches:
        assert m.schema_name in SSET.schemas
        assert set(m.has) <= set(SSET.fields) | STANDARD, (m.schema_name, m.has)


def test_a_match_rule_only_uses_fields_that_belong_to_one_type_alone():
    """The guarantee behind 'a rule never guesses': no other record type names the field a rule is built on."""
    for m in SSET.matches:
        flat = {n: resolve(d, SSET.facets) for n, d in SSET.schemas.items()}
        others = [n for n, d in flat.items() if n != m.schema_name and set(m.has) <= _named_fields(d)]
        assert not others, f"rule {m.schema_name} {m.has} is also satisfiable by the type(s) {others}"


def test_proposed_items_are_marked_in_the_document():
    md = build(parse_schemas('[field.IBAN]\nstatus = "proposed"\ndescription = "x"\nkind = "identifier"\n')).markdown
    assert "| proposed |" in md


def test_the_decision_log_is_newest_first():
    log = build(SSET).markdown.split("## Decision log")[1]
    dates = re.findall(r"- (\d{4}-\d{2}-\d{2}) ", log)
    assert dates == sorted(dates, reverse=True)
