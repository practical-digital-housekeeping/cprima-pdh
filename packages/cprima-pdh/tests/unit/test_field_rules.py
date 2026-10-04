"""`_schema` and/or field-based match rules: an entry's record types are the union of both.

    [[match]]
    schema = "bank-account"
    has = ["IBAN"]          # every field listed is present (non-empty)

An entry with the field is typed `bank-account` even without a `_schema`; with a `_schema` too, both apply.
"""
import pytest
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.conform import conformance
from cprima_pdh.schema import SchemaError, parse_schemas, typing_of, unclassified, validate

TOML = """
[facet.login]
required = ["Title", "UserName", "Password", "URL"]

[schema.website]
facets = ["login"]

[schema.bank-account]
facets = ["login"]
required = ["IBAN"]

[schema.credit-card]
required = ["Title"]
optional = ["card_number", "CVV"]
closed = true

[schema.membership]
required = ["Title", "member_no"]

[schema.wifi-access-point]
required = ["Title", "SSID"]
recommended = ["wifi_key"]

[[match]]
schema = "bank-account"
has = ["IBAN"]

[[match]]
schema = "credit-card"
has = ["CVV"]

[[match]]
schema = "membership"
has = ["member_no"]

[[match]]
schema = "wifi-access-point"
has = ["SSID", "wifi_key"]

[[match]]
schema = "wifi-access-point"
has = ["SSID", "MAC"]
"""
SSET = parse_schemas(TOML)
NO_LOGIN = dict(username="", password="", url="")


def typing(entry):
    return typing_of(entry, SSET)


# --- the semantics -------------------------------------------------------------------------------

def test_a_field_binds_a_record_type_without_any_schema_field():
    t = typing(E(custom={"IBAN": "x"}))
    assert (t.explicit, t.by_fields, t.unknown) == ([], ["bank-account"], [])


def test_schema_alone_still_works():
    t = typing(E(schema="website"))
    assert (t.explicit, t.by_fields) == (["website"], [])


def test_both_apply_together():
    t = typing(E(schema="website", custom={"member_no": "7"}))
    assert (t.explicit, t.by_fields) == (["website"], ["membership"])


def test_a_type_named_and_matched_counts_once_as_explicit():
    t = typing(E(schema="bank-account", custom={"IBAN": "x"}))
    assert (t.explicit, t.by_fields) == (["bank-account"], [])


def test_every_listed_field_is_needed():
    assert typing(E(**NO_LOGIN, custom={"SSID": "n"})).by_fields == []
    assert typing(E(**NO_LOGIN, custom={"SSID": "n", "wifi_key": "k"})).by_fields == ["wifi-access-point"]


def test_several_rules_may_bind_one_type_and_it_is_bound_once():
    t = typing(E(**NO_LOGIN, custom={"SSID": "n", "wifi_key": "k", "MAC": "m"}))
    assert t.by_fields == ["wifi-access-point"]


def test_an_empty_field_does_not_count():
    assert typing(E(custom={"IBAN": ""})).by_fields == []


def test_standard_fields_count_too():
    sset = parse_schemas('[schema.login]\nrequired=["Title"]\n[[match]]\nschema="login"\nhas=["URL","Password"]\n')
    assert typing_of(E(), sset).by_fields == ["login"] and typing_of(E(url=""), sset).by_fields == []


def test_an_unknown_schema_name_is_still_reported_and_does_not_hide_the_rules():
    t = typing(E(schema="nope", custom={"IBAN": "x"}))
    assert (t.explicit, t.by_fields, t.unknown) == ([], ["bank-account"], ["nope"])


# --- what the rest of the tool sees ------------------------------------------------------------------

def test_a_field_bound_type_is_checked_like_an_explicit_one():
    rep = validate(StubKP([E(url="", custom={"IBAN": "x"})]), SSET)  # no URL: bank-account requires it
    assert [(f.schema_name, f.rule) for f in rep.findings] == [("bank-account", "required:URL")]


def test_field_bound_entries_are_typed_not_unclassified():
    entries = [E(title="a", custom={"IBAN": "x"}), E(title="b")]
    rep = conformance(StubKP(entries), SSET, status="all")
    assert (rep.conform, rep.unclassified) == (1, 1)
    assert unclassified(StubKP(entries), SSET, True).entries == ["Area/b"]


def test_explicit_and_field_rules_each_add_their_requirements():
    """A website that also carries an IBAN is a bank-account too: the IBAN rule asks nothing more, the login is shared."""
    rep = conformance(StubKP([E(schema="website", custom={"IBAN": "x"})]), SSET, status="all")
    assert rep.conform == 1


def test_a_closed_type_still_refuses_unknown_fields_when_bound_by_a_field():
    rep = validate(StubKP([E(**NO_LOGIN, custom={"CVV": "1", "Fax": "2"})]), SSET)
    assert ("credit-card", "closed:unknown-field") in {(f.schema_name, f.rule) for f in rep.findings}


# --- the file -------------------------------------------------------------------------------------

@pytest.mark.parametrize("text,fragment", [
    ('[[match]]\nschema = "nope"\nhas = ["X"]\n', "nope"),                       # the type must exist
    ('[schema.a]\nstatus = "proposed"\n[[match]]\nschema = "a"\nhas = ["X"]\n', "a"),  # and be active
    ('[schema.a]\n[[match]]\nschema = "a"\nhas = []\n', ""),                     # a rule needs a field
    ('[schema.a]\n[[match]]\nschema = "a"\n', ""),
    ('[schema.a]\n[[match]]\nschema = "a"\nhas = ["X"]\nwhen = "y"\n', ""),      # nothing else is a key
])
def test_a_bad_match_rule_is_rejected(text, fragment):
    with pytest.raises(SchemaError):
        parse_schemas(text)


def test_matches_are_kept_in_file_order():
    assert [(m.schema_name, m.has) for m in SSET.matches][:2] == [("bank-account", ["IBAN"]), ("credit-card", ["CVV"])]
