"""Credit card versus bank card, against the public taxonomy.

A card has a validity (the entry's expiry date). A credit card may carry a CVV (allowed, not required);
a bank card has none, so a CVV on it is an unknown field. Nothing here judges whether a value is correct.
"""
import pytest
from pdh_testkit.paths import TAXONOMY
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.schema import load_schemas, validate

REAL = load_schemas(TAXONOMY)

PROTECTED = ("PIN", "card_number", "CVV")  # as KeePass protects them; keeps the vocabulary out of these cases


def card(schema: str, custom: dict[str, str], expires: bool = True, **kw):
    return E(schema=schema, url="", custom=custom, protected=PROTECTED, expires=expires, **kw)


# (case id, entry, expected {(schema, rule)})
CASES = [
    ("bank-card-with-a-pin-only", card("bank-card", {"PIN": "1234"}), set()),
    ("bank-card-with-number-and-pin", card("bank-card", {"PIN": "1234", "card_number": "4111 1111 1111 1111"}), set()),
    ("bank-card-without-validity", card("bank-card", {"PIN": "1234"}, expires=False), {("bank-card", "expires")}),
    ("bank-card-with-a-cvv-is-a-mismatch", card("bank-card", {"PIN": "1234", "CVV": "123"}),
     {("bank-card", "closed:unknown-field")}),
    ("bank-card-with-another-unknown-field", card("bank-card", {"PIN": "1234", "foo": "x"}),
     {("bank-card", "closed:unknown-field")}),
    ("credit-card-with-a-cvv", card("credit-card", {"card_number": "4111 1111 1111 1111", "CVV": "123"}), set()),
    ("credit-card-without-a-cvv-is-fine", card("credit-card", {"card_number": "4111 1111 1111 1111"}), set()),
    ("credit-card-without-validity", card("credit-card", {"CVV": "123"}, expires=False), {("credit-card", "expires")}),
    ("credit-card-with-an-unknown-field", card("credit-card", {"CVV": "123", "foo": "x"}),
     {("credit-card", "closed:unknown-field")}),
    ("card-and-website-on-one-entry", E(schema="credit-card, website", custom={"CVV": "123"}, protected=PROTECTED,
                                        expires=True), set()),
    ("card-and-website-needs-the-websites-url", card("credit-card, website", {"CVV": "123"}),
     {("website", "required:URL")}),
    ("card-number-must-be-protected", E(schema="bank-card", url="", custom={"card_number": "4111 1111 1111 1111"},
                                        protected=(), expires=True), {("vocabulary", "protected:card_number")}),
    ("payment-card-no-longer-exists", E(schema="payment-card"), {("schema-field", "schema:unknown")}),
]


@pytest.mark.parametrize("entry,expected", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_card_findings(entry, expected):
    report = validate(StubKP([entry]), REAL)
    assert {(f.schema_name, f.rule) for f in report.findings} == expected


def test_both_card_types_share_one_facet():
    assert REAL.schemas["credit-card"].facets == ["card-core"]
    assert REAL.schemas["bank-card"].facets == ["card-core"]
    assert REAL.facets["card-core"].expires is True


def test_the_only_difference_is_the_cvv():
    assert REAL.schemas["credit-card"].optional == ["CVV"]
    assert REAL.schemas["bank-card"].optional == []
