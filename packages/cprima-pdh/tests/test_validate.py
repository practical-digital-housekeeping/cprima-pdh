"""Table-driven validation cases: an entry with defined properties -> the findings it must produce.

Expected is a set of (schema, rule). An empty set means the entry is valid. No files are touched.
"""
import pytest
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.schema import SCHEMA_PSEUDO, parse_schemas, read, summarize, unclassified, validate

SCHEMAS = parse_schemas("""
[field.pin]
pattern = '[0-9]{4,8}'

[field.cvv]
pattern = '[0-9]{3,4}'

[facet.login]
required = ["Title", "UserName", "Password", "URL"]
https_only = true

[schema.website]
facets = ["login"]

[schema.shop]
facets = ["login"]
optional = ["customer_no"]
closed = true

[schema.card]
required = ["Title", "card_number", "pin"]
optional = ["cardholder"]
expires = true
closed = true

[schema.card.types]
pin = "pin"

[schema.a]
optional = ["X"]

[schema.a.types]
X = "pin"

[schema.b]
optional = ["X"]

[schema.b.types]
X = "cvv"

[schema.aliased]
[schema.aliased.aliases]
customer_no = ["customerno"]

[schema.vault]
protected = ["token"]

[schema.locked]
protected = ["token"]
closed = true
""")

UNKNOWN = (SCHEMA_PSEUDO, "schema:unknown")
CARD = {"card_number": "4111111111111111", "pin": "1234"}

# (case id, entry, expected {(schema, rule)})
CASES = [
    # --- one schema -------------------------------------------------------
    ("website-valid", E(schema="website"), set()),
    ("website-http-and-no-username", E(schema="website", username="", url="http://x.example"),
     {("website", "required:UserName"), ("website", "url:https")}),
    ("website-empty-title-and-password", E(schema="website", title="", password=""),
     {("website", "required:Title"), ("website", "required:Password")}),
    ("website-url-with-uppercase-scheme-is-fine", E(schema="website", url="HTTPS://X.example"), set()),
    ("shop-optional-field-allowed", E(schema="shop", custom={"customer_no": "K1"}), set()),
    ("shop-closed-flags-unknown-field", E(schema="shop", custom={"foo": "x"}), {("shop", "closed:unknown-field")}),
    ("shop-totp-field-is-always-allowed", E(schema="shop", totp="otpauth://totp/x?secret=ABC"), set()),
    ("shop-keepass2-otp-fields-allowed", E(schema="shop", custom={"TimeOtp-Secret-Base32": "ABC"}), set()),
    ("card-valid", E(schema="card", url="", custom=CARD, expires=True), set()),
    ("card-missing-pin-and-expiry", E(schema="card", url="", custom={"card_number": "4111"}),
     {("card", "required:pin"), ("card", "expires")}),
    ("card-pin-fails-type-pattern", E(schema="card", url="", custom={"card_number": "4111", "pin": "12"}, expires=True),
     {("card", "pattern:pin")}),
    ("closed-schema-knows-fields-it-declares-as-protected",
     E(schema="locked", custom={"token": "t"}, protected=("token",)), set()),
    ("alias-must-be-renamed", E(schema="aliased", custom={"customerno": "K1"}), {("aliased", "alias:customer_no")}),
    ("protected-field-unprotected", E(schema="vault", custom={"token": "t"}), {("vault", "protected:token")}),
    ("protected-field-protected", E(schema="vault", custom={"token": "t"}, protected=("token",)), set()),

    # --- no schema --------------------------------------------------------
    ("no-schema-is-unchecked", E(username="", url=""), set()),
    ("empty-schema-value-is-unclassified", E(schema="", username=""), set()),
    ("whitespace-and-duplicate-names", E(schema=" website ,, website ,  "), set()),

    # --- several schemas: union -------------------------------------------
    ("two-schemas-share-a-rule-reported-once", E(schema="shop, website", url=""), {("shop", "required:URL")}),
    ("union-allows-fields-of-either-schema", E(schema="card, website", custom=CARD, expires=True), set()),
    ("closed-over-the-union", E(schema="shop, website", custom={"customer_no": "K1", "foo": "x"}),
     {("shop+website", "closed:unknown-field")}),
    ("one-closed-schema-closes-the-union", E(schema="website, card", custom={**CARD, "foo": "x"}, expires=True),
     {("website+card", "closed:unknown-field")}),
    ("same-field-typed-differently", E(schema="a, b", custom={"X": "1234"}), {("a+b", "schema:type-conflict")}),
    ("type-pattern-applies-per-schema", E(schema="a", custom={"X": "12"}), {("a", "pattern:X")}),

    # --- unknown names ----------------------------------------------------
    ("unknown-name-reported-known-one-applies", E(schema="website, nope"), {UNKNOWN}),
    ("unknown-name-and-known-one-failing", E(schema="website, nope", username=""),
     {UNKNOWN, ("website", "required:UserName")}),
    ("only-unknown-name", E(schema="nope"), {UNKNOWN}),
    ("names-are-case-sensitive", E(schema="Website"), {UNKNOWN}),
]


def findings_of(entry) -> set[tuple[str, str]]:
    return {(f.schema_name, f.rule) for f in validate(StubKP([entry]), SCHEMAS).findings}


@pytest.mark.parametrize("entry,expected", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_entry_findings(entry, expected):
    assert findings_of(entry) == expected


def test_statistics_per_schema_and_unclassified():
    entries = [
        E(title="ok", schema="website"),
        E(title="bad", schema="website", username=""),
        E(title="both", schema="shop, website"),
        E(title="none"),
        E(title="only-unknown", schema="nope"),
    ]
    report = validate(StubKP(entries), SCHEMAS)
    assert report.schemas["website"].entries == 3      # ok, bad, both
    assert report.schemas["website"].conforming == 2   # ok, both
    assert report.schemas["shop"].entries == 1
    assert report.schemas["shop"].conforming == 1
    assert report.unclassified_entries == 2            # none, only-unknown


def test_summary_counts_distinct_entries_per_rule():
    entries = [E(title=f"e{i}", schema="website", username="") for i in range(3)]
    summary = summarize(validate(StubKP(entries), SCHEMAS))
    row = next(r for r in summary.rules if r.rule == "required:UserName")
    assert row.entries == 3


def test_unclassified_lists_entries_without_a_valid_schema():
    entries = [
        E(title="typed", schema="website", group="Money"),
        E(title="plain", group="Money"),
        E(title="typo", schema="nope", group="Online"),
    ]
    report = unclassified(StubKP(entries), SCHEMAS, list_entries=True)
    assert report.total == 2
    assert report.per_group == {"Money": 1, "Online": 1}
    assert report.entries == ["Money/plain", "Online/typo"]


def test_read_hides_protected_values_and_lists_one_record_per_schema():
    secret = "TOPSECRET-VALUE-123"
    e = E(title="t", schema="vault, website", custom={"token": secret}, protected=("token",))
    report = read(StubKP([e]), SCHEMAS)
    assert sorted(r.schema_name for r in report.entries) == ["vault", "website"]
    vault = next(r for r in report.entries if r.schema_name == "vault")
    assert vault.fields["token"] == "(protected)"
    assert secret not in report.model_dump_json()


def test_no_value_ever_appears_in_findings():
    secret = "SECRETVALUE9"  # fails the pin pattern, so it is compared but must not be reported
    e = E(schema="card", url="", custom={"card_number": "4111", "pin": secret}, expires=True)
    assert secret not in validate(StubKP([e]), SCHEMAS).model_dump_json()
