"""The global field vocabulary: alias renames, fixed protection, value patterns, unsupported field names.

Inline vocabulary for the mechanics, plus the public taxonomy as a regression guard.
"""
import pytest
from pdh_testkit.paths import TAXONOMY
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.schema import load_schemas, parse_schemas, validate

VOCAB = parse_schemas("""
[field.secret]
match = '(?i)pin|token|secret|passw|api[ _-]?key'
protected = true

[field.serial_number]
aliases = ["serialnumber", "s/n"]
protected = false

[field.customer_no]
aliases = ["customerno"]
protected = false

[field.phone]
aliases = ["phonenumber"]
pattern = '(tel:)?\\+?[0-9 ()./-]{5,}'
protected = false

[field.mobile]
pattern = '(tel:)?\\+?[0-9 ()./-]{5,}'
protected = false

[schema.card]
optional = ["cardholder"]
""")

V = "vocabulary"
UNKNOWN = (V, "unknown-field")

# (case id, entry, expected {(vocabulary, rule)})
CASES = [
    ("alias-is-flagged", E(custom={"serialnumber": "1"}), {(V, "alias:serial_number")}),
    ("canonical-name-is-fine", E(custom={"serial_number": "1"}), set()),
    ("secret-by-name-must-be-protected", E(custom={"apikey": "k"}), {(V, "protected:secret")}),
    ("secret-by-name-protected-is-fine", E(custom={"apikey": "k"}, protected=("apikey",)), set()),
    ("secret-family-by-regex", E(custom={"Service PIN": "1234"}), {(V, "protected:secret")}),
    ("fixed-non-protection", E(custom={"customer_no": "K1"}, protected=("customer_no",)),
     {(V, "unprotected:customer_no")}),
    ("alias-and-wrong-protection", E(custom={"customerno": "K1"}, protected=("customerno",)),
     {(V, "alias:customer_no"), (V, "unprotected:customer_no")}),
    ("value-pattern-violated", E(custom={"phone": "abc"}), {(V, "pattern:phone")}),
    ("alias-value-pattern-also-checked", E(custom={"phonenumber": "abc"}), {(V, "alias:phone"), (V, "pattern:phone")}),
    ("mobile-is-its-own-term-not-an-alias-of-phone", E(custom={"mobile": "+49 171 000000"}), set()),
    ("keepass2-otp-fields-are-skipped", E(custom={"TimeOtp-Secret-Base32": "ABC"}), set()),
    ("standard-fields-are-not-vocabulary", E(password="pw"), set()),
    # the taxonomy is dogma: a name outside the vocabulary is unsupported
    ("unknown-field-is-unsupported", E(custom={"totally-unrelated": "x"}), {UNKNOWN}),
    ("unknown-field-names-each-field", E(custom={"a": "1", "b": "2"}), {UNKNOWN}),
    ("field-of-an-applied-schema-is-known", E(schema="card", custom={"cardholder": "A"}), set()),
    ("schema-field-without-the-schema-is-unknown", E(custom={"cardholder": "A"}), {UNKNOWN}),
]


@pytest.mark.parametrize("entry,expected", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_vocabulary_findings(entry, expected):
    report = validate(StubKP([entry]), VOCAB)
    assert {(f.schema_name, f.rule) for f in report.findings if f.schema_name == V} == expected


def test_unknown_field_finding_is_a_warn_and_lists_the_fields():
    report = validate(StubKP([E(custom={"b": "2", "a": "1", "serial_number": "3"})]), VOCAB)
    (f,) = [f for f in report.findings if f.rule == "unknown-field"]
    assert (f.level, sorted(f.fields)) == ("WARN", ["a", "b"])


def test_the_schema_field_itself_is_never_unknown():
    report = validate(StubKP([E(schema="card")]), VOCAB)
    assert not [f for f in report.findings if f.rule == "unknown-field"]


def test_no_vocabulary_means_no_unknown_field_rule():
    report = validate(StubKP([E(custom={"anything": "x"})]), parse_schemas("[schema.a]\nrequired = ['Title']\n"))
    assert not [f for f in report.findings if f.rule == "unknown-field"]


# --- the public taxonomy ------------------------------------------------------------------------

REAL = load_schemas(TAXONOMY)

MUST_BE_PROTECTED = [
    "PIN", "PUK", "Service PIN", "ServicePIN", "SO-Pin", "User Pin",
    "apikey", "API Key", "API_KEY", "API Secret", "token", "Access Token",
    "password", "admin password", "2fa-keys", "recovery-code", "recoverycode", "wifi key", "wifikey",
    "ssh rsa key", "private key", "armored key", "gpg passphrase", "wallet seed",
    "ssh_key", "SSH_KEY", "private_key", "rsa_private_key", "ssh_rsa_key", "wallet_seed", "gpg_passphrase", "ssh-key",
    "card_number", "license_key", "CVV",
]
MUST_NOT_BE_FLAGGED = [  # not secret, or deliberately not protected
    "ssh rsa pub", "ssh public key", "fingerprint", "key check value", "Key ID",
    "Access key", "id", "SSID", "MAC", "address", "tel", "mobile", "customer_no",
    "ssh_pub", "ssh_public_key", "ssh_key_fingerprint", "key_fingerprint", "seeded", "sshd_port",
]


@pytest.mark.parametrize("name", MUST_BE_PROTECTED)
def test_real_vocabulary_demands_protection(name):
    report = validate(StubKP([E(custom={name: "1234"})]), REAL)  # unprotected on purpose
    assert any(f.rule.startswith("protected:") and f.fields == [name] for f in report.findings), name


@pytest.mark.parametrize("name", MUST_NOT_BE_FLAGGED)
def test_real_vocabulary_leaves_these_alone(name):
    report = validate(StubKP([E(custom={name: "1234"})]), REAL)
    assert not [f for f in report.findings if f.fields == [name] and f.rule.startswith("protected:")], name


def test_the_public_taxonomy_defines_no_aliases():
    assert not [n for n, t in REAL.fields.items() if t.aliases]


@pytest.mark.parametrize("spelling", ["serialnumber", "Customer ID", "phonenumber", "MAC Address"])
def test_a_non_canonical_spelling_is_unsupported(spelling):
    report = validate(StubKP([E(custom={spelling: "1234"})]), REAL)
    assert any(f.rule == "unknown-field" and spelling in f.fields for f in report.findings), spelling


def test_mobile_is_not_an_alias_of_phone():
    report = validate(StubKP([E(custom={"mobile": "+49 171 000000"})]), REAL)
    assert not [f for f in report.findings if f.rule.startswith("alias:") or f.rule == "unknown-field"]
