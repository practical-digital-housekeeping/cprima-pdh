"""The snapshot validator gives exactly the answers of the XPath engine (the gate for removing the XPath engine).

Both run on the same vault: `schema.validate(kp, sset)` on the live pykeepass object, `validate_entries(snapshot, sset)` on
what the KDBX backend hands out. Compared: the whole report (findings with rule, level, message and fields; per-schema
counts; unclassified). Fixtures: the messy vault, the canonical and the sample vault under both packaged profiles, and a
generated vault that exercises every rule: aliases, closed schemas, https, expiry, protection both ways, patterns, links of every
status, union typing, unknown schema names, field-based typing, OTP plugin fields.
"""
import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault, vaults
from pdh_testkit.mess import messy_vault
from pykeepass import PyKeePass

from cprima_pdh import profiles
from cprima_pdh.backends.kdbx import KdbxVault
from cprima_pdh.schema import (
    links_report,
    links_report_xpath,
    make_ref,
    parse_schemas,
    read,
    read_xpath,
    unclassified,
    unclassified_xpath,
    validate_xpath as validate,
)
from cprima_pdh.source import pykeepass_open
from cprima_pdh.validation import validate_entries

FRAGMENT = parse_schemas("""
[field.serial_number]
aliases = ["serialnumber"]
protected = false
pattern = '[A-Z]{2}-[0-9]+'

[field.PIN]
protected = true
pattern = '[0-9]{4}'

[field.secret]
match = '(?i)token|api[ _-]?key'
protected = true

[field.device]
kind = "link"

[field.customer_no]
aliases = ["customerno"]

[facet.login]
required = ["Title", "UserName", "Password", "URL"]
https_only = true

[schema.website]
facets = ["login"]

[schema.shop]
facets = ["login"]
recommended = ["customer_no"]
closed = true
expires = true

[schema.card]
required = ["Title"]
protected = ["PIN"]
closed = true
[schema.card.types]
PIN = "PIN"

[schema.hardware]
required = ["Title"]
optional = ["serial_number"]
[schema.hardware.types]
serial_number = "serial_number"

[schema.device-account]
required = ["Title", "device"]
[schema.device-account.links]
device = ["hardware"]

[[match]]
schema = "hardware"
has = ["serial_number"]
""")

ENTRIES = [
    Entry("ok site", group="G", username="u", password="p", url="https://ok.example.org", custom={"_schema": "website"}),
    Entry("http site", group="G", username="u", password="p", url="HTTP://x.example.org", custom={"_schema": "website"}),
    Entry("blank url", group="G", username="u", password="p", url="   ", custom={"_schema": "website"}),
    Entry("no user", group="G", username="", password="p", url="https://x.org", custom={"_schema": "website"}),
    Entry("shop", group="G", username="u", password="p", url="https://s.org", custom={"_schema": "shop", "stray": "1", "TimeOtp-Secret-Base32": "X"}),
    Entry("shop ok", group="G", username="u", password="p", url="https://s.org", custom={"_schema": "shop", "customer_no": "C"},
          expires=__import__("datetime").datetime(2031, 1, 1, tzinfo=__import__("datetime").timezone.utc)),
    Entry("alias", group="G", username="u", password="p", url="https://a.org", custom={"_schema": "website", "serialnumber": "XY-1", "customerno": "9"}),
    Entry("union", group="G", username="u", password="p", url="https://u.org", custom={"_schema": "shop, website", "x": "y"}),
    Entry("card bad pin", group="G", custom={"_schema": "card", "PIN": "12"}),
    Entry("card good pin", group="G", custom={"_schema": "card", "PIN": "1234"}, protected=frozenset({"PIN"})),
    Entry("card unprotected", group="G", custom={"_schema": "card", "PIN": "1234"}),
    Entry("card extra", group="G", custom={"_schema": "card", "PIN": "1234", "other": "1"}, protected=frozenset({"PIN"})),
    Entry("hw", group="G", custom={"_schema": "hardware", "serial_number": "AB-1"}),
    Entry("hw bad serial", group="G", custom={"_schema": "hardware", "serial_number": "bad"}),
    Entry("hw by fields only", group="G", custom={"serial_number": "CD-2"}),
    Entry("acct good", group="G", custom={"_schema": "device-account"}),
    Entry("acct dangling", group="G", custom={"_schema": "device-account", "device": "{REF:T@I:00000000000000000000000000000000}"}),
    Entry("acct invalid", group="G", custom={"_schema": "device-account", "device": "not-a-link"}),
    Entry("acct self", group="G", custom={"_schema": "device-account"}),
    Entry("acct wrong", group="G", custom={"_schema": "device-account"}),
    Entry("acct unclassified target", group="G", custom={"_schema": "device-account"}),
    Entry("plain target", group="G", custom={}),
    Entry("unknown schema", group="G", custom={"_schema": "nope, website"}, username="u", password="p", url="https://z.org"),
    Entry("untyped", group="G", username="u", password="p", custom={"api_key": "k", "token": "t", "weird": "w", "PIN": "1"}),
    Entry("untyped protected", group="G", custom={"api_key": "k"}, protected=frozenset({"api_key"})),
    Entry("serial protected", group="G", custom={"serial_number": "EF-3"}, protected=frozenset({"serial_number"})),
    Entry("in bin", group="Bin stand-in", username="u", password="p", custom={"_schema": "website"}),
]


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    path = synthetic_vault(tmp_path_factory.mktemp("parity") / "p.kdbx", ENTRIES)
    kp = PyKeePass(str(path), password=DEFAULT_PASSWORD)
    by = {e.title: e for e in kp.entries}
    by["acct good"].set_custom_property("device", make_ref(by["hw"].uuid))
    by["acct self"].set_custom_property("device", make_ref(by["acct self"].uuid))
    by["acct wrong"].set_custom_property("device", make_ref(by["ok site"].uuid))
    by["acct unclassified target"].set_custom_property("device", make_ref(by["plain target"].uuid))
    kp.trash_entry(by["in bin"])
    kp.save()
    return path


def both(path, sset):
    kp = pykeepass_open(path, DEFAULT_PASSWORD, None)
    return validate(kp, sset), validate_entries(KdbxVault(kp).entries(), sset)


def show(old, new):
    return f"\nold-only: {[f for f in old.findings if f not in new.findings][:5]}\nnew-only: {[f for f in new.findings if f not in old.findings][:5]}"


@pytest.mark.parametrize("sset", [FRAGMENT, profiles.load("pdh-default"), profiles.load("pdh-minimal")],
                         ids=["fragment", "pdh-default", "pdh-minimal"])
def test_the_generated_vault_gives_identical_reports(generated, sset):
    old, new = both(generated, sset)
    assert old.findings == new.findings, show(old, new)
    assert old == new


def test_the_generated_vault_really_exercises_the_rules(generated):
    """Guards the test itself: the fragment must produce a wide variety of findings, or parity proves little."""
    old, _ = both(generated, FRAGMENT)
    kinds = {f.rule.split(":")[0] for f in old.findings} | {f.rule for f in old.findings}
    for needed in ("required", "recommended", "protected", "unprotected", "url:https", "expires", "alias", "pattern",
                   "closed:unknown-field", "unknown-field", "link:invalid", "link:dangling", "link:self",
                   "link:wrong-schema", "link:target-unclassified", "schema:unknown"):
        assert needed in kinds, f"the generated vault never triggers {needed}"
    assert old.unclassified_entries >= 2


def test_the_messy_vault_gives_identical_reports(tmp_path):
    path = messy_vault(tmp_path / "m.kdbx").path
    for sset in (profiles.load("pdh-default"), FRAGMENT):
        old, new = both(path, sset)
        assert old == new, show(old, new)


def test_the_canonical_and_the_sample_vault_give_identical_reports():
    from pdh_testkit.paths import REPO_ROOT

    sset = profiles.load("pdh-default")
    for p, pw in ((vaults.load("canonical-kdbx4").path, vaults.load("canonical-kdbx4").password),
                  (REPO_ROOT / "examples" / "pdh-default" / "sample.kdbx", "sample-test")):
        kp = pykeepass_open(p, pw, None)
        old, new = validate(kp, sset), validate_entries(KdbxVault(kp).entries(), sset)
        assert old == new, show(old, new)
        assert old.findings == []  # (both are conforming by construction)


def test_read_links_and_unclassified_reports_are_identical_too(generated):
    for sset in (FRAGMENT, profiles.load("pdh-default")):
        kp = pykeepass_open(generated, DEFAULT_PASSWORD, None)
        assert read(kp, sset) == read_xpath(kp, sset)
        assert read(kp, sset, only="card") == read_xpath(kp, sset, only="card")
        assert links_report(kp, sset) == links_report_xpath(kp, sset)
        assert unclassified(kp, sset, True) == unclassified_xpath(kp, sset, True)
